package handler

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/bluerange/bluerange/internal/auth"
	"github.com/bluerange/bluerange/internal/db"
	"github.com/bluerange/bluerange/internal/enrichment"
	"github.com/bluerange/bluerange/internal/grader"
	"github.com/bluerange/bluerange/internal/lab"
)

type Handler struct {
	db       *db.DB
	labs     *lab.Registry
	tmpls    map[string]*template.Template
	staticFS http.Handler
	log      *slog.Logger
}

func New(database *db.DB, labs *lab.Registry, tmpls map[string]*template.Template, staticDir string, log *slog.Logger) *Handler {
	return &Handler{
		db:       database,
		labs:     labs,
		tmpls:    tmpls,
		staticFS: http.FileServer(http.Dir(staticDir)),
		log:      log,
	}
}

func (h *Handler) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(auth.Middleware(h.db))

	r.Handle("/static/*", http.StripPrefix("/static/", h.staticFS))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		if auth.UserFromCtx(r.Context()) != nil {
			http.Redirect(w, r, "/queue", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}
	})

	r.Get("/login", h.getLogin)
	r.Post("/login", h.postLogin)
	r.Post("/logout", h.postLogout)
	r.Get("/register", h.getRegister)
	r.Post("/register", h.postRegister)

	r.Group(func(r chi.Router) {
		r.Use(auth.RequireLogin)
		r.Get("/queue", h.getQueue)
		r.Get("/dashboard", h.getDashboard)
		r.Get("/investigate/{labID}", h.getInvestigate)
		r.Post("/investigate/{labID}/start", h.postStartInvestigation)
		r.Post("/investigate/{labID}/submit", h.postSubmit)
		r.Post("/investigate/{labID}/draft", h.postDraft)
		r.Post("/investigate/{labID}/reset", h.postReset)
		r.Get("/result/{labID}", h.getResult)
		r.Get("/walkthrough/{labID}", h.getWalkthrough)
		r.Get("/playbooks", h.getPlaybooks)
		r.Get("/leaderboard", h.getLeaderboard)
		r.Get("/analytics", h.getAnalytics)

		// Live alert investigation
		r.Get("/alert/{alertID}", h.getLiveAlert)
		r.Post("/alert/{alertID}/submit", h.postSubmitLiveAlert)
		r.Post("/alert/{alertID}/draft", h.postDraftLiveAlert)
		r.Get("/alert/{alertID}/result", h.getLiveAlertResult)

		// Shift (SOC simulation)
		r.Get("/shift", h.getShiftLobby)
		r.Post("/shift/start", h.postStartShift)
		r.Get("/shift/{shiftID}", h.getShift)
		r.Post("/shift/{shiftID}/end", h.postEndShift)
		r.Get("/shift/{shiftID}/result", h.getShiftResult)

		// Campaigns (multi-stage incidents)
		r.Get("/campaigns", h.getCampaigns)
		r.Post("/campaigns/{key}/start", h.postStartCampaign)
		r.Get("/campaigns/{key}", h.getCampaign)
		r.Get("/campaigns/{key}/stage/{stage}", h.getCampaignStage)
		r.Get("/campaigns/{key}/result", h.getCampaignResult)

		// Threat hunt mode
		r.Get("/hunt", h.getHuntList)
		r.Get("/hunt/{key}", h.getHunt)
		r.Post("/hunt/{key}/submit", h.postSubmitHunt)
		r.Get("/hunt/{key}/result", h.getHuntResult)

		// Interview simulator
		r.Get("/interview", h.getInterviewList)
		r.Post("/interview/start", h.postStartInterview)
		r.Get("/interview/{id}", h.getInterview)
		r.Post("/interview/{id}/answer", h.postInterviewAnswer)
		r.Get("/interview/{id}/result", h.getInterviewResult)

		// Reports & certifications
		r.Get("/report/lab/{labID}", h.getLabReport)
		r.Get("/report/alert/{alertID}", h.getLiveAlertReport)
		r.Get("/certifications", h.getCertifications)

		// SSE for live alert notifications
		r.Get("/api/sse", h.apiSSE)

		// Daily briefing dismiss
		r.Post("/api/briefing/seen", h.postBriefingSeen)

		// htmx API endpoints
		r.Get("/api/logs/{labID}", h.apiLogs)
		r.Post("/api/enrichment", h.apiEnrichment)
		r.Get("/api/email/{labID}", h.apiEmail)
		r.Get("/api/notes/{labID}", h.apiGetNotes)
		r.Post("/api/notes/{labID}", h.apiSaveNotes)
		r.Get("/api/hunt/{key}/search", h.apiHuntSearch)

		// REST API v1
		r.Get("/api/v1/me", h.apiV1Me)
		r.Get("/api/v1/me/progress", h.apiV1Progress)
		r.Get("/api/v1/me/badges", h.apiV1Badges)
		r.Get("/api/v1/me/streak", h.apiV1Streak)
		r.Get("/api/v1/labs", h.apiV1Labs)

		r.Group(func(r chi.Router) {
			r.Use(auth.RequireAdmin)
			r.Get("/admin", h.getAdmin)
			r.Post("/admin/users/{id}/delete", h.adminDeleteUser)
			r.Post("/admin/users/{id}/promote", h.postAdminPromoteUser)
			r.Post("/admin/users/{id}/reset-progress", h.postAdminResetProgress)
			r.Get("/admin/invites", h.getAdminInvites)
			r.Post("/admin/invites", h.postAdminCreateInvite)
			r.Post("/admin/invites/{code}/revoke", h.postAdminRevokeInvite)
			r.Get("/admin/audit", h.getAdminAudit)
		})
	})

	return r
}

// ── Login ────────────────────────────────────────────────────────────────────

func (h *Handler) getLogin(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "login.html", map[string]any{
		"Error": r.URL.Query().Get("error"),
	})
}

func (h *Handler) postLogin(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	var u auth.User
	var hash string
	err := h.db.QueryRow(`SELECT id, username, role, password_hash FROM users WHERE username=?`, username).
		Scan(&u.ID, &u.Username, &u.Role, &hash)
	if err != nil || !auth.CheckPassword(password, hash) {
		http.Redirect(w, r, "/login?error=Invalid+username+or+password", http.StatusSeeOther)
		return
	}
	token, err := auth.CreateSession(h.db, u.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	auth.SetCookie(w, token)
	h.auditLog(u.ID, "login", username, r)
	next := r.FormValue("next")
	if next == "" || !strings.HasPrefix(next, "/") {
		next = "/queue"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (h *Handler) postLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("br_session"); err == nil {
		auth.DeleteSession(h.db, c.Value)
	}
	auth.ClearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ── Queue ────────────────────────────────────────────────────────────────────

type alertRow struct {
	Lab       *lab.Lab
	Status    string
	Score     *int
	StartedAt *time.Time
}

type liveAlertRow struct {
	ID          int64
	Severity    string
	Source      string
	Category    string
	RuleText    string
	TriggeredAt time.Time
	Status      string
	IsNew       bool
}

func (h *Handler) getQueue(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	allLabs := h.labs.All()

	// Sort: intro first, then core, then realistic
	diffOrder := map[string]int{"intro": 0, "core": 1, "realistic": 2}
	sort.Slice(allLabs, func(i, j int) bool {
		di := diffOrder[allLabs[i].Difficulty]
		dj := diffOrder[allLabs[j].Difficulty]
		if di != dj {
			return di < dj
		}
		return allLabs[i].ID < allLabs[j].ID
	})

	rows, _ := h.db.Query(`SELECT lab_id, status, score, started_at FROM investigations WHERE user_id=?`, u.ID)
	defer rows.Close()
	invMap := map[string]alertRow{}
	for rows.Next() {
		var labID, status string
		var score sql.NullInt64
		var startedAt sql.NullTime
		rows.Scan(&labID, &status, &score, &startedAt)
		ar := alertRow{Status: status}
		if score.Valid {
			v := int(score.Int64)
			ar.Score = &v
		}
		if startedAt.Valid {
			t := startedAt.Time
			ar.StartedAt = &t
		}
		invMap[labID] = ar
	}

	var alerts []alertRow
	for _, l := range allLabs {
		ar := invMap[l.ID]
		ar.Lab = l
		alerts = append(alerts, ar)
	}

	// Split into today's rotation and backlog
	dailyIDs := getDailyLabIDs(allLabs, u.ID, h.db)
	dailySet := map[string]bool{}
	for _, id := range dailyIDs {
		dailySet[id] = true
	}
	var dailyAlerts, backlogAlerts []alertRow
	for _, a := range alerts {
		if dailySet[a.Lab.ID] {
			dailyAlerts = append(dailyAlerts, a)
		} else {
			backlogAlerts = append(backlogAlerts, a)
		}
	}

	// Query live alerts
	liveRows, _ := h.db.Query(`
		SELECT la.id, la.severity, la.source, la.category, la.rule_text, la.triggered_at,
		       COALESCE(li.status,'')
		FROM live_alerts la
		LEFT JOIN live_investigations li ON li.alert_id=la.id AND li.user_id=?
		WHERE la.expires_at > CURRENT_TIMESTAMP
		ORDER BY CASE la.severity
			WHEN 'critical' THEN 1 WHEN 'high' THEN 2
			WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
		la.triggered_at DESC
		LIMIT 20`, u.ID)
	var liveAlerts []liveAlertRow
	if liveRows != nil {
		defer liveRows.Close()
		for liveRows.Next() {
			var a liveAlertRow
			var ts string
			liveRows.Scan(&a.ID, &a.Severity, &a.Source, &a.Category, &a.RuleText, &ts, &a.Status)
			a.TriggeredAt, _ = time.Parse("2006-01-02T15:04:05Z", ts)
			a.IsNew = time.Since(a.TriggeredAt) < 30*time.Minute
			liveAlerts = append(liveAlerts, a)
		}
	}

	// Career tier needed for mission generation
	h.db.Exec(`INSERT OR IGNORE INTO user_streak(user_id) VALUES(?)`, u.ID)
	var bonusXP, cachedTier int
	h.db.QueryRow(`SELECT COALESCE(bonus_xp,0), COALESCE(career_tier,1) FROM user_streak WHERE user_id=?`, u.ID).Scan(&bonusXP, &cachedTier)
	if cachedTier < 1 {
		cachedTier = 1
	}
	h.ensureDailyMissions(u.ID, cachedTier)
	missions := h.loadTodayMissions(u.ID)

	// Show briefing modal on first queue visit of the day
	today := time.Now().UTC().Format("2006-01-02")
	var lastSeen string
	h.db.QueryRow(`SELECT COALESCE(last_seen,'') FROM daily_briefing WHERE user_id=?`, u.ID).Scan(&lastSeen)
	showBriefing := lastSeen != today

	var liveCount int
	h.db.QueryRow(`SELECT COUNT(*) FROM live_alerts WHERE expires_at > CURRENT_TIMESTAMP`).Scan(&liveCount)

	h.render(w, r, "queue.html", map[string]any{
		"DailyAlerts":   dailyAlerts,
		"BacklogAlerts": backlogAlerts,
		"LiveAlerts":    liveAlerts,
		"Missions":      missions,
		"ShowBriefing":  showBriefing,
		"ThreatOfDay":   threatOfTheDay(),
		"LiveCount":     liveCount,
	})
}

// ── Dashboard ────────────────────────────────────────────────────────────────

type skillBar struct {
	Name     string
	Key      string
	Score    int
	MaxScore int
}

type levelInfo struct {
	Level  int
	Title  string
	XP     int
	PrevXP int
	NextXP int
}

type badgeInfo struct {
	Key      string
	Icon     string
	Name     string
	Desc     string
	Earned   bool
	EarnedAt *time.Time
}

var xpThresholds = []int{0, 50, 120, 220, 350, 500, 700, 950, 1250, 1600}
var xpTitles = []string{"Trainee", "Analyst I", "Analyst II", "Senior Analyst", "Threat Hunter", "IR Specialist", "SOC Lead", "Expert", "Elite", "L1 Champion"}

var badgeCatalogue = []badgeInfo{
	{Key: "first_blood", Icon: "🩸", Name: "First Blood", Desc: "Completed your first investigation"},
	{Key: "perfect_score", Icon: "💯", Name: "Perfect Score", Desc: "Scored 100/100 on a lab"},
	{Key: "phish_slayer", Icon: "🎣", Name: "Phish Slayer", Desc: "Passed a phishing investigation"},
	{Key: "malware_hunter", Icon: "🦠", Name: "Malware Hunter", Desc: "Passed a malware triage lab"},
	{Key: "network_ninja", Icon: "🕵", Name: "Network Ninja", Desc: "Passed a C2 or exfil investigation"},
	{Key: "mitre_master", Icon: "🗺", Name: "MITRE Master", Desc: "Correctly used 5+ distinct techniques"},
	{Key: "all_intro", Icon: "🎓", Name: "Intro Graduate", Desc: "Passed all intro-difficulty labs"},
	{Key: "all_labs", Icon: "🏆", Name: "Lab Champion", Desc: "Passed every lab in the platform"},
	{Key: "streak_3", Icon: "🔥", Name: "On Fire", Desc: "Maintained a 3-day practice streak"},
	{Key: "streak_7", Icon: "⚡", Name: "Week Warrior", Desc: "7 days of consecutive practice"},
	{Key: "streak_14", Icon: "💪", Name: "Fortnight Grind", Desc: "14-day practice streak"},
	{Key: "streak_30", Icon: "👑", Name: "Monthly Master", Desc: "30-day unbroken streak"},
	{Key: "shift_ace", Icon: "🎯", Name: "Shift Ace", Desc: "Completed a full shift with zero SLA breaches"},
	{Key: "speed_triage", Icon: "⚡", Name: "Speed Triage", Desc: "Averaged under 5 minutes per alert in a shift"},
	{Key: "night_owl", Icon: "🦉", Name: "Night Owl", Desc: "Completed a SOC shift after midnight"},
	// Career rank badges
	{Key: "rank_l1", Icon: "🔵", Name: "SOC Analyst L1", Desc: "Promoted to SOC Analyst L1"},
	{Key: "rank_l2", Icon: "🟣", Name: "SOC Analyst L2", Desc: "Promoted to SOC Analyst L2"},
	{Key: "rank_senior", Icon: "🟡", Name: "Senior Analyst", Desc: "Promoted to Senior Analyst"},
	{Key: "rank_ti_lead", Icon: "🟠", Name: "Threat Intel Lead", Desc: "Promoted to Threat Intelligence Lead"},
	{Key: "rank_ir_lead", Icon: "🔴", Name: "IR Lead", Desc: "Promoted to Incident Response Lead"},
	{Key: "rank_director", Icon: "⭐", Name: "SOC Director", Desc: "Reached the highest rank — SOC Director"},
}

func computeLevel(xp int) levelInfo {
	lvl := 0
	for i, t := range xpThresholds {
		if xp >= t {
			lvl = i
		}
	}
	info := levelInfo{
		Level: lvl + 1,
		Title: xpTitles[lvl],
		XP:    xp,
		PrevXP: xpThresholds[lvl],
	}
	if lvl < len(xpThresholds)-1 {
		info.NextXP = xpThresholds[lvl+1]
	} else {
		info.NextXP = xpThresholds[len(xpThresholds)-1]
	}
	return info
}

func (h *Handler) getDashboard(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())

	var completed, total int
	total = len(h.labs.All())
	h.db.QueryRow(`SELECT COUNT(*) FROM investigations WHERE user_id=? AND status='submitted'`, u.ID).Scan(&completed)

	var totalScore int
	var bonusXP int
	h.db.QueryRow(`SELECT COALESCE(SUM(score),0) FROM investigations WHERE user_id=? AND status='submitted'`, u.ID).Scan(&totalScore)
	h.db.QueryRow(`SELECT COALESCE(bonus_xp,0) FROM user_streak WHERE user_id=?`, u.ID).Scan(&bonusXP)
	totalScore += bonusXP

	// Skill bars
	skillKeys := []struct{ key, name string }{
		{"phishing", "Phishing & Email"},
		{"log_analysis", "Log Analysis"},
		{"network", "Network Monitoring"},
		{"endpoint", "Endpoint / EDR"},
		{"malware", "Malware Triage"},
		{"threat_intel", "Threat Intelligence"},
		{"mitre", "MITRE ATT&CK"},
		{"incident_response", "Incident Response"},
	}
	rows, _ := h.db.Query(`SELECT skill_key, score FROM user_skills WHERE user_id=?`, u.ID)
	skillMap := map[string]int{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			var s int
			rows.Scan(&k, &s)
			skillMap[k] = s
		}
	}

	var skills []skillBar
	for _, sk := range skillKeys {
		skills = append(skills, skillBar{
			Name:     sk.name,
			Key:      sk.key,
			Score:    skillMap[sk.key],
			MaxScore: 100,
		})
	}

	readiness := 0
	if total > 0 {
		readiness = completed * 100 / total
	}

	// XP level
	lvl := computeLevel(totalScore)

	// Badges
	earnedRows, _ := h.db.Query(`SELECT badge_key, earned_at FROM badges WHERE user_id=?`, u.ID)
	earnedMap := map[string]time.Time{}
	if earnedRows != nil {
		for earnedRows.Next() {
			var k string
			var t time.Time
			earnedRows.Scan(&k, &t)
			earnedMap[k] = t
		}
		earnedRows.Close()
	}
	badges := make([]badgeInfo, len(badgeCatalogue))
	copy(badges, badgeCatalogue)
	for i := range badges {
		if t, ok := earnedMap[badges[i].Key]; ok {
			badges[i].Earned = true
			tt := t
			badges[i].EarnedAt = &tt
		}
	}

	// Streak data
	type streakInfo struct {
		Count    int
		LastDate string
		Shield   int
		BonusXP  int
	}
	var streak streakInfo
	h.db.QueryRow(`SELECT streak_count, COALESCE(streak_last_date,''), streak_shield, bonus_xp FROM user_streak WHERE user_id=?`, u.ID).
		Scan(&streak.Count, &streak.LastDate, &streak.Shield, &streak.BonusXP)
	activeToday := streak.LastDate == time.Now().UTC().Format("2006-01-02")

	// Career tier + daily missions
	tier := h.computeCareerTier(u.ID, totalScore)
	h.ensureDailyMissions(u.ID, tier.Num)
	missions := h.loadTodayMissions(u.ID)

	h.render(w, r, "dashboard.html", map[string]any{
		"Completed":   completed,
		"Total":       total,
		"TotalScore":  totalScore,
		"Skills":      skills,
		"Readiness":   readiness,
		"Level":       lvl,
		"Badges":      badges,
		"Streak":      streak,
		"ActiveToday": activeToday,
		"Tier":        tier,
		"Missions":    missions,
	})
}

// ── Investigation ────────────────────────────────────────────────────────────

type investigation struct {
	ID        int64
	UserID    int64
	LabID     string
	Status    string
	Mode      string
	Verdict   string
	Severity  string
	Rationale string
	Mitre     []string
	Escalated bool
	Score     *int
	Feedback  []grader.FeedbackItem
}

func (h *Handler) getInvestigate(w http.ResponseWriter, r *http.Request) {
	labID := chi.URLParam(r, "labID")
	l, ok := h.labs.Get(labID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	u := auth.UserFromCtx(r.Context())

	inv := h.loadOrNilInv(u.ID, labID)

	h.render(w, r, "investigate.html", map[string]any{
		"Lab":         l,
		"Inv":         inv,
		"MitreList":   allMitreTechniques(),
	})
}

func (h *Handler) postStartInvestigation(w http.ResponseWriter, r *http.Request) {
	labID := chi.URLParam(r, "labID")
	if _, ok := h.labs.Get(labID); !ok {
		http.NotFound(w, r)
		return
	}
	u := auth.UserFromCtx(r.Context())
	mode := r.FormValue("mode")
	if mode != "exam" {
		mode = "guided"
	}
	h.db.Exec(`
		INSERT INTO investigations(user_id, lab_id, mode) VALUES(?,?,?)
		ON CONFLICT(user_id, lab_id) DO UPDATE SET mode=excluded.mode, status='in_progress', submitted_at=NULL
	`, u.ID, labID, mode)
	http.Redirect(w, r, "/investigate/"+labID, http.StatusSeeOther)
}

func (h *Handler) postSubmit(w http.ResponseWriter, r *http.Request) {
	labID := chi.URLParam(r, "labID")
	l, ok := h.labs.Get(labID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	u := auth.UserFromCtx(r.Context())

	var mitre []string
	for _, m := range r.Form["mitre"] {
		if strings.TrimSpace(m) != "" {
			mitre = append(mitre, strings.TrimSpace(m))
		}
	}
	mitreJSON, _ := json.Marshal(mitre)

	// Compute time taken and IOC enrichment count for grading v2
	var startedAt time.Time
	h.db.QueryRow(`SELECT started_at FROM investigations WHERE user_id=? AND lab_id=?`, u.ID, labID).Scan(&startedAt)
	timeTaken := 0
	if !startedAt.IsZero() {
		timeTaken = int(time.Since(startedAt).Minutes())
	}
	var iocCount int
	h.db.QueryRow(`SELECT COUNT(*) FROM enrichment_log WHERE user_id=? AND lab_id=?`, u.ID, labID).Scan(&iocCount)

	sub := grader.Submission{
		Verdict:      r.FormValue("verdict"),
		Severity:     r.FormValue("severity"),
		Rationale:    r.FormValue("rationale"),
		Mitre:        mitre,
		Escalated:    r.FormValue("escalation") == "escalate",
		TimeTakenMin: timeTaken,
		IOCsEnriched: iocCount,
	}
	result := grader.Grade(l, sub)

	_, err := h.db.Exec(`
		UPDATE investigations
		SET verdict=?, severity=?, rationale=?, mitre_tags=?, escalated=?,
		    score=?, feedback_json=?, status='submitted', submitted_at=CURRENT_TIMESTAMP,
		    best_score=MAX(COALESCE(best_score,0),?)
		WHERE user_id=? AND lab_id=?`,
		sub.Verdict, sub.Severity, sub.Rationale, string(mitreJSON),
		boolToInt(sub.Escalated), result.Score, result.JSON(), result.Score, u.ID, labID)
	if err != nil {
		h.log.Error("update investigation", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Update skill scores, award badges, update daily streak, and mark shift alert if active
	h.updateSkills(u.ID, l, result)
	h.awardBadges(u.ID, l, result)
	h.completeShiftAlert(u.ID, labID, result.Score)
	su := h.updateStreak(u.ID)

	// XP multipliers
	bonus := 0
	var invMode string
	h.db.QueryRow(`SELECT mode FROM investigations WHERE user_id=? AND lab_id=?`, u.ID, labID).Scan(&invMode)
	if invMode == "exam" && result.Score > 0 {
		bonus += result.Score * 15 / 100
	}
	hour := time.Now().UTC().Hour()
	if hour >= 22 || hour < 5 {
		bonus += result.Score * 10 / 100 // on-call shift bonus
	}
	if bonus > 0 {
		h.db.Exec(`INSERT INTO user_streak(user_id,bonus_xp) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET bonus_xp=bonus_xp+excluded.bonus_xp`, u.ID, bonus)
	}

	// Mission progress
	wordCount := len(strings.Fields(sub.Rationale))
	missionMeta := map[string]any{
		"score":       result.Score,
		"category":    l.Category,
		"mode":        invMode,
		"mitre_count": len(mitre),
		"word_count":  wordCount,
	}
	completedMissions := h.updateMissionProgress(u.ID, "lab_submit", missionMeta)

	toastMsg := "Investigation+submitted"
	toastType := "success"
	if su.IsNewDay && su.Milestone > 0 {
		toastMsg = fmt.Sprintf("%%F0%%9F%%94%%A5+%d-Day+Streak%%21+%%2B%d+bonus+XP", su.StreakCount, su.BonusXP)
	} else if su.IsNewDay {
		toastMsg = fmt.Sprintf("Investigation+submitted+%%E2%%80%%94+%%F0%%9F%%94%%A5+Day+%d+streak", su.StreakCount)
	} else if len(completedMissions) > 0 {
		toastMsg = fmt.Sprintf("%%E2%%9C%%85+Mission+Complete%%3A+%s", strings.ReplaceAll(completedMissions[0], " ", "+"))
	}
	http.Redirect(w, r, "/result/"+labID+"?toast="+toastMsg+"&toast_type="+toastType, http.StatusSeeOther)
}

func (h *Handler) postDraft(w http.ResponseWriter, r *http.Request) {
	labID := chi.URLParam(r, "labID")
	u := auth.UserFromCtx(r.Context())
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var mitre []string
	for _, m := range r.Form["mitre"] {
		if m = strings.TrimSpace(m); m != "" {
			mitre = append(mitre, m)
		}
	}
	mitreJSON, _ := json.Marshal(mitre)
	escalated := 0
	if r.FormValue("escalation") == "escalate" {
		escalated = 1
	}
	h.db.Exec(`
		UPDATE investigations
		SET verdict=?, severity=?, rationale=?, mitre_tags=?, escalated=?
		WHERE user_id=? AND lab_id=? AND status='in_progress'`,
		r.FormValue("verdict"), r.FormValue("severity"),
		r.FormValue("rationale"), string(mitreJSON), escalated,
		u.ID, labID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) postReset(w http.ResponseWriter, r *http.Request) {
	labID := chi.URLParam(r, "labID")
	if _, ok := h.labs.Get(labID); !ok {
		http.NotFound(w, r)
		return
	}
	u := auth.UserFromCtx(r.Context())
	mode := r.FormValue("mode")
	if mode != "exam" {
		mode = "guided"
	}
	h.db.Exec(`
		UPDATE investigations
		SET status='in_progress', mode=?, verdict=NULL, severity=NULL,
		    rationale=NULL, mitre_tags='[]', escalated=0,
		    score=NULL, feedback_json=NULL, submitted_at=NULL,
		    started_at=CURRENT_TIMESTAMP
		WHERE user_id=? AND lab_id=?`, mode, u.ID, labID)
	http.Redirect(w, r, "/investigate/"+labID+"?toast=Lab+reset.+Good+luck%21&toast_type=info", http.StatusSeeOther)
}

func (h *Handler) getResult(w http.ResponseWriter, r *http.Request) {
	labID := chi.URLParam(r, "labID")
	l, ok := h.labs.Get(labID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	u := auth.UserFromCtx(r.Context())
	inv := h.loadOrNilInv(u.ID, labID)
	if inv == nil || inv.Status != "submitted" {
		http.Redirect(w, r, "/investigate/"+labID, http.StatusSeeOther)
		return
	}

	// Compute time taken for display
	var startedAt, submittedAt time.Time
	h.db.QueryRow(`SELECT started_at, COALESCE(submitted_at, started_at) FROM investigations WHERE user_id=? AND lab_id=?`, u.ID, labID).Scan(&startedAt, &submittedAt)
	timeTaken := int(submittedAt.Sub(startedAt).Minutes())

	// Difficulty modifier display
	mod := l.Rubric.DifficultyModifier
	if mod <= 0 || mod == 1.0 {
		mod = 0
	}

	h.render(w, r, "result.html", map[string]any{
		"Lab":           l,
		"Inv":           inv,
		"TimeTaken":     timeTaken,
		"DifficultyMod": mod,
	})
}

func (h *Handler) getWalkthrough(w http.ResponseWriter, r *http.Request) {
	labID := chi.URLParam(r, "labID")
	l, ok := h.labs.Get(labID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	wtPath := filepath.Join(l.LabDir, "walkthrough.md")
	content, _ := os.ReadFile(wtPath)
	h.render(w, r, "walkthrough.html", map[string]any{
		"Lab":     l,
		"Content": string(content),
	})
}

func (h *Handler) getPlaybooks(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "playbooks.html", nil)
}

func (h *Handler) getAnalytics(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())

	type labStat struct {
		Lab         *lab.Lab
		Score       int
		BestScore   int
		MinutesTaken int
		Attempts    int
		PassedFirst bool
		SubmittedAt time.Time
	}

	rows, _ := h.db.Query(`
		SELECT i.lab_id, i.score, COALESCE(i.best_score,i.score),
		       CAST((julianday(i.submitted_at)-julianday(i.started_at))*1440 AS INTEGER),
		       i.submitted_at
		FROM investigations i
		WHERE i.user_id=? AND i.status='submitted'
		ORDER BY i.submitted_at`, u.ID)
	var stats []labStat
	totalScore := 0
	if rows != nil {
		for rows.Next() {
			var s labStat
			var labID string
			var submittedAt time.Time
			rows.Scan(&labID, &s.Score, &s.BestScore, &s.MinutesTaken, &submittedAt)
			s.SubmittedAt = submittedAt
			if l, ok := h.labs.Get(labID); ok {
				s.Lab = l
			}
			totalScore += s.Score
			stats = append(stats, s)
		}
		rows.Close()
	}

	// Skill scores
	skillRows, _ := h.db.Query(`SELECT skill_key, score FROM user_skills WHERE user_id=?`, u.ID)
	skillMap := map[string]int{}
	if skillRows != nil {
		for skillRows.Next() {
			var k string; var v int
			skillRows.Scan(&k, &v)
			skillMap[k] = v
		}
		skillRows.Close()
	}

	// Weakest skill recommendation
	skillKeys := []struct{ key, name string }{
		{"phishing","Phishing & Email"},{"log_analysis","Log Analysis"},
		{"network","Network Monitoring"},{"endpoint","Endpoint / EDR"},
		{"malware","Malware Triage"},{"threat_intel","Threat Intelligence"},
		{"mitre","MITRE ATT&CK"},{"incident_response","Incident Response"},
	}
	weakest := skillKeys[0]
	for _, sk := range skillKeys {
		if skillMap[sk.key] < skillMap[weakest.key] {
			weakest = sk
		}
	}

	// Interview readiness check
	allReady := true
	for _, sk := range skillKeys {
		if skillMap[sk.key] < 60 {
			allReady = false
			break
		}
	}
	var completedCore int
	h.db.QueryRow(`SELECT COUNT(*) FROM investigations i JOIN labs l ON l.id=i.lab_id
		WHERE i.user_id=? AND i.status='submitted' AND i.score>=70 AND l.difficulty IN ('intro','core')`, u.ID).Scan(&completedCore)
	totalCore := len(h.labs.ByDifficulty("intro")) + len(h.labs.ByDifficulty("core"))
	interviewReady := allReady && completedCore >= totalCore

	// Win rate
	var totalSubs, firstPassSubs int
	h.db.QueryRow(`SELECT COUNT(*) FROM investigations WHERE user_id=? AND status='submitted'`, u.ID).Scan(&totalSubs)
	h.db.QueryRow(`SELECT COUNT(*) FROM investigations WHERE user_id=? AND status='submitted' AND score>=70`, u.ID).Scan(&firstPassSubs)
	winRate := 0
	if totalSubs > 0 {
		winRate = firstPassSubs * 100 / totalSubs
	}

	// Compute SVG radar polygon points (8 axes at 45° increments, starting from top=network)
	// Angle 0=top(network), 45=endpoint, 90=malware, 135=ti, 180=mitre, 225=ir, 270=phishing, 315=log
	radarOrder := []string{"network", "endpoint", "malware", "threat_intel", "mitre", "incident_response", "phishing", "log_analysis"}
	radarPoints := ""
	for i, key := range radarOrder {
		angleRad := float64(i)*math.Pi/4 - math.Pi/2
		r := float64(skillMap[key]) // 0-100 maps to 0-100 px radius
		x := r * math.Cos(angleRad)
		y := r * math.Sin(angleRad)
		if i > 0 {
			radarPoints += " "
		}
		radarPoints += fmt.Sprintf("%.1f,%.1f", x, y)
	}

	type skillBar struct {
		Key   string
		Name  string
		Score int
	}
	var skillBars []skillBar
	for _, sk := range skillKeys {
		skillBars = append(skillBars, skillBar{Key: sk.key, Name: sk.name, Score: skillMap[sk.key]})
	}

	h.render(w, r, "analytics.html", map[string]any{
		"Stats":          stats,
		"SkillMap":       skillMap,
		"SkillBars":      skillBars,
		"RadarPoints":    radarPoints,
		"WeakestSkill":   weakest,
		"InterviewReady": interviewReady,
		"WinRate":        winRate,
		"TotalScore":     totalScore,
		"TotalLabs":      len(h.labs.All()),
	})
}

type leaderRow struct {
	Rank      int
	Username  string
	Score     int
	Completed int
	Level     int
	Title     string
	TopBadge  string
}

func (h *Handler) getLeaderboard(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	rows, err := h.db.Query(`
		SELECT u.username,
		       COALESCE(SUM(CASE WHEN i.status='submitted' THEN i.score ELSE 0 END),0) AS total,
		       COALESCE(COUNT(CASE WHEN i.status='submitted' THEN 1 END),0) AS completed
		FROM users u
		LEFT JOIN investigations i ON i.user_id = u.id
		WHERE u.role != 'admin'
		GROUP BY u.id
		ORDER BY total DESC, completed DESC
		LIMIT 50`)
	if err != nil {
		h.log.Error("leaderboard query", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var board []leaderRow
	rank := 0
	for rows.Next() {
		rank++
		var lr leaderRow
		rows.Scan(&lr.Username, &lr.Score, &lr.Completed)
		lr.Rank = rank
		lvl := computeLevel(lr.Score)
		lr.Level = lvl.Level
		lr.Title = lvl.Title
		h.db.QueryRow(`SELECT badge_key FROM badges WHERE user_id=(SELECT id FROM users WHERE username=?) ORDER BY earned_at DESC LIMIT 1`, lr.Username).Scan(&lr.TopBadge)
		board = append(board, lr)
	}

	h.render(w, r, "leaderboard.html", map[string]any{
		"Board":       board,
		"CurrentUser": u.Username,
	})
}

// ── HTMX API ─────────────────────────────────────────────────────────────────

type logEntry struct {
	Source    string `json:"source"`
	Timestamp string `json:"ts"`
	Level     string `json:"level"`
	Host      string `json:"host"`
	Message   string `json:"message"`
}

func (h *Handler) apiLogs(w http.ResponseWriter, r *http.Request) {
	labID := chi.URLParam(r, "labID")
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	source := r.URL.Query().Get("source")

	var (
		rows *sql.Rows
		err  error
	)
	if q != "" {
		safeQ := sanitizeFTS(q)
		if source != "" {
			rows, err = h.db.Query(`
				SELECT source, ts, level, host, message FROM logs_fts
				WHERE lab_id=? AND source=? AND logs_fts MATCH ?
				ORDER BY ts LIMIT 200`, labID, source, safeQ)
		} else {
			rows, err = h.db.Query(`
				SELECT source, ts, level, host, message FROM logs_fts
				WHERE lab_id=? AND logs_fts MATCH ?
				ORDER BY ts LIMIT 200`, labID, safeQ)
		}
	} else {
		if source != "" {
			rows, err = h.db.Query(`
				SELECT source, ts, level, host, message FROM logs_fts
				WHERE lab_id=? AND source=?
				ORDER BY ts LIMIT 200`, labID, source)
		} else {
			rows, err = h.db.Query(`
				SELECT source, ts, level, host, message FROM logs_fts
				WHERE lab_id=?
				ORDER BY ts LIMIT 200`, labID)
		}
	}
	if err != nil {
		h.log.Error("log query", "err", err)
		http.Error(w, "query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var entries []logEntry
	for rows.Next() {
		var e logEntry
		rows.Scan(&e.Source, &e.Timestamp, &e.Level, &e.Host, &e.Message)
		entries = append(entries, e)
	}

	// Emit distinct sources header on unconstrained loads so the UI can build pill tabs
	if source == "" && q == "" {
		srcRows, _ := h.db.Query(`SELECT DISTINCT source FROM logs_fts WHERE lab_id=? ORDER BY source`, labID)
		if srcRows != nil {
			var sources []string
			for srcRows.Next() {
				var s string
				srcRows.Scan(&s)
				sources = append(sources, s)
			}
			srcRows.Close()
			if b, err := json.Marshal(sources); err == nil {
				w.Header().Set("X-Log-Sources", string(b))
			}
		}
	}
	w.Header().Set("X-Log-Count", strconv.Itoa(len(entries)))

	// Return htmx partial
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if len(entries) == 0 {
		fmt.Fprintf(w, `<p class="no-results">No logs match your query.</p>`)
		return
	}
	for _, e := range entries {
		lvlClass := "log-info"
		switch strings.ToLower(e.Level) {
		case "warn", "warning":
			lvlClass = "log-warn"
		case "error", "critical", "alert":
			lvlClass = "log-error"
		}
		fmt.Fprintf(w, `<div class="log-row %s"><span class="log-ts">%s</span><span class="log-src">%s</span><span class="log-host">%s</span><span class="log-msg">%s</span></div>`,
			template.HTMLEscapeString(lvlClass),
			template.HTMLEscapeString(e.Timestamp),
			template.HTMLEscapeString(e.Source),
			template.HTMLEscapeString(e.Host),
			template.HTMLEscapeString(e.Message),
		)
	}
}

func (h *Handler) apiEnrichment(w http.ResponseWriter, r *http.Request) {
	indicator := strings.TrimSpace(r.FormValue("indicator"))
	if indicator == "" {
		http.Error(w, "indicator required", http.StatusBadRequest)
		return
	}
	// Log enrichment lookup for grading credit (lab_id from referer or query param)
	if u := auth.UserFromCtx(r.Context()); u != nil {
		labID := r.URL.Query().Get("lab")
		if labID == "" {
			// Try to extract from Referer header: /investigate/{labID}
			ref := r.Referer()
			if idx := strings.Index(ref, "/investigate/"); idx >= 0 {
				labID = strings.TrimPrefix(ref[idx:], "/investigate/")
				if i := strings.Index(labID, "/"); i >= 0 {
					labID = labID[:i]
				}
				if i := strings.Index(labID, "?"); i >= 0 {
					labID = labID[:i]
				}
			}
		}
		if labID != "" {
			h.db.Exec(`INSERT INTO enrichment_log(user_id,lab_id,indicator) VALUES(?,?,?)`, u.ID, labID, indicator)
		}
	}
	res := enrichment.Lookup(indicator)
	verdictClass := map[enrichment.Verdict]string{
		enrichment.VerdictMalicious:  "verdict-malicious",
		enrichment.VerdictSuspicious: "verdict-suspicious",
		enrichment.VerdictClean:      "verdict-clean",
		enrichment.VerdictUnknown:    "verdict-unknown",
	}[res.Verdict]

	tags := ""
	for _, t := range res.Tags {
		tags += fmt.Sprintf(`<span class="tag">%s</span>`, template.HTMLEscapeString(t))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
<div class="enrichment-result">
  <div class="enrichment-header">
    <span class="enrichment-indicator">%s</span>
    <span class="enrichment-type badge">%s</span>
    <span class="%s badge">%s</span>
    <span class="confidence">%d%% confidence</span>
  </div>
  <div class="enrichment-tags">%s</div>
  <p class="enrichment-note">%s</p>
</div>`,
		template.HTMLEscapeString(res.Indicator),
		template.HTMLEscapeString(res.Type),
		template.HTMLEscapeString(verdictClass),
		template.HTMLEscapeString(string(res.Verdict)),
		res.Confidence,
		tags,
		template.HTMLEscapeString(res.Note),
	)
}

func (h *Handler) apiEmail(w http.ResponseWriter, r *http.Request) {
	labID := chi.URLParam(r, "labID")
	l, ok := h.labs.Get(labID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	emailDir := filepath.Join(l.LabDir, "email")
	entries, err := os.ReadDir(emailDir)
	if err != nil || len(entries) == 0 {
		fmt.Fprintf(w, `<p class="no-results">No email samples for this lab.</p>`)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".eml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(emailDir, e.Name()))
		if err != nil {
			continue
		}
		headers, body := parseEML(string(data))
		fmt.Fprintf(w, `<div class="email-sample"><h3 class="email-filename">%s</h3>`, template.HTMLEscapeString(e.Name()))
		fmt.Fprintf(w, `<table class="email-headers">`)
		for _, hdr := range headers {
			fmt.Fprintf(w, `<tr><td class="hdr-key">%s</td><td class="hdr-val">%s</td></tr>`,
				template.HTMLEscapeString(hdr[0]),
				template.HTMLEscapeString(hdr[1]))
		}
		fmt.Fprintf(w, `</table><pre class="email-body">%s</pre></div>`, template.HTMLEscapeString(body))
	}
}

// ── Admin ────────────────────────────────────────────────────────────────────

func (h *Handler) getAdmin(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`SELECT id, username, role, created_at FROM users ORDER BY id`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type userRow struct {
		ID        int64
		Username  string
		Role      string
		CreatedAt time.Time
	}
	var users []userRow
	for rows.Next() {
		var u userRow
		rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt)
		users = append(users, u)
	}
	h.render(w, r, "admin.html", map[string]any{
		"Users": users,
		"Labs":  h.labs.All(),
	})
}

func (h *Handler) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	u := auth.UserFromCtx(r.Context())
	if id == u.ID {
		http.Error(w, "cannot delete yourself", http.StatusBadRequest)
		return
	}
	h.db.Exec(`DELETE FROM users WHERE id=?`, id)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func (h *Handler) render(w http.ResponseWriter, r *http.Request, tmpl string, data map[string]any) {
	t, ok := h.tmpls[tmpl]
	if !ok {
		h.log.Error("template not found", "tmpl", tmpl)
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	if data == nil {
		data = map[string]any{}
	}
	data["User"] = auth.UserFromCtx(r.Context())
	data["Now"] = time.Now()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		h.log.Error("render template", "tmpl", tmpl, "err", err)
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

func (h *Handler) loadOrNilInv(userID int64, labID string) *investigation {
	var inv investigation
	var mitreJSON, feedbackJSON sql.NullString
	var score sql.NullInt64
	var escalatedInt int
	err := h.db.QueryRow(`
		SELECT id, user_id, lab_id, status, mode,
		       COALESCE(verdict,''), COALESCE(severity,''), COALESCE(rationale,''),
		       mitre_tags, escalated, score, feedback_json
		FROM investigations WHERE user_id=? AND lab_id=?`, userID, labID).
		Scan(&inv.ID, &inv.UserID, &inv.LabID, &inv.Status, &inv.Mode,
			&inv.Verdict, &inv.Severity, &inv.Rationale,
			&mitreJSON, &escalatedInt, &score, &feedbackJSON)
	if err != nil {
		return nil
	}
	inv.Escalated = escalatedInt != 0
	if score.Valid {
		v := int(score.Int64)
		inv.Score = &v
	}
	if mitreJSON.Valid {
		json.Unmarshal([]byte(mitreJSON.String), &inv.Mitre)
	}
	if feedbackJSON.Valid {
		json.Unmarshal([]byte(feedbackJSON.String), &inv.Feedback)
	}
	return &inv
}

func (h *Handler) updateSkills(userID int64, l *lab.Lab, result grader.Result) {
	skillMap := map[string]string{
		"phishing":          "phishing",
		"brute-force":       "log_analysis",
		"web-attack":        "log_analysis",
		"malware":           "malware",
		"c2":                "network",
		"lateral-movement":  "endpoint",
		"data-exfil":        "network",
		"multi-stage":       "incident_response",
	}
	skillKey := skillMap[l.Category]
	if skillKey == "" {
		skillKey = "log_analysis"
	}
	points := result.Score / 10
	h.db.Exec(`
		INSERT INTO user_skills(user_id, skill_key, score) VALUES(?,?,?)
		ON CONFLICT(user_id, skill_key) DO UPDATE SET score = MIN(100, score + excluded.score)
	`, userID, skillKey, points)
	// always add mitre points
	h.db.Exec(`
		INSERT INTO user_skills(user_id, skill_key, score) VALUES(?,?,?)
		ON CONFLICT(user_id, skill_key) DO UPDATE SET score = MIN(100, score + excluded.score)
	`, userID, "mitre", result.Score/20)
}

func (h *Handler) awardBadges(userID int64, l *lab.Lab, result grader.Result) {
	award := func(key string) {
		h.db.Exec(`INSERT OR IGNORE INTO badges(user_id, badge_key) VALUES(?,?)`, userID, key)
	}

	// first_blood: first lab ever submitted
	var total int
	h.db.QueryRow(`SELECT COUNT(*) FROM investigations WHERE user_id=? AND status='submitted'`, userID).Scan(&total)
	if total == 1 {
		award("first_blood")
	}

	// perfect_score: 100/100
	if result.MaxScore > 0 && result.Score == result.MaxScore {
		award("perfect_score")
	}

	// category-based badges (only when passing)
	if result.Passed {
		switch l.Category {
		case "phishing":
			award("phish_slayer")
		case "malware":
			award("malware_hunter")
		case "c2", "data-exfil":
			award("network_ninja")
		}
	}

	// all_intro: all intro-difficulty labs passed
	introLabs := h.labs.ByDifficulty("intro")
	if len(introLabs) > 0 {
		var passedIntro int
		h.db.QueryRow(`
			SELECT COUNT(*) FROM investigations i
			JOIN labs lb ON lb.id=i.lab_id
			WHERE i.user_id=? AND i.status='submitted' AND i.score>=70 AND lb.difficulty='intro'`,
			userID).Scan(&passedIntro)
		if passedIntro >= len(introLabs) {
			award("all_intro")
		}
	}

	// all_labs: every lab passed
	allLabs := h.labs.All()
	if len(allLabs) > 0 {
		var passedAll int
		h.db.QueryRow(`SELECT COUNT(*) FROM investigations WHERE user_id=? AND status='submitted' AND score>=70`, userID).Scan(&passedAll)
		if passedAll >= len(allLabs) {
			award("all_labs")
		}
	}

	// mitre_master: 5+ correct MITRE tags across all submissions
	var mitreMasterRows *sql.Rows
	mitreMasterRows, _ = h.db.Query(`SELECT mitre_tags FROM investigations WHERE user_id=? AND status='submitted'`, userID)
	if mitreMasterRows != nil {
		uniqueMitre := map[string]struct{}{}
		for mitreMasterRows.Next() {
			var mjson string
			mitreMasterRows.Scan(&mjson)
			var tags []string
			json.Unmarshal([]byte(mjson), &tags)
			for _, t := range tags {
				uniqueMitre[strings.ToUpper(t)] = struct{}{}
			}
		}
		mitreMasterRows.Close()
		if len(uniqueMitre) >= 5 {
			award("mitre_master")
		}
	}
}

// ── Streak ───────────────────────────────────────────────────────────────────

type streakUpdate struct {
	IsNewDay   bool
	StreakCount int
	BonusXP    int
	ShieldUsed bool
	Milestone  int
}

func (h *Handler) updateStreak(userID int64) streakUpdate {
	today := time.Now().UTC().Format("2006-01-02")
	h.db.Exec(`INSERT OR IGNORE INTO user_streak(user_id) VALUES(?)`, userID)

	var count int
	var lastDate sql.NullString
	var shield int
	h.db.QueryRow(`SELECT streak_count, streak_last_date, streak_shield FROM user_streak WHERE user_id=?`, userID).
		Scan(&count, &lastDate, &shield)

	if lastDate.Valid && lastDate.String == today {
		return streakUpdate{}
	}

	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	var upd streakUpdate
	upd.IsNewDay = true

	if !lastDate.Valid || lastDate.String < yesterday {
		if lastDate.Valid && shield > 0 {
			upd.ShieldUsed = true
			shield--
			count++
		} else {
			count = 1
		}
	} else {
		count++
	}

	bonusXP := 10
	for _, m := range []int{3, 7, 14, 30} {
		if count == m {
			upd.Milestone = m
			bonusXP += m * 5
		}
	}
	upd.StreakCount = count
	upd.BonusXP = bonusXP

	h.db.Exec(`UPDATE user_streak SET streak_count=?, streak_last_date=?, streak_shield=?, bonus_xp=bonus_xp+? WHERE user_id=?`,
		count, today, shield, bonusXP, userID)

	// Award streak milestone badges
	streakBadges := map[int]string{3: "streak_3", 7: "streak_7", 14: "streak_14", 30: "streak_30"}
	if key, ok := streakBadges[count]; ok {
		h.db.Exec(`INSERT OR IGNORE INTO badges(user_id, badge_key) VALUES(?,?)`, userID, key)
	}
	return upd
}

// ── Daily Alert Rotation ─────────────────────────────────────────────────────

func getDailyLabIDs(labs []*lab.Lab, userID int64, database *db.DB) []string {
	daysSinceEpoch := int(time.Now().UTC().Unix() / 86400)

	type scored struct {
		id  string
		pri int
	}
	pool := make([]scored, 0, len(labs))
	for _, l := range labs {
		var status string
		database.QueryRow(`SELECT COALESCE(status,'') FROM investigations WHERE user_id=? AND lab_id=?`, userID, l.ID).Scan(&status)
		priMap := map[string]int{"": 3, "in_progress": 2, "submitted": 1}
		pri := priMap[status]
		pool = append(pool, scored{l.ID, pri})
	}

	sort.SliceStable(pool, func(i, j int) bool {
		if pool[i].pri != pool[j].pri {
			return pool[i].pri > pool[j].pri
		}
		hi := fnv1a(pool[i].id + strconv.Itoa(daysSinceEpoch))
		hj := fnv1a(pool[j].id + strconv.Itoa(daysSinceEpoch))
		return hi < hj
	})

	count := 3
	if len(pool) < count {
		count = len(pool)
	}
	ids := make([]string, count)
	for i := range ids {
		ids[i] = pool[i].id
	}
	return ids
}

func fnv1a(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// ── Briefing ─────────────────────────────────────────────────────────────────

func (h *Handler) postBriefingSeen(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	today := time.Now().UTC().Format("2006-01-02")
	h.db.Exec(
		`INSERT INTO daily_briefing(user_id, last_seen) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET last_seen=excluded.last_seen`,
		u.ID, today,
	)
	w.WriteHeader(http.StatusNoContent)
}

func sanitizeFTS(q string) string {
	// Wrap bare terms to avoid FTS5 syntax errors from user input
	q = strings.ReplaceAll(q, `"`, `""`)
	return `"` + q + `"`
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func parseEML(raw string) ([][2]string, string) {
	var headers [][2]string
	var bodyLines []string
	inBody := false
	var pendingKey, pendingVal string

	flush := func() {
		if pendingKey != "" {
			headers = append(headers, [2]string{pendingKey, strings.TrimSpace(pendingVal)})
		}
		pendingKey, pendingVal = "", ""
	}

	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		if inBody {
			bodyLines = append(bodyLines, line)
			continue
		}
		if line == "" {
			flush()
			inBody = true
			continue
		}
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			pendingVal += " " + strings.TrimSpace(line)
			continue
		}
		flush()
		idx := strings.Index(line, ":")
		if idx > 0 {
			pendingKey = line[:idx]
			pendingVal = line[idx+1:]
		}
	}
	flush()
	return headers, strings.Join(bodyLines, "\n")
}

func allMitreTechniques() []lab.MitreTag {
	return []lab.MitreTag{
		{ID: "T1566.001", Name: "Phishing: Spearphishing Attachment"},
		{ID: "T1566.002", Name: "Phishing: Spearphishing Link"},
		{ID: "T1078",     Name: "Valid Accounts"},
		{ID: "T1110",     Name: "Brute Force"},
		{ID: "T1110.001", Name: "Brute Force: Password Guessing"},
		{ID: "T1110.003", Name: "Brute Force: Password Spraying"},
		{ID: "T1190",     Name: "Exploit Public-Facing Application"},
		{ID: "T1059",     Name: "Command and Scripting Interpreter"},
		{ID: "T1059.001", Name: "PowerShell"},
		{ID: "T1059.003", Name: "Windows Command Shell"},
		{ID: "T1003",     Name: "OS Credential Dumping"},
		{ID: "T1003.001", Name: "LSASS Memory"},
		{ID: "T1021",     Name: "Remote Services"},
		{ID: "T1021.002", Name: "SMB/Windows Admin Shares"},
		{ID: "T1047",     Name: "Windows Management Instrumentation"},
		{ID: "T1071",     Name: "Application Layer Protocol"},
		{ID: "T1071.001", Name: "Web Protocols (C2)"},
		{ID: "T1071.004", Name: "DNS (C2/Exfil)"},
		{ID: "T1048",     Name: "Exfiltration Over Alternative Protocol"},
		{ID: "T1486",     Name: "Data Encrypted for Impact (Ransomware)"},
		{ID: "T1547",     Name: "Boot or Logon Autostart Execution"},
		{ID: "T1053",     Name: "Scheduled Task/Job"},
		{ID: "T1027",     Name: "Obfuscated Files or Information"},
		{ID: "T1562",     Name: "Impair Defenses"},
		{ID: "T1055",     Name: "Process Injection"},
	}
}
