package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/bluerange/bluerange/internal/auth"
)

type certDef struct {
	Key         string
	Title       string
	Description string
	Icon        string
	Criteria    string
}

var certDefs = []certDef{
	{
		Key:         "analyst_trainee",
		Title:       "SOC Analyst Trainee",
		Description: "Completed all introductory labs with a passing score.",
		Icon:        "🎓",
		Criteria:    "Pass 3 or more intro labs with a score of 60+.",
	},
	{
		Key:         "alert_triage",
		Title:       "Alert Triage Specialist",
		Description: "Demonstrated rapid alert triage across live alerts.",
		Icon:        "📡",
		Criteria:    "Submit 10 live alert investigations.",
	},
	{
		Key:         "soc_analyst",
		Title:       "SOC Analyst Level 1",
		Description: "Core SOC skills demonstrated across all difficulty tiers.",
		Icon:        "🔍",
		Criteria:    "Pass all core labs + 25 live alerts submitted.",
	},
	{
		Key:         "threat_hunter",
		Title:       "Threat Hunter",
		Description: "Proactively hunted for threats using log analysis.",
		Icon:        "🐺",
		Criteria:    "Complete all 4 threat hunt missions with a passing score.",
	},
	{
		Key:         "campaign_commander",
		Title:       "Campaign Commander",
		Description: "Completed a full multi-stage incident campaign.",
		Icon:        "🏴",
		Criteria:    "Complete 1 campaign from start to finish.",
	},
	{
		Key:         "senior_analyst",
		Title:       "Senior SOC Analyst",
		Description: "Elite analyst. All labs, campaigns, and a 7-day streak.",
		Icon:        "🏆",
		Criteria:    "Pass all labs + complete 1 campaign + maintain a 7-day streak.",
	},
}

// GET /report/lab/{labID}
func (h *Handler) getLabReport(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	labID := chi.URLParam(r, "labID")

	// Load lab
	var title, difficulty, category, scenario, mitreTags string
	h.db.QueryRow(`SELECT title, difficulty, category, scenario, mitre_tags FROM labs WHERE id=?`, labID).
		Scan(&title, &difficulty, &category, &scenario, &mitreTags)

	// Load investigation
	var verdict, severity, rationale, feedbackJSON, mitreTagsSub string
	var score int
	var submittedAt time.Time
	var submittedStr string
	h.db.QueryRow(`SELECT verdict, severity, rationale, mitre_tags, score, feedback_json, submitted_at FROM investigations WHERE user_id=? AND lab_id=? AND status='submitted'`,
		u.ID, labID).Scan(&verdict, &severity, &rationale, &mitreTagsSub, &score, &feedbackJSON, &submittedStr)
	submittedAt, _ = time.Parse("2006-01-02T15:04:05Z", submittedStr)

	var feedback []map[string]any
	json.Unmarshal([]byte(feedbackJSON), &feedback)

	h.render(w, r, "report.html", map[string]any{
		"Type":        "lab",
		"LabID":       labID,
		"Title":       title,
		"Difficulty":  difficulty,
		"Category":    category,
		"Scenario":    scenario,
		"MITRETags":   mitreTags,
		"Verdict":     verdict,
		"Severity":    severity,
		"Rationale":   rationale,
		"MITRESub":    mitreTagsSub,
		"Score":       score,
		"Feedback":    feedback,
		"SubmittedAt": submittedAt,
	})
}

// GET /report/alert/{alertID}
func (h *Handler) getLiveAlertReport(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	alertID, _ := strconv.ParseInt(chi.URLParam(r, "alertID"), 10, 64)

	// Load alert
	var severity, source, category, ruleText, scenario string
	h.db.QueryRow(`SELECT severity, source, category, rule_text, scenario FROM live_alerts WHERE id=?`, alertID).
		Scan(&severity, &source, &category, &ruleText, &scenario)

	// Load investigation
	var verdict, rationale, feedbackJSON, mitreTagsSub string
	var score int
	var submittedStr string
	h.db.QueryRow(`SELECT verdict, rationale, mitre_tags, score, feedback_json, submitted_at FROM live_investigations WHERE user_id=? AND alert_id=? AND status='submitted'`,
		u.ID, alertID).Scan(&verdict, &rationale, &mitreTagsSub, &score, &feedbackJSON, &submittedStr)
	submittedAt, _ := time.Parse("2006-01-02T15:04:05Z", submittedStr)

	var feedback []map[string]any
	json.Unmarshal([]byte(feedbackJSON), &feedback)

	h.render(w, r, "report.html", map[string]any{
		"Type":        "alert",
		"AlertID":     alertID,
		"Title":       ruleText,
		"Difficulty":  severity,
		"Category":    category,
		"Scenario":    scenario,
		"Source":      source,
		"Verdict":     verdict,
		"Rationale":   rationale,
		"MITRESub":    mitreTagsSub,
		"Score":       score,
		"Feedback":    feedback,
		"SubmittedAt": submittedAt,
	})
}

// GET /certifications
func (h *Handler) getCertifications(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())

	// Check and award certs
	h.checkAndAwardCerts(u.ID)

	// Load earned certs
	earnedMap := map[string]time.Time{}
	rows, _ := h.db.Query(`SELECT cert_key, earned_at FROM certifications WHERE user_id=?`, u.ID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var key, ts string
			rows.Scan(&key, &ts)
			t, _ := time.Parse("2006-01-02T15:04:05Z", ts)
			earnedMap[key] = t
		}
	}

	type certRow struct {
		Def      certDef
		Earned   bool
		EarnedAt time.Time
	}
	var certs []certRow
	for _, cd := range certDefs {
		row := certRow{Def: cd}
		if t, ok := earnedMap[cd.Key]; ok {
			row.Earned = true
			row.EarnedAt = t
		}
		certs = append(certs, row)
	}

	h.render(w, r, "certifications.html", map[string]any{"Certs": certs})
}

func (h *Handler) checkAndAwardCerts(userID int64) {
	award := func(key string) {
		h.db.Exec(`INSERT OR IGNORE INTO certifications(user_id, cert_key) VALUES(?,?)`, userID, key)
	}

	// analyst_trainee: 3+ intro labs with score >= 60
	var introCount int
	h.db.QueryRow(`SELECT COUNT(*) FROM investigations i JOIN labs l ON l.id=i.lab_id WHERE i.user_id=? AND i.status='submitted' AND i.score>=60 AND l.difficulty='intro'`, userID).Scan(&introCount)
	if introCount >= 3 {
		award("analyst_trainee")
	}

	// alert_triage: 10+ live alert submissions
	var alertCount int
	h.db.QueryRow(`SELECT COUNT(*) FROM live_investigations WHERE user_id=? AND status='submitted'`, userID).Scan(&alertCount)
	if alertCount >= 10 {
		award("alert_triage")
	}

	// soc_analyst: all core labs + 25 live alerts
	var coreTotal, corePassed int
	h.db.QueryRow(`SELECT COUNT(*) FROM labs WHERE difficulty='core' AND enabled=1`).Scan(&coreTotal)
	h.db.QueryRow(`SELECT COUNT(*) FROM investigations i JOIN labs l ON l.id=i.lab_id WHERE i.user_id=? AND i.status='submitted' AND i.score>=60 AND l.difficulty='core'`, userID).Scan(&corePassed)
	if coreTotal > 0 && corePassed >= coreTotal && alertCount >= 25 {
		award("soc_analyst")
	}

	// threat_hunter: 4 hunt sessions submitted with score >= 50
	var huntPassed int
	h.db.QueryRow(`SELECT COUNT(*) FROM hunt_sessions WHERE user_id=? AND status='submitted' AND score>=50`, userID).Scan(&huntPassed)
	if huntPassed >= 4 {
		award("threat_hunter")
	}

	// campaign_commander: at least 1 campaign completed
	var campDone int
	h.db.QueryRow(`SELECT COUNT(*) FROM campaign_runs WHERE user_id=? AND status='completed'`, userID).Scan(&campDone)
	if campDone >= 1 {
		award("campaign_commander")
	}

	// senior_analyst: all labs passed + 1 campaign + streak >= 7
	var totalLabs, passedLabs, streak int
	h.db.QueryRow(`SELECT COUNT(*) FROM labs WHERE enabled=1`).Scan(&totalLabs)
	h.db.QueryRow(`SELECT COUNT(*) FROM investigations i JOIN labs l ON l.id=i.lab_id WHERE i.user_id=? AND i.status='submitted' AND i.score>=60`, userID).Scan(&passedLabs)
	h.db.QueryRow(`SELECT COALESCE(streak_count,0) FROM user_streak WHERE user_id=?`, userID).Scan(&streak)
	if totalLabs > 0 && passedLabs >= totalLabs && campDone >= 1 && streak >= 7 {
		award("senior_analyst")
	}
}
