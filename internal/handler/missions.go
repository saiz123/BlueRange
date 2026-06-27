package handler

import (
	"fmt"
	"strings"
	"time"
)

// ── Mission catalogue ─────────────────────────────────────────────────────────

type missionDef struct {
	Type        string
	TitleFmt    string // may contain %d for target_n
	Description string
	BaseXP      int
}

var missionCatalogue = []missionDef{
	{
		Type:        "streak_active",
		TitleFmt:    "Stay on the clock",
		Description: "Submit any investigation or live alert today to maintain your streak.",
		BaseXP:      10,
	},
	{
		Type:        "triage_alerts",
		TitleFmt:    "Triage %d live alert(s)",
		Description: "Close live alert investigations from the queue.",
		BaseXP:      20,
	},
	{
		Type:        "pass_lab",
		TitleFmt:    "Resolve a %s incident",
		Description: "Submit a lab investigation in the target category with a passing score (≥60).",
		BaseXP:      20,
	},
	{
		Type:        "exam_mode",
		TitleFmt:    "Work without the safety net",
		Description: "Pass any lab in Exam mode — no guided hints.",
		BaseXP:      35,
	},
	{
		Type:        "mitre_mapping",
		TitleFmt:    "Map %d+ MITRE techniques in one report",
		Description: "Submit a single investigation tagging the required number of MITRE techniques.",
		BaseXP:      25,
	},
	{
		Type:        "quality_report",
		TitleFmt:    "Write a detailed incident report",
		Description: "Submit an investigation with a rationale of at least 75 words.",
		BaseXP:      20,
	},
	{
		Type:        "hunt_session",
		TitleFmt:    "Run a threat hunt",
		Description: "Submit any threat hunt session.",
		BaseXP:      35,
	},
	{
		Type:        "campaign_advance",
		TitleFmt:    "Advance your active campaign",
		Description: "Complete any campaign stage investigation.",
		BaseXP:      35,
	},
	{
		Type:        "shift_complete",
		TitleFmt:    "Complete a full SOC shift",
		Description: "Start and finish a SOC shift simulation.",
		BaseXP:      35,
	},
}

// ── Mission row (from DB) ─────────────────────────────────────────────────────

type missionRow struct {
	ID          int64
	Slot        int
	Type        string
	Title       string
	Description string
	TargetN     int
	Progress    int
	Completed   bool
	RewardXP    int
}

func (m missionRow) ProgressPct() int {
	if m.TargetN == 0 {
		return 100
	}
	p := m.Progress * 100 / m.TargetN
	if p > 100 {
		return 100
	}
	return p
}

// ── ensureDailyMissions ───────────────────────────────────────────────────────

// ensureDailyMissions creates today's 3 missions for the user if they don't exist yet.
func (h *Handler) ensureDailyMissions(userID int64, tier int) {
	today := time.Now().UTC().Format("2006-01-02")

	var count int
	h.db.QueryRow(`SELECT COUNT(*) FROM daily_missions WHERE user_id=? AND date_key=?`, userID, today).Scan(&count)
	if count >= 3 {
		return
	}

	// Slot 1 — always easy: streak_active
	h.insertMission(userID, today, 1, "streak_active", "Stay on the clock",
		"Submit any investigation or live alert today to maintain your streak.",
		1, 10)

	// Slot 2 — medium: target weakest skill domain
	h.insertMission(userID, today, 2, h.buildSlot2Mission(userID, tier))

	// Slot 3 — hard: rotates by day of year
	h.insertMission(userID, today, 3, h.buildSlot3Mission(tier, today))
}

func (h *Handler) insertMission(userID int64, dateKey string, slot int, mType, title, desc string, targetN, rewardXP int) {
	h.db.Exec(
		`INSERT OR IGNORE INTO daily_missions(user_id,date_key,slot,type,title,description,target_n,reward_xp) VALUES(?,?,?,?,?,?,?,?)`,
		userID, dateKey, slot, mType, title, desc, targetN, rewardXP,
	)
}

// skill domain → lab category mapping for pass_lab missions
var skillToCategory = map[string]string{
	"phishing":          "phishing",
	"log_analysis":      "brute-force",
	"network":           "c2",
	"endpoint":          "lateral-movement",
	"malware":           "malware",
	"threat_intel":      "data-exfil",
	"mitre":             "malware",
	"incident_response": "multi-stage",
}

var categoryLabel = map[string]string{
	"phishing":          "phishing",
	"brute-force":       "brute-force",
	"c2":                "C2/network",
	"lateral-movement":  "lateral movement",
	"malware":           "malware",
	"data-exfil":        "data exfiltration",
	"multi-stage":       "multi-stage incident",
}

func (h *Handler) buildSlot2Mission(userID int64, tier int) (mType, title, desc string, targetN, rewardXP int) {
	// Find weakest skill
	var weakKey string
	h.db.QueryRow(`SELECT skill_key FROM user_skills WHERE user_id=? ORDER BY score ASC LIMIT 1`, userID).Scan(&weakKey)
	if weakKey == "" {
		weakKey = "phishing"
	}
	cat := skillToCategory[weakKey]
	if cat == "" {
		cat = "malware"
	}
	label := categoryLabel[cat]
	if label == "" {
		label = cat
	}

	xp := 20
	if tier >= 5 {
		xp = 30
	}
	return "pass_lab", fmt.Sprintf("Resolve a %s incident", label),
		fmt.Sprintf("Pass a lab in the '%s' category (score ≥60) to build your weakest skill.", label),
		1, xp
}

// Hard slot rotates: day0=hunt, day1=campaign, day2=exam_mode, day3=shift, day4=mitre, day5=quality
var hardMissions = []struct {
	mType  string
	titleFn func(tier int) string
	desc   string
	targetN int
	xp     int
}{
	{"hunt_session", func(_ int) string { return "Run a threat hunt" },
		"Submit any threat hunt session.", 1, 35},
	{"campaign_advance", func(_ int) string { return "Advance your active campaign" },
		"Complete any campaign stage.", 1, 35},
	{"exam_mode", func(_ int) string { return "Work without the safety net" },
		"Pass any lab in Exam mode — no guided hints.", 1, 35},
	{"shift_complete", func(_ int) string { return "Complete a full SOC shift" },
		"Start and finish a timed SOC shift simulation.", 1, 35},
	{"mitre_mapping", func(tier int) string {
		n := 2 + tier/3
		return fmt.Sprintf("Tag %d+ MITRE techniques in one report", n)
	}, "Submit a single investigation with multiple MITRE tags.", 0, 30}, // targetN set below
	{"quality_report", func(_ int) string { return "Write a detailed incident report" },
		"Submit an investigation with a rationale of at least 75 words.", 1, 25},
}

func (h *Handler) buildSlot3Mission(tier int, dateKey string) (mType, title, desc string, targetN, rewardXP int) {
	// Pick by day-of-year mod len
	t, _ := time.Parse("2006-01-02", dateKey)
	idx := t.YearDay() % len(hardMissions)
	m := hardMissions[idx]

	tn := m.targetN
	if m.mType == "mitre_mapping" {
		tn = 2 + tier/3
		if tn < 2 {
			tn = 2
		}
	}
	xp := m.xp
	if tier >= 5 {
		xp = xp * 3 / 2 // ×1.5 for senior tiers
	}
	return m.mType, m.titleFn(tier), m.desc, tn, xp
}

// ── loadTodayMissions ─────────────────────────────────────────────────────────

func (h *Handler) loadTodayMissions(userID int64) []missionRow {
	today := time.Now().UTC().Format("2006-01-02")
	rows, err := h.db.Query(
		`SELECT id, slot, type, title, description, target_n, progress, completed, reward_xp
		 FROM daily_missions WHERE user_id=? AND date_key=? ORDER BY slot`,
		userID, today,
	)
	if err != nil || rows == nil {
		return nil
	}
	defer rows.Close()
	var missions []missionRow
	for rows.Next() {
		var m missionRow
		var completed int
		rows.Scan(&m.ID, &m.Slot, &m.Type, &m.Title, &m.Description, &m.TargetN, &m.Progress, &completed, &m.RewardXP)
		m.Completed = completed == 1
		missions = append(missions, m)
	}
	return missions
}

// ── updateMissionProgress ─────────────────────────────────────────────────────

// updateMissionProgress checks today's missions, increments matching ones, and awards XP.
// Returns titles of newly-completed missions (for toast notifications).
func (h *Handler) updateMissionProgress(userID int64, eventType string, meta map[string]any) []string {
	today := time.Now().UTC().Format("2006-01-02")
	missions := h.loadTodayMissions(userID)
	var completed []string

	for _, m := range missions {
		if m.Completed {
			continue
		}
		newProgress := m.Progress
		switch m.Type {
		case "streak_active":
			// Any event counts
			newProgress = m.TargetN

		case "triage_alerts":
			if eventType == "live_alert_submit" {
				newProgress++
			}

		case "pass_lab":
			if eventType == "lab_submit" {
				score, _ := meta["score"].(int)
				cat, _ := meta["category"].(string)
				// Match if category matches mission title hint
				if score >= 60 && strings.Contains(strings.ToLower(m.Title), strings.ToLower(cat)) {
					newProgress = m.TargetN
				} else if score >= 60 && !strings.Contains(m.Title, "phishing") &&
					!strings.Contains(m.Title, "malware") && !strings.Contains(m.Title, "C2") &&
					!strings.Contains(m.Title, "lateral") && !strings.Contains(m.Title, "data") &&
					!strings.Contains(m.Title, "multi") && !strings.Contains(m.Title, "brute") {
					newProgress = m.TargetN
				}
			}

		case "exam_mode":
			if eventType == "lab_submit" {
				mode, _ := meta["mode"].(string)
				score, _ := meta["score"].(int)
				if mode == "exam" && score >= 60 {
					newProgress = m.TargetN
				}
			}

		case "mitre_mapping":
			if eventType == "lab_submit" || eventType == "live_alert_submit" {
				mitreCount, _ := meta["mitre_count"].(int)
				if mitreCount >= m.TargetN {
					newProgress = m.TargetN
				}
			}

		case "quality_report":
			if eventType == "lab_submit" || eventType == "live_alert_submit" {
				wordCount, _ := meta["word_count"].(int)
				if wordCount >= 75 {
					newProgress = m.TargetN
				}
			}

		case "hunt_session":
			if eventType == "hunt_submit" {
				newProgress = m.TargetN
			}

		case "campaign_advance":
			if eventType == "campaign_stage" {
				newProgress = m.TargetN
			}

		case "shift_complete":
			if eventType == "shift_end" {
				newProgress = m.TargetN
			}
		}

		if newProgress != m.Progress {
			h.db.Exec(`UPDATE daily_missions SET progress=? WHERE id=?`, newProgress, m.ID)
		}
		if newProgress >= m.TargetN && !m.Completed {
			h.db.Exec(`UPDATE daily_missions SET completed=1 WHERE id=?`, m.ID)
			// Award XP
			h.db.Exec(
				`UPDATE user_streak SET bonus_xp=bonus_xp+? WHERE user_id=?`,
				m.RewardXP, userID,
			)
			completed = append(completed, m.Title)
		}
	}

	// Bonus XP if all 3 missions now complete
	var doneCount int
	h.db.QueryRow(`SELECT COUNT(*) FROM daily_missions WHERE user_id=? AND date_key=? AND completed=1`, userID, today).Scan(&doneCount)
	if doneCount == 3 && len(completed) > 0 {
		// Check we haven't already given the all-complete bonus (by checking a sentinel)
		// Use a slot=0 row as sentinel
		var alreadyBonused int
		h.db.QueryRow(`SELECT COUNT(*) FROM daily_missions WHERE user_id=? AND date_key=? AND slot=0`, userID, today).Scan(&alreadyBonused)
		if alreadyBonused == 0 {
			h.db.Exec(
				`INSERT OR IGNORE INTO daily_missions(user_id,date_key,slot,type,title,description,target_n,progress,completed,reward_xp) VALUES(?,?,0,'bonus','All missions complete','',1,1,1,25)`,
				userID, today,
			)
			h.db.Exec(`UPDATE user_streak SET bonus_xp=bonus_xp+25 WHERE user_id=?`, userID)
			completed = append(completed, "All missions complete (+25 bonus XP)")
		}
	}

	return completed
}

// ── computeCareerTier ─────────────────────────────────────────────────────────

type careerTier struct {
	Num       int
	Title     string
	Color     string
	NextTitle string
	NextGate  string
	IsNew     bool
}

var tierDefs = []struct {
	num      int
	title    string
	color    string
	xpGate   int
	skillFn  func(h *Handler, userID int64, xp int) bool
	nextGate string
}{
	{1, "Probationary Analyst", "gray", 0, func(_ *Handler, _ int64, _ int) bool { return true },
		"Submit 3 labs to advance"},
	{2, "SOC Analyst L1", "blue", 150, func(h *Handler, uid int64, xp int) bool {
		var n int
		h.db.QueryRow(`SELECT COUNT(*) FROM investigations WHERE user_id=? AND status='submitted'`, uid).Scan(&n)
		return n >= 3
	}, "Pass all intro labs + close 5 live alerts"},
	{3, "SOC Analyst L2", "teal", 400, func(h *Handler, uid int64, xp int) bool {
		var introPassed, introTotal, liveCount int
		h.db.QueryRow(`SELECT COUNT(*) FROM labs WHERE difficulty='intro' AND enabled=1`).Scan(&introTotal)
		h.db.QueryRow(`SELECT COUNT(*) FROM investigations i JOIN labs l ON l.id=i.lab_id WHERE i.user_id=? AND l.difficulty='intro' AND i.status='submitted' AND i.score>=70`, uid).Scan(&introPassed)
		h.db.QueryRow(`SELECT COUNT(*) FROM live_investigations WHERE user_id=? AND status='submitted'`, uid).Scan(&liveCount)
		return introTotal > 0 && introPassed >= introTotal && liveCount >= 5
	}, "Pass 5 core labs + 2 skill scores ≥60 + 7-day streak"},
	{4, "Senior Analyst", "purple", 700, func(h *Handler, uid int64, xp int) bool {
		var corePassed, skillsAbove60, streak int
		h.db.QueryRow(`SELECT COUNT(*) FROM investigations i JOIN labs l ON l.id=i.lab_id WHERE i.user_id=? AND l.difficulty='core' AND i.status='submitted' AND i.score>=60`, uid).Scan(&corePassed)
		h.db.QueryRow(`SELECT COUNT(*) FROM user_skills WHERE user_id=? AND score>=60`, uid).Scan(&skillsAbove60)
		h.db.QueryRow(`SELECT COALESCE(streak_count,0) FROM user_streak WHERE user_id=?`, uid).Scan(&streak)
		return corePassed >= 5 && skillsAbove60 >= 2 && streak >= 7
	}, "Complete 2 threat hunts + earn Alert Triage Specialist cert"},
	{5, "Threat Intelligence Lead", "amber", 1000, func(h *Handler, uid int64, xp int) bool {
		var hunts, hasCert int
		h.db.QueryRow(`SELECT COUNT(*) FROM hunt_sessions WHERE user_id=? AND status='submitted'`, uid).Scan(&hunts)
		h.db.QueryRow(`SELECT COUNT(*) FROM certifications WHERE user_id=? AND cert_key='alert_triage'`, uid).Scan(&hasCert)
		return hunts >= 2 && hasCert > 0
	}, "Complete 1 campaign + earn SOC Analyst L1 cert"},
	{6, "Incident Response Lead", "red", 1400, func(h *Handler, uid int64, xp int) bool {
		var camps, hasCert int
		h.db.QueryRow(`SELECT COUNT(*) FROM campaign_runs WHERE user_id=? AND status='completed'`, uid).Scan(&camps)
		h.db.QueryRow(`SELECT COUNT(*) FROM certifications WHERE user_id=? AND cert_key='soc_analyst'`, uid).Scan(&hasCert)
		return camps >= 1 && hasCert > 0
	}, "Earn Senior Analyst cert + complete all 4 campaigns"},
	{7, "SOC Director", "gold", 1800, func(h *Handler, uid int64, xp int) bool {
		var camps, hasCert int
		h.db.QueryRow(`SELECT COUNT(*) FROM campaign_runs WHERE user_id=? AND status='completed'`, uid).Scan(&camps)
		h.db.QueryRow(`SELECT COUNT(*) FROM certifications WHERE user_id=? AND cert_key='senior_analyst'`, uid).Scan(&hasCert)
		return camps >= 4 && hasCert > 0
	}, ""},
}

func (h *Handler) computeCareerTier(userID int64, xp int) careerTier {
	h.db.Exec(`INSERT OR IGNORE INTO user_streak(user_id) VALUES(?)`, userID)
	current := 1
	for _, td := range tierDefs {
		if xp >= td.xpGate && td.skillFn(h, userID, xp) {
			current = td.num
		}
	}

	def := tierDefs[current-1]
	ct := careerTier{
		Num:   def.num,
		Title: def.title,
		Color: def.color,
	}
	if current < len(tierDefs) {
		next := tierDefs[current]
		ct.NextTitle = next.title
		ct.NextGate = next.nextGate
	}

	// Check if this is a promotion
	var cached int
	h.db.QueryRow(`SELECT COALESCE(career_tier,1) FROM user_streak WHERE user_id=?`, userID).Scan(&cached)
	if current > cached {
		ct.IsNew = true
		h.db.Exec(`UPDATE user_streak SET career_tier=?, tier_changed_at=CURRENT_TIMESTAMP WHERE user_id=?`, current, userID)
		// Award career badge
		badgeKey := []string{"", "rank_l1", "rank_l2", "rank_senior", "rank_ti_lead", "rank_ir_lead", "rank_director"}
		if current <= len(badgeKey)-1 && badgeKey[current] != "" {
			h.db.Exec(`INSERT OR IGNORE INTO badges(user_id,badge_key) VALUES(?,?)`, userID, badgeKey[current])
		}
	}

	return ct
}

// ── Threat of the day ─────────────────────────────────────────────────────────

var threatBlurbs = []string{
	"Scattered Spider is actively targeting Okta helpdesks via social engineering — verify all MFA resets.",
	"LockBit affiliates are exploiting Citrix Bleed (CVE-2023-4966) against unpatched NetScaler gateways.",
	"AsyncRAT campaigns using .NET loaders distributed via phishing PDFs — block unusual .NET process spawns.",
	"TA577 targeting WinRAR users with patched CVE-2023-38831 — ensure all endpoints are on v6.23+.",
	"Qakbot resurgence: watch for malicious OneNote attachments embedding HTML Application files.",
	"BEC actors are using EvilProxy to bypass MFA — investigate any mailbox rule changes.",
	"Royal ransomware group observed using Cobalt Strike with modified malleable C2 profiles to evade EDR.",
	"UAC-0099 targeting Ukrainian orgs with WinRAR exploits — check for PowerShell from archive handlers.",
	"TA416 deploying PlugX variants through DLL sideloading on compromised legitimate software.",
	"Lazarus Group abusing GitHub for C2 via legitimate API calls — monitor unusual GitHub traffic.",
	"FIN7 distributing DICELOADER via USB drives at conferences — flag removable media on secure hosts.",
	"New Mirai botnet variant scanning for exposed NVDIA GPU management interfaces on TCP/7070.",
	"Volt Typhoon using living-off-the-land techniques; unusual certutil and netsh activity is a key indicator.",
	"MuddyWater deploying Syncro RMM for persistent access — watch for unexpected RMM tool installs.",
	"Akira ransomware exploiting Cisco VPN accounts without MFA — audit VPN authentication logs now.",
	"DarkGate delivered via Microsoft Teams messages from compromised external accounts — verify DLP rules.",
	"SolarMarker using sophisticated multi-stage PowerShell to establish persistence via registry run keys.",
	"New credential-harvesting campaign targeting Azure AD via adversary-in-the-middle proxy frameworks.",
	"Earth Lusca using TurlaPoisonIvy implants — look for outbound connections to cloud storage providers.",
	"RA World ransomware abusing Plink for SOCKS tunneling — unexpected SSH-related binaries on Windows.",
	"Redline Stealer evading EDR by running entirely in-memory via process hollowing into legitimate apps.",
	"Midnight Blizzard (APT29) targeting M365 tenants with password spray attacks — enable Smart Lockout.",
	"ALPHV/BlackCat introducing new encryptor variant with faster encryption — backup verification critical.",
	"GhostLocker 2.0 sold as MaaS — expect increased RaaS attempts against SMB targets this week.",
	"Turla deploying ComRAT v4 via email — watch for Outlook using unusual COM interfaces.",
}

func threatOfTheDay() string {
	idx := time.Now().UTC().YearDay() % len(threatBlurbs)
	return threatBlurbs[idx]
}
