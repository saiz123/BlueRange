package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/bluerange/bluerange/internal/alertengine"
	"github.com/bluerange/bluerange/internal/auth"
)

type mitreEntry struct {
	ID   string
	Name string
}

func commonMITRE() []mitreEntry {
	return []mitreEntry{
		{"T1059", "Command and Scripting Interpreter"},
		{"T1055", "Process Injection"},
		{"T1486", "Data Encrypted for Impact"},
		{"T1490", "Inhibit System Recovery"},
		{"T1566", "Phishing"},
		{"T1078", "Valid Accounts"},
		{"T1110", "Brute Force"},
		{"T1021", "Remote Services"},
		{"T1041", "Exfiltration Over C2 Channel"},
		{"T1048", "Exfiltration Over Alt Protocol"},
		{"T1071", "Application Layer Protocol"},
		{"T1053", "Scheduled Task/Job"},
		{"T1136", "Create Account"},
		{"T1098", "Account Manipulation"},
		{"T1105", "Ingress Tool Transfer"},
		{"T1027", "Obfuscated Files or Information"},
		{"T1046", "Network Service Discovery"},
		{"T1560", "Archive Collected Data"},
		{"T1568", "Dynamic Resolution"},
		{"T1195", "Supply Chain Compromise"},
		{"T1552", "Unsecured Credentials"},
		{"T1561", "Disk Wipe"},
		{"T1485", "Data Destruction"},
		{"T1133", "External Remote Services"},
		{"T1547", "Boot/Logon Autostart Execution"},
		{"T1068", "Exploitation for Privilege Escalation"},
		{"T1134", "Access Token Manipulation"},
		{"T1176", "Browser Extensions"},
		{"T1530", "Data from Cloud Storage"},
		{"T1567", "Exfiltration to Cloud Storage"},
	}
}

func categoryToSkill(cat string) string {
	m := map[string]string{
		"malware":              "malware",
		"phishing":             "phishing",
		"c2":                   "network",
		"brute-force":          "identity",
		"data-exfil":           "data",
		"web-attack":           "web",
		"lateral-movement":     "network",
		"persistence":          "endpoint",
		"privilege-escalation": "identity",
		"recon":                "network",
		"compliance":           "process",
	}
	if s, ok := m[cat]; ok {
		return s
	}
	return "endpoint"
}

func (h *Handler) loadLiveAlert(id int64) (alertengine.GeneratedAlert, error) {
	var a alertengine.GeneratedAlert
	var logJSON, rubricJSON, triggeredAt, expiresAt string
	err := h.db.QueryRow(
		`SELECT id,template_key,severity,source,category,rule_text,scenario,src_ip,hostname,username_val,log_json,rubric_json,triggered_at,expires_at FROM live_alerts WHERE id=?`, id,
	).Scan(&a.ID, &a.TemplateKey, &a.Severity, &a.Source, &a.Category, &a.RuleText, &a.Scenario,
		&a.SrcIP, &a.Hostname, &a.Username, &logJSON, &rubricJSON, &triggeredAt, &expiresAt)
	if err != nil {
		return a, err
	}
	json.Unmarshal([]byte(logJSON), &a.Logs)
	json.Unmarshal([]byte(rubricJSON), &a.Rubric)
	a.TriggeredAt, _ = time.Parse("2006-01-02T15:04:05Z", triggeredAt)
	a.ExpiresAt, _ = time.Parse("2006-01-02T15:04:05Z", expiresAt)
	return a, nil
}

// GET /alert/{alertID}
func (h *Handler) getLiveAlert(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	alertID, err := strconv.ParseInt(chi.URLParam(r, "alertID"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	alert, err := h.loadLiveAlert(alertID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Auto-create investigation record
	h.db.Exec(`INSERT OR IGNORE INTO live_investigations(alert_id, user_id) VALUES(?,?)`, alertID, u.ID)

	// Check if already submitted → redirect to result
	var submittedAt sql.NullTime
	h.db.QueryRow(`SELECT submitted_at FROM live_investigations WHERE alert_id=? AND user_id=?`, alertID, u.ID).Scan(&submittedAt)
	if submittedAt.Valid {
		http.Redirect(w, r, "/alert/"+chi.URLParam(r, "alertID")+"/result", http.StatusSeeOther)
		return
	}

	// Load draft state
	var verdict, severity, rationale, mitreJSON string
	var escalated int
	h.db.QueryRow(
		`SELECT COALESCE(verdict,''), COALESCE(severity_sub,''), COALESCE(rationale,''), COALESCE(mitre_tags,'[]'), COALESCE(escalated,0) FROM live_investigations WHERE alert_id=? AND user_id=?`,
		alertID, u.ID,
	).Scan(&verdict, &severity, &rationale, &mitreJSON, &escalated)

	var mitreTags []string
	json.Unmarshal([]byte(mitreJSON), &mitreTags)

	h.render(w, r, "live_alert.html", map[string]any{
		"Alert":     alert,
		"Verdict":   verdict,
		"Severity":  severity,
		"Rationale": rationale,
		"MITRETags": mitreTags,
		"Escalated": escalated == 1,
		"MITREAll":  commonMITRE(),
	})
}

// POST /alert/{alertID}/submit
func (h *Handler) postSubmitLiveAlert(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	alertID, err := strconv.ParseInt(chi.URLParam(r, "alertID"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	alert, err := h.loadLiveAlert(alertID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	r.ParseForm()
	verdict := r.FormValue("verdict")
	severity := r.FormValue("severity")
	rationale := r.FormValue("rationale")
	escalated := r.FormValue("escalated") == "true"
	mitreRaw := r.Form["mitre"]

	sub := alertengine.LiveSubmission{
		Verdict:   verdict,
		Severity:  severity,
		Rationale: rationale,
		MITRETags: mitreRaw,
		Escalated: escalated,
	}
	result := alertengine.GradeLive(alert.Rubric, sub)

	feedbackJSON, _ := json.Marshal(result.Feedback)
	mitreJSON, _ := json.Marshal(mitreRaw)

	h.db.Exec(
		`UPDATE live_investigations SET status='submitted', verdict=?, severity_sub=?, rationale=?, mitre_tags=?, escalated=?, score=?, feedback_json=?, submitted_at=CURRENT_TIMESTAMP WHERE alert_id=? AND user_id=?`,
		verdict, severity, rationale, string(mitreJSON), boolToInt(escalated), result.Score,
		string(feedbackJSON), alertID, u.ID,
	)

	// Credit skill score
	skill := categoryToSkill(alert.Category)
	skillPoints := result.Score / 10
	if skillPoints > 0 {
		h.db.Exec(
			`INSERT INTO user_skills(user_id,skill_key,score) VALUES(?,?,?) ON CONFLICT(user_id,skill_key) DO UPDATE SET score=score+?`,
			u.ID, skill, skillPoints, skillPoints,
		)
	}

	// Check if this alert belongs to a campaign stage
	h.completeCampaignStage(u.ID, alertID, result.Score)

	http.Redirect(w, r, "/alert/"+chi.URLParam(r, "alertID")+"/result", http.StatusSeeOther)
}

// POST /alert/{alertID}/draft — auto-save, no redirect
func (h *Handler) postDraftLiveAlert(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	alertID, err := strconv.ParseInt(chi.URLParam(r, "alertID"), 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	r.ParseForm()
	mitreRaw := r.Form["mitre"]
	mitreJSON, _ := json.Marshal(mitreRaw)
	h.db.Exec(
		`UPDATE live_investigations SET verdict=?, severity_sub=?, rationale=?, mitre_tags=?, escalated=? WHERE alert_id=? AND user_id=? AND status='in_progress'`,
		r.FormValue("verdict"), r.FormValue("severity"), r.FormValue("rationale"),
		string(mitreJSON), boolToInt(r.FormValue("escalated") == "true"), alertID, u.ID,
	)
	w.WriteHeader(http.StatusNoContent)
}

// GET /alert/{alertID}/result
func (h *Handler) getLiveAlertResult(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	alertID, err := strconv.ParseInt(chi.URLParam(r, "alertID"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	alert, err := h.loadLiveAlert(alertID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	var verdict, severity, rationale, mitreJSON string
	var escalated, score int
	h.db.QueryRow(
		`SELECT COALESCE(verdict,''), COALESCE(severity_sub,''), COALESCE(rationale,''), COALESCE(mitre_tags,'[]'), COALESCE(escalated,0), COALESCE(score,0) FROM live_investigations WHERE alert_id=? AND user_id=?`,
		alertID, u.ID,
	).Scan(&verdict, &severity, &rationale, &mitreJSON, &escalated, &score)

	var mitreTags []string
	json.Unmarshal([]byte(mitreJSON), &mitreTags)

	sub := alertengine.LiveSubmission{
		Verdict:   verdict,
		Severity:  severity,
		Rationale: rationale,
		MITRETags: mitreTags,
		Escalated: escalated == 1,
	}
	result := alertengine.GradeLive(alert.Rubric, sub)

	h.render(w, r, "live_result.html", map[string]any{
		"Alert":  alert,
		"Result": result,
		"Score":  score,
	})
}
