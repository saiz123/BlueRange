package handler

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
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
	tmpl     *template.Template
	staticFS http.Handler
	log      *slog.Logger
}

func New(database *db.DB, labs *lab.Registry, tmpl *template.Template, staticDir string, log *slog.Logger) *Handler {
	return &Handler{
		db:       database,
		labs:     labs,
		tmpl:     tmpl,
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

	r.Group(func(r chi.Router) {
		r.Use(auth.RequireLogin)
		r.Get("/queue", h.getQueue)
		r.Get("/dashboard", h.getDashboard)
		r.Get("/investigate/{labID}", h.getInvestigate)
		r.Post("/investigate/{labID}/start", h.postStartInvestigation)
		r.Post("/investigate/{labID}/submit", h.postSubmit)
		r.Get("/result/{labID}", h.getResult)
		r.Get("/walkthrough/{labID}", h.getWalkthrough)
		r.Get("/playbooks", h.getPlaybooks)

		// htmx API endpoints
		r.Get("/api/logs/{labID}", h.apiLogs)
		r.Post("/api/enrichment", h.apiEnrichment)
		r.Get("/api/email/{labID}", h.apiEmail)

		r.Group(func(r chi.Router) {
			r.Use(auth.RequireAdmin)
			r.Get("/admin", h.getAdmin)
			r.Post("/admin/users/{id}/delete", h.adminDeleteUser)
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
	Lab        *lab.Lab
	Status     string
	Score      *int
	StartedAt  *time.Time
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

	h.render(w, r, "queue.html", map[string]any{
		"Alerts": alerts,
	})
}

// ── Dashboard ────────────────────────────────────────────────────────────────

type skillBar struct {
	Name    string
	Key     string
	Score   int
	MaxScore int
}

func (h *Handler) getDashboard(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())

	var completed, total int
	total = len(h.labs.All())
	h.db.QueryRow(`SELECT COUNT(*) FROM investigations WHERE user_id=? AND status='submitted'`, u.ID).Scan(&completed)

	var totalScore int
	h.db.QueryRow(`SELECT COALESCE(SUM(score),0) FROM investigations WHERE user_id=? AND status='submitted'`, u.ID).Scan(&totalScore)

	// skill bars
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

	h.render(w, r, "dashboard.html", map[string]any{
		"Completed":  completed,
		"Total":      total,
		"TotalScore": totalScore,
		"Skills":     skills,
		"Readiness":  readiness,
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

	sub := grader.Submission{
		Verdict:   r.FormValue("verdict"),
		Severity:  r.FormValue("severity"),
		Rationale: r.FormValue("rationale"),
		Mitre:     mitre,
		Escalated: r.FormValue("escalation") == "escalate",
	}
	result := grader.Grade(l, sub)

	_, err := h.db.Exec(`
		UPDATE investigations
		SET verdict=?, severity=?, rationale=?, mitre_tags=?, escalated=?,
		    score=?, feedback_json=?, status='submitted', submitted_at=CURRENT_TIMESTAMP
		WHERE user_id=? AND lab_id=?`,
		sub.Verdict, sub.Severity, sub.Rationale, string(mitreJSON),
		boolToInt(sub.Escalated), result.Score, result.JSON(), u.ID, labID)
	if err != nil {
		h.log.Error("update investigation", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Update skill scores
	h.updateSkills(u.ID, l, result)

	http.Redirect(w, r, "/result/"+labID, http.StatusSeeOther)
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
	h.render(w, r, "result.html", map[string]any{
		"Lab": l,
		"Inv": inv,
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
	if data == nil {
		data = map[string]any{}
	}
	data["User"] = auth.UserFromCtx(r.Context())
	data["Now"] = time.Now()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, tmpl, data); err != nil {
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
