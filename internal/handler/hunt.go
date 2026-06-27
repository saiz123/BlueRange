package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/bluerange/bluerange/internal/auth"
	"github.com/bluerange/bluerange/internal/hunt"
)

type huntFinding struct {
	RowID   int64  `json:"row_id"`
	Source  string `json:"source"`
	Host    string `json:"host"`
	Message string `json:"message"`
	Ts      string `json:"ts"`
}

// GET /hunt
func (h *Handler) getHuntList(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())

	// Load completed sessions
	rows, _ := h.db.Query(`SELECT hunt_key, status, score, submitted_at FROM hunt_sessions WHERE user_id=? ORDER BY started_at DESC`, u.ID)
	doneMap := map[string]struct {
		Score       int
		SubmittedAt time.Time
	}{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var key, status string
			var score sql.NullInt64
			var submittedAt sql.NullString
			rows.Scan(&key, &status, &score, &submittedAt)
			if status == "submitted" {
				doneMap[key] = struct {
					Score       int
					SubmittedAt time.Time
				}{int(score.Int64), time.Time{}}
			}
		}
	}

	type huntRow struct {
		Hunt  hunt.Hunt
		Done  bool
		Score int
	}
	var list []huntRow
	for _, hh := range hunt.Hunts {
		row := huntRow{Hunt: hh}
		if d, ok := doneMap[hh.Key]; ok {
			row.Done = true
			row.Score = d.Score
		}
		list = append(list, row)
	}

	h.render(w, r, "hunt_list.html", map[string]any{"Hunts": list})
}

// GET /hunt/{key}
func (h *Handler) getHunt(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	key := chi.URLParam(r, "key")

	hh := hunt.Get(key)
	if hh == nil {
		http.NotFound(w, r)
		return
	}

	// Ensure session exists
	h.db.Exec(`INSERT OR IGNORE INTO hunt_sessions(user_id, hunt_key) VALUES(?,?)`, u.ID, key)

	var sessionID int64
	var status string
	var findingsJSON string
	h.db.QueryRow(`SELECT id, status, findings_json FROM hunt_sessions WHERE user_id=? AND hunt_key=?`, u.ID, key).
		Scan(&sessionID, &status, &findingsJSON)

	if status == "submitted" {
		http.Redirect(w, r, "/hunt/"+key+"/result", http.StatusSeeOther)
		return
	}

	var findings []huntFinding
	json.Unmarshal([]byte(findingsJSON), &findings)

	h.render(w, r, "hunt.html", map[string]any{
		"Hunt":      hh,
		"SessionID": sessionID,
		"Findings":  findings,
	})
}

// GET /api/hunt/{key}/search  — HTMX partial for log search
func (h *Handler) apiHuntSearch(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	hh := hunt.Get(key)
	if hh == nil {
		w.WriteHeader(404)
		return
	}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		w.Write([]byte(`<p class="no-results">Enter a search term above.</p>`))
		return
	}

	// Build lab_id filter
	labFilter := strings.Join(hh.LabScope, "','")

	type logRow struct {
		RowID   int64
		Source  string
		Ts      string
		Host    string
		Message string
	}
	var results []logRow

	rows, err := h.db.Query(
		`SELECT rowid, source, ts, host, message FROM logs_fts WHERE lab_id IN ('`+labFilter+`') AND logs_fts MATCH ? ORDER BY ts LIMIT 50`,
		q,
	)
	if err == nil && rows != nil {
		defer rows.Close()
		for rows.Next() {
			var lr logRow
			rows.Scan(&lr.RowID, &lr.Source, &lr.Ts, &lr.Host, &lr.Message)
			results = append(results, lr)
		}
	}

	// Render HTML partial
	w.Header().Set("Content-Type", "text/html")
	if len(results) == 0 {
		w.Write([]byte(`<p class="no-results">No results for that query.</p>`))
		return
	}

	var sb strings.Builder
	sb.WriteString(`<div class="log-results">`)
	for _, lr := range results {
		sb.WriteString(`<div class="log-row" style="cursor:pointer" onclick="addFinding(` +
			`{row_id:` + itoa64(lr.RowID) + `,source:'` + htmlEsc(lr.Source) + `',host:'` + htmlEsc(lr.Host) +
			`',message:'` + htmlEsc(lr.Message) + `',ts:'` + htmlEsc(lr.Ts) + `'})">`)
		sb.WriteString(`<span class="log-ts">` + htmlEsc(lr.Ts) + `</span>`)
		sb.WriteString(`<span class="log-src">` + htmlEsc(lr.Source) + `</span>`)
		sb.WriteString(`<span class="log-host">` + htmlEsc(lr.Host) + `</span>`)
		sb.WriteString(`<span class="log-msg">` + htmlEsc(lr.Message) + `</span>`)
		sb.WriteString(`<span style="margin-left:auto;color:var(--blue);font-size:11px">+ Mark</span>`)
		sb.WriteString(`</div>`)
	}
	sb.WriteString(`</div>`)
	w.Write([]byte(sb.String()))
}

// POST /hunt/{key}/submit
func (h *Handler) postSubmitHunt(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	key := chi.URLParam(r, "key")

	hh := hunt.Get(key)
	if hh == nil {
		http.NotFound(w, r)
		return
	}

	r.ParseForm()
	findingsRaw := r.FormValue("findings_json")
	var findings []huntFinding
	json.Unmarshal([]byte(findingsRaw), &findings)

	// Grade: check which seed terms appear in findings messages
	allText := ""
	for _, f := range findings {
		allText += " " + strings.ToLower(f.Message) + " " + strings.ToLower(f.Source)
	}

	score := 0
	for _, seed := range hh.Seeds {
		if strings.Contains(allText, strings.ToLower(seed.Term)) {
			score += seed.Points
		}
	}
	if score > hh.MaxScore {
		score = hh.MaxScore
	}

	findingsJSON, _ := json.Marshal(findings)
	h.db.Exec(
		`UPDATE hunt_sessions SET status='submitted', findings_json=?, score=?, submitted_at=CURRENT_TIMESTAMP WHERE user_id=? AND hunt_key=?`,
		string(findingsJSON), score, u.ID, key,
	)

	// Skill credit
	h.db.Exec(
		`INSERT INTO user_skills(user_id,skill_key,score) VALUES(?,?,?) ON CONFLICT(user_id,skill_key) DO UPDATE SET score=score+?`,
		u.ID, "threat_intel", score/10, score/10,
	)

	h.updateMissionProgress(u.ID, "hunt_submit", map[string]any{"score": score})

	http.Redirect(w, r, "/hunt/"+key+"/result", http.StatusSeeOther)
}

// GET /hunt/{key}/result
func (h *Handler) getHuntResult(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	key := chi.URLParam(r, "key")

	hh := hunt.Get(key)
	if hh == nil {
		http.NotFound(w, r)
		return
	}

	var score int
	var findingsJSON string
	h.db.QueryRow(`SELECT COALESCE(score,0), findings_json FROM hunt_sessions WHERE user_id=? AND hunt_key=?`, u.ID, key).
		Scan(&score, &findingsJSON)

	var findings []huntFinding
	json.Unmarshal([]byte(findingsJSON), &findings)

	// Which seeds were found?
	allText := ""
	for _, f := range findings {
		allText += " " + strings.ToLower(f.Message) + " " + strings.ToLower(f.Source)
	}

	type seedResult struct {
		Term        string
		Description string
		Points      int
		Found       bool
	}
	var seedResults []seedResult
	for _, seed := range hh.Seeds {
		seedResults = append(seedResults, seedResult{
			Term:        seed.Term,
			Description: seed.Description,
			Points:      seed.Points,
			Found:       strings.Contains(allText, strings.ToLower(seed.Term)),
		})
	}

	h.render(w, r, "hunt_result.html", map[string]any{
		"Hunt":        hh,
		"Score":       score,
		"MaxScore":    hh.MaxScore,
		"Findings":    findings,
		"SeedResults": seedResults,
		"Passed":      score >= hh.MaxScore/2,
	})
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }
func htmlEsc(s string) string {
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, `"`, `&quot;`)
	s = strings.ReplaceAll(s, `<`, `&lt;`)
	s = strings.ReplaceAll(s, `>`, `&gt;`)
	return s
}
