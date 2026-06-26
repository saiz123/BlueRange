package handler

// Platform professionalization: invite codes, registration, audit log, REST API, admin improvements.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/bluerange/bluerange/internal/auth"
)

// ── Invite Codes ──────────────────────────────────────────────────────────────

func (h *Handler) getRegister(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	h.render(w, r, "register.html", map[string]any{
		"Code":  code,
		"Error": r.URL.Query().Get("error"),
	})
}

func (h *Handler) postRegister(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.FormValue("code"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	if code == "" || username == "" || password == "" {
		http.Redirect(w, r, "/register?error=All+fields+required", http.StatusSeeOther)
		return
	}
	if len(password) < 8 {
		http.Redirect(w, r, "/register?code="+code+"&error=Password+must+be+8%2B+characters", http.StatusSeeOther)
		return
	}

	// Validate invite code
	var maxUses, useCount int
	var expiresAt *time.Time
	err := h.db.QueryRow(`SELECT max_uses, use_count, expires_at FROM invite_codes WHERE code=? AND used_by IS NULL`, code).
		Scan(&maxUses, &useCount, &expiresAt)
	if err != nil {
		http.Redirect(w, r, "/register?code="+code+"&error=Invalid+or+expired+invite+code", http.StatusSeeOther)
		return
	}
	if expiresAt != nil && time.Now().After(*expiresAt) {
		http.Redirect(w, r, "/register?code="+code+"&error=Invite+code+has+expired", http.StatusSeeOther)
		return
	}
	if maxUses > 0 && useCount >= maxUses {
		http.Redirect(w, r, "/register?code="+code+"&error=Invite+code+already+used", http.StatusSeeOther)
		return
	}

	// Check username availability
	var existing int
	h.db.QueryRow(`SELECT COUNT(*) FROM users WHERE username=?`, username).Scan(&existing)
	if existing > 0 {
		http.Redirect(w, r, "/register?code="+code+"&error=Username+already+taken", http.StatusSeeOther)
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	res, err := h.db.Exec(`INSERT INTO users(username, password_hash, role) VALUES(?,?,'learner')`, username, hash)
	if err != nil {
		http.Redirect(w, r, "/register?code="+code+"&error=Registration+failed", http.StatusSeeOther)
		return
	}
	newUserID, _ := res.LastInsertId()
	h.db.Exec(`UPDATE invite_codes SET used_by=?, used_at=CURRENT_TIMESTAMP, use_count=use_count+1 WHERE code=?`, newUserID, code)
	h.auditLog(newUserID, "register", username, r)

	// Auto-login
	token, _ := auth.CreateSession(h.db, newUserID)
	http.SetCookie(w, &http.Cookie{Name: "br_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/queue?toast=Welcome+to+BlueRange%21&toast_type=success", http.StatusSeeOther)
}

// ── Admin: Invite Management ──────────────────────────────────────────────────

type inviteRow struct {
	Code      string
	CreatedAt time.Time
	UsedBy    *string
	ExpiresAt *time.Time
	MaxUses   int
	UseCount  int
}

func (h *Handler) getAdminInvites(w http.ResponseWriter, r *http.Request) {
	rows, _ := h.db.Query(`
		SELECT i.code, i.max_uses, i.use_count, i.expires_at,
		       u.username
		FROM invite_codes i
		LEFT JOIN users u ON u.id = i.used_by
		ORDER BY rowid DESC LIMIT 50`)
	var invites []inviteRow
	if rows != nil {
		for rows.Next() {
			var iv inviteRow
			var usedBy *string
			rows.Scan(&iv.Code, &iv.MaxUses, &iv.UseCount, &iv.ExpiresAt, &usedBy)
			iv.UsedBy = usedBy
			invites = append(invites, iv)
		}
		rows.Close()
	}
	h.render(w, r, "admin_invites.html", map[string]any{"Invites": invites})
}

func (h *Handler) postAdminCreateInvite(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 8)
	rand.Read(b)
	code := hex.EncodeToString(b)
	u := auth.UserFromCtx(r.Context())

	expiryDays, _ := strconv.Atoi(r.FormValue("expiry_days"))
	var expiresAt *time.Time
	if expiryDays > 0 {
		t := time.Now().AddDate(0, 0, expiryDays)
		expiresAt = &t
	}

	h.db.Exec(`INSERT INTO invite_codes(code, created_by, expires_at, max_uses) VALUES(?,?,?,1)`,
		code, u.ID, expiresAt)
	h.auditLog(u.ID, "create_invite", code, r)
	http.Redirect(w, r, "/admin/invites?toast=Invite+code+created%3A+"+code+"&toast_type=success", http.StatusSeeOther)
}

func (h *Handler) postAdminRevokeInvite(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "code")
	u := auth.UserFromCtx(r.Context())
	h.db.Exec(`DELETE FROM invite_codes WHERE code=? AND used_by IS NULL`, code)
	h.auditLog(u.ID, "revoke_invite", code, r)
	http.Redirect(w, r, "/admin/invites?toast=Invite+revoked&toast_type=info", http.StatusSeeOther)
}

// ── Admin: User Management Improvements ──────────────────────────────────────

func (h *Handler) postAdminPromoteUser(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	u := auth.UserFromCtx(r.Context())

	var currentRole string
	h.db.QueryRow(`SELECT role FROM users WHERE id=?`, id).Scan(&currentRole)
	newRole := "admin"
	if currentRole == "admin" {
		newRole = "learner"
	}
	h.db.Exec(`UPDATE users SET role=? WHERE id=?`, newRole, id)
	h.auditLog(u.ID, "promote_user", fmt.Sprintf("id=%d role=%s", id, newRole), r)
	http.Redirect(w, r, "/admin?toast=User+role+updated&toast_type=success", http.StatusSeeOther)
}

func (h *Handler) postAdminResetProgress(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	u := auth.UserFromCtx(r.Context())
	if id == u.ID {
		http.Error(w, "cannot reset own progress", http.StatusBadRequest)
		return
	}
	h.db.Exec(`DELETE FROM investigations WHERE user_id=?`, id)
	h.db.Exec(`DELETE FROM user_skills WHERE user_id=?`, id)
	h.db.Exec(`DELETE FROM badges WHERE user_id=?`, id)
	h.db.Exec(`DELETE FROM user_streak WHERE user_id=?`, id)
	h.auditLog(u.ID, "reset_progress", fmt.Sprintf("target_user=%d", id), r)
	http.Redirect(w, r, "/admin?toast=User+progress+reset&toast_type=info", http.StatusSeeOther)
}

// ── Audit Log ─────────────────────────────────────────────────────────────────

func (h *Handler) auditLog(userID int64, action, target string, r *http.Request) {
	ip := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = strings.Split(fwd, ",")[0]
	}
	h.db.Exec(`INSERT INTO audit_log(user_id, action, target, ip_address) VALUES(?,?,?,?)`,
		userID, action, target, ip)
}

func (h *Handler) getAdminAudit(w http.ResponseWriter, r *http.Request) {
	type auditRow struct {
		ID        int64
		Username  string
		Action    string
		Target    string
		IP        string
		CreatedAt time.Time
	}
	rows, _ := h.db.Query(`
		SELECT al.id, COALESCE(u.username,'system'), al.action, COALESCE(al.target,''), COALESCE(al.ip_address,''), al.created_at
		FROM audit_log al
		LEFT JOIN users u ON u.id = al.user_id
		ORDER BY al.created_at DESC LIMIT 200`)
	var entries []auditRow
	if rows != nil {
		for rows.Next() {
			var e auditRow
			rows.Scan(&e.ID, &e.Username, &e.Action, &e.Target, &e.IP, &e.CreatedAt)
			entries = append(entries, e)
		}
		rows.Close()
	}
	h.render(w, r, "admin_audit.html", map[string]any{"Entries": entries})
}

// ── REST API v1 ───────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (h *Handler) apiV1Me(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	var completed, totalScore int
	h.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(score),0) FROM investigations WHERE user_id=? AND status='submitted'`, u.ID).Scan(&completed, &totalScore)
	var bonusXP int
	h.db.QueryRow(`SELECT COALESCE(bonus_xp,0) FROM user_streak WHERE user_id=?`, u.ID).Scan(&bonusXP)
	totalScore += bonusXP
	lvl := computeLevel(totalScore)
	jsonOK(w, map[string]any{
		"id":        u.ID,
		"username":  u.Username,
		"role":      u.Role,
		"completed": completed,
		"total_xp":  totalScore,
		"level":     lvl.Level,
		"title":     lvl.Title,
	})
}

func (h *Handler) apiV1Progress(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	rows, _ := h.db.Query(`SELECT lab_id, status, score, best_score, submitted_at FROM investigations WHERE user_id=?`, u.ID)
	type progRow struct {
		LabID       string     `json:"lab_id"`
		Status      string     `json:"status"`
		Score       *int       `json:"score"`
		BestScore   *int       `json:"best_score"`
		SubmittedAt *time.Time `json:"submitted_at"`
	}
	var out []progRow
	if rows != nil {
		for rows.Next() {
			var p progRow
			rows.Scan(&p.LabID, &p.Status, &p.Score, &p.BestScore, &p.SubmittedAt)
			out = append(out, p)
		}
		rows.Close()
	}
	jsonOK(w, out)
}

func (h *Handler) apiV1Labs(w http.ResponseWriter, r *http.Request) {
	type labOut struct {
		ID         string `json:"id"`
		Title      string `json:"title"`
		Difficulty string `json:"difficulty"`
		Category   string `json:"category"`
	}
	var out []labOut
	for _, l := range h.labs.All() {
		out = append(out, labOut{l.ID, l.Title, l.Difficulty, l.Category})
	}
	jsonOK(w, out)
}

func (h *Handler) apiV1Streak(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	var count int
	var lastDate string
	var shield, bonusXP int
	h.db.QueryRow(`SELECT streak_count, COALESCE(streak_last_date,''), streak_shield, bonus_xp FROM user_streak WHERE user_id=?`, u.ID).
		Scan(&count, &lastDate, &shield, &bonusXP)
	today := time.Now().UTC().Format("2006-01-02")
	jsonOK(w, map[string]any{
		"streak_count":    count,
		"streak_last_date": lastDate,
		"active_today":    lastDate == today,
		"shield":          shield,
		"bonus_xp":        bonusXP,
	})
}

// GET /api/sse — Server-Sent Events for live alert notifications
func (h *Handler) apiSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Send initial heartbeat
	fmt.Fprintf(w, "event: ping\ndata: {}\n\n")
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	lastID := int64(0)

	// Seed last seen
	h.db.QueryRow(`SELECT COALESCE(MAX(id),0) FROM live_alerts`).Scan(&lastID)

	done := r.Context().Done()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			// Heartbeat
			fmt.Fprintf(w, "event: ping\ndata: {}\n\n")
			// Check for new critical/high alerts
			rows, err := h.db.Query(
				`SELECT id, severity, rule_text FROM live_alerts WHERE id>? AND severity IN ('critical','high') ORDER BY id LIMIT 5`,
				lastID,
			)
			if err == nil && rows != nil {
				for rows.Next() {
					var id int64
					var sev, rule string
					rows.Scan(&id, &sev, &rule)
					if id > lastID {
						lastID = id
					}
					payload := strings.ReplaceAll(rule, `"`, `\"`)
					fmt.Fprintf(w, "event: alert\ndata: {\"id\":%d,\"severity\":\"%s\",\"rule\":\"%s\"}\n\n",
						id, sev, payload)
				}
				rows.Close()
			}
			flusher.Flush()
		}
	}
}

func (h *Handler) apiV1Badges(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	type badgeOut struct {
		Key      string    `json:"key"`
		Name     string    `json:"name"`
		Earned   bool      `json:"earned"`
		EarnedAt *time.Time `json:"earned_at,omitempty"`
	}
	rows, _ := h.db.Query(`SELECT badge_key, earned_at FROM badges WHERE user_id=?`, u.ID)
	earned := map[string]time.Time{}
	if rows != nil {
		for rows.Next() {
			var k string; var t time.Time
			rows.Scan(&k, &t)
			earned[k] = t
		}
		rows.Close()
	}
	var out []badgeOut
	for _, b := range badgeCatalogue {
		bo := badgeOut{Key: b.Key, Name: b.Name}
		if t, ok := earned[b.Key]; ok {
			bo.Earned = true; tt := t; bo.EarnedAt = &tt
		}
		out = append(out, bo)
	}
	jsonOK(w, out)
}
