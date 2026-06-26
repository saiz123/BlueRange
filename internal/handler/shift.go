package handler

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/bluerange/bluerange/internal/auth"
	"github.com/bluerange/bluerange/internal/lab"
)

// ── Data types ───────────────────────────────────────────────────────────────

type shiftRow struct {
	ID          int64
	StartedAt   time.Time
	EndedAt     *time.Time
	Status      string
	DurationMin int
	Score       int
}

type shiftAlertRow struct {
	ID          int64
	ShiftID     int64
	Lab         *lab.Lab
	AssignedAt  time.Time
	DueAt       time.Time
	CompletedAt *time.Time
	SLAMet      bool
	Score       *int
	MinutesLeft int // computed at render time
}

type shiftSummary struct {
	AlertsTriaged int `json:"alerts_triaged"`
	SLABreaches   int `json:"sla_breaches"`
	AvgMinutes    int `json:"avg_minutes"`
}

// sla minutes by severity
var slaBySeverity = map[string]int{
	"critical": 10,
	"high":     15,
	"medium":   25,
	"low":      45,
	"info":     60,
}

// ── Shift Lobby ───────────────────────────────────────────────────────────────

func (h *Handler) getShiftLobby(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())

	// Load recent shifts
	rows, _ := h.db.Query(`
		SELECT id, started_at, ended_at, status, duration_min, score
		FROM shifts WHERE user_id=? ORDER BY started_at DESC LIMIT 5`, u.ID)
	var recent []shiftRow
	if rows != nil {
		for rows.Next() {
			var s shiftRow
			var endedAt *time.Time
			rows.Scan(&s.ID, &s.StartedAt, &endedAt, &s.Status, &s.DurationMin, &s.Score)
			s.EndedAt = endedAt
			recent = append(recent, s)
		}
		rows.Close()
	}

	// Check for active shift
	var activeShiftID int64
	h.db.QueryRow(`SELECT id FROM shifts WHERE user_id=? AND status='active' LIMIT 1`, u.ID).Scan(&activeShiftID)

	h.render(w, r, "shift_lobby.html", map[string]any{
		"RecentShifts":  recent,
		"ActiveShiftID": activeShiftID,
	})
}

// ── Start Shift ───────────────────────────────────────────────────────────────

func (h *Handler) postStartShift(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())

	// Only one active shift at a time
	var existing int64
	h.db.QueryRow(`SELECT id FROM shifts WHERE user_id=? AND status='active'`, u.ID).Scan(&existing)
	if existing > 0 {
		http.Redirect(w, r, fmt.Sprintf("/shift/%d", existing), http.StatusSeeOther)
		return
	}

	durationMin := 20
	if v, _ := strconv.Atoi(r.FormValue("duration")); v > 0 {
		durationMin = v
	}
	if durationMin > 60 {
		durationMin = 60
	}

	// Create shift
	res, err := h.db.Exec(`INSERT INTO shifts(user_id, duration_min) VALUES(?,?)`, u.ID, durationMin)
	if err != nil {
		h.log.Error("create shift", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	shiftID, _ := res.LastInsertId()

	// Pick labs: prefer unsubmitted, fill with others
	allLabs := h.labs.All()
	sort.Slice(allLabs, func(i, j int) bool {
		// shuffle within priority groups using time seed
		return rand.Intn(2) == 0
	})

	// Priority: critical+high first, then medium, then low
	sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.SliceStable(allLabs, func(i, j int) bool {
		return sevOrder[allLabs[i].Alert.Severity] < sevOrder[allLabs[j].Alert.Severity]
	})

	count := 3 + durationMin/20
	if count > len(allLabs) {
		count = len(allLabs)
	}

	now := time.Now().UTC()
	for i := 0; i < count; i++ {
		l := allLabs[i]
		slaMin := slaBySeverity[l.Alert.Severity]
		if slaMin == 0 {
			slaMin = 30
		}
		due := now.Add(time.Duration(slaMin) * time.Minute)
		h.db.Exec(`INSERT INTO shift_alerts(shift_id, lab_id, due_at) VALUES(?,?,?)`,
			shiftID, l.ID, due.Format("2006-01-02T15:04:05Z"))
	}

	http.Redirect(w, r, fmt.Sprintf("/shift/%d", shiftID)+"?toast=Shift+started%21+Good+luck%21&toast_type=info", http.StatusSeeOther)
}

// ── Active Shift Workspace ────────────────────────────────────────────────────

func (h *Handler) getShift(w http.ResponseWriter, r *http.Request) {
	shiftID, _ := strconv.ParseInt(chi.URLParam(r, "shiftID"), 10, 64)
	u := auth.UserFromCtx(r.Context())

	var shift shiftRow
	var endedAt *time.Time
	err := h.db.QueryRow(`SELECT id,started_at,ended_at,status,duration_min,score FROM shifts WHERE id=? AND user_id=?`,
		shiftID, u.ID).Scan(&shift.ID, &shift.StartedAt, &endedAt, &shift.Status, &shift.DurationMin, &shift.Score)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	shift.EndedAt = endedAt

	if shift.Status != "active" {
		http.Redirect(w, r, fmt.Sprintf("/shift/%d/result", shiftID), http.StatusSeeOther)
		return
	}

	// Auto-end if time is up
	shiftDeadline := shift.StartedAt.Add(time.Duration(shift.DurationMin) * time.Minute)
	if time.Now().UTC().After(shiftDeadline) {
		h.endShift(shiftID, u.ID)
		http.Redirect(w, r, fmt.Sprintf("/shift/%d/result", shiftID), http.StatusSeeOther)
		return
	}

	alerts := h.loadShiftAlerts(shiftID)
	secsLeft := int(time.Until(shiftDeadline).Seconds())

	h.render(w, r, "shift.html", map[string]any{
		"Shift":    shift,
		"Alerts":   alerts,
		"SecsLeft": secsLeft,
		"Deadline": shiftDeadline.Format(time.RFC3339),
	})
}

// ── End Shift ─────────────────────────────────────────────────────────────────

func (h *Handler) postEndShift(w http.ResponseWriter, r *http.Request) {
	shiftID, _ := strconv.ParseInt(chi.URLParam(r, "shiftID"), 10, 64)
	u := auth.UserFromCtx(r.Context())
	h.endShift(shiftID, u.ID)
	http.Redirect(w, r, fmt.Sprintf("/shift/%d/result", shiftID)+"?toast=Shift+complete%21&toast_type=success", http.StatusSeeOther)
}

func (h *Handler) endShift(shiftID, userID int64) {
	// Mark any uncompleted alerts as SLA breached
	h.db.Exec(`UPDATE shift_alerts SET sla_met=0 WHERE shift_id=? AND completed_at IS NULL`, shiftID)

	// Compute shift score = sum of alert scores × SLA multiplier
	rows, _ := h.db.Query(`SELECT score, sla_met FROM shift_alerts WHERE shift_id=?`, shiftID)
	total := 0
	if rows != nil {
		for rows.Next() {
			var score *int
			var slaMet int
			rows.Scan(&score, &slaMet)
			if score != nil {
				pts := *score
				if slaMet == 1 {
					pts = pts * 125 / 100
				} else {
					pts = pts * 75 / 100
				}
				total += pts
			}
		}
		rows.Close()
	}

	// Build summary JSON
	var triaged, breaches int
	var totalMins int
	rows2, _ := h.db.Query(`SELECT completed_at, sla_met, assigned_at FROM shift_alerts WHERE shift_id=?`, shiftID)
	if rows2 != nil {
		for rows2.Next() {
			var completedAt *time.Time
			var slaMet int
			var assignedAt time.Time
			rows2.Scan(&completedAt, &slaMet, &assignedAt)
			if completedAt != nil {
				triaged++
				totalMins += int(completedAt.Sub(assignedAt).Minutes())
			}
			if slaMet == 0 {
				breaches++
			}
		}
		rows2.Close()
	}
	avg := 0
	if triaged > 0 {
		avg = totalMins / triaged
	}
	summary := shiftSummary{AlertsTriaged: triaged, SLABreaches: breaches, AvgMinutes: avg}
	sumJSON, _ := json.Marshal(summary)

	h.db.Exec(`UPDATE shifts SET status='completed', ended_at=CURRENT_TIMESTAMP, score=?, summary_json=? WHERE id=? AND user_id=?`,
		total, string(sumJSON), shiftID, userID)

	// Award shift badges
	if breaches == 0 && triaged > 0 {
		h.db.Exec(`INSERT OR IGNORE INTO badges(user_id,badge_key) VALUES(?,'shift_ace')`, userID)
	}
	if avg > 0 && avg < 5 {
		h.db.Exec(`INSERT OR IGNORE INTO badges(user_id,badge_key) VALUES(?,'speed_triage')`, userID)
	}
	hour := time.Now().UTC().Hour()
	if hour >= 23 || hour < 4 {
		h.db.Exec(`INSERT OR IGNORE INTO badges(user_id,badge_key) VALUES(?,'night_owl')`, userID)
	}
}

// ── Shift Result ──────────────────────────────────────────────────────────────

func (h *Handler) getShiftResult(w http.ResponseWriter, r *http.Request) {
	shiftID, _ := strconv.ParseInt(chi.URLParam(r, "shiftID"), 10, 64)
	u := auth.UserFromCtx(r.Context())

	var shift shiftRow
	var endedAt *time.Time
	var summaryJSON string
	err := h.db.QueryRow(`SELECT id,started_at,ended_at,status,duration_min,score,COALESCE(summary_json,'{}') FROM shifts WHERE id=? AND user_id=?`,
		shiftID, u.ID).Scan(&shift.ID, &shift.StartedAt, &endedAt, &shift.Status, &shift.DurationMin, &shift.Score, &summaryJSON)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	shift.EndedAt = endedAt

	var summary shiftSummary
	json.Unmarshal([]byte(summaryJSON), &summary)

	alerts := h.loadShiftAlerts(shiftID)
	slaRate := 0
	if len(alerts) > 0 {
		met := 0
		for _, a := range alerts {
			if a.SLAMet {
				met++
			}
		}
		slaRate = met * 100 / len(alerts)
	}

	duration := 0
	if shift.EndedAt != nil {
		duration = int(shift.EndedAt.Sub(shift.StartedAt).Minutes())
	}

	h.render(w, r, "shift_result.html", map[string]any{
		"Shift":    shift,
		"Alerts":   alerts,
		"Summary":  summary,
		"SLARate":  slaRate,
		"Duration": duration,
	})
}

// ── Notes API ─────────────────────────────────────────────────────────────────

func (h *Handler) apiGetNotes(w http.ResponseWriter, r *http.Request) {
	labID := chi.URLParam(r, "labID")
	u := auth.UserFromCtx(r.Context())
	var noteText string
	h.db.QueryRow(`SELECT COALESCE(note_text,'') FROM investigation_notes WHERE user_id=? AND lab_id=?`, u.ID, labID).Scan(&noteText)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, noteText)
}

func (h *Handler) apiSaveNotes(w http.ResponseWriter, r *http.Request) {
	labID := chi.URLParam(r, "labID")
	u := auth.UserFromCtx(r.Context())
	noteText := r.FormValue("notes")
	// Use DELETE+INSERT as SQLite ON CONFLICT requires unique index; notes table has no unique constraint yet
	h.db.Exec(`DELETE FROM investigation_notes WHERE user_id=? AND lab_id=?`, u.ID, labID)
	if strings.TrimSpace(noteText) != "" {
		h.db.Exec(`INSERT INTO investigation_notes(user_id,lab_id,note_text) VALUES(?,?,?)`, u.ID, labID, noteText)
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (h *Handler) loadShiftAlerts(shiftID int64) []shiftAlertRow {
	rows, _ := h.db.Query(`
		SELECT id, lab_id, assigned_at, due_at, completed_at, sla_met, score
		FROM shift_alerts WHERE shift_id=? ORDER BY due_at ASC`, shiftID)
	var alerts []shiftAlertRow
	if rows == nil {
		return alerts
	}
	defer rows.Close()
	now := time.Now().UTC()
	for rows.Next() {
		var a shiftAlertRow
		a.ShiftID = shiftID
		var labID string
		var completedAt *time.Time
		var score *int
		var slaMet int
		rows.Scan(&a.ID, &labID, &a.AssignedAt, &a.DueAt, &completedAt, &slaMet, &score)
		a.CompletedAt = completedAt
		a.SLAMet = slaMet == 1
		a.Score = score
		a.MinutesLeft = int(a.DueAt.Sub(now).Minutes())
		if l, ok := h.labs.Get(labID); ok {
			a.Lab = l
		}
		alerts = append(alerts, a)
	}
	return alerts
}

// completeShiftAlert is called from postSubmit when an investigation linked to a shift is completed.
func (h *Handler) completeShiftAlert(userID int64, labID string, score int) {
	now := time.Now().UTC()
	// Find the open shift_alert for this user's active shift
	var alertID int64
	var dueAt time.Time
	err := h.db.QueryRow(`
		SELECT sa.id, sa.due_at FROM shift_alerts sa
		JOIN shifts s ON s.id = sa.shift_id
		WHERE s.user_id=? AND s.status='active' AND sa.lab_id=? AND sa.completed_at IS NULL
		LIMIT 1`, userID, labID).Scan(&alertID, &dueAt)
	if err != nil {
		return
	}
	slaMet := 0
	if now.Before(dueAt) {
		slaMet = 1
	}
	h.db.Exec(`UPDATE shift_alerts SET completed_at=?, sla_met=?, score=? WHERE id=?`,
		now.Format("2006-01-02T15:04:05Z"), slaMet, score, alertID)
}

// severityBadgeClass maps severity to CSS class for the shift UI
func severityBadgeClass(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "sev-critical"
	case "high":
		return "sev-high"
	case "medium":
		return "sev-medium"
	case "low":
		return "sev-low"
	}
	return "sev-info"
}
