package handler

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/bluerange/bluerange/internal/alertengine"
	"github.com/bluerange/bluerange/internal/auth"
	"github.com/bluerange/bluerange/internal/campaign"
)

type campaignRunRow struct {
	CampaignKey  string
	Status       string
	CurrentStage int
	Score        int
	StartedAt    time.Time
	CompletedAt  *time.Time
}

type stageData struct {
	Num     int
	Title   string
	Hint    string
	Status  string // pending | active | completed
	Score   *int
	AlertID *int64
}

// GET /campaigns
func (h *Handler) getCampaigns(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())

	runMap := map[string]campaignRunRow{}
	rows, _ := h.db.Query(`SELECT campaign_key, status, current_stage, score, started_at, completed_at FROM campaign_runs WHERE user_id=?`, u.ID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var d campaignRunRow
			var completedAt sql.NullTime
			var startedAt string
			rows.Scan(&d.CampaignKey, &d.Status, &d.CurrentStage, &d.Score, &startedAt, &completedAt)
			d.StartedAt, _ = time.Parse("2006-01-02T15:04:05Z", startedAt)
			if completedAt.Valid {
				t := completedAt.Time
				d.CompletedAt = &t
			}
			runMap[d.CampaignKey] = d
		}
	}

	type campaignRow struct {
		Camp campaign.Campaign
		Run  *campaignRunRow
	}
	var list []campaignRow
	for _, c := range campaign.Campaigns {
		row := campaignRow{Camp: c}
		if rd, ok := runMap[c.Key]; ok {
			rd2 := rd
			row.Run = &rd2
		}
		list = append(list, row)
	}

	h.render(w, r, "campaigns.html", map[string]any{"Campaigns": list})
}

// POST /campaigns/{key}/start
func (h *Handler) postStartCampaign(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	key := chi.URLParam(r, "key")

	c := campaign.Get(key)
	if c == nil {
		http.NotFound(w, r)
		return
	}

	h.db.Exec(`INSERT OR IGNORE INTO campaign_runs(user_id, campaign_key) VALUES(?,?)`, u.ID, key)

	var runID int64
	var status string
	h.db.QueryRow(`SELECT id, status FROM campaign_runs WHERE user_id=? AND campaign_key=?`, u.ID, key).Scan(&runID, &status)

	if status != "completed" {
		h.ensureStageAlert(runID, c, 1)
	}

	http.Redirect(w, r, "/campaigns/"+key, http.StatusSeeOther)
}

// GET /campaigns/{key}
func (h *Handler) getCampaign(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	key := chi.URLParam(r, "key")

	c := campaign.Get(key)
	if c == nil {
		http.NotFound(w, r)
		return
	}

	var runID int64
	var status string
	var currentStage, score int
	err := h.db.QueryRow(
		`SELECT id, status, current_stage, score FROM campaign_runs WHERE user_id=? AND campaign_key=?`,
		u.ID, key,
	).Scan(&runID, &status, &currentStage, &score)
	if err != nil {
		http.Redirect(w, r, "/campaigns", http.StatusSeeOther)
		return
	}

	// Load stage run data
	stageRows, _ := h.db.Query(
		`SELECT stage_num, COALESCE(live_alert_id,0), status, COALESCE(score,0) FROM campaign_stage_runs WHERE run_id=? ORDER BY stage_num`,
		runID,
	)
	type stageRun struct {
		alertID int64
		status  string
		score   int
	}
	srMap := map[int]stageRun{}
	if stageRows != nil {
		defer stageRows.Close()
		for stageRows.Next() {
			var sn int
			var sr stageRun
			stageRows.Scan(&sn, &sr.alertID, &sr.status, &sr.score)
			srMap[sn] = sr
		}
	}

	var stages []stageData
	for _, s := range c.Stages {
		sd := stageData{Num: s.Num, Title: s.Title, Hint: s.TransitionHint, Status: "pending"}
		if sr, ok := srMap[s.Num]; ok {
			sd.Status = sr.status
			if sr.alertID != 0 {
				v := sr.alertID
				sd.AlertID = &v
			}
			if sr.status == "completed" {
				v := sr.score
				sd.Score = &v
			}
		}
		stages = append(stages, sd)
	}

	h.render(w, r, "campaign.html", map[string]any{
		"Campaign":     c,
		"Stages":       stages,
		"RunStatus":    status,
		"CurrentStage": currentStage,
		"Score":        score,
	})
}

// GET /campaigns/{key}/stage/{stage} — redirect to the live alert
func (h *Handler) getCampaignStage(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromCtx(r.Context())
	key := chi.URLParam(r, "key")
	stageNum, _ := strconv.Atoi(chi.URLParam(r, "stage"))

	var runID int64
	h.db.QueryRow(`SELECT id FROM campaign_runs WHERE user_id=? AND campaign_key=?`, u.ID, key).Scan(&runID)
	if runID == 0 {
		http.Redirect(w, r, "/campaigns/"+key, http.StatusSeeOther)
		return
	}

	var alertID sql.NullInt64
	h.db.QueryRow(`SELECT live_alert_id FROM campaign_stage_runs WHERE run_id=? AND stage_num=?`, runID, stageNum).Scan(&alertID)
	if !alertID.Valid {
		http.Redirect(w, r, "/campaigns/"+key, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/alert/"+strconv.FormatInt(alertID.Int64, 10), http.StatusSeeOther)
}

// ensureStageAlert creates a live_alert for stage N if not yet created.
func (h *Handler) ensureStageAlert(runID int64, c *campaign.Campaign, stageNum int) {
	var existing int
	h.db.QueryRow(`SELECT COUNT(*) FROM campaign_stage_runs WHERE run_id=? AND stage_num=?`, runID, stageNum).Scan(&existing)
	if existing > 0 {
		return
	}

	var stage *campaign.Stage
	for _, s := range c.Stages {
		if s.Num == stageNum {
			s2 := s
			stage = &s2
			break
		}
	}
	if stage == nil {
		return
	}

	var tmpl *alertengine.AlertTemplate
	for _, t := range alertengine.Library {
		if t.Key == stage.AlertTemplateKey {
			t2 := t
			tmpl = &t2
			break
		}
	}
	if tmpl == nil {
		return
	}

	engine := alertengine.New(h.db, h.log)
	alertID := engine.InsertCampaignAlert(tmpl)
	if alertID == 0 {
		return
	}

	status := "pending"
	if stageNum == 1 {
		status = "active"
	}
	h.db.Exec(
		`INSERT OR IGNORE INTO campaign_stage_runs(run_id, stage_num, live_alert_id, status) VALUES(?,?,?,?)`,
		runID, stageNum, alertID, status,
	)
}

// completeCampaignStage is called after a live alert is submitted — checks if it belongs to a campaign.
func (h *Handler) completeCampaignStage(userID, alertID int64, score int) {
	var runID int64
	var stageNum int
	err := h.db.QueryRow(
		`SELECT csr.run_id, csr.stage_num FROM campaign_stage_runs csr
		 JOIN campaign_runs cr ON cr.id=csr.run_id
		 WHERE csr.live_alert_id=? AND cr.user_id=?`,
		alertID, userID,
	).Scan(&runID, &stageNum)
	if err != nil {
		return
	}

	h.db.Exec(
		`UPDATE campaign_stage_runs SET status='completed', score=?, completed_at=CURRENT_TIMESTAMP WHERE run_id=? AND stage_num=?`,
		score, runID, stageNum,
	)

	var campaignKey string
	h.db.QueryRow(`SELECT campaign_key FROM campaign_runs WHERE id=?`, runID).Scan(&campaignKey)
	c := campaign.Get(campaignKey)
	if c == nil {
		return
	}

	nextStage := stageNum + 1
	if nextStage > len(c.Stages) {
		var totalScore int
		h.db.QueryRow(`SELECT COALESCE(SUM(score),0) FROM campaign_stage_runs WHERE run_id=?`, runID).Scan(&totalScore)
		h.db.Exec(
			`UPDATE campaign_runs SET status='completed', score=?, completed_at=CURRENT_TIMESTAMP WHERE id=?`,
			totalScore, runID,
		)
		h.db.Exec(
			`INSERT INTO user_skills(user_id,skill_key,score) VALUES(?,?,50) ON CONFLICT(user_id,skill_key) DO UPDATE SET score=score+50`,
			userID, "incident_response",
		)
	} else {
		h.db.Exec(`UPDATE campaign_runs SET current_stage=? WHERE id=?`, nextStage, runID)
		h.ensureStageAlert(runID, c, nextStage)
	}
}
