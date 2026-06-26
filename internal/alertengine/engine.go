package alertengine

import (
	"context"
	"encoding/json"
	"log/slog"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/bluerange/bluerange/internal/db"
)

type Engine struct {
	db       *db.DB
	log      *slog.Logger
	interval time.Duration
	maxOpen  int
}

func New(database *db.DB, log *slog.Logger) *Engine {
	return &Engine{db: database, log: log, interval: 5 * time.Minute, maxOpen: 15}
}

func (e *Engine) Start(ctx context.Context) {
	e.log.Info("alert engine started", "interval", e.interval, "maxOpen", e.maxOpen)
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e.generateBatch()
		case <-ctx.Done():
			return
		}
	}
}

func (e *Engine) GenerateInitial(n int) {
	// Ensure a realistic severity mix on startup
	severities := []string{"critical", "high", "high", "medium", "medium", "medium", "medium", "low", "low", "info"}
	generated := 0
	for _, sev := range severities {
		if generated >= n {
			break
		}
		tmpl := randomBySeverity(sev)
		if tmpl == nil {
			continue
		}
		params := generateParams(tmpl)
		if err := e.insertAlert(tmpl, params); err != nil {
			e.log.Warn("insert initial alert", "sev", sev, "err", err)
			continue
		}
		generated++
	}
	// Fill remainder with weighted random
	for generated < n {
		tmpl := weightedRandomTemplate()
		params := generateParams(tmpl)
		if err := e.insertAlert(tmpl, params); err != nil {
			e.log.Warn("insert initial alert", "err", err)
		}
		generated++
	}
	e.log.Info("generated initial alerts", "count", generated)
}

func (e *Engine) generateBatch() {
	var openCount int
	e.db.QueryRow(`SELECT COUNT(*) FROM live_alerts WHERE expires_at > CURRENT_TIMESTAMP`).Scan(&openCount)
	toGenerate := e.maxOpen - openCount
	if toGenerate <= 0 {
		return
	}
	for i := 0; i < toGenerate; i++ {
		tmpl := weightedRandomTemplate()
		params := generateParams(tmpl)
		if err := e.insertAlert(tmpl, params); err != nil {
			e.log.Warn("generate batch", "err", err)
		}
	}
	e.log.Info("generated alerts", "count", toGenerate)
}

// weightedRandomTemplate selects severity: critical=5%, high=20%, medium=40%, low=25%, info=10%
func weightedRandomTemplate() *AlertTemplate {
	r := rand.Intn(100)
	var sev string
	switch {
	case r < 5:
		sev = "critical"
	case r < 25:
		sev = "high"
	case r < 65:
		sev = "medium"
	case r < 90:
		sev = "low"
	default:
		sev = "info"
	}
	return randomBySeverity(sev)
}

func randomBySeverity(sev string) *AlertTemplate {
	var pool []AlertTemplate
	for _, t := range Library {
		if t.Severity == sev {
			pool = append(pool, t)
		}
	}
	if len(pool) == 0 {
		t := Library[0]
		return &t
	}
	t := pool[rand.Intn(len(pool))]
	return &t
}

func generateParams(tmpl *AlertTemplate) AlertParams {
	counts := []int{3, 5, 7, 12, 15, 20, 50, 100, 150, 250, 500}
	ports := []int{22, 80, 443, 445, 3389, 8080, 8443, 4444, 9001}
	return AlertParams{
		SrcIP:    srcIPs[rand.Intn(len(srcIPs))],
		DstIP:    internalIPs[rand.Intn(len(internalIPs))],
		Hostname: hostnames[rand.Intn(len(hostnames))],
		Username: usernames[rand.Intn(len(usernames))],
		Count:    counts[rand.Intn(len(counts))],
		Filename: filenames[rand.Intn(len(filenames))],
		Domain:   domains[rand.Intn(len(domains))],
		Hash:     randomHex(8),
		Port:     ports[rand.Intn(len(ports))],
	}
}

func (e *Engine) insertAlert(tmpl *AlertTemplate, params AlertParams) error {
	ruleTxt := fillTemplate(tmpl.RuleTemplate, params)
	scenarioTxt := fillTemplate(tmpl.ScenarioTmpl, params)
	logs := generateLogs(tmpl, params)

	rubric := LiveRubric{
		ExpectedVerdict:    tmpl.ExpectedVerdict,
		ExpectedEscalation: tmpl.ExpectedEscalation,
		RequiredMITRE:      tmpl.RequiredMITRE,
		Keywords:           tmpl.Keywords,
		ScoreBreakdown:     tmpl.ScoreBreakdown,
		DifficultyModifier: tmpl.DifficultyModifier,
		MinWriteupWords:    20,
	}

	logJSON, _ := json.Marshal(logs)
	rubricJSON, _ := json.Marshal(rubric)
	now := time.Now().UTC()
	expires := now.Add(24 * time.Hour)

	_, err := e.db.Exec(
		`INSERT INTO live_alerts(template_key,severity,source,category,rule_text,scenario,src_ip,hostname,username_val,log_json,rubric_json,triggered_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		tmpl.Key, tmpl.Severity, tmpl.Source, tmpl.Category,
		ruleTxt, scenarioTxt, params.SrcIP, params.Hostname, params.Username,
		string(logJSON), string(rubricJSON),
		now.Format("2006-01-02T15:04:05Z"),
		expires.Format("2006-01-02T15:04:05Z"),
	)
	return err
}

func generateLogs(tmpl *AlertTemplate, params AlertParams) []LogEntry {
	now := time.Now().UTC()
	var logs []LogEntry
	for i, lt := range tmpl.LogTemplates {
		offset := time.Duration(-len(tmpl.LogTemplates)+i) * time.Minute
		logs = append(logs, LogEntry{
			Timestamp: now.Add(offset).Format("2006-01-02T15:04:05Z"),
			Level:     lt.Level,
			Host:      params.Hostname,
			Source:    tmpl.Source,
			Message:   fillTemplate(lt.MsgTmpl, params),
		})
	}
	return logs
}

func fillTemplate(tmpl string, p AlertParams) string {
	r := strings.NewReplacer(
		"{src_ip}", p.SrcIP,
		"{dst_ip}", p.DstIP,
		"{hostname}", p.Hostname,
		"{username}", p.Username,
		"{count}", strconv.Itoa(p.Count),
		"{filename}", p.Filename,
		"{domain}", p.Domain,
		"{hash}", p.Hash,
		"{port}", strconv.Itoa(p.Port),
	)
	return r.Replace(tmpl)
}

// InsertCampaignAlert inserts a live_alert for the given template and returns its row ID.
func (e *Engine) InsertCampaignAlert(tmpl *AlertTemplate) int64 {
	params := generateParams(tmpl)
	if err := e.insertAlert(tmpl, params); err != nil {
		e.log.Warn("insert campaign alert", "key", tmpl.Key, "err", err)
		return 0
	}
	var id int64
	e.db.QueryRow(`SELECT last_insert_rowid()`).Scan(&id)
	return id
}

func randomHex(n int) string {
	const chars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}
