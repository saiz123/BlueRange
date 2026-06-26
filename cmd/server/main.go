package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bluerange/bluerange/internal/alertengine"
	"github.com/bluerange/bluerange/internal/auth"
	"github.com/bluerange/bluerange/internal/db"
	"github.com/bluerange/bluerange/internal/handler"
	"github.com/bluerange/bluerange/internal/lab"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := struct {
		addr       string
		dataDir    string
		labsDir    string
		staticDir  string
		tmplDir    string
		adminUser  string
		adminPass  string
	}{
		addr:      getenv("ADDR", ":8080"),
		dataDir:   getenv("DATA_DIR", "/app/data"),
		labsDir:   getenv("LABS_DIR", "/app/labs"),
		staticDir: getenv("STATIC_DIR", "/app/web/static"),
		tmplDir:   getenv("TMPL_DIR", "/app/web/templates"),
		adminUser: getenv("ADMIN_USER", "admin"),
		adminPass: getenv("ADMIN_PASS", "changeme"),
	}

	database, err := db.Open(cfg.dataDir)
	if err != nil {
		log.Error("open db", "err", err)
		os.Exit(1)
	}
	defer database.Close()

	// Seed admin account on first boot
	if err := seedAdmin(database, cfg.adminUser, cfg.adminPass); err != nil {
		log.Error("seed admin", "err", err)
		os.Exit(1)
	}

	// Load lab registry
	registry, err := lab.LoadRegistry(cfg.labsDir)
	if err != nil {
		log.Error("load labs", "err", err)
		os.Exit(1)
	}
	log.Info("labs loaded", "count", len(registry.All()))

	// Sync labs into DB and ingest logs
	if err := syncLabs(database, registry, cfg.labsDir, log); err != nil {
		log.Error("sync labs", "err", err)
		os.Exit(1)
	}

	// Load templates
	tmpl, err := loadTemplates(cfg.tmplDir)
	if err != nil {
		log.Error("load templates", "err", err)
		os.Exit(1)
	}

	// Start dynamic alert engine
	alertCtx, alertCancel := context.WithCancel(context.Background())
	defer alertCancel()
	engine := alertengine.New(database, log)
	engine.GenerateInitial(15)
	go engine.Start(alertCtx)

	h := handler.New(database, registry, tmpl, cfg.staticDir, log)
	srv := &http.Server{
		Addr:         cfg.addr,
		Handler:      h.Routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Info("BlueRange starting", "addr", cfg.addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Error("server", "err", err)
		os.Exit(1)
	}
}

func seedAdmin(database *db.DB, username, password string) error {
	var count int
	database.QueryRow(`SELECT COUNT(*) FROM users WHERE username=?`, username).Scan(&count)
	if count > 0 {
		return nil
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = database.Exec(`INSERT INTO users(username, password_hash, role) VALUES(?,?,'admin')`, username, hash)
	return err
}

func syncLabs(database *db.DB, registry *lab.Registry, labsDir string, log *slog.Logger) error {
	for _, l := range registry.All() {
		_, err := database.Exec(`
			INSERT INTO labs(id, title, difficulty, category, mitre_tags, scenario, alert_json, rubric_json)
			VALUES(?,?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET
			  title=excluded.title, difficulty=excluded.difficulty,
			  category=excluded.category, mitre_tags=excluded.mitre_tags,
			  scenario=excluded.scenario, alert_json=excluded.alert_json,
			  rubric_json=excluded.rubric_json`,
			l.ID, l.Title, l.Difficulty, l.Category,
			l.MitreTagsJSON(), l.Scenario, l.AlertJSON(), l.RubricJSON())
		if err != nil {
			return fmt.Errorf("upsert lab %s: %w", l.ID, err)
		}

		// Ingest logs (skip if already loaded)
		var existing int
		database.QueryRow(`SELECT COUNT(*) FROM logs_fts WHERE lab_id=?`, l.ID).Scan(&existing)
		if existing > 0 {
			continue
		}
		if err := ingestLogs(database, l, log); err != nil {
			log.Warn("ingest logs", "lab", l.ID, "err", err)
		}
	}
	return nil
}

func ingestLogs(database *db.DB, l *lab.Lab, log *slog.Logger) error {
	logsDir := filepath.Join(l.LabDir, "logs")
	entries, err := os.ReadDir(logsDir)
	if err != nil {
		return nil // no logs dir is fine
	}

	tx, err := database.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO logs_fts(lab_id, source, ts, level, host, message, raw) VALUES(?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	count := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(logsDir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		source := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var entry struct {
				Timestamp string `json:"timestamp"`
				Ts        string `json:"ts"`
				Time      string `json:"time"`
				Level     string `json:"level"`
				Severity  string `json:"severity"`
				Host      string `json:"host"`
				Hostname  string `json:"hostname"`
				Message   string `json:"message"`
				Msg       string `json:"msg"`
			}
			ts, level, host, msg := "", "info", "", line
			if err := json.Unmarshal([]byte(line), &entry); err == nil {
				ts = coalesce(entry.Timestamp, entry.Ts, entry.Time)
				level = coalesce(entry.Level, entry.Severity, "info")
				host = coalesce(entry.Host, entry.Hostname)
				msg = coalesce(entry.Message, entry.Msg, line)
			}
			if _, err := stmt.Exec(l.ID, source, ts, level, host, msg, line); err != nil {
				log.Warn("insert log", "lab", l.ID, "err", err)
			}
			count++
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	log.Info("ingested logs", "lab", l.ID, "rows", count)
	return nil
}

func loadTemplates(tmplDir string) (map[string]*template.Template, error) {
	funcMap := template.FuncMap{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"join":  strings.Join,
		"add":   func(a, b int) int { return a + b },
		"mitreTags": func(tags []string) template.JS {
			if len(tags) == 0 {
				return "[]"
			}
			b, _ := json.Marshal(tags)
			return template.JS(b)
		},
		"derefInt": func(p *int) int {
			if p == nil {
				return 0
			}
			return *p
		},
		"ge": func(a, b int) bool { return a >= b },
		"pct": func(score, max int) int {
			if max == 0 {
				return 0
			}
			return score * 100 / max
		},
		"scoreClass": func(score, max int) string {
			if max == 0 {
				return "score-zero"
			}
			pct := score * 100 / max
			switch {
			case pct >= 80:
				return "score-high"
			case pct >= 50:
				return "score-mid"
			default:
				return "score-low"
			}
		},
		"diffClass": func(d string) string {
			switch d {
			case "intro":
				return "diff-intro"
			case "core":
				return "diff-core"
			case "realistic":
				return "diff-realistic"
			}
			return ""
		},
		"sevClass": func(s string) string {
			switch strings.ToLower(s) {
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
		},
		"sub": func(a, b int) int { return a - b },
		"deref": func(p *string) string {
			if p == nil {
				return ""
			}
			return *p
		},
		"mul": func(a, b int) int { return a * b },
		"js": func(v any) template.JS {
			// For strings: return without surrounding quotes (bare JS value)
			// For other types (slices, maps): return JSON representation
			if s, ok := v.(string); ok {
				b, _ := json.Marshal(s)
				if len(b) >= 2 {
					return template.JS(b[1 : len(b)-1])
				}
				return template.JS("")
			}
			b, _ := json.Marshal(v)
			if b == nil {
				return template.JS("null")
			}
			return template.JS(b)
		},
		"markdownHTML": func(src string) template.HTML {
			if src == "" {
				return ""
			}
			var buf bytes.Buffer
			md := goldmark.New(goldmark.WithExtensions(extension.GFM))
			if err := md.Convert([]byte(src), &buf); err != nil {
				return template.HTML(template.HTMLEscapeString(src))
			}
			return template.HTML(buf.String())
		},
	}

	basePath := filepath.Join(tmplDir, "base.html")
	entries, err := os.ReadDir(tmplDir)
	if err != nil {
		return nil, fmt.Errorf("read template dir %s: %w", tmplDir, err)
	}

	tmpls := make(map[string]*template.Template)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".html" || name == "base.html" {
			continue
		}
		t, err := template.New("").Funcs(funcMap).ParseFiles(basePath, filepath.Join(tmplDir, name))
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		tmpls[name] = t
	}
	return tmpls, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Implement the DB interface required by auth package for the handler DB
var _ interface {
	QueryRow(string, ...any) *sql.Row
} = (*db.DB)(nil)
