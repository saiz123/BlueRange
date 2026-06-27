package db

import "database/sql"

func (db *DB) migrate() error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)`); err != nil {
		return err
	}
	var version int
	_ = db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_version`).Scan(&version)

	migrations := []struct {
		v   int
		sql string
	}{
		{1, sqlV1},
		{2, `ALTER TABLE investigations ADD COLUMN best_score INTEGER;`},
		{3, `CREATE TABLE IF NOT EXISTS user_streak (
			user_id          INTEGER PRIMARY KEY REFERENCES users(id),
			streak_count     INTEGER NOT NULL DEFAULT 0,
			streak_last_date TEXT,
			streak_shield    INTEGER NOT NULL DEFAULT 1,
			bonus_xp         INTEGER NOT NULL DEFAULT 0
		);`},
		{4, `
CREATE TABLE IF NOT EXISTS shifts (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id      INTEGER NOT NULL REFERENCES users(id),
	started_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
	ended_at     DATETIME,
	status       TEXT NOT NULL DEFAULT 'active',
	duration_min INTEGER NOT NULL DEFAULT 20,
	score        INTEGER DEFAULT 0,
	summary_json TEXT
);
CREATE TABLE IF NOT EXISTS shift_alerts (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	shift_id     INTEGER NOT NULL REFERENCES shifts(id) ON DELETE CASCADE,
	lab_id       TEXT NOT NULL,
	assigned_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
	due_at       DATETIME NOT NULL,
	completed_at DATETIME,
	sla_met      INTEGER DEFAULT 0,
	score        INTEGER
);
CREATE TABLE IF NOT EXISTS investigation_notes (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id    INTEGER NOT NULL REFERENCES users(id),
	lab_id     TEXT NOT NULL,
	note_text  TEXT NOT NULL DEFAULT '',
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS enrichment_log (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id      INTEGER NOT NULL REFERENCES users(id),
	lab_id       TEXT NOT NULL,
	indicator    TEXT NOT NULL,
	looked_up_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS invite_codes (
	code       TEXT PRIMARY KEY,
	created_by INTEGER REFERENCES users(id),
	used_by    INTEGER REFERENCES users(id),
	expires_at DATETIME,
	used_at    DATETIME,
	max_uses   INTEGER DEFAULT 1,
	use_count  INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit_log (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id    INTEGER REFERENCES users(id),
	action     TEXT NOT NULL,
	target     TEXT,
	ip_address TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`},
		{5, `
CREATE TABLE IF NOT EXISTS live_alerts (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  template_key TEXT NOT NULL,
  severity     TEXT NOT NULL,
  source       TEXT NOT NULL,
  category     TEXT NOT NULL,
  rule_text    TEXT NOT NULL,
  scenario     TEXT NOT NULL,
  src_ip       TEXT NOT NULL DEFAULT '',
  hostname     TEXT NOT NULL DEFAULT '',
  username_val TEXT NOT NULL DEFAULT '',
  extra_json   TEXT NOT NULL DEFAULT '{}',
  log_json     TEXT NOT NULL DEFAULT '[]',
  rubric_json  TEXT NOT NULL DEFAULT '{}',
  triggered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at   DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS live_investigations (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id      INTEGER NOT NULL REFERENCES live_alerts(id) ON DELETE CASCADE,
  user_id       INTEGER NOT NULL REFERENCES users(id),
  status        TEXT NOT NULL DEFAULT 'in_progress',
  verdict       TEXT,
  severity_sub  TEXT,
  rationale     TEXT,
  mitre_tags    TEXT DEFAULT '[]',
  escalated     INTEGER DEFAULT 0,
  score         INTEGER,
  best_score    INTEGER,
  feedback_json TEXT,
  started_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  submitted_at  DATETIME,
  UNIQUE(alert_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_live_alerts_expires ON live_alerts(expires_at);
CREATE INDEX IF NOT EXISTS idx_live_alerts_sev ON live_alerts(severity, triggered_at);
`},
		{6, `
CREATE TABLE IF NOT EXISTS campaign_runs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL REFERENCES users(id),
  campaign_key  TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active',
  current_stage INTEGER NOT NULL DEFAULT 1,
  score         INTEGER DEFAULT 0,
  started_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  completed_at  DATETIME,
  UNIQUE(user_id, campaign_key)
);
CREATE TABLE IF NOT EXISTS campaign_stage_runs (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id         INTEGER NOT NULL REFERENCES campaign_runs(id) ON DELETE CASCADE,
  stage_num      INTEGER NOT NULL,
  live_alert_id  INTEGER REFERENCES live_alerts(id),
  status         TEXT NOT NULL DEFAULT 'pending',
  score          INTEGER,
  completed_at   DATETIME,
  UNIQUE(run_id, stage_num)
);
CREATE TABLE IF NOT EXISTS hunt_sessions (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL REFERENCES users(id),
  hunt_key      TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active',
  findings_json TEXT NOT NULL DEFAULT '[]',
  score         INTEGER,
  started_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  submitted_at  DATETIME
);
CREATE TABLE IF NOT EXISTS certifications (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  cert_key   TEXT NOT NULL,
  earned_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, cert_key)
);
`},
		{7, `
ALTER TABLE user_streak ADD COLUMN career_tier INTEGER NOT NULL DEFAULT 1;
ALTER TABLE user_streak ADD COLUMN tier_changed_at DATETIME;
CREATE TABLE IF NOT EXISTS daily_missions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id),
  date_key    TEXT NOT NULL,
  slot        INTEGER NOT NULL,
  type        TEXT NOT NULL,
  title       TEXT NOT NULL,
  description TEXT NOT NULL,
  target_n    INTEGER NOT NULL DEFAULT 1,
  progress    INTEGER NOT NULL DEFAULT 0,
  completed   INTEGER NOT NULL DEFAULT 0,
  reward_xp   INTEGER NOT NULL DEFAULT 15,
  UNIQUE(user_id, date_key, slot)
);
CREATE TABLE IF NOT EXISTS daily_briefing (
  user_id   INTEGER PRIMARY KEY REFERENCES users(id),
  last_seen TEXT NOT NULL DEFAULT ''
);
`},
	}

	for _, m := range migrations {
		if version >= m.v {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(m.sql); err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.Exec(`INSERT INTO schema_version(version) VALUES(?)`, m.v); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

const sqlV1 = `
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT    UNIQUE NOT NULL,
	password_hash TEXT    NOT NULL,
	role          TEXT    NOT NULL DEFAULT 'learner',
	created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
	token      TEXT    PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	expires_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS labs (
	id          TEXT PRIMARY KEY,
	title       TEXT NOT NULL,
	difficulty  TEXT NOT NULL,
	category    TEXT NOT NULL,
	mitre_tags  TEXT NOT NULL DEFAULT '[]',
	scenario    TEXT NOT NULL,
	alert_json  TEXT NOT NULL DEFAULT '{}',
	rubric_json TEXT NOT NULL DEFAULT '{}',
	enabled     INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS investigations (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id       INTEGER NOT NULL REFERENCES users(id),
	lab_id        TEXT    NOT NULL REFERENCES labs(id),
	status        TEXT    NOT NULL DEFAULT 'in_progress',
	mode          TEXT    NOT NULL DEFAULT 'guided',
	verdict       TEXT,
	severity      TEXT,
	rationale     TEXT,
	mitre_tags    TEXT    DEFAULT '[]',
	escalated     INTEGER DEFAULT 0,
	score         INTEGER,
	feedback_json TEXT,
	started_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
	submitted_at  DATETIME,
	UNIQUE(user_id, lab_id)
);

CREATE TABLE IF NOT EXISTS user_skills (
	user_id   INTEGER NOT NULL REFERENCES users(id),
	skill_key TEXT    NOT NULL,
	score     INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (user_id, skill_key)
);

CREATE TABLE IF NOT EXISTS badges (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id    INTEGER NOT NULL REFERENCES users(id),
	badge_key  TEXT    NOT NULL,
	earned_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(user_id, badge_key)
);

CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
	lab_id    UNINDEXED,
	source,
	ts,
	level,
	host,
	message,
	raw,
	tokenize = 'unicode61'
);
`

func (db *DB) Tx(fn func(*sql.Tx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
