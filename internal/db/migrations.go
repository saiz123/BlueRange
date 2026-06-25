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
