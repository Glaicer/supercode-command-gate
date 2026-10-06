package reviewer

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type reviewLog struct {
	db  *sql.DB
	id  string
	err error
}

func newReviewLog(configured string) (*reviewLog, error) {
	dir, err := resolveStateDir(configured)
	if err != nil {
		return nil, err
	}
	dir = filepath.Join(dir, "logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create review log directory: %w", err)
	}
	path, err := filepath.Abs(filepath.Join(dir, "reviews.sqlite"))
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create review database: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	dsn := url.URL{Scheme: "file", Path: path}
	query := url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(1000)"}}
	dsn.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, fmt.Errorf("open review database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure review database: %w", err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS review_events (
		id INTEGER PRIMARY KEY,
		review_id TEXT NOT NULL,
		recorded_at TEXT NOT NULL,
		event TEXT NOT NULL,
		detail TEXT NOT NULL CHECK (json_valid(detail))
	);
	CREATE INDEX IF NOT EXISTS review_events_review ON review_events(review_id, id)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize review database: %w", err)
	}
	id, err := randomID()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &reviewLog{db: db, id: id}, nil
}

func (log *reviewLog) record(event string, detail map[string]any) {
	if log.err != nil {
		return
	}
	detail["event"] = event
	detail["recordedAt"] = time.Now().UTC().Format(time.RFC3339Nano)
	payload, err := json.Marshal(detail)
	if err == nil {
		var value any
		err = json.Unmarshal(payload, &value)
		if err == nil {
			payload, err = json.Marshal(redactLogValue(value))
		}
	}
	if err == nil {
		_, err = log.db.Exec(
			`INSERT INTO review_events (review_id, recorded_at, event, detail) VALUES (?, ?, ?, ?)`,
			log.id, detail["recordedAt"], event, string(payload),
		)
	}
	if err != nil {
		log.err = fmt.Errorf("write review log: %w", err)
	}
}

func (log *reviewLog) close() error {
	err := log.db.Close()
	if log.err != nil {
		return log.err
	}
	if err != nil {
		return fmt.Errorf("close review log: %w", err)
	}
	return nil
}

func redactLogValue(value any) any {
	switch typed := value.(type) {
	case string:
		return redact(typed)
	case []any:
		for index := range typed {
			typed[index] = redactLogValue(typed[index])
		}
	case map[string]any:
		for key := range typed {
			typed[key] = redactLogValue(typed[key])
		}
	}
	return value
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
