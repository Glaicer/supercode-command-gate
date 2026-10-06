package reviewer_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/supercode/auto-approval-reviewer/internal/reviewer"
)

func readReviewLog(t *testing.T, dir string) []map[string]any {
	t.Helper()
	path := filepath.Join(dir, "logs", "reviews.sqlite")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("log permissions: %v, %v", info, err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT detail FROM review_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var records []map[string]any
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(payload), &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return records
}

func TestReviewLogDecisionRoutes(t *testing.T) {
	for _, tc := range []struct {
		name, command, source string
		model                 bool
	}{
		{"auto", "pwd", reviewer.SourceAutoAllow, false},
		{"hard-deny", "rm -rf /", reviewer.SourceHardDeny, false},
		{"model", "touch ./output", reviewer.SourceAssessor, true},
		{"parse-failure", `echo "`, reviewer.SourceAssessor, true},
		{"unavailable", "touch ./output", reviewer.SourceUnavailable, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			options := reviewer.Options{StateDir: dir}
			if tc.model {
				options.Config = &reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "test"}}
				options.ModelCall = &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":[]}`}}
			}
			decision, err := reviewer.Check(assessorRequest(t, tc.command), options)
			if err != nil {
				t.Fatal(err)
			}
			records := readReviewLog(t, dir)
			if records[0]["event"] != "received" || records[0]["command"] != tc.command || records[1]["event"] != "parsed" {
				t.Fatalf("missing request or parse: %#v", records)
			}
			last := records[len(records)-1]
			if last["event"] != "verdict" || last["source"] != tc.source || last["decision"] != decision.Decision || last["auditId"] != decision.AuditID || last["reason"] != decision.Reason {
				t.Fatalf("incorrect verdict: %#v", last)
			}
			calls := 0
			for _, record := range records {
				if record["event"] == "assessor-call" {
					calls++
					if record["model"] != "test" {
						t.Fatalf("incorrect model: %#v", record)
					}
				}
			}
			if (calls > 0) != tc.model {
				t.Fatalf("model calls = %d, expected model = %v", calls, tc.model)
			}
		})
	}
}

func TestReviewLogRedactsParsedArgumentsAndResponses(t *testing.T) {
	dir := t.TempDir()
	request := assessorRequest(t, "unknown --token sensitive-value")
	_, err := reviewer.Check(request, reviewer.Options{
		StateDir:  dir,
		Config:    &reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "test"}},
		ModelCall: &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":["token=sensitive-value"]}`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	records := readReviewLog(t, dir)
	payload, _ := json.Marshal(records)
	if strings.Contains(string(payload), "sensitive-value") || !strings.Contains(string(payload), "[REDACTED]") {
		t.Fatalf("unsafe log: %s", payload)
	}
}

func TestReviewLogRecordsInvalidRequest(t *testing.T) {
	dir := t.TempDir()
	request := assessorRequest(t, "pwd")
	request.SchemaVersion = "invalid"
	_, err := reviewer.Check(request, reviewer.Options{StateDir: dir})
	if err == nil {
		t.Fatal("expected invalid request error")
	}
	records := readReviewLog(t, dir)
	if len(records) != 2 || records[1]["error"] != err.Error() {
		t.Fatalf("missing failure: %#v", records)
	}
}

func TestReviewLogFailureDoesNotReturnAllow(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "logs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	decision, err := reviewer.Check(assessorRequest(t, "pwd"), reviewer.Options{StateDir: dir})
	if err == nil || decision.Decision == reviewer.DecisionAllow {
		t.Fatalf("log failure returned allow: %#v, %v", decision, err)
	}
}

func TestReviewDatabaseKeepsChecksSeparateAndPersistsEvents(t *testing.T) {
	dir := t.TempDir()
	const count = 12
	cwd := t.TempDir()
	var group sync.WaitGroup
	errors := make(chan error, count)
	start := make(chan struct{})
	for range count {
		group.Go(func() {
			<-start
			_, err := reviewer.Check(reviewer.Request{
				SchemaVersion: reviewer.RequestSchemaVersion,
				Command:       "pwd", CWD: cwd,
				Session: reviewer.Session{ID: "log-test", Host: "opencode"},
			}, reviewer.Options{StateDir: dir, Config: &reviewer.Config{}})
			errors <- err
		})
	}
	close(start)
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "logs", "reviews.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT review_id, count(*), sum(event = 'received'), sum(event = 'verdict') FROM review_events GROUP BY review_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	checks := 0
	for rows.Next() {
		var id string
		var events, received, verdicts int
		if err := rows.Scan(&id, &events, &received, &verdicts); err != nil {
			t.Fatal(err)
		}
		if len(id) != 32 || events != 4 || received != 1 || verdicts != 1 {
			t.Fatalf("review %q has %d events, %d received, %d verdicts", id, events, received, verdicts)
		}
		checks++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if checks != count {
		t.Fatalf("stored checks = %d, want %d", checks, count)
	}
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("database integrity = %q, error = %v", integrity, err)
	}
}

func TestReviewDatabaseRejectsCorruptDatabase(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "logs", "reviews.sqlite"), []byte("corrupt database"), 0o600); err != nil {
		t.Fatal(err)
	}
	decision, err := reviewer.Check(assessorRequest(t, "pwd"), reviewer.Options{StateDir: dir})
	if err == nil || decision.Decision == reviewer.DecisionAllow {
		t.Fatalf("corrupt database returned allow: %#v, %v", decision, err)
	}
}

type inspectingLogModelCall struct {
	t   *testing.T
	dir string
}

func (call inspectingLogModelCall) Call(_ context.Context, _ reviewer.ModelCallRequest) (string, error) {
	records := readReviewLog(call.t, call.dir)
	if len(records) != 4 || records[0]["event"] != "received" || records[3]["event"] != "assessor-call" {
		call.t.Fatalf("events not committed before model call: %#v", records)
	}
	return `{"risks":[],"uncertainties":[]}`, nil
}

func TestReviewDatabaseCommitsEventsBeforeAssessmentFinishes(t *testing.T) {
	dir := t.TempDir()
	_, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{
		StateDir:  dir,
		Config:    &reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "test"}},
		ModelCall: inspectingLogModelCall{t: t, dir: dir},
	})
	if err != nil {
		t.Fatal(err)
	}
}
