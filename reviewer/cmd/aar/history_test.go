package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glaicer/supercode-command-gate/reviewer/internal/reviewer"
)

func TestCleanupPreservesWorkingStateAndAllowsNewHistory(t *testing.T) {
	state := t.TempDir()
	t.Setenv("AAR_STATE_DIR", state)
	t.Setenv("AAR_CONFIG", filepath.Join(t.TempDir(), "absent.toml"))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	request := reviewer.Request{SchemaVersion: reviewer.RequestSchemaVersion, Command: "pwd", CWD: t.TempDir(), Session: reviewer.Session{ID: "session", Host: "test"}}
	decision, err := reviewer.Check(request, reviewer.Options{StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"grants.json", "trust.json", "stats.json", "config.toml"} {
		if err := os.WriteFile(filepath.Join(state, name), []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if err := run([]string{"cleanup"}, nil, &output, &output); err != nil {
		t.Fatal(err)
	}
	if _, err := reviewer.Explain(decision.AuditID, reviewer.Options{StateDir: state}); err == nil {
		t.Fatal("audit retained")
	}
	db, err := sql.Open("sqlite", filepath.Join(state, "logs", "reviews.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT count(*) FROM review_events").Scan(&count); err != nil || count != 0 {
		t.Fatalf("events %d: %v", count, err)
	}
	for _, name := range []string{"grants.json", "trust.json", "stats.json", "config.toml"} {
		payload, err := os.ReadFile(filepath.Join(state, name))
		if err != nil || string(payload) != "keep" {
			t.Fatalf("%s changed: %s %v", name, payload, err)
		}
	}
	if err := run([]string{"cleanup"}, nil, &output, &output); err != nil {
		t.Fatal(err)
	}
	if _, err := reviewer.Check(request, reviewer.Options{StateDir: state}); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT count(*) FROM review_events").Scan(&count); err != nil || count == 0 {
		t.Fatalf("new history %d: %v", count, err)
	}
}

func TestHistoryConfigMergeDoctorAndCleanupWithoutLogs(t *testing.T) {
	state := t.TempDir()
	workspace := t.TempDir()
	t.Setenv("AAR_STATE_DIR", "")
	t.Setenv("AAR_WORKSPACE_ROOT", workspace)
	configPath := filepath.Join(t.TempDir(), "config.toml")
	t.Setenv("AAR_CONFIG", configPath)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := os.WriteFile(configPath, []byte("[audit]\nenabled = false\ndir = '"+state+"'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"doctor"}, nil, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"loggingEnabled":false`)) {
		t.Fatalf("doctor %s", output.String())
	}
	if err := os.WriteFile(filepath.Join(workspace, ".aar.toml"), []byte("[audit]\nenabled = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run([]string{"doctor"}, nil, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"loggingEnabled":true`)) {
		t.Fatalf("doctor %s", output.String())
	}
	if err := os.WriteFile(filepath.Join(workspace, ".aar.toml"), []byte("[audit]\nenabled = 'false'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"doctor"}, nil, &output, &output); err == nil {
		t.Fatal("invalid logging value accepted")
	}
	if err := os.WriteFile(filepath.Join(workspace, ".aar.toml"), []byte("[audit]\nenabled = false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := run([]string{"cleanup"}, nil, &output, &output); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"logs", "audit"} {
		if _, err := os.Stat(filepath.Join(state, name)); !os.IsNotExist(err) {
			t.Fatalf("created history %s: %v", name, err)
		}
	}
}

func TestCleanupRefusesSymlinksWithoutTouchingExternalHistory(t *testing.T) {
	for _, name := range []string{"audit", "logs", "logs/reviews.sqlite", "logs/reviews.sqlite-wal", "logs/reviews.sqlite-shm", "audit/old.json"} {
		t.Run(name, func(t *testing.T) {
			state, outside := t.TempDir(), t.TempDir()
			t.Setenv("AAR_STATE_DIR", state)
			t.Setenv("AAR_CONFIG", filepath.Join(t.TempDir(), "absent.toml"))
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			sentinel := filepath.Join(outside, "sentinel.json")
			if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			target := sentinel
			if name == "audit" || name == "logs" {
				target = outside
			}
			if err := os.MkdirAll(filepath.Dir(filepath.Join(state, name)), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(state, name)); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := run([]string{"cleanup"}, nil, &output, &output); err == nil {
				t.Fatal("symlink accepted")
			}
			payload, err := os.ReadFile(sentinel)
			if err != nil || string(payload) != "keep" {
				t.Fatalf("outside modified: %s %v", payload, err)
			}
		})
	}
}

type waitingHistoryModel struct{ entered, release chan struct{} }

func (model waitingHistoryModel) Call(_ context.Context, _ reviewer.ModelCallRequest) (string, error) {
	close(model.entered)
	<-model.release
	return `{"risks":[],"uncertainties":[]}`, nil
}

func TestCleanupReportsBusyDuringCheckAndPreservesDatabase(t *testing.T) {
	state := t.TempDir()
	t.Setenv("AAR_STATE_DIR", state)
	t.Setenv("AAR_CONFIG", filepath.Join(t.TempDir(), "absent.toml"))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	request := reviewer.Request{SchemaVersion: reviewer.RequestSchemaVersion, Command: "touch ./output", CWD: t.TempDir(), Session: reviewer.Session{ID: "s", Host: "test"}}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := reviewer.Check(request, reviewer.Options{StateDir: state, Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "test"}}, ModelCall: waitingHistoryModel{entered, release}})
		done <- err
	}()
	<-entered
	var output bytes.Buffer
	err := run([]string{"cleanup"}, nil, &output, &output)
	close(release)
	if checkErr := <-done; checkErr != nil {
		t.Fatal(checkErr)
	}
	if err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("cleanup during check: %v", err)
	}
	db, err := sql.Open("sqlite", filepath.Join(state, "logs", "reviews.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var integrity string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("integrity %q %v", integrity, err)
	}
	if _, err := db.Exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	err = run([]string{"cleanup"}, nil, &output, &output)
	if _, rollbackErr := db.Exec("ROLLBACK"); rollbackErr != nil {
		t.Fatal(rollbackErr)
	}
	if err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("cleanup while SQLite writer active: %v", err)
	}
	if err := run([]string{"cleanup"}, nil, &output, &output); err != nil {
		t.Fatal(err)
	}
	if _, err := reviewer.Check(request, reviewer.Options{StateDir: state}); err != nil {
		t.Fatal(err)
	}
}

func TestCLICheckDisabledHistoryReturnsCorrelationWithoutSavedRecord(t *testing.T) {
	state := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.toml")
	t.Setenv("AAR_STATE_DIR", state)
	t.Setenv("AAR_CONFIG", configPath)
	if err := os.WriteFile(configPath, []byte("[audit]\nenabled = false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	request := reviewer.Request{SchemaVersion: reviewer.RequestSchemaVersion, Command: "pwd", CWD: t.TempDir(), Session: reviewer.Session{ID: "s", Host: "test"}}
	input, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"check"}, bytes.NewReader(input), &output, &output); err != nil {
		t.Fatal(err)
	}
	var decision reviewer.Decision
	if err := json.Unmarshal(output.Bytes(), &decision); err != nil {
		t.Fatal(err)
	}
	if decision.Decision != reviewer.DecisionAllow || decision.AuditID == "" {
		t.Fatalf("decision %#v", decision)
	}
	err = run([]string{"explain", "--audit-id", decision.AuditID}, nil, &output, &output)
	if err == nil || !strings.Contains(err.Error(), "was not saved or is absent") {
		t.Fatalf("explain unsaved record: %v", err)
	}
	for _, name := range []string{"audit", "logs"} {
		if _, err := os.Stat(filepath.Join(state, name)); !os.IsNotExist(err) {
			t.Fatalf("history created %s: %v", name, err)
		}
	}
}
