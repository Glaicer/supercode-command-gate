package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glaicer/supercode-command-gate/reviewer/internal/reviewer"
)

func TestStatsCLIProcess(t *testing.T) {
	if os.Getenv("AAR_STATS_WORKER") != "1" {
		return
	}
	request := reviewer.Request{SchemaVersion: reviewer.RequestSchemaVersion, Command: "pwd", CWD: os.Getenv("AAR_STATS_CWD"), Session: reviewer.Session{ID: "worker", Host: "test"}}
	payload, _ := json.Marshal(request)
	var output bytes.Buffer
	if err := run([]string{"check"}, bytes.NewReader(payload), &output, os.Stderr); err != nil {
		t.Fatal(err)
	}
}

func TestStatsCLIPersistsConcurrentChecksAndReportsPeriod(t *testing.T) {
	state := t.TempDir()
	config := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(config, []byte("[audit]\nenabled = false\ndir = '"+state+"'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAR_CONFIG", config)
	t.Setenv("AAR_STATE_DIR", "")
	t.Setenv("AAR_STATS_WORKER", "1")
	t.Setenv("AAR_STATS_CWD", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var output bytes.Buffer
	if err := run([]string{"stats"}, nil, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Processed: 0") || !strings.Contains(output.String(), "not started") {
		t.Fatal(output.String())
	}
	const workers = 16
	commands := make([]*exec.Cmd, workers)
	for index := range commands {
		commands[index] = exec.Command(os.Args[0], "-test.run=^TestStatsCLIProcess$")
		commands[index].Stdout = &bytes.Buffer{}
		commands[index].Stderr = commands[index].Stdout
		if err := commands[index].Start(); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatalf("worker: %v %s", err, command.Stdout)
		}
	}
	output.Reset()
	if err := run([]string{"stats"}, nil, &output, &output); err != nil {
		t.Fatal(err)
	}
	summary := output.String()
	for _, text := range []string{fmt.Sprintf("Processed: %d", workers), "Approved by policy: 16", "Approved by LLM: 0 (fresh: 0, reused: 0)", "Reviewer outcomes only", "Ask remains Ask"} {
		if !strings.Contains(summary, text) {
			t.Fatalf("missing %q: %s", text, summary)
		}
	}
	if strings.Contains(summary, "not started") {
		t.Fatal(summary)
	}
	for _, input := range []string{"broken", "{}", `{} {}`} {
		if err := run([]string{"check"}, strings.NewReader(input), &output, &output); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	if err := run([]string{"cleanup"}, nil, &output, &output); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run([]string{"stats"}, nil, &output, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != summary {
		t.Fatalf("read/invalid input/cleanup altered counters: %s", output.String())
	}
}

func TestStatsCLIWriteFailureKeepsDecisionAndReportsDiagnostic(t *testing.T) {
	state := t.TempDir()
	t.Setenv("AAR_STATE_DIR", state)
	config := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(config, []byte("[audit]\nenabled = false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAR_CONFIG", config)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := os.Mkdir(filepath.Join(state, "stats.json.tmp"), 0700); err != nil {
		t.Fatal(err)
	}
	request := reviewer.Request{SchemaVersion: reviewer.RequestSchemaVersion, Command: "rm -rf /", CWD: t.TempDir(), Session: reviewer.Session{ID: "denied", Host: "test"}}
	payload, _ := json.Marshal(request)
	var output, diagnostic bytes.Buffer
	if err := run([]string{"check"}, bytes.NewReader(payload), &output, &diagnostic); err != nil {
		t.Fatal(err)
	}
	var decision reviewer.Decision
	if err := json.Unmarshal(output.Bytes(), &decision); err != nil {
		t.Fatal(err)
	}
	if decision.Decision != "deny" || !strings.Contains(diagnostic.String(), "statistics were not updated") {
		t.Fatalf("decision %s diagnostic %s", output.String(), diagnostic.String())
	}
}
