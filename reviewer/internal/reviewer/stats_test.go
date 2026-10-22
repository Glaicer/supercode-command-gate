package reviewer_test

import (
	"github.com/Glaicer/supercode-command-gate/reviewer/internal/reviewer"
	"os"
	"path/filepath"
	"testing"
)

func TestStatisticsCountPolicyAndDenyWithoutHistory(t *testing.T) {
	disabled := false
	options := reviewer.Options{StateDir: t.TempDir(), Config: &reviewer.Config{Audit: reviewer.AuditConfig{Enabled: &disabled}}}
	request := reviewer.Request{SchemaVersion: reviewer.RequestSchemaVersion, Command: "pwd", CWD: t.TempDir(), Session: reviewer.Session{ID: "stats", Host: "test"}}
	for _, command := range []string{"pwd", "rm -rf /"} {
		request.Command = command
		if _, err := reviewer.Check(request, options); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := reviewer.Stats(options)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Processed != 2 || stats.Policy != 1 || stats.Denied != 1 {
		t.Fatalf("stats: %+v", stats)
	}
	if _, err := reviewer.Cleanup(options); err != nil {
		t.Fatal(err)
	}
	after, err := reviewer.Stats(options)
	if err != nil || after != stats {
		t.Fatalf("cleanup stats: %+v %v", after, err)
	}
}

func TestStatisticsPartitionReviewerResultsAndRetries(t *testing.T) {
	req, options, _ := trustFixture(t)
	disabled := false
	options.Config.Audit.Enabled = &disabled
	options.ModelCall = &fakeModelCall{responses: []string{"invalid assessment", `{"risks":[],"uncertainties":[]}`}}
	for range 2 {
		if _, err := reviewer.Check(req, options); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := reviewer.Stats(options)
	if err != nil || stats.Processed != 2 || stats.LLMFresh != 1 || stats.LLMReused != 1 {
		t.Fatalf("fresh/reused/retries: %+v %v", stats, err)
	}
	req.Command = "touch ./output"
	req.Session.IntentID = "intent"
	options.Config.Grants.SessionTrust = true
	options.Config.Policy.Profile = "balanced"
	options.ModelCall = &grantModelCall{responses: []string{privilegeAssessment()}}
	ask, err := reviewer.Check(req, options)
	if err != nil || ask.Decision != "ask" {
		t.Fatalf("ask: %+v %v", ask, err)
	}
	if err := reviewer.Grant(req.Session.ID, ask.RequestFingerprint, reviewer.GrantScopeOnce, options); err != nil {
		t.Fatal(err)
	}
	if _, err := reviewer.Check(req, options); err != nil {
		t.Fatal(err)
	}
	options.ModelCall = &grantModelCall{responses: []string{privilegeAssessment()}}
	ask, err = reviewer.Check(req, options)
	if err != nil || ask.Decision != "ask" {
		t.Fatalf("second ask: %+v %v", ask, err)
	}
	if err := reviewer.DenyNote(req.Session.ID, ask.RequestFingerprint, options); err != nil {
		t.Fatal(err)
	}
	if d, err := reviewer.Check(req, options); err != nil {
		t.Fatal(err)
	} else if d.Source != reviewer.SourceDenyNote {
		t.Fatalf("deny-note: %+v", d)
	}
	req.Session.ID = "unavailable"
	options.ModelCall = &fakeModelCall{}
	if d, err := reviewer.Check(req, options); err != nil {
		t.Fatal(err)
	} else if d.Source != reviewer.SourceUnavailable {
		t.Fatalf("unavailable: %+v", d)
	}
	req.Command = "pwd"
	if _, err := reviewer.Check(req, options); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"audit", "logs"} {
		if _, err := os.Stat(filepath.Join(options.StateDir, name)); !os.IsNotExist(err) {
			t.Fatalf("history exists: %s %v", name, err)
		}
	}
	options.ConfigPath = filepath.Join(t.TempDir(), "broken.toml")
	options.Config = nil
	if err := os.WriteFile(options.ConfigPath, []byte("[audit]\nenabled = 'invalid'"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := reviewer.Check(req, options); err == nil {
		t.Fatal("invalid config accepted")
	}
	options.ConfigPath = ""
	options.Config = &reviewer.Config{Audit: reviewer.AuditConfig{Enabled: &disabled}}
	stats, err = reviewer.Stats(options)
	if err != nil || stats.Processed != 9 || stats.Policy != 1 || stats.LLMFresh != 1 || stats.LLMReused != 1 || stats.Ask != 2 || stats.Human != 1 || stats.Denied != 2 || stats.Errors != 1 {
		t.Fatalf("partition: %+v %v", stats, err)
	}

}

func TestStatisticsFailurePreservesVerdictAndDiagnosesUnknownState(t *testing.T) {
	disabled := false
	options := reviewer.Options{StateDir: t.TempDir(), Config: &reviewer.Config{Audit: reviewer.AuditConfig{Enabled: &disabled}}}
	req := reviewer.Request{SchemaVersion: reviewer.RequestSchemaVersion, CWD: t.TempDir(), Session: reviewer.Session{ID: "stats", Host: "test"}}
	for _, payload := range []string{`{"version":42}`, `broken`, `{"version":1,"startedAt":"2026-10-06T00:00:00Z","processed":10,"denied":1}`} {
		if err := os.WriteFile(filepath.Join(options.StateDir, "stats.json"), []byte(payload), 0600); err != nil {
			t.Fatal(err)
		}
		for _, command := range []string{"pwd", "rm -rf /", "touch output"} {
			req.Command = command
			decision, err := reviewer.Check(req, options)
			if err != nil || decision.StatsError == "" {
				t.Fatalf("stats failure altered Decision: %+v %v", decision, err)
			}
		}
		if _, err := reviewer.Stats(options); err == nil {
			t.Fatal("invalid totals presented")
		}
	}
	if err := os.Remove(filepath.Join(options.StateDir, "stats.json")); err != nil {
		t.Fatal(err)
	}
	req.SchemaVersion = "invalid"
	if _, err := reviewer.Check(req, options); err == nil {
		t.Fatal("invalid request accepted")
	}
	stats, err := reviewer.Stats(options)
	if err != nil || stats.Processed != 0 {
		t.Fatalf("invalid request counted: %+v %v", stats, err)
	}
}
