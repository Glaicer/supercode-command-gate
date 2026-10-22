package reviewer_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glaicer/supercode-command-gate/reviewer/internal/reviewer"
)

func goldenRequestFiles(t *testing.T) []string {
	t.Helper()
	return []string{
		filepath.Join("..", "..", "cmd", "aar", "testdata", "pwd-request.json"),
		filepath.Join("..", "..", "cmd", "aar", "testdata", "unknown-request.json"),
	}
}

func TestRequestWithoutBackgroundSerializesByteForByte(t *testing.T) {
	t.Parallel()

	for _, path := range goldenRequestFiles(t) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture %s: %v", path, err)
		}
		var request reviewer.Request
		if err := json.Unmarshal(raw, &request); err != nil {
			t.Fatalf("decode fixture %s: %v", path, err)
		}
		if request.Background {
			t.Fatalf("fixture %s decoded background = true, want false", path)
		}
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatalf("encode fixture %s: %v", path, err)
		}
		want := strings.TrimSpace(string(raw))
		if string(encoded) != want {
			t.Fatalf("serialization of %s changed\nwant: %s\n got: %s", path, want, encoded)
		}
	}
}

func TestCheckAcceptsRequestsWithAndWithoutBackgroundFact(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"schemaVersion":"aar-request-v1","command":"pwd","cwd":"/workspace/project","workspaceRoot":null,"env":{"PWD":"/workspace/project"},"session":{"id":"golden-session","host":"opencode","intentId":"intent-1"},"intent":{"goal":"inspect the workspace","latestUserRequest":"show me the current directory","purpose":"read-only inspection"}}`)

	var foreground reviewer.Request
	if err := json.Unmarshal(raw, &foreground); err != nil {
		t.Fatalf("decode request without background: %v", err)
	}
	decision, err := reviewer.Check(foreground, reviewer.Options{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Check() without background error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAllow {
		t.Fatalf("decision without background = %q, want allow", decision.Decision)
	}

	backgroundRaw := []byte(`{"schemaVersion":"aar-request-v1","command":"pwd","cwd":"/workspace/project","workspaceRoot":null,"env":{"PWD":"/workspace/project"},"background":true,"session":{"id":"golden-session","host":"opencode","intentId":"intent-1"},"intent":{"goal":"inspect the workspace","latestUserRequest":"show me the current directory","purpose":"read-only inspection"}}`)
	var background reviewer.Request
	if err := json.Unmarshal(backgroundRaw, &background); err != nil {
		t.Fatalf("decode request with background: %v", err)
	}
	if !background.Background {
		t.Fatal("decoded background = false, want true")
	}
	decision, err = reviewer.Check(background, reviewer.Options{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Check() with background error = %v", err)
	}
	if decision.SchemaVersion != reviewer.DecisionSchemaVersion {
		t.Fatalf("decision schemaVersion = %q, want %q", decision.SchemaVersion, reviewer.DecisionSchemaVersion)
	}
}

func TestBackgroundInvocationHasADifferentRequestFingerprint(t *testing.T) {
	t.Parallel()

	request := reviewer.Request{
		SchemaVersion: reviewer.RequestSchemaVersion,
		Command:       "pwd",
		CWD:           t.TempDir(),
		Session:       reviewer.Session{ID: "session-1", Host: "test", IntentID: "intent-1"},
	}
	foreground, err := reviewer.Check(request, reviewer.Options{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("foreground Check() error = %v", err)
	}
	background := request
	background.Background = true
	backgroundDecision, err := reviewer.Check(background, reviewer.Options{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("background Check() error = %v", err)
	}
	if foreground.RequestFingerprint == backgroundDecision.RequestFingerprint {
		t.Fatalf("background requestFingerprint = %q equals foreground fingerprint", backgroundDecision.RequestFingerprint)
	}

	factsRequest := grantRequest(t, "intent-1")
	factsConfig := grantConfig()
	factsForeground, err := reviewer.Check(factsRequest, reviewer.Options{StateDir: t.TempDir(), Config: factsConfig, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("foreground assessor Check() error = %v", err)
	}
	factsBackground := factsRequest
	factsBackground.Background = true
	factsBackgroundDecision, err := reviewer.Check(factsBackground, reviewer.Options{StateDir: t.TempDir(), Config: factsConfig, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("background assessor Check() error = %v", err)
	}
	if factsForeground.RequestFingerprint == factsBackgroundDecision.RequestFingerprint {
		t.Fatalf("background facts requestFingerprint = %q equals foreground facts fingerprint", factsBackgroundDecision.RequestFingerprint)
	}
}

func TestForegroundGrantDoesNotAuthorizeTheBackgroundInvocation(t *testing.T) {
	stateDir := t.TempDir()
	request := grantRequest(t, "intent-1")
	config := grantConfig()

	ask, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("initial Check() error = %v", err)
	}
	if ask.Decision != reviewer.DecisionAsk {
		t.Fatalf("initial decision = %#v, want assessor ask", ask)
	}
	if err := reviewer.Grant(request.Session.ID, ask.RequestFingerprint, reviewer.GrantScopeOnce, reviewer.Options{StateDir: stateDir, Config: config}); err != nil {
		t.Fatalf("Grant() error = %v", err)
	}

	background := request
	background.Background = true
	backgroundRetry, err := reviewer.Check(background, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("background retry Check() error = %v", err)
	}
	if backgroundRetry.Source == reviewer.SourceGrant {
		t.Fatalf("background retry decision = %#v, want no grant match", backgroundRetry)
	}

	foregroundRetry, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{}}})
	if err != nil {
		t.Fatalf("foreground retry Check() error = %v", err)
	}
	if foregroundRetry.Decision != reviewer.DecisionAllow || foregroundRetry.Source != reviewer.SourceGrant {
		t.Fatalf("foreground retry decision = %#v, want grant allow", foregroundRetry)
	}
}

func TestReceivedAuditEventContainsTheBackgroundFact(t *testing.T) {
	t.Parallel()

	backgroundDir := t.TempDir()
	background := reviewer.Request{
		SchemaVersion: reviewer.RequestSchemaVersion,
		Command:       "pwd",
		CWD:           t.TempDir(),
		Session:       reviewer.Session{ID: "session-1", Host: "test"},
		Background:    true,
	}
	if _, err := reviewer.Check(background, reviewer.Options{StateDir: backgroundDir}); err != nil {
		t.Fatalf("background Check() error = %v", err)
	}
	records := readReviewLog(t, backgroundDir)
	if records[0]["event"] != "received" {
		t.Fatalf("first event = %#v, want received", records[0])
	}
	if records[0]["background"] != true {
		t.Fatalf("received event background = %#v, want true", records[0]["background"])
	}

	foregroundDir := t.TempDir()
	foreground := background
	foreground.Background = false
	if _, err := reviewer.Check(foreground, reviewer.Options{StateDir: foregroundDir}); err != nil {
		t.Fatalf("foreground Check() error = %v", err)
	}
	records = readReviewLog(t, foregroundDir)
	if records[0]["event"] != "received" {
		t.Fatalf("first event = %#v, want received", records[0])
	}
	if records[0]["background"] != false {
		t.Fatalf("received event background = %#v, want false", records[0]["background"])
	}
}

func TestAuditRecordContainsTheBackgroundFact(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	request := reviewer.Request{
		SchemaVersion: reviewer.RequestSchemaVersion,
		Command:       "pwd",
		CWD:           t.TempDir(),
		Session:       reviewer.Session{ID: "session-1", Host: "test"},
		Background:    true,
	}
	decision, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("background Check() error = %v", err)
	}
	explained, err := reviewer.Explain(decision.AuditID, reviewer.Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(explained, &record); err != nil {
		t.Fatalf("decode audit record: %v", err)
	}
	if record["background"] != true {
		t.Fatalf("audit record background = %#v, want true", record["background"])
	}

	foreground := request
	foreground.Background = false
	foregroundDecision, err := reviewer.Check(foreground, reviewer.Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("foreground Check() error = %v", err)
	}
	explained, err = reviewer.Explain(foregroundDecision.AuditID, reviewer.Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	record = nil
	if err := json.Unmarshal(explained, &record); err != nil {
		t.Fatalf("decode audit record: %v", err)
	}
	if _, ok := record["background"]; ok {
		t.Fatalf("foreground audit record background = %#v, want absent", record["background"])
	}
}
