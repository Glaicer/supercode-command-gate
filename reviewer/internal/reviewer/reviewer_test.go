package reviewer_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glaicer/supercode-command-gate/reviewer/internal/reviewer"
)

func TestCheckAllowsStaticPwd(t *testing.T) {
	t.Parallel()

	request := reviewer.Request{
		SchemaVersion: "aar-request-v1",
		Command:       "pwd",
		CWD:           t.TempDir(),
		Session:       reviewer.Session{ID: "session-1", Host: "opencode"},
	}

	decision, err := reviewer.Check(request, reviewer.Options{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAllow {
		t.Fatalf("decision = %q, want allow", decision.Decision)
	}
	if decision.Source != reviewer.SourceAutoAllow {
		t.Fatalf("source = %q, want auto-allow", decision.Source)
	}
	if decision.Rule == nil || *decision.Rule != "AA001" {
		t.Fatalf("rule = %v, want AA001", decision.Rule)
	}
}

func TestCheckAllowNeverExecutesCommand(t *testing.T) {
	target := filepath.Join(t.TempDir(), "reviewer-executed")
	binDir := t.TempDir()
	fakePwd := filepath.Join(binDir, "pwd")
	if err := os.WriteFile(fakePwd, []byte("#!/bin/sh\ntouch "+target+"\n"), 0o700); err != nil {
		t.Fatalf("write fake pwd: %v", err)
	}
	t.Setenv("PATH", binDir)

	request := reviewer.Request{
		SchemaVersion: "aar-request-v1",
		Command:       "pwd",
		CWD:           t.TempDir(),
		Session:       reviewer.Session{ID: "session-1", Host: "opencode"},
	}
	decision, err := reviewer.Check(request, reviewer.Options{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAllow {
		t.Fatalf("decision = %q, want allow", decision.Decision)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("reviewer executed the command; stat error = %v", err)
	}
}

func TestCheckDeniesEveryOtherCommandWithoutExecutingIt(t *testing.T) {
	t.Parallel()

	target := filepath.Join(t.TempDir(), "must-not-exist")
	request := reviewer.Request{
		SchemaVersion: "aar-request-v1",
		Command:       "touch " + target,
		CWD:           filepath.Dir(target),
		Session:       reviewer.Session{ID: "session-1", Host: "opencode"},
	}

	decision, err := reviewer.Check(request, reviewer.Options{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionDeny {
		t.Fatalf("decision = %q, want deny", decision.Decision)
	}
	if decision.Source != reviewer.SourceUnavailable {
		t.Fatalf("source = %q, want unavailable", decision.Source)
	}
	if !strings.Contains(decision.Reason, "not proven safe") {
		t.Fatalf("reason = %q, want an effect-based safety reason", decision.Reason)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("reviewer executed the command; stat error = %v", err)
	}
}

func TestCheckAllowsAReadOnlyPipelineOnlyWhenEveryChildIsSafe(t *testing.T) {
	t.Parallel()

	request := reviewer.Request{
		SchemaVersion: "aar-request-v1",
		Command:       "pwd | cat",
		CWD:           t.TempDir(),
		Session:       reviewer.Session{ID: "session-1", Host: "opencode"},
	}

	decision, err := reviewer.Check(request, reviewer.Options{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAllow {
		t.Fatalf("decision = %q, want allow", decision.Decision)
	}
	if decision.Dynamic {
		t.Fatal("decision.Dynamic = true, want a static pipeline")
	}
}

func TestAuditContainsDecisionMetadataWithoutRawSecret(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	request := reviewer.Request{
		SchemaVersion: "aar-request-v1",
		Command:       "echo AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=aws-secret password:pw-secret token=sk-test-secret-value https://user:url-secret@example.com --password cli-secret --api-key 'raw-secret' PASSWORD=\"quoted-secret\"",
		CWD:           filepath.Join(t.TempDir(), "password:cwd-secret"),
		Session:       reviewer.Session{ID: "session-1", Host: "opencode"},
	}

	decision, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	audit, err := os.ReadFile(filepath.Join(stateDir, "audit", decision.AuditID+".json"))
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !strings.Contains(string(audit), `"decision"`) || !strings.Contains(string(audit), `"source"`) || !strings.Contains(string(audit), `"requestFingerprint"`) {
		t.Fatalf("audit lacks decision metadata: %s", audit)
	}
	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "aws-secret", "pw-secret", "sk-test-secret-value", "url-secret", "cli-secret", "raw-secret", "quoted-secret", "cwd-secret"} {
		if strings.Contains(string(audit), secret) {
			t.Fatalf("audit leaked a secret-like literal: %s", audit)
		}
	}

	var record map[string]any
	if err := json.Unmarshal(audit, &record); err != nil {
		t.Fatalf("audit is not JSON: %v", err)
	}
	if record["schemaVersion"] != reviewer.AuditSchemaVersion || record["outcome"] != reviewer.AuditOutcomeDeterministic {
		t.Fatalf("audit classification = %#v, want secret-safe deterministic outcome", record)
	}
}

func TestAuditExplainDistinguishesDeterministicModelAndGrantOutcomes(t *testing.T) {
	t.Parallel()

	t.Run("deterministic", func(t *testing.T) {
		stateDir := t.TempDir()
		request := reviewer.Request{
			SchemaVersion: reviewer.RequestSchemaVersion,
			Command:       "pwd",
			CWD:           t.TempDir(),
			Session:       reviewer.Session{ID: "deterministic-session", Host: "test"},
		}
		decision, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir})
		if err != nil {
			t.Fatal(err)
		}
		assertAuditOutcome(t, stateDir, decision.AuditID, reviewer.AuditOutcomeDeterministic)
	})

	t.Run("model", func(t *testing.T) {
		stateDir := t.TempDir()
		request := reviewer.Request{
			SchemaVersion: reviewer.RequestSchemaVersion,
			Command:       "touch ./output",
			CWD:           t.TempDir(),
			Session:       reviewer.Session{ID: "model-session", Host: "test"},
		}
		fake := &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":[]}`}}
		decision, err := reviewer.Check(request, reviewer.Options{
			StateDir: stateDir,
			Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{
				Model:         "primary",
				OnUnavailable: reviewer.DecisionDeny,
			}},
			ModelCall: fake,
		})
		if err != nil {
			t.Fatal(err)
		}
		assertAuditOutcome(t, stateDir, decision.AuditID, reviewer.AuditOutcomeModel)
	})

	t.Run("failure", func(t *testing.T) {
		stateDir := t.TempDir()
		request := reviewer.Request{
			SchemaVersion: reviewer.RequestSchemaVersion,
			Command:       "python3 -c 'print(1)'",
			CWD:           t.TempDir(),
			Session:       reviewer.Session{ID: "failure-session", Host: "test"},
		}
		decision, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir})
		if err != nil {
			t.Fatal(err)
		}
		assertAuditOutcome(t, stateDir, decision.AuditID, reviewer.AuditOutcomeFailure)
	})

	t.Run("grant", func(t *testing.T) {
		stateDir := t.TempDir()
		cwd := t.TempDir()
		request := reviewer.Request{
			SchemaVersion: reviewer.RequestSchemaVersion,
			Command:       "touch ./output",
			CWD:           cwd,
			Session:       reviewer.Session{ID: "grant-session", Host: "test", IntentID: "intent-1"},
			Intent:        reviewer.Intent{LatestUserRequest: "approve the output"},
		}
		response := `{"risks":[{"category":"privilege","likelihood":"likely","severity":"high","reversible":false,"affectsProtectedPaths":false,"evidence":"requires an elevated effect"}],"uncertainties":[]}`
		config := &reviewer.Config{
			Assessor: reviewer.AssessorConfig{Model: "primary", OnUnavailable: reviewer.DecisionDeny},
			Policy:   reviewer.PolicyConfig{Profile: "balanced"},
			Grants:   reviewer.GrantsConfig{SessionTrust: true},
		}
		first, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &fakeModelCall{responses: []string{response}}})
		if err != nil {
			t.Fatal(err)
		}
		if first.Decision != reviewer.DecisionAsk || !first.GrantEligible {
			t.Fatalf("initial decision = %#v, want eligible ask", first)
		}
		if err := reviewer.Grant(request.Session.ID, first.RequestFingerprint, reviewer.GrantScopeSession, reviewer.Options{StateDir: stateDir, Config: config}); err != nil {
			t.Fatal(err)
		}
		second, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &fakeModelCall{responses: []string{response}}})
		if err != nil {
			t.Fatal(err)
		}
		if second.Decision != reviewer.DecisionAllow || second.Source != reviewer.SourceGrant {
			t.Fatalf("granted decision = %#v, want grant allow", second)
		}
		assertAuditOutcome(t, stateDir, second.AuditID, reviewer.AuditOutcomeGrant)
	})
}

func assertAuditOutcome(t *testing.T, stateDir, auditID, want string) {
	t.Helper()
	data, err := reviewer.Explain(auditID, reviewer.Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("Explain() returned invalid JSON: %v", err)
	}
	if record["auditId"] != auditID || record["schemaVersion"] != reviewer.AuditSchemaVersion || record["outcome"] != want {
		t.Fatalf("audit = %#v, want audit %s outcome %s", record, auditID, want)
	}
}

func TestCheckRejectsWrongRequestSchema(t *testing.T) {
	_, err := reviewer.Check(reviewer.Request{SchemaVersion: "wrong", Command: "pwd"}, reviewer.Options{StateDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "schemaVersion") {
		t.Fatalf("Check() error = %v, want schemaVersion validation error", err)
	}
}
