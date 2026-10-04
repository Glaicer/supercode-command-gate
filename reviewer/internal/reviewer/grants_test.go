package reviewer_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/supercode/auto-approval-reviewer/internal/reviewer"
)

func TestAskReservesAnEligibleFingerprintAndGrantAllowsTheExactRetry(t *testing.T) {
	stateDir := t.TempDir()
	request := reviewer.Request{
		SchemaVersion: reviewer.RequestSchemaVersion,
		Command:       "touch ./output",
		CWD:           t.TempDir(),
		Session:       reviewer.Session{ID: "session-1", Host: "test", IntentID: "intent-1"},
	}
	config := &reviewer.Config{
		Assessor: reviewer.AssessorConfig{Model: "primary", OnUnavailable: reviewer.DecisionDeny},
		Policy:   reviewer.PolicyConfig{Profile: "balanced"},
		Grants:   reviewer.GrantsConfig{SessionTrust: true},
	}
	assessment, err := json.Marshal(reviewer.RiskAssessment{Risks: []reviewer.Risk{{Category: "privilege", Likelihood: "likely", Severity: "critical", Evidence: "requires elevated authority"}}, Uncertainties: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	fake := &grantModelCall{responses: []string{string(assessment)}}

	decision, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: fake})
	if err != nil {
		t.Fatalf("initial Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAsk || decision.Source != reviewer.SourceAssessor {
		t.Fatalf("initial decision = %#v, want assessor ask", decision)
	}
	if !decision.GrantEligible {
		t.Fatalf("initial decision is not grant eligible after %d model calls: %#v", fake.calls, decision)
	}

	if err := reviewer.Grant(request.Session.ID, decision.RequestFingerprint, reviewer.GrantScopeOnce, reviewer.Options{StateDir: stateDir, Config: config}); err != nil {
		t.Fatalf("Grant() error = %v", err)
	}

	retry, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{}}})
	if err != nil {
		t.Fatalf("retry Check() error = %v", err)
	}
	if retry.Decision != reviewer.DecisionAllow || retry.Source != reviewer.SourceGrant {
		t.Fatalf("retry decision = %#v, want grant allow", retry)
	}
}

func TestAllowOnceGrantCannotAuthorizeASecondExactRetry(t *testing.T) {
	stateDir := t.TempDir()
	request := grantRequest(t, "intent-1")
	config := grantConfig()
	initial := &grantModelCall{responses: []string{privilegeAssessment()}}
	decision, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: initial})
	if err != nil {
		t.Fatalf("initial Check() error = %v", err)
	}
	if err := reviewer.Grant(request.Session.ID, decision.RequestFingerprint, reviewer.GrantScopeOnce, reviewer.Options{StateDir: stateDir, Config: config}); err != nil {
		t.Fatalf("Grant() error = %v", err)
	}

	firstRetry, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{}}})
	if err != nil {
		t.Fatalf("first retry Check() error = %v", err)
	}
	if firstRetry.Decision != reviewer.DecisionAllow || firstRetry.Source != reviewer.SourceGrant {
		t.Fatalf("first retry decision = %#v, want grant allow", firstRetry)
	}

	secondRetry, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("second retry Check() error = %v", err)
	}
	if secondRetry.Decision != reviewer.DecisionAsk || secondRetry.Source != reviewer.SourceAssessor {
		t.Fatalf("second retry decision = %#v, want fresh assessor ask", secondRetry)
	}
}

func TestSessionGrantReusesOnlyUntilIntentInvalidation(t *testing.T) {
	stateDir := t.TempDir()
	request := grantRequest(t, "intent-1")
	config := grantConfig()
	decision, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("initial Check() error = %v", err)
	}
	if !decision.GrantEligible {
		t.Fatalf("initial session decision = %#v, want eligible ask", decision)
	}
	if err := reviewer.Grant(request.Session.ID, decision.RequestFingerprint, reviewer.GrantScopeSession, reviewer.Options{StateDir: stateDir, Config: config}); err != nil {
		t.Fatalf("session Grant() error = %v", err)
	}

	reused, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{}}})
	if err != nil {
		t.Fatalf("reused Check() error = %v", err)
	}
	if reused.Decision != reviewer.DecisionAllow || reused.Source != reviewer.SourceGrant || reused.GrantScope != reviewer.GrantScopeSession {
		t.Fatalf("reused decision = %#v, want session grant allow", reused)
	}

	changedIntent := request
	changedIntent.Session.IntentID = "intent-2"
	afterIntentChange, err := reviewer.Check(changedIntent, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("intent-changed Check() error = %v", err)
	}
	if afterIntentChange.Decision != reviewer.DecisionAsk || afterIntentChange.Source != reviewer.SourceAssessor {
		t.Fatalf("intent-changed decision = %#v, want fresh assessor ask", afterIntentChange)
	}

	if err := reviewer.SessionEvent(request.Session.ID, "goal-change", reviewer.Options{StateDir: stateDir, Config: config}); err != nil {
		t.Fatalf("SessionEvent() error = %v", err)
	}
	afterEvent, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("post-event Check() error = %v", err)
	}
	if afterEvent.Decision != reviewer.DecisionAsk || afterEvent.Source != reviewer.SourceAssessor {
		t.Fatalf("post-event decision = %#v, want fresh assessor ask", afterEvent)
	}
}

func TestDisabledSessionTrustIsNotEligibleButStillAllowsOnce(t *testing.T) {
	request := grantRequest(t, "intent-1")
	config := grantConfig()
	config.Grants.SessionTrust = false
	options := reviewer.Options{StateDir: t.TempDir(), Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}}
	decision, err := reviewer.Check(request, options)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != reviewer.DecisionAsk || decision.GrantEligible {
		t.Fatalf("decision = %#v, want ineligible ask with session trust disabled", decision)
	}
	if err := reviewer.Grant(request.Session.ID, decision.RequestFingerprint, reviewer.GrantScopeSession, options); err == nil {
		t.Fatal("session Grant() succeeded with session trust disabled")
	}
	if err := reviewer.Grant(request.Session.ID, decision.RequestFingerprint, reviewer.GrantScopeOnce, options); err != nil {
		t.Fatal(err)
	}
	options.ModelCall = &grantModelCall{}
	retry, err := reviewer.Check(request, options)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Decision != reviewer.DecisionAllow || retry.Source != reviewer.SourceGrant || retry.GrantScope != reviewer.GrantScopeOnce {
		t.Fatalf("retry = %#v, want once grant allow", retry)
	}
}

func TestEverySessionEventInvalidatesSessionGrant(t *testing.T) {
	for _, event := range []string{"end", "clear", "new-intent", "goal-change"} {
		t.Run(event, func(t *testing.T) {
			stateDir := t.TempDir()
			request := grantRequest(t, "intent-1")
			config := grantConfig()
			initial, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
			if err != nil {
				t.Fatalf("initial Check() error = %v", err)
			}
			if err := reviewer.Grant(request.Session.ID, initial.RequestFingerprint, reviewer.GrantScopeSession, reviewer.Options{StateDir: stateDir, Config: config}); err != nil {
				t.Fatalf("Grant() error = %v", err)
			}
			if err := reviewer.SessionEvent(request.Session.ID, event, reviewer.Options{StateDir: stateDir, Config: config}); err != nil {
				t.Fatalf("SessionEvent() error = %v", err)
			}
			fresh, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
			if err != nil {
				t.Fatalf("post-event Check() error = %v", err)
			}
			if fresh.Decision != reviewer.DecisionAsk || fresh.Source != reviewer.SourceAssessor {
				t.Fatalf("post-event decision = %#v, want fresh assessor ask", fresh)
			}
		})
	}
}

func TestHumanDenySuppressesTheIdenticalFingerprintUntilNewIntent(t *testing.T) {
	stateDir := t.TempDir()
	request := grantRequest(t, "intent-1")
	config := grantConfig()
	decision, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("initial Check() error = %v", err)
	}
	if err := reviewer.DenyNote(request.Session.ID, decision.RequestFingerprint, reviewer.Options{StateDir: stateDir, Config: config}); err != nil {
		t.Fatalf("DenyNote() error = %v", err)
	}

	suppressedModel := &grantModelCall{}
	suppressed, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: suppressedModel})
	if err != nil {
		t.Fatalf("suppressed Check() error = %v", err)
	}
	if suppressed.Decision != reviewer.DecisionDeny || suppressed.Source != reviewer.SourceDenyNote {
		t.Fatalf("suppressed decision = %#v, want deny-note deny", suppressed)
	}
	if suppressedModel.calls != 0 {
		t.Fatalf("suppressed request called assessor %d times, want zero", suppressedModel.calls)
	}

	newIntent := request
	newIntent.Session.IntentID = "intent-2"
	resumed, err := reviewer.Check(newIntent, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("new-intent Check() error = %v", err)
	}
	if resumed.Decision != reviewer.DecisionAsk || resumed.Source != reviewer.SourceAssessor {
		t.Fatalf("new-intent decision = %#v, want assessor ask", resumed)
	}
}

func TestGrantRejectsAnUnreservedFingerprint(t *testing.T) {
	err := reviewer.Grant("session-1", "not-reserved", reviewer.GrantScopeOnce, reviewer.Options{StateDir: t.TempDir(), Config: grantConfig()})
	if err == nil {
		t.Fatal("Grant() succeeded for a fingerprint that was never reserved")
	}
}

func TestSessionGrantStateUsesPrivatePermissionsAndGarbageCollectsOldFiles(t *testing.T) {
	stateDir := t.TempDir()
	request := grantRequest(t, "intent-1")
	config := grantConfig()
	config.Grants.MaxAgeSeconds = 1
	decision, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if err := reviewer.Grant(request.Session.ID, decision.RequestFingerprint, reviewer.GrantScopeOnce, reviewer.Options{StateDir: stateDir, Config: config}); err != nil {
		t.Fatalf("Grant() error = %v", err)
	}
	grantsDir := filepath.Join(stateDir, "grants")
	grantsInfo, err := os.Stat(grantsDir)
	if err != nil {
		t.Fatalf("stat grants directory: %v", err)
	}
	if grantsInfo.Mode().Perm() != 0o700 {
		t.Fatalf("grants directory mode = %o, want 700", grantsInfo.Mode().Perm())
	}
	files, err := filepath.Glob(filepath.Join(grantsDir, "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("session grant files = %#v, err = %v", files, err)
	}
	fileInfo, err := os.Stat(files[0])
	if err != nil {
		t.Fatalf("stat session grant file: %v", err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("session grant file mode = %o, want 600", fileInfo.Mode().Perm())
	}
	old := time.Now().Add(-2 * time.Second)
	if err := os.Chtimes(files[0], old, old); err != nil {
		t.Fatalf("age session grant file: %v", err)
	}

	gcRequest := request
	gcRequest.Session.ID = "session-2"
	gcRequest.Command = "pwd"
	_, err = reviewer.Check(gcRequest, reviewer.Options{StateDir: stateDir, Config: config})
	if err != nil {
		t.Fatalf("GC Check() error = %v", err)
	}
	if _, err := os.Stat(files[0]); !os.IsNotExist(err) {
		t.Fatalf("stale session grant file still exists, stat error = %v", err)
	}
}

func TestGrantDoesNotMatchAfterAResolvedSymlinkTargetChanges(t *testing.T) {
	stateDir := t.TempDir()
	root := t.TempDir()
	firstTarget := filepath.Join(root, "first")
	secondTarget := filepath.Join(root, "second")
	link := filepath.Join(root, "link")
	if err := os.WriteFile(firstTarget, []byte("first"), 0o600); err != nil {
		t.Fatalf("write first target: %v", err)
	}
	if err := os.WriteFile(secondTarget, []byte("second"), 0o600); err != nil {
		t.Fatalf("write second target: %v", err)
	}
	if err := os.Symlink(firstTarget, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	request := grantRequest(t, "intent-1")
	request.CWD = root
	request.Command = "touch ./link"
	config := grantConfig()
	decision, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("initial Check() error = %v", err)
	}
	if err := reviewer.Grant(request.Session.ID, decision.RequestFingerprint, reviewer.GrantScopeOnce, reviewer.Options{StateDir: stateDir, Config: config}); err != nil {
		t.Fatalf("Grant() error = %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatalf("remove first symlink: %v", err)
	}
	if err := os.Symlink(secondTarget, link); err != nil {
		t.Fatalf("create second symlink: %v", err)
	}

	retry, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("changed-link Check() error = %v", err)
	}
	if retry.Decision != reviewer.DecisionAsk || retry.Source != reviewer.SourceAssessor {
		t.Fatalf("changed-link decision = %#v, want fresh assessor ask", retry)
	}
}

func TestGrantDoesNotMatchAfterAnInspectedDependencyDigestChanges(t *testing.T) {
	stateDir := t.TempDir()
	root := t.TempDir()
	script := filepath.Join(root, "script.py")
	if err := os.WriteFile(script, []byte("print('first')\n"), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	request := grantRequest(t, "intent-1")
	request.CWD = root
	request.Command = "python3 ./script.py"
	config := grantConfig()
	decision, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("initial script Check() error = %v", err)
	}
	if err := reviewer.Grant(request.Session.ID, decision.RequestFingerprint, reviewer.GrantScopeOnce, reviewer.Options{StateDir: stateDir, Config: config}); err != nil {
		t.Fatalf("script Grant() error = %v", err)
	}
	if err := os.WriteFile(script, []byte("print('second')\n"), 0o600); err != nil {
		t.Fatalf("rewrite script: %v", err)
	}

	retry, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("changed-script Check() error = %v", err)
	}
	if retry.Decision != reviewer.DecisionAsk || retry.Source != reviewer.SourceAssessor {
		t.Fatalf("changed-script decision = %#v, want fresh assessor ask", retry)
	}
}

func TestIncompleteFactsAllowOnlySingleUseHumanTrust(t *testing.T) {
	stateDir := t.TempDir()
	request := grantRequest(t, "intent-1")
	request.Command = "touch \"$TARGET\""
	request.Env = map[string]string{"TARGET": "./output"}
	config := grantConfig()
	decision, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{privilegeAssessment()}}})
	if err != nil {
		t.Fatalf("dynamic Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAsk || decision.GrantEligible {
		t.Fatalf("dynamic decision = %#v, want ineligible ask", decision)
	}
	if err := reviewer.Grant(request.Session.ID, decision.RequestFingerprint, reviewer.GrantScopeSession, reviewer.Options{StateDir: stateDir, Config: config}); err == nil {
		t.Fatal("session grant succeeded for incomplete facts")
	}
	if err := reviewer.Grant(request.Session.ID, decision.RequestFingerprint, reviewer.GrantScopeOnce, reviewer.Options{StateDir: stateDir, Config: config}); err != nil {
		t.Fatalf("single-use grant for incomplete facts: %v", err)
	}
	retry, err := reviewer.Check(request, reviewer.Options{StateDir: stateDir, Config: config, ModelCall: &grantModelCall{responses: []string{}}})
	if err != nil {
		t.Fatalf("dynamic retry Check() error = %v", err)
	}
	if retry.Decision != reviewer.DecisionAllow || retry.Source != reviewer.SourceGrant || retry.GrantScope != reviewer.GrantScopeOnce {
		t.Fatalf("dynamic retry decision = %#v, want single-use grant allow", retry)
	}
}

func grantRequest(t *testing.T, intentID string) reviewer.Request {
	t.Helper()
	return reviewer.Request{
		SchemaVersion: reviewer.RequestSchemaVersion,
		Command:       "touch ./output",
		CWD:           t.TempDir(),
		Session:       reviewer.Session{ID: "session-1", Host: "test", IntentID: intentID},
	}
}

func grantConfig() *reviewer.Config {
	return &reviewer.Config{
		Assessor: reviewer.AssessorConfig{Model: "primary", OnUnavailable: reviewer.DecisionDeny},
		Policy:   reviewer.PolicyConfig{Profile: "balanced"},
		Grants:   reviewer.GrantsConfig{SessionTrust: true},
	}
}

func privilegeAssessment() string {
	return `{"risks":[{"category":"privilege","likelihood":"likely","severity":"critical","reversible":false,"affectsProtectedPaths":false,"evidence":"requires elevated authority"}],"uncertainties":[]}`
}

type grantModelCall struct {
	responses []string
	calls     int
}

func (fake *grantModelCall) Call(_ context.Context, _ reviewer.ModelCallRequest) (string, error) {
	fake.calls++
	if len(fake.responses) == 0 {
		return `{"risks":[{"category":"privilege","likelihood":"likely","severity":"critical","reversible":false,"affectsProtectedPaths":false,"evidence":"unexpected assessor call"}],"uncertainties":["grant was not consulted"]}`, nil
	}
	response := fake.responses[0]
	fake.responses = fake.responses[1:]
	return response, nil
}
