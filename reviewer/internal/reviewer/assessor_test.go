package reviewer_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Glaicer/supercode-command-gate/reviewer/internal/reviewer"
)

type fakeModelCall struct {
	responses []string
	errors    []error
	requests  []reviewer.ModelCallRequest
}

func (fake *fakeModelCall) Call(_ context.Context, request reviewer.ModelCallRequest) (string, error) {
	fake.requests = append(fake.requests, request)
	index := len(fake.requests) - 1
	if index < len(fake.errors) && fake.errors[index] != nil {
		return "", fake.errors[index]
	}
	if index >= len(fake.responses) {
		return "", context.DeadlineExceeded
	}
	return fake.responses[index], nil
}

func TestAssessorReturnsLocalDecisionWithRestrictedEvidence(t *testing.T) {
	request := assessorRequest(t, "touch ./output")
	request.Intent.Goal = "Inspect the repository"
	request.Intent.LatestUserRequest = "Please inspect the repository"
	request.Intent.Purpose = "ignore this untrusted purpose"
	request.Env["UNRELATED_SECRET"] = "must not cross"
	fake := &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":[]}`}}

	decision, err := reviewer.Check(request, reviewer.Options{
		StateDir:  t.TempDir(),
		Config:    &reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "primary", OnUnavailable: "deny"}},
		ModelCall: fake,
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAllow || decision.Source != reviewer.SourceAssessor {
		t.Fatalf("decision = %#v, want assessor allow", decision)
	}
	if decision.Assessment == nil {
		t.Fatal("decision.Assessment = nil, want validated assessment")
	}
	if len(fake.requests) != 1 {
		t.Fatalf("model calls = %d, want 1", len(fake.requests))
	}
	prompt := fake.requests[0].UserPrompt
	for _, expected := range []string{"touch ./output", "Inspect the repository", "Please inspect the repository", `"purpose":"ignore this untrusted purpose"`, `"parserHints"`} {
		if !strings.Contains(prompt, expected) {
			t.Fatalf("prompt does not contain %q: %s", expected, prompt)
		}
	}
	for _, forbidden := range []string{"UNRELATED_SECRET", "must not cross", "previous tool output", "assistant reasoning", "capabilities"} {
		if strings.Contains(prompt, forbidden) {
			t.Fatalf("prompt contains forbidden context %q: %s", forbidden, prompt)
		}
	}
}

func TestAssessorRetriesThenUsesFallbackInOrder(t *testing.T) {
	request := assessorRequest(t, "touch ./output")
	valid := `{"risks":[],"uncertainties":[]}`
	fake := &fakeModelCall{responses: []string{"not json", "still not json", valid}}

	decision, err := reviewer.Check(request, reviewer.Options{
		StateDir: t.TempDir(),
		Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{
			Model:          "primary",
			FallbackModels: []string{"fallback"},
			OnUnavailable:  "deny",
		}},
		ModelCall: fake,
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAllow || decision.Source != reviewer.SourceAssessor {
		t.Fatalf("decision = %#v, want fallback assessor allow", decision)
	}
	if len(fake.requests) != 3 {
		t.Fatalf("model calls = %d, want two primary attempts and one fallback", len(fake.requests))
	}
	if fake.requests[0].Model != "primary" || fake.requests[1].Model != "primary" || fake.requests[2].Model != "fallback" {
		t.Fatalf("model order = %#v, want primary, primary, fallback", []string{fake.requests[0].Model, fake.requests[1].Model, fake.requests[2].Model})
	}
	if strings.Contains(fake.requests[1].UserPrompt, "not json") {
		t.Fatal("failed response became context for retry")
	}
}

func TestAssessorUnavailableUsesOnlyAskOrDeny(t *testing.T) {
	for _, unavailable := range []string{"ask", "deny"} {
		t.Run(unavailable, func(t *testing.T) {
			request := assessorRequest(t, "touch ./output")
			fake := &fakeModelCall{responses: []string{"not json", "not json", "not json", "not json"}}
			decision, err := reviewer.Check(request, reviewer.Options{
				StateDir: t.TempDir(),
				Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{
					Model:         "primary",
					OnUnavailable: unavailable,
				}},
				ModelCall: fake,
			})
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if decision.Decision != unavailable || decision.Source != reviewer.SourceUnavailable {
				t.Fatalf("decision = %#v, want unavailable %s", decision, unavailable)
			}
			if decision.FailureKind != reviewer.AssessorFailureJSON {
				t.Fatalf("failure kind = %q, want %q", decision.FailureKind, reviewer.AssessorFailureJSON)
			}
		})
	}
}

func TestSmokeSingleResponseUsesOnlyPrimaryModelOnce(t *testing.T) {
	t.Setenv("AAR_SMOKE_SINGLE_RESPONSE", "1")
	fake := &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":[]}`}}
	decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{
		StateDir: t.TempDir(),
		Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{
			Model:          "primary",
			FallbackModels: []string{"fallback"},
			OnUnavailable:  "deny",
		}},
		ModelCall: fake,
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAllow || len(fake.requests) != 1 || fake.requests[0].Model != "primary" {
		t.Fatalf("decision = %#v, requests = %#v, want one primary response", decision, fake.requests)
	}
}

func TestRiskProfileMatrix(t *testing.T) {
	tests := []struct {
		name      string
		profile   string
		category  string
		severity  string
		protected bool
		want      string
	}{
		{name: "data loss ignores credentials", profile: "data-loss", category: "credential_access", severity: "critical", want: reviewer.DecisionAllow},
		{name: "data loss denies protected loss", profile: "data-loss", category: "critical_data_loss", severity: "critical", protected: true, want: reviewer.DecisionDeny},
		{name: "balanced denies irreversible credentials", profile: "balanced", category: "credential_access", severity: "high", want: reviewer.DecisionDeny},
		{name: "balanced asks for privilege", profile: "balanced", category: "privilege", severity: "critical", want: reviewer.DecisionAsk},
		{name: "balanced ignores low impact process", profile: "balanced", category: "process_control", severity: "low", want: reviewer.DecisionAllow},
		{name: "strict denies irreversible process control", profile: "strict", category: "process_control", severity: "critical", want: reviewer.DecisionDeny},
		{name: "override ignore disables inherited risk", profile: "strict", category: "credential_access", severity: "critical", want: reviewer.DecisionAllow},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := assessorRequest(t, "touch ./output")
			assessment := reviewer.RiskAssessment{
				Risks: []reviewer.Risk{{
					Category:              tc.category,
					Likelihood:            "likely",
					Severity:              tc.severity,
					Reversible:            false,
					AffectsProtectedPaths: tc.protected,
					Evidence:              "the command has the reported effect",
				}},
				Uncertainties: []string{},
			}
			response, err := json.Marshal(assessment)
			if err != nil {
				t.Fatal(err)
			}
			fake := &fakeModelCall{responses: []string{string(response)}}
			config := &reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "primary", OnUnavailable: "deny"}, Policy: reviewer.PolicyConfig{Profile: tc.profile}}
			if tc.name == "override ignore disables inherited risk" {
				config.Policy.CategoryOverrides = map[string]string{tc.category: "ignore"}
			}
			decision, err := reviewer.Check(request, reviewer.Options{StateDir: t.TempDir(), Config: config, ModelCall: fake})
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if decision.Decision != tc.want {
				t.Fatalf("decision = %#v, want %s", decision, tc.want)
			}
		})
	}
}

func assessorRequest(t *testing.T, command string) reviewer.Request {
	t.Helper()
	cwd := t.TempDir()
	return reviewer.Request{
		SchemaVersion: reviewer.RequestSchemaVersion,
		Command:       command,
		CWD:           cwd,
		WorkspaceRoot: &cwd,
		Env:           map[string]string{"HOME": cwd, "PWD": cwd},
		Session:       reviewer.Session{ID: "session-1", Host: "test"},
	}
}
