package reviewer_test

import (
	"testing"

	"github.com/supercode/auto-approval-reviewer/internal/reviewer"
)

func TestStrictLocalEvidenceUncertaintyForcesAsk(t *testing.T) {
	request := assessorRequest(t, `cat "$TARGET"`)
	fake := &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":[]}`}}
	decision, err := reviewer.Check(request, reviewer.Options{
		StateDir:  t.TempDir(),
		Config:    &reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "primary", OnUnavailable: "deny"}, Policy: reviewer.PolicyConfig{Profile: "strict"}},
		ModelCall: fake,
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAsk || decision.Source != reviewer.SourceAssessor {
		t.Fatalf("decision = %#v, want assessor ask for dynamic evidence", decision)
	}
	if decision.GrantEligible {
		t.Fatal("decision.GrantEligible = true, want false for uncertain evidence")
	}
}

func TestStrictInterpreterWithoutScriptEvidenceForcesAsk(t *testing.T) {
	request := assessorRequest(t, "python3 script.py")
	fake := &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":[]}`}}
	decision, err := reviewer.Check(request, reviewer.Options{
		StateDir:  t.TempDir(),
		Config:    &reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "primary", OnUnavailable: "deny"}, Policy: reviewer.PolicyConfig{Profile: "strict"}},
		ModelCall: fake,
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAsk {
		t.Fatalf("decision = %#v, want ask without script evidence", decision)
	}
	if decision.GrantEligible {
		t.Fatal("decision.GrantEligible = true, want false without script evidence")
	}
}

func TestDisabledCategoryUncertaintyDoesNotAsk(t *testing.T) {
	request := assessorRequest(t, "touch ./output")
	fake := &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":["credential access was not observable"]}`}}
	decision, err := reviewer.Check(request, reviewer.Options{
		StateDir: t.TempDir(),
		Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{
			Model:         "primary",
			OnUnavailable: "deny",
		}},
		ModelCall: fake,
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAllow {
		t.Fatalf("decision = %#v, want data-loss to ignore disabled credential uncertainty", decision)
	}
}

func TestSchemaInvalidAssessmentUsesUnavailableAction(t *testing.T) {
	request := assessorRequest(t, "touch ./output")
	fake := &fakeModelCall{responses: []string{
		`{"risks":[],"uncertainties":[1]}`,
		"```json\n{\"risks\":[],\"uncertainties\":[]}\n```",
	}}
	decision, err := reviewer.Check(request, reviewer.Options{
		StateDir: t.TempDir(),
		Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{
			Model:         "primary",
			OnUnavailable: "ask",
		}},
		ModelCall: fake,
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAsk || decision.Source != reviewer.SourceUnavailable {
		t.Fatalf("decision = %#v, want unavailable ask", decision)
	}
	if decision.Assessment != nil {
		t.Fatalf("assessment = %#v, want nil after failed attempts", decision.Assessment)
	}
}
