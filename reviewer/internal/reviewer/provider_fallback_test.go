package reviewer_test

import (
	"context"
	"encoding/json"
	"github.com/Glaicer/supercode-command-gate/reviewer/internal/reviewer"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIndependentProviderFallbackKeepsCredentialsAndOptionsIsolated(t *testing.T) {
	calls := []string{}
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, "primary")
		if r.Header.Get("Authorization") != "Bearer primary-secret" {
			t.Error("wrong primary credential")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["temperature"] != float64(0.1) {
			t.Errorf("primary options = %v", body)
		}
		w.WriteHeader(503)
	}))
	defer primary.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, "fallback")
		if r.Header.Get("Authorization") != "Bearer fallback-secret" {
			t.Error("wrong fallback credential")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["temperature"] != float64(0.9) {
			t.Errorf("fallback options = %v", body)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"risks\":[],\"uncertainties\":[]}"}}]}`))
	}))
	defer fallback.Close()
	t.Setenv("PRIMARY_KEY", "primary-secret")
	t.Setenv("FALLBACK_KEY", "fallback-secret")
	config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "same", BaseURL: primary.URL, APIKeyEnv: "PRIMARY_KEY", Options: map[string]any{"temperature": 0.1}, Fallbacks: []reviewer.AssessorConnection{{Model: "same", BaseURL: fallback.URL, APIKeyEnv: "FALLBACK_KEY", Options: map[string]any{"temperature": 0.9}}}}}
	stateDir := t.TempDir()
	decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: stateDir, Config: &config})
	if err != nil || decision.Decision != reviewer.DecisionAllow {
		t.Fatalf("decision = %#v, err = %v", decision, err)
	}
	if len(calls) != 3 || calls[0] != "primary" || calls[1] != "primary" || calls[2] != "fallback" {
		t.Fatalf("calls = %v", calls)
	}
	audit, err := os.ReadFile(filepath.Join(stateDir, "audit", decision.AuditID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), `"assessorConnection":"fallback[0]"`) {
		t.Fatalf("missing connection diagnostic: %s", audit)
	}
	for _, secret := range []string{"primary-secret", "fallback-secret", "Authorization", primary.URL, fallback.URL} {
		if strings.Contains(string(audit), secret) {
			t.Fatalf("audit exposes %s", secret)
		}
	}

}

func TestDoctorAndRuntimeCanUseFallbackWithMissingPrimaryCredential(t *testing.T) {
	t.Setenv("PRIMARY_KEY", "")
	t.Setenv("FALLBACK_KEY", "fallback-secret")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fallback-secret" {
			t.Error("wrong fallback credential")
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"risks\":[],\"uncertainties\":[]}"}}]}`))
	}))
	defer server.Close()
	config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "same", BaseURL: server.URL, APIKeyEnv: "PRIMARY_KEY", Fallbacks: []reviewer.AssessorConnection{{Model: "same", BaseURL: server.URL, APIKeyEnv: "FALLBACK_KEY"}}}}
	options := reviewer.Options{StateDir: t.TempDir(), Config: &config}
	report, err := reviewer.Doctor(assessorRequest(t, "touch ./output"), options)
	payload, _ := json.Marshal(report)
	if len(report.Connections) != 2 || report.Connections[0].CredentialAvailable || !report.Connections[1].CredentialAvailable || strings.Contains(string(payload), "fallback-secret") {
		t.Fatalf("diagnostics=%s", payload)
	}
	if err != nil || report.Status != "ok" {
		t.Fatalf("doctor = %#v, err = %v", report, err)
	}
	decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), options)
	if err != nil || decision.Decision != reviewer.DecisionAllow {
		t.Fatalf("decision = %#v, err = %v", decision, err)
	}
}

type deadlineFallback struct{ calls []string }

func (fake *deadlineFallback) Call(ctx context.Context, request reviewer.ModelCallRequest) (string, error) {
	fake.calls = append(fake.calls, request.Connection)
	if request.Connection == "primary" {
		<-ctx.Done()
		return "", ctx.Err()
	}
	return `{"risks":[],"uncertainties":[]}`, nil
}
func TestPrimaryDeadlinePreservesFallbackBudget(t *testing.T) {
	fake := &deadlineFallback{}
	config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "same", BaseURL: "https://primary.invalid", TotalTimeoutMs: 120, Fallbacks: []reviewer.AssessorConnection{{Model: "same", BaseURL: "https://fallback.invalid", APIKeyEnv: "KEY"}}}}
	start := time.Now()
	decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config, ModelCall: fake})
	if err != nil || decision.Decision != reviewer.DecisionAllow {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
	if len(fake.calls) != 2 || fake.calls[1] != "fallback[0]" {
		t.Fatalf("calls=%v", fake.calls)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("chain exceeded deadline")
	}
}
func TestIndependentFallbackConfigReplacesProjectArrayAndRejectsMixedLegacy(t *testing.T) {
	cwd := t.TempDir()
	base := filepath.Join(t.TempDir(), "base.toml")
	_ = os.WriteFile(base, []byte(`[assessor]
 model="primary"
 baseUrl="https://primary.invalid"
 [[assessor.fallbacks]]
 model="base"
 baseUrl="https://base.invalid"
 apiKeyEnv="BASE"
 options={temperature=0.1}
 `), 0600)
	_ = os.WriteFile(filepath.Join(cwd, ".aar.toml"), []byte(`[assessor]
 fallbacks=[{model="project",baseUrl="https://project.invalid",apiKeyEnv="PROJECT",options={temperature=0.9},contextWindow=10000}]
 `), 0600)
	t.Setenv("AAR_CONFIG", base)
	config, err := reviewer.ResolveConfig(reviewer.Request{CWD: cwd})
	if err != nil || len(config.Assessor.Fallbacks) != 1 || config.Assessor.Fallbacks[0].Model != "project" || config.Assessor.Fallbacks[0].Options["temperature"] != float64(0.9) {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	config.Assessor.FallbackModels = []string{"legacy"}
	_, err = reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("mixed config err=%v", err)
	}
}

func TestIndependentFallbackStopsAfterValidPolicyDeny(t *testing.T) {
	fake := &fakeModelCall{responses: []string{`{"risks":[{"category":"critical_data_loss","likelihood":"likely","severity":"critical","reversible":false,"affectsProtectedPaths":true,"evidence":"deletes the whole workspace"}],"uncertainties":[]}`}}
	config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "same", BaseURL: "https://primary.invalid", Fallbacks: []reviewer.AssessorConnection{{Model: "same", BaseURL: "https://fallback.invalid", APIKeyEnv: "KEY"}}}}
	decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config, ModelCall: fake})
	if err != nil || decision.Decision != reviewer.DecisionDeny || decision.Source != reviewer.SourceAssessor || len(fake.requests) != 1 {
		t.Fatalf("decision=%#v err=%v requests=%d", decision, err, len(fake.requests))
	}
}

func TestIndependentFallbackRejectsMalformedConnectionBeforeAssessment(t *testing.T) {
	for _, connection := range []reviewer.AssessorConnection{
		{Model: "m", BaseURL: "http://remote.invalid", APIKeyEnv: "KEY"},
		{Model: "m", BaseURL: "https://remote.invalid?token=secret", APIKeyEnv: "KEY"},
		{Model: "m", BaseURL: "https://remote.invalid", APIKeyEnv: "KEY", Options: map[string]any{"api_key": "secret"}},
		{Model: "m", BaseURL: "https://remote.invalid"},
	} {
		fake := &fakeModelCall{}
		config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "m", BaseURL: "https://primary.invalid", Fallbacks: []reviewer.AssessorConnection{connection}}}
		_, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config, ModelCall: fake})
		if err == nil || len(fake.requests) != 0 || strings.Contains(err.Error(), "token=secret") {
			t.Fatalf("err=%v requests=%d", err, len(fake.requests))
		}
	}
}

func TestIndependentFallbackExhaustionUsesConfiguredUnavailable(t *testing.T) {
	for _, responses := range [][]string{{"not json", "not json", "not json", "not json"}, {`{"risks":[]}`, `{"risks":[]}`, `{"risks":[]}`, `{"risks":[]}`}} {
		fake := &fakeModelCall{responses: responses}
		config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "same", BaseURL: "https://primary.invalid", OnUnavailable: "ask", Fallbacks: []reviewer.AssessorConnection{{Model: "same", BaseURL: "https://fallback.invalid", APIKeyEnv: "KEY"}}}}
		decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config, ModelCall: fake})
		if err != nil || decision.Decision != reviewer.DecisionAsk || decision.Source != reviewer.SourceUnavailable || len(fake.requests) != 4 {
			t.Fatalf("decision=%#v err=%v calls=%d", decision, err, len(fake.requests))
		}
	}
}

func TestProviderRedirectCannotForwardCredentialToAnotherEndpoint(t *testing.T) {
	leaked := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true; t.Error("redirect target contacted") }))
	defer target.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer primary.Close()
	t.Setenv("PRIMARY_KEY", "primary-secret")
	config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "m", BaseURL: primary.URL, APIKeyEnv: "PRIMARY_KEY"}}
	decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config})
	if err != nil || decision.Source != reviewer.SourceUnavailable || leaked {
		t.Fatalf("decision=%#v err=%v leaked=%v", decision, err, leaked)
	}
}

type exhaustedDeadlineCall struct{}

func (exhaustedDeadlineCall) Call(ctx context.Context, request reviewer.ModelCallRequest) (string, error) {
	<-ctx.Done()
	return `{"risks":[],"uncertainties":[]}`, nil
}
func TestExpiredAssessmentCannotAuthorizeCommand(t *testing.T) {
	config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "same", BaseURL: "https://primary.invalid", TotalTimeoutMs: 40, OnUnavailable: "ask", Fallbacks: []reviewer.AssessorConnection{{Model: "same", BaseURL: "https://fallback.invalid", APIKeyEnv: "KEY"}}}}
	decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config, ModelCall: exhaustedDeadlineCall{}})
	if err != nil || decision.Decision != reviewer.DecisionAsk || decision.Source != reviewer.SourceUnavailable {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
}
