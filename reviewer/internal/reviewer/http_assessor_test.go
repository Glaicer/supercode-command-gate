package reviewer_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/supercode/auto-approval-reviewer/internal/reviewer"
)

func TestHTTPAssessorUsesOpenAICompatibleEndpointAndDoesNotLeakKey(t *testing.T) {
	const secret = "test-api-key-never-in-body"
	var received map[string]any
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		authorization = request.Header.Get("Authorization")
		if request.URL.Path != "/v1/chat/completions" {
			t.Errorf("path = %q, want /v1/chat/completions", request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Errorf("decode request: %v", err)
		}
		payload := `{"choices":[{"message":{"content":"{\"risks\":[],\"uncertainties\":[]}"}}]}`
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(payload))
	}))
	defer server.Close()
	t.Setenv("AAR_TEST_API_KEY", secret)

	stateDir := t.TempDir()
	request := assessorRequest(t, "touch ./output")
	decision, err := reviewer.Check(request, reviewer.Options{
		StateDir: stateDir,
		Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{
			Model:         "primary",
			BaseURL:       server.URL + "/v1",
			APIKeyEnv:     "AAR_TEST_API_KEY",
			OnUnavailable: "deny",
		}},
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAllow || decision.Source != reviewer.SourceAssessor {
		t.Fatalf("decision = %#v, want HTTP assessor allow", decision)
	}
	if authorization != "Bearer "+secret {
		t.Fatalf("Authorization = %q, want bearer key", authorization)
	}
	encoded, err := json.Marshal(received)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("request body leaked API key: %s", encoded)
	}
	audit, err := os.ReadFile(filepath.Join(stateDir, "audit", decision.AuditID+".json"))
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if strings.Contains(string(audit), secret) {
		t.Fatalf("audit leaked API key: %s", audit)
	}
}

func TestHTTPAssessorRetriesMalformedResponsesThenUsesFallback(t *testing.T) {
	responses := []string{
		"prose wrapped response",
		`{"risks":[],"uncertainties":[1]}`,
		`{"risks":[],"uncertainties":[]}`,
	}
	models := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var payload struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		models = append(models, payload.Model)
		index := len(models) - 1
		if index >= len(responses) {
			index = len(responses) - 1
		}
		body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": responses[index]}}}})
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(body)
	}))
	defer server.Close()

	decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{
		StateDir: t.TempDir(),
		Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{
			Model:          "primary",
			FallbackModels: []string{"fallback"},
			BaseURL:        server.URL,
			OnUnavailable:  "deny",
		}},
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAllow || decision.Source != reviewer.SourceAssessor {
		t.Fatalf("decision = %#v, want fallback allow", decision)
	}
	if strings.Join(models, ",") != "primary,primary,fallback" {
		t.Fatalf("model order = %v, want primary,primary,fallback", models)
	}
}

func TestHTTPAssessorContextCapacitySkipsToFallback(t *testing.T) {
	models := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var payload struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		models = append(models, payload.Model)
		response.Header().Set("Content-Type", "application/json")
		if len(models) == 1 {
			response.WriteHeader(http.StatusBadRequest)
			_, _ = response.Write([]byte(`{"error":{"message":"maximum context length exceeded"}}`))
			return
		}
		_, _ = response.Write([]byte(`{"choices":[{"message":{"content":"{\"risks\":[],\"uncertainties\":[]}"}}]}`))
	}))
	defer server.Close()

	decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{
		StateDir: t.TempDir(),
		Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{
			Model:          "primary",
			FallbackModels: []string{"fallback"},
			BaseURL:        server.URL,
			OnUnavailable:  "deny",
		}},
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAllow || decision.Source != reviewer.SourceAssessor {
		t.Fatalf("decision = %#v, want fallback assessor allow", decision)
	}
	if strings.Join(models, ",") != "primary,fallback" {
		t.Fatalf("model order = %v, want one primary context failure then fallback", models)
	}
}

func TestHTTPAssessorTimeoutUsesOnUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = response.Write([]byte(`{"choices":[{"message":{"content":"{\"risks\":[],\"uncertainties\":[]}"}}]}`))
	}))
	defer server.Close()

	decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{
		StateDir: t.TempDir(),
		Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{
			Model:          "primary",
			BaseURL:        server.URL,
			TotalTimeoutMs: 5,
			OnUnavailable:  "ask",
		}},
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAsk || decision.Source != reviewer.SourceUnavailable {
		t.Fatalf("decision = %#v, want timeout ask", decision)
	}
}

func TestHTTPAssessorRejectsPublicPlaintextEndpoint(t *testing.T) {
	decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{
		StateDir: t.TempDir(),
		Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{
			Model:         "primary",
			BaseURL:       "http://model.example.test/v1",
			OnUnavailable: "ask",
		}},
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAsk || decision.Source != reviewer.SourceUnavailable {
		t.Fatalf("decision = %#v, want unavailable ask for public plaintext", decision)
	}
}
