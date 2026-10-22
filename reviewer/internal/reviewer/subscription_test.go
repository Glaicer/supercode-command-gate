package reviewer_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/Glaicer/supercode-command-gate/reviewer/internal/reviewer"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type subscriptionHTTP func(*http.Request) (*http.Response, error)

func (call subscriptionHTTP) RoundTrip(request *http.Request) (*http.Response, error) {
	return call(request)
}
func codexFixture(t *testing.T, expiry time.Time) string {
	t.Helper()
	claims, _ := json.Marshal(map[string]any{"exp": expiry.Unix()})
	token := "header." + base64.RawURLEncoding.EncodeToString(claims) + ".synthetic-access-secret"
	payload, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": map[string]any{"access_token": token, "refresh_token": "synthetic-refresh-secret", "id_token": "synthetic-id-secret", "account_id": "synthetic-account-secret"}, "unrelated": "preserve"})
	filename := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(filename, payload, 0600); err != nil {
		t.Fatal(err)
	}
	return filename
}
func TestSubscriptionUsesStatelessFixedOriginResponses(t *testing.T) {
	authPath := codexFixture(t, time.Now().Add(time.Hour))
	original := http.DefaultClient
	defer func() { http.DefaultClient = original }()
	http.DefaultClient = &http.Client{Transport: subscriptionHTTP(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://chatgpt.com/backend-api/codex/responses" {
			t.Errorf("unsafe endpoint %s", request.URL)
		}
		if !strings.HasSuffix(request.Header.Get("Authorization"), "synthetic-access-secret") || request.Header.Get("ChatGPT-Account-ID") != "synthetic-account-secret" {
			t.Error("missing subscription auth")
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["store"] != false || body["stream"] != true || body["tool_choice"] != "none" || body["previous_response_id"] != nil || len(body["tools"].([]any)) != 0 {
			t.Errorf("non-stateless body %v", body)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"{\\\"risks\\\":[],\\\"uncertainties\\\":[]}\"}]}]}}\n\n")), Header: http.Header{"Content-Type": []string{"text/event-stream"}}}, nil
	})}
	config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "gpt-6-luna", AuthMode: "codex", AuthJSONPath: authPath}}
	decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config})
	if err != nil || decision.Decision != reviewer.DecisionAllow || decision.Source != reviewer.SourceAssessor {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
}

func TestSubscriptionDoctorRejectsExpiryThenReloadsOwnerRefreshedFile(t *testing.T) {
	authPath := codexFixture(t, time.Now().Add(-time.Minute))
	config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "gpt-6-luna", AuthMode: "codex", AuthJSONPath: authPath}}
	options := reviewer.Options{StateDir: t.TempDir(), Config: &config}
	_, err := reviewer.Doctor(assessorRequest(t, "touch ./output"), options)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expiry err=%v", err)
	}
	fresh := codexFixture(t, time.Now().Add(time.Hour))
	data, _ := os.ReadFile(fresh)
	if err := os.WriteFile(authPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	original := http.DefaultClient
	defer func() { http.DefaultClient = original }()
	http.DefaultClient = &http.Client{Transport: subscriptionHTTP(func(*http.Request) (*http.Response, error) {
		t.Error("doctor attempted network")
		return nil, context.Canceled
	})}
	report, err := reviewer.Doctor(assessorRequest(t, "touch ./output"), options)
	if err != nil || report.Status != "ok" || !report.Connections[0].CredentialAvailable {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	after, _ := os.ReadFile(authPath)
	if string(after) != string(data) {
		t.Error("doctor modified owner credentials")
	}
}

func TestSubscriptionFailuresNeverAllowOrExposeCredentials(t *testing.T) {
	for _, status := range []int{401, 403, 429, 500, 307} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			authPath := codexFixture(t, time.Now().Add(time.Hour))
			original := http.DefaultClient
			defer func() { http.DefaultClient = original }()
			http.DefaultClient = &http.Client{Transport: subscriptionHTTP(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("synthetic-access-secret synthetic-refresh-secret synthetic-account-secret")), Header: http.Header{"Location": []string{"https://evil.invalid"}}}, nil
			})}
			config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "gpt-6-luna", AuthMode: "codex", AuthJSONPath: authPath, OnUnavailable: "ask"}}
			stateDir := t.TempDir()
			decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: stateDir, Config: &config})
			if err != nil || decision.Decision != reviewer.DecisionAsk || decision.Source != reviewer.SourceUnavailable {
				t.Fatalf("decision=%#v err=%v", decision, err)
			}
			payload, _ := json.Marshal(decision)
			audit, _ := os.ReadFile(filepath.Join(stateDir, "audit", decision.AuditID+".json"))
			logs, _ := json.Marshal(readReviewLog(t, stateDir))
			for _, secret := range []string{"synthetic-access-secret", "synthetic-refresh-secret", "synthetic-id-secret", "synthetic-account-secret", "Authorization", "evil.invalid"} {
				if strings.Contains(string(payload)+string(audit)+string(logs), secret) {
					t.Fatalf("credential exposed: %s", secret)
				}
			}
		})
	}
}

func TestSubscriptionRejectsUnsafeOrMalformedConfig(t *testing.T) {
	authPath := codexFixture(t, time.Now().Add(time.Hour))
	for _, assessor := range []reviewer.AssessorConfig{
		{Model: "m", AuthMode: "codex", AuthJSONPath: authPath, BaseURL: "https://evil.invalid"},
		{Model: "m", AuthMode: "codex", AuthJSONPath: authPath, APIKeyEnv: "KEY"},
		{Model: "m", AuthMode: "codex", AuthJSONPath: authPath, Fallbacks: []reviewer.AssessorConnection{{Model: "m", BaseURL: "https://paid.invalid", APIKeyEnv: "KEY"}}},
		{Model: "m", AuthMode: "codex", AuthJSONPath: authPath, Options: map[string]any{"tools": []any{"shell"}}},
		{Model: "m", AuthMode: "codex", AuthJSONPath: "relative.json"},
	} {
		_, err := reviewer.Doctor(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &reviewer.Config{Assessor: assessor}})
		if err == nil {
			t.Fatalf("unsafe config accepted: %#v", assessor)
		}
	}
}

func TestSubscriptionRefusesIncompleteAndMalformedStreams(t *testing.T) {
	for _, stream := range []string{
		"data: not-json\n\n",
		"data: {\"type\":\"response.output_text.delta\",\"delta\":\"{\\\"risks\\\":[],\\\"uncertainties\\\":[]}\"}\n\n",
		"data: {\"type\":\"response.failed\",\"error\":\"synthetic-access-secret\"}\n\n",
		"data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"function_call\"}]}}\n\n",
	} {
		authPath := codexFixture(t, time.Now().Add(time.Hour))
		original := http.DefaultClient
		http.DefaultClient = &http.Client{Transport: subscriptionHTTP(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(stream)), Header: http.Header{}}, nil
		})}
		config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "gpt-6-luna", AuthMode: "codex", AuthJSONPath: authPath}}
		decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config})
		http.DefaultClient = original
		if err != nil || decision.Decision != reviewer.DecisionDeny || decision.Source != reviewer.SourceUnavailable {
			t.Fatalf("decision=%#v err=%v", decision, err)
		}
	}
}

func TestSubscriptionRejectsCredentialMaterialInAssessment(t *testing.T) {
	authPath := codexFixture(t, time.Now().Add(time.Hour))
	original := http.DefaultClient
	defer func() { http.DefaultClient = original }()
	text := `{"risks":[],"uncertainties":["synthetic-refresh-secret"]}`
	event, _ := json.Marshal(map[string]any{"type": "response.completed", "response": map[string]any{"status": "completed", "output": []any{map[string]any{"type": "message", "content": []any{map[string]any{"type": "output_text", "text": text}}}}}})
	http.DefaultClient = &http.Client{Transport: subscriptionHTTP(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("data: " + string(event) + "\n\n")), Header: http.Header{}}, nil
	})}
	config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "gpt-6-luna", AuthMode: "codex", AuthJSONPath: authPath}}
	stateDir := t.TempDir()
	decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: stateDir, Config: &config})
	if err != nil || decision.Source != reviewer.SourceUnavailable {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
	records, _ := json.Marshal(readReviewLog(t, stateDir))
	if strings.Contains(string(records), "synthetic-refresh-secret") {
		t.Fatal("stream exposed credential to logs")
	}
}

func TestSubscriptionParallelDoctorsKeepOwnerCredentialsUnchanged(t *testing.T) {
	authPath := codexFixture(t, time.Now().Add(time.Hour))
	before, _ := os.ReadFile(authPath)
	config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "gpt-6-luna", AuthMode: "codex", AuthJSONPath: authPath}}
	request := assessorRequest(t, "touch ./output")
	results := make(chan error, 6)
	for i := 0; i < 6; i++ {
		stateDir := t.TempDir()
		go func() {
			_, err := reviewer.Doctor(request, reviewer.Options{StateDir: stateDir, Config: &config})
			results <- err
		}()
	}
	for i := 0; i < 6; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	after, _ := os.ReadFile(authPath)
	if string(before) != string(after) {
		t.Fatal("parallel readers modified owner credentials")
	}
}

func TestSubscriptionDoctorRejectsMissingMalformedAndPublicCredentials(t *testing.T) {
	root := t.TempDir()
	fixtures := []string{filepath.Join(root, "missing.json")}
	for i, payload := range []string{"not-json", `{"auth_mode":"api_key","OPENAI_API_KEY":"synthetic-secret"}`, `{"auth_mode":"chatgpt","tokens":{}}`} {
		filename := filepath.Join(root, string(rune('a'+i))+".json")
		_ = os.WriteFile(filename, []byte(payload), 0600)
		fixtures = append(fixtures, filename)
	}
	public := codexFixture(t, time.Now().Add(time.Hour))
	_ = os.Chmod(public, 0644)
	fixtures = append(fixtures, public)
	for _, filename := range fixtures {
		config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "gpt-6-luna", AuthMode: "codex", AuthJSONPath: filename}}
		_, err := reviewer.Doctor(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config})
		if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatalf("unsafe doctor result err=%v", err)
		}
	}
}

func TestSubscriptionReloadsOwnerFileBetweenAuthenticationRetries(t *testing.T) {
	authPath := codexFixture(t, time.Now().Add(time.Hour))
	fresh := codexFixture(t, time.Now().Add(2*time.Hour))
	updated, _ := os.ReadFile(fresh)
	first, _ := os.ReadFile(authPath)
	original := http.DefaultClient
	defer func() { http.DefaultClient = original }()
	calls := 0
	http.DefaultClient = &http.Client{Transport: subscriptionHTTP(func(request *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			if err := os.WriteFile(authPath, updated, 0600); err != nil {
				t.Fatal(err)
			}
			return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
		}
		var credentials struct {
			Tokens struct {
				AccessToken string `json:"access_token"`
			} `json:"tokens"`
		}
		_ = json.Unmarshal(updated, &credentials)
		if request.Header.Get("Authorization") != "Bearer "+credentials.Tokens.AccessToken {
			t.Error("retry used cached token")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("data: {\"type\":\"response.output_text.delta\",\"delta\":\"{\\\"risks\\\":[],\\\"uncertainties\\\":[]}\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}\n\n")), Header: http.Header{}}, nil
	})}
	config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "gpt-6-luna", AuthMode: "codex", AuthJSONPath: authPath}}
	decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config})
	if err != nil || decision.Source != reviewer.SourceAssessor || decision.Decision != reviewer.DecisionAllow || calls != 2 {
		t.Fatalf("decision=%#v err=%v calls=%d", decision, err, calls)
	}
	after, _ := os.ReadFile(authPath)
	if string(after) != string(updated) || string(first) == string(updated) {
		t.Fatal("updated owner credentials were not preserved")
	}
}

func TestSubscriptionConfigParsesExplicitAuthSelection(t *testing.T) {
	authPath := codexFixture(t, time.Now().Add(time.Hour))
	filename := filepath.Join(t.TempDir(), "config.toml")
	source := "[assessor]\nmodel=\"gpt-6-luna\"\nauthMode=\"codex\"\nauthJsonPath=\"" + authPath + "\"\noptions={reasoning={effort=\"none\"}}\n"
	_ = os.WriteFile(filename, []byte(source), 0600)
	t.Setenv("AAR_CONFIG", filename)
	config, err := reviewer.ResolveConfig(reviewer.Request{CWD: t.TempDir()})
	if err != nil || config.Assessor.AuthMode != "codex" || config.Assessor.AuthJSONPath != authPath || config.Assessor.APIKeyEnv != "" {
		t.Fatalf("config=%#v err=%v", config, err)
	}
}
