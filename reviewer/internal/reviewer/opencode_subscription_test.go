package reviewer_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/supercode/auto-approval-reviewer/internal/reviewer"
)

func openCodeAuthFixture(t *testing.T, expiry time.Time, payloadOverride string) string {
	t.Helper()
	claims, _ := json.Marshal(map[string]any{"exp": expiry.Unix()})
	token := "header." + base64.RawURLEncoding.EncodeToString(claims) + ".opencode-access-secret"
	payload, _ := json.Marshal([]any{
		map[string]any{"id": "inactive", "integrationID": "openai", "active": false, "value": map[string]any{"type": "oauth", "methodID": "chatgpt-browser", "access": "inactive-secret"}},
		map[string]any{"id": "other", "integrationID": "anthropic", "active": true, "value": map[string]any{"type": "key", "key": "other-provider-secret"}},
		map[string]any{"id": "active", "integrationID": "openai", "active": true, "value": map[string]any{"type": "oauth", "methodID": "chatgpt-browser", "access": token, "refresh": "opencode-refresh-secret", "expires": expiry.UnixMilli(), "metadata": map[string]any{"accountID": "opencode-account-secret"}}},
	})
	if payloadOverride != "" {
		payload = []byte(payloadOverride)
	}
	root := t.TempDir()
	auth := filepath.Join(root, "owner-export.json")
	if err := os.WriteFile(auth, payload, 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "opencode")
	script := "#!/bin/sh\n[ \"$#\" = 2 ] && [ \"$1\" = auth ] && [ \"$2\" = export ] || exit 2\ncat '" + auth + "'\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENCODE_BIN", binary)
	return auth
}

func TestOpenCodeSubscriptionSelectsActiveOAuthAndReloadsOwner(t *testing.T) {
	auth := openCodeAuthFixture(t, time.Now().Add(time.Hour), "")
	before, _ := os.ReadFile(auth)
	original := http.DefaultClient
	defer func() { http.DefaultClient = original }()
	calls := 0
	http.DefaultClient = &http.Client{Transport: subscriptionHTTP(func(req *http.Request) (*http.Response, error) {
		calls++
		expected := "opencode-access-secret"
		if calls > 1 {
			expected += "-renewed"
		}
		if req.URL.String() != "https://chatgpt.com/backend-api/codex/responses" || !strings.HasSuffix(req.Header.Get("Authorization"), expected) || req.Header.Get("ChatGPT-Account-ID") != "opencode-account-secret" {
			t.Error("wrong active OpenCode auth")
		}
		if calls == 1 {
			updated := strings.ReplaceAll(string(before), "opencode-access-secret", "opencode-access-secret-renewed")
			if err := os.WriteFile(auth, []byte(updated), 0600); err != nil {
				t.Fatal(err)
			}
			return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("opencode-refresh-secret")), Header: http.Header{}}, nil
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"{\\\"risks\\\":[],\\\"uncertainties\\\":[]}\"}]}]}}\n\n")), Header: http.Header{}}, nil
	})}
	config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "gpt-6-luna", AuthMode: "opencode"}}
	state := t.TempDir()
	decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: state, Config: &config})
	if err != nil || decision.Source != reviewer.SourceAssessor || calls != 2 {
		t.Fatalf("decision=%#v err=%v calls=%d", decision, err, calls)
	}
	after, _ := os.ReadFile(auth)
	if string(after) != strings.ReplaceAll(string(before), "opencode-access-secret", "opencode-access-secret-renewed") {
		t.Fatal("AAR modified owner export")
	}
	audit, _ := reviewer.Explain(decision.AuditID, reviewer.Options{StateDir: state})
	logs, _ := json.Marshal(readReviewLog(t, state))
	for _, secret := range []string{"opencode-access-secret", "opencode-refresh-secret", "opencode-account-secret", "inactive-secret", "other-provider-secret"} {
		if strings.Contains(string(audit)+string(logs), secret) {
			t.Fatalf("credential leaked: %s", secret)
		}
	}
}

func TestOpenCodeSubscriptionDoctorRejectsUnusableOwnerWithoutProviderCalls(t *testing.T) {
	original := http.DefaultClient
	defer func() { http.DefaultClient = original }()
	http.DefaultClient = &http.Client{Transport: subscriptionHTTP(func(*http.Request) (*http.Response, error) {
		t.Fatal("doctor contacted a provider")
		return nil, nil
	})}
	for _, payload := range []string{"[]", "not-json", `[{"integrationID":"openai","active":true,"value":{"type":"key","key":"synthetic-secret"}}]`, `[{"integrationID":"openai","active":true,"value":{"type":"oauth","methodID":"other","access":"synthetic-secret"}}]`} {
		t.Run(payload, func(t *testing.T) {
			openCodeAuthFixture(t, time.Now().Add(time.Hour), payload)
			config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "gpt-6-luna", AuthMode: "opencode"}}
			_, err := reviewer.Doctor(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config})
			if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatalf("unusable owner accepted or leaked: %v", err)
			}
		})
	}
	openCodeAuthFixture(t, time.Now().Add(-time.Minute), "")
	config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "gpt-6-luna", AuthMode: "opencode"}}
	_, err := reviewer.Doctor(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expiry: %v", err)
	}
}

func TestOpenCodeSubscriptionCLIIsBoundedAndSanitized(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		timeout      int
	}{
		{"failed export", "printf 'synthetic-secret' >&2; exit 1", 1000},
		{"oversized export", "head -c 1048577 /dev/zero", 1000},
		{"deadline", "exec sleep 30", 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			openCodeAuthFixture(t, time.Now().Add(time.Hour), "")
			if err := os.WriteFile(os.Getenv("OPENCODE_BIN"), []byte("#!/bin/sh\n"+tc.script+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "gpt-6-luna", AuthMode: "opencode", TotalTimeoutMs: tc.timeout}}
			started := time.Now()
			_, err := reviewer.Doctor(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config})
			if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatalf("CLI failure accepted or leaked: %v", err)
			}
			if time.Since(started) > 2*time.Second {
				t.Fatal("CLI exceeded bounded deadline")
			}
		})
	}
}

func TestOpenCodeSubscriptionConfigAndDoctorUseOwner(t *testing.T) {
	auth := openCodeAuthFixture(t, time.Now().Add(time.Hour), "")
	filename := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(filename, []byte("[assessor]\nmodel=\"gpt-6-luna\"\nauthMode=\"opencode\"\noptions={reasoning={effort=\"none\"}}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAR_CONFIG", filename)
	request := assessorRequest(t, "touch ./output")
	config, err := reviewer.ResolveConfig(request)
	if err != nil || config.Assessor.AuthMode != "opencode" || config.Assessor.AuthJSONPath != "" {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	before, _ := os.ReadFile(auth)
	original := http.DefaultClient
	defer func() { http.DefaultClient = original }()
	http.DefaultClient = &http.Client{Transport: subscriptionHTTP(func(*http.Request) (*http.Response, error) {
		t.Fatal("doctor contacted a provider")
		return nil, nil
	})}
	report, err := reviewer.Doctor(request, reviewer.Options{StateDir: t.TempDir(), Config: &config})
	if err != nil || report.Status != "ok" || len(report.Connections) != 1 || !report.Connections[0].CredentialAvailable {
		t.Fatalf("doctor=%#v err=%v", report, err)
	}
	after, _ := os.ReadFile(auth)
	if string(before) != string(after) {
		t.Fatal("doctor changed owner credentials")
	}
	var entries []map[string]any
	if err := json.Unmarshal(before, &entries); err != nil {
		t.Fatal(err)
	}
	entries = append(entries, entries[len(entries)-1])
	duplicated, _ := json.Marshal(entries)
	if err := os.WriteFile(auth, duplicated, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = reviewer.Doctor(request, reviewer.Options{StateDir: t.TempDir(), Config: &config})
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous active credentials: %v", err)
	}
}

func TestOpenCodeSubscriptionRejectsForeignTransportConfiguration(t *testing.T) {
	for _, assessor := range []reviewer.AssessorConfig{
		{Model: "m", AuthMode: "opencode", AuthJSONPath: "/synthetic/auth.json"},
		{Model: "m", AuthMode: "opencode", BaseURL: "https://foreign.invalid"},
		{Model: "m", AuthMode: "opencode", APIKeyEnv: "KEY"},
		{Model: "m", AuthMode: "opencode", Options: map[string]any{"tools": []any{"shell"}}},
	} {
		config := reviewer.Config{Assessor: assessor}
		_, err := reviewer.Doctor(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config})
		if err == nil {
			t.Fatal("foreign subscription configuration accepted")
		}
	}
}

func TestOpenCodeSubscriptionExplicitAPIFallback(t *testing.T) {
	for _, mode := range []string{"expired", "rejected", "valid"} {
		t.Run(mode, func(t *testing.T) {
			expiry := time.Now().Add(time.Hour)
			if mode == "expired" {
				expiry = time.Now().Add(-time.Minute)
			}
			openCodeAuthFixture(t, expiry, "")
			t.Setenv("SYNTHETIC_HYPER_KEY", "hyper-secret")
			original := http.DefaultClient
			defer func() { http.DefaultClient = original }()
			primary, fallback := 0, 0
			http.DefaultClient = &http.Client{Transport: subscriptionHTTP(func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "chatgpt.com" {
					primary++
					if strings.Contains(req.Header.Get("Authorization"), "hyper-secret") {
						t.Fatal("Hyper credential reached subscription")
					}
					if mode == "rejected" {
						return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
					}
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"{\\\"risks\\\":[],\\\"uncertainties\\\":[]}\"}]}]}}\n\n")), Header: http.Header{}}, nil
				}
				fallback++
				if req.URL.String() != "https://hyper.example/v1/chat/completions" || req.Header.Get("Authorization") != "Bearer hyper-secret" || req.Header.Get("ChatGPT-Account-ID") != "" {
					t.Fatal("mixed provider credentials")
				}
				var body map[string]any
				if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body["model"] != "glm-5.3-flash" || body["reasoning"] != nil {
					t.Fatal("fallback inherited primary settings")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"choices":[{"message":{"content":"{\"risks\":[],\"uncertainties\":[]}"}}]}`)), Header: http.Header{}}, nil
			})}
			config := reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "gpt-6-luna", AuthMode: "opencode", Options: map[string]any{"reasoning": map[string]any{"effort": "none"}}, Fallbacks: []reviewer.AssessorConnection{{Model: "glm-5.3-flash", BaseURL: "https://hyper.example/v1", APIKeyEnv: "SYNTHETIC_HYPER_KEY"}}}}
			report, err := reviewer.Doctor(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config})
			if err != nil || len(report.Connections) != 2 || !report.Connections[1].CredentialAvailable {
				t.Fatalf("doctor=%#v err=%v", report, err)
			}
			decision, err := reviewer.Check(assessorRequest(t, "touch ./output"), reviewer.Options{StateDir: t.TempDir(), Config: &config})
			if err != nil || decision.Source != reviewer.SourceAssessor || decision.Decision != reviewer.DecisionAllow {
				t.Fatalf("decision=%#v err=%v", decision, err)
			}
			if mode == "valid" && (primary != 1 || fallback != 0) {
				t.Fatalf("valid assessment did not stop chain: %d/%d", primary, fallback)
			}
			if mode != "valid" && fallback != 1 {
				t.Fatalf("missing explicit fallback: %d", fallback)
			}
		})
	}
}
