package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/supercode/auto-approval-reviewer/internal/reviewer"
)

func TestCLICheckMatchesGoldenProtocol(t *testing.T) {
	root := moduleRoot(t)
	goBinary := goBinary()
	compiled := filepath.Join(t.TempDir(), "aar")
	build := exec.Command(goBinary, "build", "-o", compiled, "./cmd/aar")
	build.Dir = root
	build.Env = append(os.Environ(), "GOCACHE="+testGoCache(t), "GOMODCACHE="+moduleCache())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build aar: %v\n%s", err, output)
	}

	for _, name := range []string{"pwd", "unknown"} {
		t.Run(name, func(t *testing.T) {
			request := mustRead(t, filepath.Join(root, "cmd", "aar", "testdata", name+"-request.json"))
			golden := strings.TrimSpace(string(mustRead(t, filepath.Join(root, "cmd", "aar", "testdata", name+"-response.json"))))
			stateDir := t.TempDir()
			command := exec.Command(compiled, "check")
			command.Dir = root
			command.Env = append(os.Environ(), "AAR_STATE_DIR="+stateDir)
			command.Stdin = bytes.NewReader(request)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("aar check: %v\n%s", err, output)
			}
			if strings.Count(string(output), "\n") != 1 {
				t.Fatalf("want exactly one JSON output line, got %q", output)
			}
			var actual map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(output), &actual); err != nil {
				t.Fatalf("decode decision: %v", err)
			}
			actual["auditId"] = "__audit_id__"
			actual["requestFingerprint"] = "__request_fingerprint__"
			encoded, err := json.Marshal(actual)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != golden {
				t.Fatalf("golden mismatch\nwant: %s\n got: %s", golden, encoded)
			}
		})
	}

	doctorState := t.TempDir()
	doctor := exec.Command(compiled, "doctor")
	doctor.Dir = root
	doctor.Env = append(os.Environ(), "AAR_STATE_DIR="+doctorState)
	doctorOutput, err := doctor.CombinedOutput()
	if err != nil {
		t.Fatalf("aar doctor: %v\n%s", err, doctorOutput)
	}
	var report map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(doctorOutput), &report); err != nil {
		t.Fatalf("decode doctor report: %v", err)
	}
	if report["schemaVersion"] != "aar-doctor-v1" || report["status"] != "ok" {
		t.Fatalf("doctor report = %#v, want healthy aar-doctor-v1 report", report)
	}
}

func TestCLIGrantRoundTripAcrossProcesses(t *testing.T) {
	root := moduleRoot(t)
	compiled := filepath.Join(t.TempDir(), "aar")
	build := exec.Command(goBinary(), "build", "-o", compiled, "./cmd/aar")
	build.Dir = root
	build.Env = append(os.Environ(), "GOCACHE="+testGoCache(t), "GOMODCACHE="+moduleCache())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build aar: %v\n%s", err, output)
	}

	stateDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(configPath, []byte("[assessor]\nonUnavailable = \"ask\"\n"), 0o600); err != nil {
		t.Fatalf("write ask config: %v", err)
	}
	cwd := t.TempDir()
	request := fmt.Sprintf(`{"schemaVersion":"aar-request-v1","command":"touch ./output","cwd":%q,"workspaceRoot":null,"env":{},"session":{"id":"cross-process","host":"test","intentId":"intent-1"},"intent":{"goal":"test grants","latestUserRequest":"test grants","purpose":null}}`, cwd)
	run := func(args ...string) ([]byte, error) {
		command := exec.Command(compiled, args...)
		command.Dir = root
		command.Env = append(os.Environ(), "AAR_STATE_DIR="+stateDir, "AAR_CONFIG="+configPath)
		command.Stdin = bytes.NewBufferString(request)
		return command.CombinedOutput()
	}

	initialOutput, err := run("check")
	if err != nil {
		t.Fatalf("initial aar check: %v\n%s", err, initialOutput)
	}
	var initial map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(initialOutput), &initial); err != nil {
		t.Fatalf("decode initial decision: %v", err)
	}
	if initial["decision"] != reviewer.DecisionAsk {
		t.Fatalf("initial decision = %#v, want ask", initial["decision"])
	}
	fingerprint, ok := initial["requestFingerprint"].(string)
	if !ok || fingerprint == "" {
		t.Fatalf("initial fingerprint = %#v", initial["requestFingerprint"])
	}

	if output, err := run("grant", "--session", "cross-process", "--fingerprint", "unreserved", "--scope", "once"); err == nil {
		t.Fatalf("unreserved grant succeeded: %s", output)
	}
	if output, err := run("grant", "--session", "cross-process", "--fingerprint", fingerprint, "--scope", "once"); err != nil {
		t.Fatalf("grant action: %v\n%s", err, output)
	}

	retryOutput, err := run("check")
	if err != nil {
		t.Fatalf("granted aar check: %v\n%s", err, retryOutput)
	}
	var retry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(retryOutput), &retry); err != nil {
		t.Fatalf("decode granted decision: %v", err)
	}
	if retry["decision"] != reviewer.DecisionAllow || retry["source"] != reviewer.SourceGrant || retry["grantScope"] != reviewer.GrantScopeOnce {
		t.Fatalf("granted decision = %#v, want one-use grant allow", retry)
	}

	secondOutput, err := run("check")
	if err != nil {
		t.Fatalf("second aar check: %v\n%s", err, secondOutput)
	}
	var second map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(secondOutput), &second); err != nil {
		t.Fatalf("decode second decision: %v", err)
	}
	if second["decision"] != reviewer.DecisionAsk || second["source"] != reviewer.SourceUnavailable {
		t.Fatalf("second decision = %#v, want fresh unavailable ask", second)
	}
}

func TestCLISessionGrantAndInvalidationAcrossProcesses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"choices":[{"message":{"content":"{\"risks\":[{\"category\":\"privilege\",\"likelihood\":\"likely\",\"severity\":\"critical\",\"reversible\":false,\"affectsProtectedPaths\":false,\"evidence\":\"requires elevated authority\"}],\"uncertainties\":[]}"}}]}`))
	}))
	defer server.Close()

	root := moduleRoot(t)
	compiled := filepath.Join(t.TempDir(), "aar")
	build := exec.Command(goBinary(), "build", "-o", compiled, "./cmd/aar")
	build.Dir = root
	build.Env = append(os.Environ(), "GOCACHE="+testGoCache(t), "GOMODCACHE="+moduleCache())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build aar: %v\n%s", err, output)
	}

	stateDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.toml")
	config := fmt.Sprintf("[assessor]\nmodel = \"test\"\nbaseUrl = \"%s/v1\"\nonUnavailable = \"ask\"\n[policy]\nprofile = \"balanced\"\n[grants]\nsessionTrust = true\n", server.URL)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write assessor config: %v", err)
	}
	cwd := t.TempDir()
	requestFor := func(intentID string) string {
		return fmt.Sprintf(`{"schemaVersion":"aar-request-v1","command":"touch ./output","cwd":%q,"workspaceRoot":null,"env":{},"session":{"id":"cross-session","host":"test","intentId":%q},"intent":{"goal":"test grants","latestUserRequest":"test grants","purpose":null}}`, cwd, intentID)
	}
	run := func(input string, args ...string) ([]byte, error) {
		command := exec.Command(compiled, args...)
		command.Dir = root
		command.Env = append(os.Environ(), "AAR_STATE_DIR="+stateDir, "AAR_CONFIG="+configPath)
		command.Stdin = bytes.NewBufferString(input)
		return command.CombinedOutput()
	}
	check := func(input string) map[string]any {
		output, err := run(input, "check")
		if err != nil {
			t.Fatalf("aar check: %v\n%s", err, output)
		}
		var decision map[string]any
		if err := json.Unmarshal(bytes.TrimSpace(output), &decision); err != nil {
			t.Fatalf("decode decision: %v", err)
		}
		return decision
	}
	grant := func(decision map[string]any) {
		fingerprint, ok := decision["requestFingerprint"].(string)
		if !ok || fingerprint == "" {
			t.Fatalf("decision fingerprint = %#v", decision["requestFingerprint"])
		}
		if output, err := run("", "grant", "--session", "cross-session", "--fingerprint", fingerprint, "--scope", "session"); err != nil {
			t.Fatalf("session grant: %v\n%s", err, output)
		}
	}

	initial := check(requestFor("intent-1"))
	if initial["decision"] != reviewer.DecisionAsk || initial["source"] != reviewer.SourceAssessor || initial["grantEligible"] != true {
		t.Fatalf("initial decision = %#v, want eligible assessor ask", initial)
	}
	grant(initial)
	reused := check(requestFor("intent-1"))
	if reused["decision"] != reviewer.DecisionAllow || reused["source"] != reviewer.SourceGrant || reused["grantScope"] != reviewer.GrantScopeSession {
		t.Fatalf("reused decision = %#v, want session grant allow", reused)
	}

	changedIntent := check(requestFor("intent-2"))
	if changedIntent["decision"] != reviewer.DecisionAsk || changedIntent["source"] != reviewer.SourceAssessor {
		t.Fatalf("intent-mismatch decision = %#v, want fresh assessor ask", changedIntent)
	}
	for _, event := range []string{"end", "clear", "new-intent", "goal-change"} {
		fresh := check(requestFor("intent-1"))
		if fresh["decision"] != reviewer.DecisionAsk || fresh["source"] != reviewer.SourceAssessor {
			t.Fatalf("before %s decision = %#v, want fresh assessor ask", event, fresh)
		}
		grant(fresh)
		if output, err := run("", "session-event", "--session", "cross-session", "--event", event); err != nil {
			t.Fatalf("session-event %s: %v\n%s", event, err, output)
		}
		invalidated := check(requestFor("intent-1"))
		if invalidated["decision"] != reviewer.DecisionAsk || invalidated["source"] != reviewer.SourceAssessor {
			t.Fatalf("after %s decision = %#v, want fresh assessor ask", event, invalidated)
		}
	}
}

func TestCLIExplainPrintsSecretSafeAuditRecord(t *testing.T) {
	root := moduleRoot(t)
	compiled := filepath.Join(t.TempDir(), "aar")
	build := exec.Command(goBinary(), "build", "-o", compiled, "./cmd/aar")
	build.Dir = root
	build.Env = append(os.Environ(), "GOCACHE="+testGoCache(t), "GOMODCACHE="+moduleCache())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build aar: %v\n%s", err, output)
	}

	stateDir := t.TempDir()
	request := `{"schemaVersion":"aar-request-v1","command":"echo password=cli-secret","cwd":"` + filepath.ToSlash(t.TempDir()) + `","workspaceRoot":null,"env":{},"session":{"id":"explain-session","host":"test","intentId":"intent-1"},"intent":{"goal":"inspect","latestUserRequest":"inspect","purpose":null}}`
	check := exec.Command(compiled, "check")
	check.Dir = root
	check.Env = append(os.Environ(), "AAR_STATE_DIR="+stateDir)
	check.Stdin = strings.NewReader(request)
	output, err := check.CombinedOutput()
	if err != nil {
		t.Fatalf("aar check: %v\n%s", err, output)
	}
	var decision map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output), &decision); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	auditID, ok := decision["auditId"].(string)
	if !ok || auditID == "" {
		t.Fatalf("audit id = %#v", decision["auditId"])
	}

	explain := exec.Command(compiled, "explain", "--audit-id", auditID)
	explain.Dir = root
	explain.Env = append(os.Environ(), "AAR_STATE_DIR="+stateDir)
	explained, err := explain.CombinedOutput()
	if err != nil {
		t.Fatalf("aar explain: %v\n%s", err, explained)
	}
	if strings.Contains(string(explained), "cli-secret") {
		t.Fatalf("aar explain leaked secret-like command data: %s", explained)
	}
	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(explained), &record); err != nil {
		t.Fatalf("decode explained audit: %v", err)
	}
	if record["auditId"] != auditID || record["schemaVersion"] != reviewer.AuditSchemaVersion {
		t.Fatalf("explained audit = %#v, want %s audit", record, auditID)
	}
}

func moduleRoot(t *testing.T) string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func goBinary() string {
	if configured := os.Getenv("GO"); configured != "" {
		return configured
	}
	if path, err := exec.LookPath("go"); err == nil {
		return path
	}
	return "/home/glaicer/.local/go/bin/go"
}

func moduleCache() string {
	if configured := os.Getenv("GOMODCACHE"); configured != "" {
		return configured
	}
	return "/tmp/aar-go-modcache"
}

func testGoCache(t *testing.T) string {
	if configured := os.Getenv("AAR_GO_CACHE"); configured != "" {
		return configured
	}
	return filepath.Join(t.TempDir(), "go-cache")
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return contents
}

func TestCLITrustResetIsProjectScopedAndValidatesArguments(t *testing.T) {
	t.Setenv("AAR_STATE_DIR", t.TempDir())
	config := filepath.Join(t.TempDir(), "empty.toml")
	if err := os.WriteFile(config, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAR_CONFIG", config)
	root := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"trust-reset", "--project", root}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(stdout.String()) != `{"status":"reset"}` {
		t.Fatalf("stdout=%s", stdout.String())
	}
	files, err := filepath.Glob(filepath.Join(os.Getenv("AAR_STATE_DIR"), "reviewed-trust", "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("state=%v err=%v", files, err)
	}
	if err := run([]string{"trust-reset"}, strings.NewReader(""), &stdout, &stderr); err == nil {
		t.Fatal("missing project accepted")
	}
}
