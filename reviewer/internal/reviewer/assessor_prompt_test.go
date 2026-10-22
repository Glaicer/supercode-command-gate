package reviewer_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Glaicer/supercode-command-gate/reviewer/internal/reviewer"
)

type compactPrompt struct {
	Command        string                     `json:"command"`
	ContextCapsule map[string]json.RawMessage `json:"contextCapsule"`
	ParserHints    struct {
		Commands []struct {
			Argv   []string `json:"argv"`
			Source string   `json:"source"`
		} `json:"commands"`
		Dynamic         bool     `json:"dynamic"`
		DynamicFeatures []string `json:"dynamicFeatures"`
		ParseError      string   `json:"parseError"`
	} `json:"parserHints"`
	Scripts []struct {
		Interpreter string `json:"interpreter"`
		Kind        string `json:"kind"`
		Path        string `json:"path"`
		Digest      string `json:"digest"`
		Status      string `json:"status"`
		Content     string `json:"content"`
	} `json:"scripts"`
	PathHints []struct {
		Source        string `json:"source"`
		Role          string `json:"role"`
		CommandIndex  *int   `json:"commandIndex"`
		ArgumentIndex *int   `json:"argumentIndex"`
		Resolution    *struct {
			Basis           string `json:"basis"`
			ResolvedPath    string `json:"resolvedPath"`
			Existence       string `json:"existence"`
			Protected       bool   `json:"protected"`
			InsideWorkspace bool   `json:"insideWorkspace"`
			InsideTemporary bool   `json:"insideTemporary"`
		} `json:"resolution"`
	} `json:"pathHints"`
	LocalUncertainty []string `json:"localUncertainty"`
}

func TestCompactAssessorPromptRemovesParserBookkeeping(t *testing.T) {
	command := `strings /usr/bin/aar-probe | grep -E 'fallbacks|authMode|apiKeyEnv|baseUrl|totalTimeoutMs' | sort -u | head -60`
	call, prompt := captureCompactPrompt(t, assessorRequest(t, command))
	if prompt.Command != command {
		t.Fatalf("command = %q, want exact source %q", prompt.Command, command)
	}
	wantArgv := [][]string{
		{"strings", "/usr/bin/aar-probe"},
		{"grep", "-E", "fallbacks|authMode|apiKeyEnv|baseUrl|totalTimeoutMs"},
		{"sort", "-u"},
		{"head", "-60"},
	}
	if len(prompt.ParserHints.Commands) != len(wantArgv) {
		t.Fatalf("commands = %#v, want four parsed commands", prompt.ParserHints.Commands)
	}
	for index, want := range wantArgv {
		got := prompt.ParserHints.Commands[index]
		if !reflect.DeepEqual(got.Argv, want) || got.Source != "" {
			t.Fatalf("command %d = %#v, want only argv %#v", index, got, want)
		}
	}
	for _, key := range []string{"goal", "purpose", "latestUserRequest", "assistantRationale"} {
		if _, exists := prompt.ContextCapsule[key]; exists {
			t.Fatalf("absent context %q was serialized", key)
		}
	}
	for _, key := range []string{"shellIR", "nodes", "span", "argumentFacts", "pathCandidates", "accessModes", "effectFacts", "pathFacts", "hardDenyCatalogMatch", "insideSafeRoot"} {
		if strings.Contains(call.UserPrompt, `"`+key+`":`) {
			t.Fatalf("prompt still contains parser bookkeeping %q", key)
		}
	}
	fullIR, err := json.Marshal(reviewer.ParseShell(command))
	if err != nil {
		t.Fatal(err)
	}
	if len(call.UserPrompt)*2 >= len(fullIR) {
		t.Fatalf("compact prompt = %d bytes, want less than half the %d-byte full IR", len(call.UserPrompt), len(fullIR))
	}
	t.Logf("compact user prompt: %d bytes; previous full IR alone: %d bytes", len(call.UserPrompt), len(fullIR))
	if len(prompt.PathHints) != 0 || strings.Contains(call.UserPrompt, `"pathHints":`) {
		t.Fatalf("unclassified file and regex arguments became path hints: %#v", prompt.PathHints)
	}
	if !strings.Contains(call.SystemPrompt, "Absence of a path hint does not establish absence of filesystem effects") {
		t.Fatal("prompt does not explain that path hints are incomplete")
	}
}

func TestCompactAssessorPromptPreservesShellEvidence(t *testing.T) {
	cases := []struct {
		name       string
		command    string
		feature    string
		parseError bool
	}{
		{name: "conditional and pipeline", command: `probe-tool one && (probe-tool two || probe-tool three) | probe-tool four`, feature: "subshell"},
		{name: "command substitution and redirection", command: `probe-tool "$(printf '%s' nested)" > ./result`, feature: "command-substitution"},
		{name: "process substitution", command: `probe-tool <(printf '%s' nested)`, feature: "process-substitution"},
		{name: "environment and background", command: `VALUE=example probe-tool &`, feature: "environment-assignment"},
		{name: "loop", command: `for item in one two; do probe-tool "$item"; done`, feature: "loop"},
		{name: "heredoc", command: "python3 - <<'PY'\nprint('preserved')\nPY\n", feature: "heredoc"},
		{name: "parse failure", command: `probe-tool '`, feature: "parse-error", parseError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, prompt := captureCompactPrompt(t, assessorRequest(t, tc.command))
			if prompt.Command != tc.command {
				t.Fatalf("command = %q, want exact shell program %q", prompt.Command, tc.command)
			}
			if !prompt.ParserHints.Dynamic || !strings.Contains(strings.Join(prompt.ParserHints.DynamicFeatures, ","), tc.feature) {
				t.Fatalf("parser hints lost dynamic feature %q: %#v", tc.feature, prompt.ParserHints)
			}
			if (prompt.ParserHints.ParseError != "") != tc.parseError {
				t.Fatalf("parse error = %q, want present %t", prompt.ParserHints.ParseError, tc.parseError)
			}
			if tc.parseError && len(prompt.LocalUncertainty) == 0 {
				t.Fatal("parse uncertainty was dropped")
			}
		})
	}
}

func TestCompactAssessorPromptTracksInferredDirectoryChange(t *testing.T) {
	command := `cd ./elsewhere && rm -- "$TARGET" ./target 2> ./errors`
	request := assessorRequest(t, command)
	if err := os.Mkdir(filepath.Join(request.CWD, "elsewhere"), 0o700); err != nil {
		t.Fatal(err)
	}
	call, prompt := captureCompactPrompt(t, request)
	if len(prompt.ParserHints.Commands) != 2 || prompt.ParserHints.Commands[1].Source != `rm -- "$TARGET" ./target` || prompt.ParserHints.Commands[1].Argv != nil {
		t.Fatalf("dynamic command = %#v, want original source rather than invented argv", prompt.ParserHints.Commands)
	}
	if !strings.Contains(call.SystemPrompt, "flat inventory, not execution order") || !strings.Contains(call.SystemPrompt, "inferred-cd") {
		t.Fatal("prompt does not explain inventory and path resolution limitations")
	}
	afterCD := filepath.Join(request.CWD, "elsewhere")
	foundTarget, foundDynamic, foundRedirection := false, false, false
	for _, hint := range prompt.PathHints {
		switch hint.Source {
		case "./target":
			foundTarget = hint.Resolution != nil && hint.Resolution.Basis == "inferred-cd" && hint.Resolution.ResolvedPath == filepath.Join(afterCD, "target")
		case `"$TARGET"`:
			foundDynamic = hint.Role == "file-operand" && hint.Resolution == nil
		case "./errors":
			foundRedirection = hint.Role == "redirection-target" && hint.Resolution != nil && hint.Resolution.ResolvedPath == filepath.Join(afterCD, "errors")
		}
	}
	if !foundTarget || !foundDynamic || !foundRedirection {
		t.Fatalf("path evidence lost inferred directory, dynamic source, or redirection: %#v", prompt.PathHints)
	}
}

func TestCompactAssessorPromptOmitsResolutionWhenDirectoryIsUnknown(t *testing.T) {
	cases := []struct {
		name    string
		command string
	}{
		{name: "dynamic cd", command: `cd "$DIR" && rm ./target`},
		{name: "conditional cd", command: `if probe-tool; then cd ./elsewhere; fi; rm ./target`},
		{name: "cd after unknown", command: `cd "$DIR" && cd ./elsewhere && rm ./target`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := assessorRequest(t, tc.command)
			if err := os.Mkdir(filepath.Join(request.CWD, "elsewhere"), 0o700); err != nil {
				t.Fatal(err)
			}
			call, prompt := captureCompactPrompt(t, request)
			requireNoPathResolution(t, call.UserPrompt, prompt)
		})
	}
}

func TestCompactAssessorPromptOmitsResolutionForCDPathRelativeChange(t *testing.T) {
	request := assessorRequest(t, `probe-tool && cd nested && rm ./target`)
	if err := os.Mkdir(filepath.Join(request.CWD, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, prompt := captureCompactPrompt(t, request)
	requireResolution(t, prompt, "./target", "inferred-cd", filepath.Join(request.CWD, "nested", "target"))

	request = assessorRequest(t, `probe-tool && cd nested && rm ./target`)
	if err := os.Mkdir(filepath.Join(request.CWD, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	request.Env["CDPATH"] = filepath.Join(t.TempDir(), "other")
	call, prompt := captureCompactPrompt(t, request)
	requireNoPathResolution(t, call.UserPrompt, prompt)
}

func TestCompactAssessorPromptOmitsResolutionAcrossAlternativeDirectories(t *testing.T) {
	cases := []struct {
		name    string
		command string
	}{
		{name: "two cds", command: `cd ./first || cd ./second; rm ./target`},
		{name: "cd or probe", command: `cd ./first || probe-tool; rm ./target`},
		{name: "dynamic cd or cd", command: `cd "$DIR" || cd ./second; rm ./target`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := assessorRequest(t, tc.command)
			for _, directory := range []string{"first", "second"} {
				if err := os.Mkdir(filepath.Join(request.CWD, directory), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			call, prompt := captureCompactPrompt(t, request)
			requireNoPathResolution(t, call.UserPrompt, prompt)
		})
	}
}

func TestCompactAssessorPromptKeepsDirectoryWhenAlternativesAgree(t *testing.T) {
	request := assessorRequest(t, `cd ./first || cd ./first; rm ./target`)
	if err := os.Mkdir(filepath.Join(request.CWD, "first"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, prompt := captureCompactPrompt(t, request)
	requireResolution(t, prompt, "./target", "inferred-cd", filepath.Join(request.CWD, "first", "target"))
}

func TestCompactAssessorPromptKeepsDirectoryAcrossConditionalWithoutCD(t *testing.T) {
	request := assessorRequest(t, `if probe-tool; then rm ./inside; fi; rm ./target`)
	_, prompt := captureCompactPrompt(t, request)
	requireResolution(t, prompt, "./inside", "initial-cwd", filepath.Join(request.CWD, "inside"))
	requireResolution(t, prompt, "./target", "initial-cwd", filepath.Join(request.CWD, "target"))
}

func TestCompactAssessorPromptOmitsResolutionInsideConditionalWithCD(t *testing.T) {
	request := assessorRequest(t, `if probe-tool; then cd ./first; rm ./inside; fi; rm ./target`)
	if err := os.Mkdir(filepath.Join(request.CWD, "first"), 0o700); err != nil {
		t.Fatal(err)
	}
	call, prompt := captureCompactPrompt(t, request)
	requireNoPathResolution(t, call.UserPrompt, prompt)
}

func TestCompactAssessorPromptKeepsParentDirectoryAcrossSubshell(t *testing.T) {
	command := `( cd ./elsewhere ) && rm ./target`
	request := assessorRequest(t, command)
	if err := os.Mkdir(filepath.Join(request.CWD, "elsewhere"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, prompt := captureCompactPrompt(t, request)
	for _, hint := range prompt.PathHints {
		if hint.Source != "./target" {
			continue
		}
		if hint.Resolution == nil || hint.Resolution.Basis != "initial-cwd" || hint.Resolution.ResolvedPath != filepath.Join(request.CWD, "target") {
			t.Fatalf("subshell cd changed the parent context: %#v", hint.Resolution)
		}
		return
	}
	t.Fatalf("no hint for the rm operand: %#v", prompt.PathHints)
}

func requireNoPathResolution(t *testing.T, payload string, prompt compactPrompt) {
	t.Helper()
	if len(prompt.PathHints) == 0 {
		t.Fatalf("expected path hints without resolution, got none: %s", payload)
	}
	for _, hint := range prompt.PathHints {
		if hint.Resolution != nil {
			t.Fatalf("unknown execution directory produced a resolution: %#v", hint)
		}
	}
	if strings.Contains(payload, `"resolution":`) {
		t.Fatalf("unknown execution directory produced resolution fields: %s", payload)
	}
}

func TestCompactAssessorPromptKeepsDecodedStaticArguments(t *testing.T) {
	command := `probe-tool $'\x2ftmp\x2fkeep' 'literal $(not-executed)'`
	_, prompt := captureCompactPrompt(t, assessorRequest(t, command))
	want := []string{"probe-tool", "/tmp/keep", "literal $(not-executed)"}
	if len(prompt.ParserHints.Commands) != 1 || !reflect.DeepEqual(prompt.ParserHints.Commands[0].Argv, want) {
		t.Fatalf("commands = %#v, want decoded argv %#v", prompt.ParserHints.Commands, want)
	}
	if prompt.ParserHints.Dynamic {
		t.Fatal("quoted literal data became dynamic execution")
	}
}

func TestCompactAssessorPromptOmitsUnclassifiedPathHints(t *testing.T) {
	cases := []struct {
		name    string
		command string
	}{
		{name: "ssh report", command: `ssh -o BatchMode=yes -o ConnectTimeout=10 hetzner 'curl --max-time 10 -fsS http://127.0.0.1:9093/api/v2/receivers; docker ps -a --format "{{.ID}} {{.Names}} {{.Image}} {{.Status}} {{.Ports}}" --filter name=alert'`},
		{name: "remote files", command: `ssh remote 'rm -- ./remote > ./remote-output'`},
		{name: "unknown command", command: `probe-tool /etc/passwd ./local https://example.invalid/path 'pattern/with/slashes'`},
		{name: "printed path", command: `probe-tool && printf '%s' /etc/passwd`},
		{name: "here string", command: `probe-tool <<< /literal/data`},
		{name: "heredoc data", command: "probe-tool <<'EOF'\n/not/a/file/operand\nEOF\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			call, prompt := captureCompactPrompt(t, assessorRequest(t, tc.command))
			if prompt.Command != tc.command || len(prompt.ParserHints.Commands) == 0 {
				t.Fatal("filtering path hints lost command evidence")
			}
			if len(prompt.PathHints) != 0 || strings.Contains(call.UserPrompt, `"pathHints":`) {
				t.Fatalf("unclassified arguments became local paths: %#v", prompt.PathHints)
			}
		})
	}
}

func TestCompactAssessorPromptKeepsKnownFileOperands(t *testing.T) {
	command := `probe-tool && mkdir -m 700 -- ./created && rm -f -- ./obsolete ./nested/file`
	request := assessorRequest(t, command)
	_, prompt := captureCompactPrompt(t, request)
	wantSources := []string{"./created", "./obsolete", "./nested/file"}
	wantCommands := []int{1, 2, 2}
	wantArguments := []int{4, 3, 4}
	if len(prompt.PathHints) != len(wantSources) {
		t.Fatalf("path hints = %#v, want mkdir/rm operands only", prompt.PathHints)
	}
	for index, hint := range prompt.PathHints {
		if hint.Source != wantSources[index] || hint.Role != "file-operand" || hint.CommandIndex == nil || *hint.CommandIndex != wantCommands[index] || hint.ArgumentIndex == nil || *hint.ArgumentIndex != wantArguments[index] {
			t.Fatalf("file operand %d lost provenance: %#v", index, hint)
		}
		if hint.Resolution == nil || hint.Resolution.Basis != "initial-cwd" || hint.Resolution.ResolvedPath != filepath.Join(request.CWD, wantSources[index]) {
			t.Fatalf("file operand %d has unexpected path: %#v", index, hint)
		}
		if hint.Resolution.Existence != "absent" {
			t.Fatalf("file operand %d existence = %q, want absent", index, hint.Resolution.Existence)
		}
	}
}

func TestCompactAssessorPromptKeepsFileRedirectionsNotDescriptors(t *testing.T) {
	command := `probe-tool < ./input > ./output 2>> ./errors 3<> ./data >& ./combined 2>&3 0<&4`
	_, prompt := captureCompactPrompt(t, assessorRequest(t, command))
	wantSources := []string{"./input", "./output", "./errors", "./data", "./combined"}
	if len(prompt.PathHints) != len(wantSources) {
		t.Fatalf("path hints = %#v, want file redirections without descriptor numbers", prompt.PathHints)
	}
	for index, hint := range prompt.PathHints {
		if hint.Source != wantSources[index] || hint.Role != "redirection-target" {
			t.Fatalf("file redirection %d = %#v", index, hint)
		}
		if hint.Resolution == nil || hint.Resolution.Basis != "initial-cwd" {
			t.Fatalf("file redirection %d lost its resolution: %#v", index, hint)
		}
	}
}

func TestCompactAssessorPromptKeepsOnlyLocalSSHRedirection(t *testing.T) {
	command := `ssh remote 'docker ps > ./remote-output' > ./local-output`
	_, prompt := captureCompactPrompt(t, assessorRequest(t, command))
	if len(prompt.PathHints) != 1 || prompt.PathHints[0].Source != "./local-output" || prompt.PathHints[0].Role != "redirection-target" {
		t.Fatalf("local and remote targets were confused: %#v", prompt.PathHints)
	}
	if prompt.Command != command {
		t.Fatal("remote command was changed")
	}
}

func TestCompactAssessorPromptRetainsUnclassifiedLocalUncertainty(t *testing.T) {
	_, prompt := captureCompactPrompt(t, assessorRequest(t, `probe-tool "$TARGET"`))
	if len(prompt.PathHints) != 0 {
		t.Fatalf("unknown operand became a path hint: %#v", prompt.PathHints)
	}
	if !strings.Contains(strings.Join(prompt.LocalUncertainty, "; "), "a relevant path target is not statically recoverable") {
		t.Fatal("model-facing filtering changed local evidence uncertainty")
	}
}

func TestCompactAssessorPromptDistinguishesMissingAndUncheckedPaths(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		request := assessorRequest(t, `probe-tool && rm ./present`)
		if err := os.WriteFile(filepath.Join(request.CWD, "present"), []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, prompt := captureCompactPrompt(t, request)
		requireExistence(t, prompt, "./present", "present")
	})

	t.Run("absent", func(t *testing.T) {
		_, prompt := captureCompactPrompt(t, assessorRequest(t, `probe-tool && rm ./absent`))
		requireExistence(t, prompt, "./absent", "absent")
	})

	t.Run("dangling symlink", func(t *testing.T) {
		request := assessorRequest(t, `probe-tool && rm ./link`)
		link := filepath.Join(request.CWD, "link")
		if err := os.Symlink(filepath.Join(request.CWD, "missing"), link); err != nil {
			t.Fatal(err)
		}
		_, prompt := captureCompactPrompt(t, request)
		requireExistence(t, prompt, "./link", "present")
		requireResolution(t, prompt, "./link", "initial-cwd", link)
	})

	t.Run("unchecked", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("permission-restricted directories cannot be simulated for this user")
		}
		request := assessorRequest(t, `probe-tool && rm ./private/item`)
		private := filepath.Join(request.CWD, "private")
		if err := os.Mkdir(private, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(private, 0o700); err != nil {
				t.Errorf("restore private directory: %v", err)
			}
		})
		_, prompt := captureCompactPrompt(t, request)
		requireExistence(t, prompt, "./private/item", "unknown")
	})
}

func requireExistence(t *testing.T, prompt compactPrompt, source, want string) {
	t.Helper()
	for _, hint := range prompt.PathHints {
		if hint.Source != source {
			continue
		}
		if hint.Resolution == nil {
			t.Fatalf("%q has no resolution", source)
		}
		if hint.Resolution.Existence != want {
			t.Fatalf("%q existence = %q, want %q", source, hint.Resolution.Existence, want)
		}
		return
	}
	t.Fatalf("no path hint for %q: %#v", source, prompt.PathHints)
}

func requireResolution(t *testing.T, prompt compactPrompt, source, wantBasis, wantPath string) {
	t.Helper()
	for _, hint := range prompt.PathHints {
		if hint.Source != source {
			continue
		}
		if hint.Resolution == nil {
			t.Fatalf("%q has no resolution", source)
		}
		if hint.Resolution.Basis != wantBasis || hint.Resolution.ResolvedPath != wantPath {
			t.Fatalf("%q resolution = %#v, want %s %q", source, hint.Resolution, wantBasis, wantPath)
		}
		return
	}
	t.Fatalf("no path hint for %q: %#v", source, prompt.PathHints)
}

func captureCompactPrompt(t *testing.T, request reviewer.Request) (reviewer.ModelCallRequest, compactPrompt) {
	t.Helper()
	fake := &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":[]}`}}
	_, err := reviewer.Check(request, reviewer.Options{
		StateDir: t.TempDir(),
		Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{
			Model: "primary", OnUnavailable: "deny",
		}},
		ModelCall: fake,
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if len(fake.requests) != 1 {
		t.Fatalf("model calls = %d, want 1", len(fake.requests))
	}
	var prompt compactPrompt
	if err := json.Unmarshal([]byte(fake.requests[0].UserPrompt), &prompt); err != nil {
		t.Fatalf("decode model prompt: %v", err)
	}
	return fake.requests[0], prompt
}

func checkWithPrompt(t *testing.T, request reviewer.Request) (reviewer.Decision, reviewer.ModelCallRequest) {
	t.Helper()
	fake := &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":[]}`}}
	decision, err := reviewer.Check(request, reviewer.Options{
		StateDir: t.TempDir(),
		Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{
			Model: "primary", OnUnavailable: "deny",
		}},
		ModelCall: fake,
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if len(fake.requests) != 1 {
		t.Fatalf("model calls = %d, want 1", len(fake.requests))
	}
	return decision, fake.requests[0]
}

func TestAssessorPromptRedactsContextSecretsWithoutTouchingFingerprintInputs(t *testing.T) {
	build := func(secret string) reviewer.Request {
		request := assessorRequest(t, "custom-cleanup")
		request.Intent = reviewer.Intent{
			Goal:               "rotate api_key=" + secret + " for the deploy",
			LatestUserRequest:  "use password=" + secret + " to log in",
			Purpose:            "run with token: " + secret,
			AssistantRationale: "the environment holds OPENROUTER_API_KEY=sk-" + secret + " and AKIA" + strings.ToUpper(secret),
		}
		return request
	}

	firstDecision, first := checkWithPrompt(t, build("firstsecretvalue"))
	secondDecision, second := checkWithPrompt(t, build("secondsecretvalue"))
	for label, prompt := range map[string]string{"first": first.UserPrompt, "second": second.UserPrompt} {
		if strings.Contains(prompt, "secretvalue") {
			t.Fatalf("%s prompt leaked a secret: %s", label, prompt)
		}
		if !strings.Contains(prompt, "[REDACTED]") {
			t.Fatalf("%s prompt did not mark redacted context: %s", label, prompt)
		}
	}
	if firstDecision.RequestFingerprint == secondDecision.RequestFingerprint {
		t.Fatal("redaction changed the fingerprint inputs; raw intent text must still bind the fingerprint")
	}
}

func TestAssessorPromptOmitsPathFromTrustedEnv(t *testing.T) {
	build := func(path string) reviewer.Request {
		request := assessorRequest(t, "custom-cleanup")
		request.Env["PATH"] = path
		return request
	}

	firstDecision, first := checkWithPrompt(t, build("/tmp/hijack:/usr/local/bin:/usr/bin"))
	secondDecision, second := checkWithPrompt(t, build("/usr/local/bin:/usr/bin"))
	for label, prompt := range map[string]string{"first": first.UserPrompt, "second": second.UserPrompt} {
		trustedEnv, ok := compactContextValue(t, prompt, "trustedEnv")
		if !ok {
			t.Fatalf("%s prompt has no trustedEnv", label)
		}
		if strings.Contains(trustedEnv, `"PATH"`) || strings.Contains(trustedEnv, "/tmp/hijack") {
			t.Fatalf("%s prompt still carries PATH: %s", label, trustedEnv)
		}
		if !strings.Contains(trustedEnv, `"HOME"`) {
			t.Fatalf("%s prompt lost the remaining environment: %s", label, trustedEnv)
		}
	}
	if firstDecision.RequestFingerprint == secondDecision.RequestFingerprint {
		t.Fatal("PATH no longer binds the fingerprint; only the prompt copy may be trimmed")
	}
}

func TestAssessorPromptOmitsRepeatedScriptContentAndLocalDigests(t *testing.T) {
	command := "python3 - <<'PY'\nprint('duplicated')\nPY\n"
	_, prompt := captureCompactPrompt(t, assessorRequest(t, command))
	if len(prompt.Scripts) != 1 {
		t.Fatalf("scripts = %#v, want the heredoc evidence", prompt.Scripts)
	}
	script := prompt.Scripts[0]
	if script.Kind != "heredoc" || script.Status != "complete" || script.Interpreter != "python3" {
		t.Fatalf("script metadata = %#v, want complete heredoc evidence", script)
	}
	if script.Content != "" {
		t.Fatalf("prompt repeated script content already present in the command: %q", script.Content)
	}
	if script.Digest != "" {
		t.Fatalf("prompt carried a local digest: %q", script.Digest)
	}

	workspace := t.TempDir()
	entrypoint := filepath.Join(workspace, "main.py")
	source := "print('from file')\n"
	if err := os.WriteFile(entrypoint, []byte(source), 0o600); err != nil {
		t.Fatalf("write entrypoint: %v", err)
	}
	_, filePrompt := captureCompactPrompt(t, reviewer.Request{
		SchemaVersion: reviewer.RequestSchemaVersion,
		Command:       "python3 " + entrypoint,
		CWD:           workspace,
		WorkspaceRoot: &workspace,
		Env:           map[string]string{"HOME": workspace, "PWD": workspace},
		Session:       reviewer.Session{ID: "session-1", Host: "test"},
	})
	if len(filePrompt.Scripts) != 1 || filePrompt.Scripts[0].Content != source {
		t.Fatalf("file script content was dropped: %#v", filePrompt.Scripts)
	}
	if filePrompt.Scripts[0].Digest != "" {
		t.Fatalf("file script digest leaked into the prompt: %#v", filePrompt.Scripts[0])
	}
}

func TestAssessorPromptStatesWorkspaceRelation(t *testing.T) {
	workspace := t.TempDir()
	request := assessorRequest(t, "custom-cleanup")
	request.WorkspaceRoot = &workspace

	request.CWD = t.TempDir()
	_, outside := captureCompactPrompt(t, request)
	if got := string(outside.ContextCapsule["outsideWorkspace"]); got != "true" {
		t.Fatalf("outsideWorkspace = %s, want true for a directory outside the workspace", got)
	}

	request.CWD = workspace
	_, inside := captureCompactPrompt(t, request)
	if got := string(inside.ContextCapsule["outsideWorkspace"]); got != "false" {
		t.Fatalf("outsideWorkspace = %s, want false inside the workspace", got)
	}

	request.WorkspaceRoot = nil
	_, unknown := captureCompactPrompt(t, request)
	if got, ok := unknown.ContextCapsule["outsideWorkspace"]; ok {
		t.Fatalf("outsideWorkspace = %s, want it omitted without a workspace root", got)
	}
}

func compactContextValue(t *testing.T, prompt, key string) (string, bool) {
	t.Helper()
	var decoded compactPrompt
	if err := json.Unmarshal([]byte(prompt), &decoded); err != nil {
		t.Fatalf("decode model prompt: %v", err)
	}
	raw, ok := decoded.ContextCapsule[key]
	if !ok {
		return "", false
	}
	return string(raw), true
}

func TestCompactAssessorPromptRecoversArgvBehindEnvironmentAssignment(t *testing.T) {
	command := "OPENBLAS_NUM_THREADS=1 PYTHONPATH=src .venv/bin/python -m model_training.checks"
	_, prompt := captureCompactPrompt(t, assessorRequest(t, command))
	if !prompt.ParserHints.Dynamic || !hasFeature(prompt.ParserHints.DynamicFeatures, "environment-assignment") {
		t.Fatalf("parser hints lost the dynamic prefix: %#v", prompt.ParserHints)
	}
	if len(prompt.ParserHints.Commands) != 1 {
		t.Fatalf("commands = %#v, want one entry", prompt.ParserHints.Commands)
	}
	hint := prompt.ParserHints.Commands[0]
	want := []string{".venv/bin/python", "-m", "model_training.checks"}
	if !reflect.DeepEqual(hint.Argv, want) || hint.Source != "" {
		t.Fatalf("command = %#v, want static argv %#v instead of source", hint, want)
	}
}

func TestCompactAssessorPromptOmitsCommandSourceThatRepeatsTheProgram(t *testing.T) {
	command := `probe-tool "$VALUE"`
	call, prompt := captureCompactPrompt(t, assessorRequest(t, command))
	if len(prompt.ParserHints.Commands) != 0 || strings.Contains(call.UserPrompt, `"commands"`) {
		t.Fatalf("commands = %#v, want the entry omitted because command already carries it", prompt.ParserHints.Commands)
	}
	if !prompt.ParserHints.Dynamic {
		t.Fatal("prompt no longer marks the program dynamic")
	}
}

func TestAssessorPromptCapsAssistantRationaleAtLineBoundary(t *testing.T) {
	const lastLine = "the user asked for the full suite before committing"
	build := func(tag string) reviewer.Request {
		request := assessorRequest(t, "custom-cleanup")
		request.Intent.AssistantRationale = strings.Repeat(tag+" unrelated deliberation about other work\n", 200) + lastLine
		return request
	}

	firstDecision, first := checkWithPrompt(t, build("alpha"))
	secondDecision, second := checkWithPrompt(t, build("bravo"))
	firstRationale := rationaleText(t, first.UserPrompt)
	secondRationale := rationaleText(t, second.UserPrompt)
	if runes := []rune(firstRationale); len(runes) > 2000 {
		t.Fatalf("assistantRationale = %d runes, want at most %d", len(runes), 2000)
	}
	if !strings.HasPrefix(firstRationale, "alpha unrelated deliberation about other work") {
		t.Fatalf("rationale does not start at a line boundary: %q", firstRationale)
	}
	if !strings.HasSuffix(firstRationale, lastLine) {
		t.Fatalf("rationale lost the recent intent: %q", firstRationale)
	}
	if len([]rune(firstRationale)) != len([]rune(secondRationale)) {
		t.Fatal("the cap depends on text outside the recent tail")
	}
	if firstDecision.RequestFingerprint == secondDecision.RequestFingerprint {
		t.Fatal("the cap changed the fingerprint inputs; the full rationale must still bind it")
	}
}

func rationaleText(t *testing.T, prompt string) string {
	t.Helper()
	raw, ok := compactContextValue(t, prompt, "assistantRationale")
	if !ok {
		t.Fatal("prompt has no assistantRationale")
	}
	var value string
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		t.Fatalf("decode assistantRationale: %v", err)
	}
	return value
}

func hasFeature(features []string, want string) bool {
	for _, feature := range features {
		if feature == want {
			return true
		}
	}
	return false
}
