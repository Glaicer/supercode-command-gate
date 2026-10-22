package reviewer_test

import (
	"encoding/json"
	"path/filepath"
	"reflect"
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
	PathHints []struct {
		Source                 string `json:"source"`
		Role                   string `json:"role"`
		CommandIndex           *int   `json:"commandIndex"`
		ArgumentIndex          *int   `json:"argumentIndex"`
		ResolvedFromInitialCWD string `json:"resolvedFromInitialCWD"`
		Unresolved             bool   `json:"unresolved"`
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
	if len(prompt.PathHints) != 2 {
		t.Fatalf("path hints = %#v, want file operand and unclassified regex", prompt.PathHints)
	}
	for index, hint := range prompt.PathHints {
		if hint.Role != "unclassified-argument" || hint.CommandIndex == nil || *hint.CommandIndex != index || hint.ArgumentIndex == nil || *hint.ArgumentIndex != index+1 {
			t.Fatalf("path hint %d lost argument provenance: %#v", index, hint)
		}
	}
	if !strings.Contains(call.SystemPrompt, "rather than a filesystem path") {
		t.Fatal("prompt does not distinguish candidate arguments from actual paths")
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

func TestCompactAssessorPromptKeepsDynamicSourceAndInitialPathContext(t *testing.T) {
	command := `cd ./elsewhere && probe-tool "$TARGET" ./target 2> ./errors`
	request := assessorRequest(t, command)
	call, prompt := captureCompactPrompt(t, request)
	if len(prompt.ParserHints.Commands) != 2 || prompt.ParserHints.Commands[1].Source != `probe-tool "$TARGET" ./target` || prompt.ParserHints.Commands[1].Argv != nil {
		t.Fatalf("dynamic command = %#v, want original source rather than invented argv", prompt.ParserHints.Commands)
	}
	if !strings.Contains(call.SystemPrompt, "flat inventory, not execution order") || !strings.Contains(call.SystemPrompt, "assume the initial working directory") {
		t.Fatal("prompt does not explain inventory and path resolution limitations")
	}
	foundTarget, foundDynamic, foundRedirection := false, false, false
	for _, hint := range prompt.PathHints {
		switch hint.Source {
		case "./target":
			foundTarget = hint.ResolvedFromInitialCWD == filepath.Join(request.CWD, "target")
		case `"$TARGET"`:
			foundDynamic = hint.Unresolved && hint.ResolvedFromInitialCWD == ""
		case "./errors":
			foundRedirection = hint.Role == "redirection-target"
		}
	}
	if !foundTarget || !foundDynamic || !foundRedirection {
		t.Fatalf("path evidence lost resolution assumptions, dynamic source, or redirection: %#v", prompt.PathHints)
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
