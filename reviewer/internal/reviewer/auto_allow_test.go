package reviewer_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glaicer/supercode-command-gate/reviewer/internal/reviewer"
)

func TestAutoAllowUsesTheCompleteProgram(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		command string
		allow   bool
	}{
		{name: "single read", command: "cat source", allow: true},
		{name: "write redirection", command: "cat source > target", allow: false},
		{name: "unsafe remainder", command: "cat source && touch target", allow: false},
		{name: "safe pipeline", command: "cat source | grep needle", allow: true},
		{name: "dynamic remainder", command: "cat source && cat $TARGET", allow: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := testRequest(t, tc.command)
			decision, err := reviewer.Check(request, reviewer.Options{StateDir: t.TempDir()})
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			got := decision.Decision == reviewer.DecisionAllow
			if got != tc.allow {
				t.Fatalf("allow = %t for %q, want %t (decision=%q source=%q reason=%q)", got, tc.command, tc.allow, decision.Decision, decision.Source, decision.Reason)
			}
		})
	}
}

func TestParseShellPreservesPolicyFacts(t *testing.T) {
	ir := reviewer.ParseShell("cat source > target && grep needle source")

	if len(ir.Commands) != 2 {
		t.Fatalf("commands = %d, want 2", len(ir.Commands))
	}
	if len(ir.Operators) == 0 {
		t.Fatal("operators are empty")
	}
	if len(ir.Redirections) != 1 || !ir.Redirections[0].WriteCapable {
		t.Fatalf("redirections = %#v, want one write-capable redirection", ir.Redirections)
	}
	if ir.Redirections[0].Target != "target" || !ir.Redirections[0].Static {
		t.Fatalf("redirection target = %#v, want static target", ir.Redirections[0])
	}
	if len(ir.PathCandidates) == 0 {
		t.Fatal("path candidates are empty")
	}
	if len(ir.AccessModes) == 0 {
		t.Fatal("access modes are empty")
	}
	if ir.Redirections[0].Span.Start >= ir.Redirections[0].Span.End {
		t.Fatalf("redirection span = %#v, want a non-empty source span", ir.Redirections[0].Span)
	}
}

func TestDynamicShellFeaturesNeverAutoAllow(t *testing.T) {
	t.Parallel()

	commands := []string{
		`cat "$HOME"`,
		`cat "$(pwd)"`,
		`cat $((1 + 1))`,
		`cat *.go`,
		`cat {a,b}`,
		`cat <(printf x)`,
		`FOO=bar cat source`,
		`alias cat=cat; cat source`,
		`f() { cat source; }; f`,
		"cat <<EOF\nsource\nEOF",
		`cat source |`,
	}

	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			decision, err := reviewer.Check(testRequest(t, command), reviewer.Options{StateDir: t.TempDir()})
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if decision.Decision == reviewer.DecisionAllow {
				t.Fatalf("dynamic command auto-allowed: source=%q reason=%q", decision.Source, decision.Reason)
			}
			if !decision.Dynamic {
				t.Fatalf("decision.Dynamic = false for dynamic command %q", command)
			}
		})
	}
}

func TestBuiltInReadOnlyRules(t *testing.T) {
	t.Parallel()

	commands := []string{
		"pwd",
		"cd . && cat source",
		"cat source | grep needle",
		"ls -la .",
		"head -n 5 source",
		"head --lines=5 source",
		"tail -n 5 source",
		"wc -l source",
		"sort source",
		"find . -type f -name '*.go' -print",
		"find . -type f -printf '%p\\n'",
		"sed -n '1,4p' source",
		"sed 's/foo/bar/' source",
		`awk '{print $1}' source`,
		"grep -e needle source",
		"rg --files .",
		"git status --short",
		"git diff -- source",
		"git branch --show-current",
	}

	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			decision, err := reviewer.Check(testRequest(t, command), reviewer.Options{StateDir: t.TempDir()})
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if decision.Decision != reviewer.DecisionAllow {
				t.Fatalf("decision = %q for %q, want allow (source=%q reason=%q)", decision.Decision, command, decision.Source, decision.Reason)
			}
			if decision.Source != reviewer.SourceAutoAllow || decision.Rule == nil {
				t.Fatalf("decision provenance = source %q rule %v, want auto-allow with rule", decision.Source, decision.Rule)
			}
		})
	}
}

func TestProtectedReadPathDoesNotAutoAllow(t *testing.T) {
	t.Parallel()

	request := testRequest(t, "cat protected/secret.txt")
	decision, err := reviewer.Check(request, reviewer.Options{
		StateDir:       t.TempDir(),
		ProtectedPaths: []string{"protected"},
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision == reviewer.DecisionAllow {
		t.Fatalf("protected path auto-allowed: %#v", decision)
	}
}

func TestCommandSpecificNearMissesRouteToAssessment(t *testing.T) {
	t.Parallel()

	commands := []string{
		"find . -delete",
		"find . -exec touch target {} +",
		"find . -ok rm {} \\",
		"find . -fprint output",
		"sed -i 's/foo/bar/' source",
		"sed -n '1w output' source",
		"sed -n '1r other' source",
		"sed -n 's/foo/bar/w output' source",
		`awk 'BEGIN { system("id") }' source`,
		`awk 'BEGIN { print "x" > "output" }' source`,
		`awk 'BEGIN { print "x" | "sort" }' source`,
		`awk 'BEGIN { print ENVIRON["HOME"] }' source`,
		`awk 'BEGIN { getline x < "/etc/passwd" }' source`,
		"awk 'BEGIN { system " + "\\" + "\n" + "(\"id\") }' source",
		`awk '@include "/etc/awk/library.awk" { print }' source`,
		"tree -o ./out .",
		"sort --compress-program=gzip source",
		"diff --from-file=/etc/passwd source",
		"file -C -m ./magic source",
		"grep --exclude-from=/etc/passwd needle source",
		"grep -R needle .",
		"rg -L needle .",
		"find . -newer /etc/passwd -print",
		"git branch new-branch",
		"git branch --edit-description",
		"git branch --set-upstream-to=origin/main",
		"git remote show",
		"git fsck --lost-found",
		"git config --global --list",
		"git config --file=/etc/gitconfig --list",
		"git config --includes --list",
		"git status --work-tree=/etc",
		"git status --git-dir=/etc",
		"git stash",
		"git reset --hard HEAD",
		"cd / && ls",
		"cd / && git status",
	}

	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			decision, err := reviewer.Check(testRequest(t, command), reviewer.Options{StateDir: t.TempDir()})
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if decision.Decision == reviewer.DecisionAllow {
				t.Fatalf("unsafe near-miss auto-allowed: %q", command)
			}
			if decision.Source == reviewer.SourceAutoAllow {
				t.Fatalf("unsafe near-miss retained auto-allow provenance: %q", command)
			}
		})
	}
}

func TestCDPathDoesNotEnterTheSafeNoOpRule(t *testing.T) {
	t.Parallel()

	request := testRequest(t, "cd nested && pwd")
	nested := filepath.Join(request.CWD, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	request.Env["CDPATH"] = filepath.Join(t.TempDir(), "other")
	decision, err := reviewer.Check(request, reviewer.Options{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision == reviewer.DecisionAllow {
		t.Fatalf("relative cd with CDPATH auto-allowed: %#v", decision)
	}
}

func TestGitEnvironmentDoesNotEnterTheReadOnlyRule(t *testing.T) {
	t.Parallel()

	request := testRequest(t, "git status")
	request.Env["GIT_CONFIG_COUNT"] = "1"
	decision, err := reviewer.Check(request, reviewer.Options{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision == reviewer.DecisionAllow {
		t.Fatalf("Git environment override auto-allowed: %#v", decision)
	}
}

func TestWriteRedirectionRequiresAProvenSafeTarget(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		command string
		allow   bool
	}{
		{command: "cat source > target", allow: false},
		{command: "cat source > ./target", allow: true},
		{command: "cat source > /tmp/aar-output", allow: true},
		{command: "cat source > /etc/aar-output", allow: false},
		{command: "cat source > /dev/sda", allow: false},
		{command: "cat source > /dev/null", allow: true},
	} {
		t.Run(tc.command, func(t *testing.T) {
			decision, err := reviewer.Check(testRequest(t, tc.command), reviewer.Options{StateDir: t.TempDir()})
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			got := decision.Decision == reviewer.DecisionAllow
			if got != tc.allow {
				t.Fatalf("allow = %t for %q, want %t (reason=%q)", got, tc.command, tc.allow, decision.Reason)
			}
		})
	}
}

func TestExactAutoAllowAdditionsRequireExactArgvAndPathScope(t *testing.T) {
	t.Parallel()

	request := testRequest(t, "my-reader source")
	options := reviewer.Options{
		StateDir: t.TempDir(),
		AutoAllowAdditions: []reviewer.AutoAllowAddition{{
			Argv:      []string{"my-reader", "source"},
			PathScope: []string{"."},
		}},
	}
	decision, err := reviewer.Check(request, options)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Decision != reviewer.DecisionAllow || decision.Rule == nil || *decision.Rule != "AA009" {
		t.Fatalf("decision = %#v, want exact configured allow AA009", decision)
	}

	for _, command := range []string{"my-reader source extra", "my-reader ../outside", "./my-reader source"} {
		t.Run(command, func(t *testing.T) {
			decision, err := reviewer.Check(testRequest(t, command), options)
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if decision.Decision == reviewer.DecisionAllow {
				t.Fatalf("non-exact addition auto-allowed: %q", command)
			}
		})
	}

	unsafeOptionRequest := testRequest(t, "my-reader --output=/etc/passwd")
	unsafeOptionDecision, err := reviewer.Check(unsafeOptionRequest, reviewer.Options{
		StateDir: t.TempDir(),
		AutoAllowAdditions: []reviewer.AutoAllowAddition{{
			Argv:      []string{"my-reader", "--output=/etc/passwd"},
			PathScope: []string{"."},
		}},
	})
	if err != nil {
		t.Fatalf("Check() error for unsafe option addition = %v", err)
	}
	if unsafeOptionDecision.Decision == reviewer.DecisionAllow {
		t.Fatalf("path-bearing option addition auto-allowed: %#v", unsafeOptionDecision)
	}
}

func testRequest(t *testing.T, command string) reviewer.Request {
	t.Helper()
	cwd := t.TempDir()
	return reviewer.Request{
		SchemaVersion: reviewer.RequestSchemaVersion,
		Command:       command,
		CWD:           cwd,
		WorkspaceRoot: stringPointer(filepath.Clean(cwd)),
		Env:           map[string]string{"PWD": cwd},
		Session:       reviewer.Session{ID: "session-1", Host: "test"},
	}
}

func stringPointer(value string) *string {
	return &value
}
