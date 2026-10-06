package reviewer_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/supercode/auto-approval-reviewer/internal/reviewer"
)

func TestSafeShellNumericHeadTail(t *testing.T) {
	for _, command := range []string{
		"rg needle source | head -60", "cat source | tail -20",
		"head -60 source", "tail -20 source", "head -n 60 source", "tail -n 20 source",
	} {
		t.Run(command, func(t *testing.T) {
			stateDir := t.TempDir()
			fake := &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":[]}`}}
			decision, err := reviewer.Check(testRequest(t, command), reviewer.Options{
				StateDir: stateDir, ModelCall: fake,
				Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "test"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			assertSafeShellAudit(t, stateDir, decision, len(fake.requests))
			if decision.Source != reviewer.SourceAutoAllow || decision.Decision != reviewer.DecisionAllow || len(fake.requests) != 0 {
				t.Fatalf("source=%s decision=%s model calls=%d", decision.Source, decision.Decision, len(fake.requests))
			}
		})
	}
}

func TestSafeShellExpansionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		command string
		allow   bool
	}{
		{"cat ABS/docs/*.md", true},
		{"cat docs/*.md 2>&1 | tail -20", true},
		{"cat docs/{2..1}.md", true},
		{"cat docs/{1..2}.*", true},
		{"cat docs/{1..256}.md", true},
		{"cat 'literal/*.md'", true},
		{`cat "literal/*.md"`, true},
		{"cat docs/?.md", true},
		{"cat docs/*/*.md", true},
		{"cd docs && cat *.md", true},
		{"cat 'links/*.md'", true},
		{"cat missing/*.md", false},
		{"cat docs/{1..257}.md", false},
		{"cat docs/{01..08}.md", false},
		{"cat docs/{1..8..2}.md", false},
		{"cat docs/{a,b}.md", false},
		{"cat docs/{1..2}{1..2}.md", false},
		{"cat docs/[12].md", false},
		{"cat docs/**/1.md", false},
		{`cat "docs/"*.md`, false},
		{"cat escape/*.conf", false},
		{"cat links/*.md", false},
		{"cat protected/*.md", false},
		{"cat many/*.md", false},
		{"cat *.inject", false},
		{"cat docs/*.md; touch ./output", false},
		{"cat docs/*.md && touch ./output", false},
		{"cat docs/*.md || touch ./output", false},
		{"cat docs/*.md | touch ./output", false},
		{`cat docs/*.md; cat "$TARGET"`, false},
		{"cat docs/*.md; cat $(pwd)", false},
		{"cat docs/*.md; cat <(pwd)", false},
		{"FOO=bar cat docs/*.md", false},
		{"for x in docs/*.md; do cat source; done", false},
		{"rm docs/*.md", false},
		{"./reader docs/*.md", false},
		{"my-reader docs/*.md", false},
		{"node docs/*.md", false},
		{"head -banana source", false},
		{"tail -20x source", false},
		{"head --60 source", false},
		{"head --linesOops source", false},
		{"head -n60 source", true},
		{"tail --lines=20 source", true},
		{"cat source 2>&1 > target", false},
		{"cat source > target 2>&1", false},
		{"cat source 2>&1 > ./target", true},
		{"cat source > ./target 2>&1", true},
		{"cat source 2>&3", false},
		{"cat source 3>&1", false},
		{"cat source 0<&1", false},
		{"cat source 2>&-", false},
		{"cat source 2>&1-", false},
		{"cat source 2>&$FD", false},
		{"cat docs/*.md > output/*.txt", false},
		{"stat --format='%s' docs/{1..8}.png", true},
	} {
		t.Run(tc.command, func(t *testing.T) {
			request := testRequest(t, tc.command)
			request.Command = strings.ReplaceAll(request.Command, "ABS", request.CWD)
			for _, path := range []string{"docs/1.md", "docs/2.md", "docs/nested/1.md", "protected/1.md", "literal/*.md", "-output.inject"} {
				full := filepath.Join(request.CWD, path)
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte("needle"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(filepath.Join(request.CWD, "links"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/etc/passwd", filepath.Join(request.CWD, "links/1.md")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/etc", filepath.Join(request.CWD, "escape")); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(request.CWD, "many"), 0o755); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 257; i++ {
				if err := os.WriteFile(filepath.Join(request.CWD, "many", fmt.Sprintf("%d.md", i)), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			stateDir := t.TempDir()
			fake := &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":[]}`}}
			decision, err := reviewer.Check(request, reviewer.Options{
				StateDir: stateDir, ModelCall: fake,
				Config: &reviewer.Config{
					Assessor: reviewer.AssessorConfig{Model: "test"},
					Policy:   reviewer.PolicyConfig{ProtectedPaths: []string{"protected"}},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			assertSafeShellAudit(t, stateDir, decision, len(fake.requests))
			if (decision.Source == reviewer.SourceAutoAllow) != tc.allow || (len(fake.requests) == 0) != tc.allow {
				t.Fatalf("source=%s model calls=%d want auto-allow=%v", decision.Source, len(fake.requests), tc.allow)
			}
		})
	}
}

func TestSafeShellRedirectionOrder(t *testing.T) {
	for _, tc := range []struct{ command, first, second string }{
		{"cat source 2>&1 > /dev/null", ">&", ">"},
		{"cat source > /dev/null 2>&1", ">", ">&"},
	} {
		ir := reviewer.ParseShell(tc.command)
		if ir.Dynamic || len(ir.Redirections) != 2 || ir.Redirections[0].Operator != tc.first || ir.Redirections[1].Operator != tc.second {
			t.Fatalf("redirections = %#v", ir.Redirections)
		}
		for _, redirection := range ir.Redirections {
			if redirection.Operator == ">&" && (redirection.FD != "2" || redirection.Target != "1" || redirection.WriteCapable) {
				t.Fatalf("duplication = %#v", redirection)
			}
		}
		for _, path := range ir.PathCandidates {
			if path.Role == "redirection-target" && path.Value == "1" {
				t.Fatal("descriptor treated as file path")
			}
		}
	}
}

func TestSafeShellPathExpansions(t *testing.T) {
	for _, command := range []string{"cat *.md", "cat tests/*.spec.ts", "rg needle tests/*.spec.ts | head -60", "cat docs/screenshots/{1..8}.png"} {
		t.Run(command, func(t *testing.T) {
			request := testRequest(t, command)
			for _, path := range []string{"a.md", "tests/a.spec.ts", "docs/screenshots/1.png", "docs/screenshots/8.png"} {
				full := filepath.Join(request.CWD, path)
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte("needle"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			stateDir := t.TempDir()
			fake := &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":[]}`}}
			decision, err := reviewer.Check(request, reviewer.Options{
				StateDir: stateDir, ModelCall: fake,
				Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "test"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			assertSafeShellAudit(t, stateDir, decision, len(fake.requests))
			if decision.Source != reviewer.SourceAutoAllow || len(fake.requests) != 0 {
				t.Fatalf("source=%s model calls=%d", decision.Source, len(fake.requests))
			}
		})
	}
}

func TestSafeShellOutputDuplication(t *testing.T) {
	for _, command := range []string{
		"cat source 2>&1 | head -60", "cat source 1>&2",
		"cat source 2>&1 > /dev/null", "cat source > /dev/null 2>&1",
	} {
		t.Run(command, func(t *testing.T) {
			stateDir := t.TempDir()
			fake := &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":[]}`}}
			decision, err := reviewer.Check(testRequest(t, command), reviewer.Options{
				StateDir: stateDir, ModelCall: fake,
				Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "test"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			assertSafeShellAudit(t, stateDir, decision, len(fake.requests))
			if decision.Source != reviewer.SourceAutoAllow || len(fake.requests) != 0 {
				t.Fatalf("source=%s model calls=%d", decision.Source, len(fake.requests))
			}
		})
	}
}

func assertSafeShellAudit(t *testing.T, stateDir string, decision reviewer.Decision, modelCalls int) {
	t.Helper()
	audit, err := os.ReadFile(filepath.Join(stateDir, "audit", decision.AuditID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(audit, &record); err != nil {
		t.Fatal(err)
	}
	if record["source"] != decision.Source || record["decision"] != decision.Decision {
		t.Fatalf("audit = %#v", record)
	}
	events := readReviewLog(t, stateDir)
	last := events[len(events)-1]
	if last["source"] != decision.Source || last["auditId"] != decision.AuditID || last["decision"] != decision.Decision {
		t.Fatalf("verdict = %#v", last)
	}
	calls := 0
	for _, event := range events {
		if event["event"] == "assessor-call" {
			calls++
		}
	}
	if calls != modelCalls {
		t.Fatalf("assessor-call events=%d want %d", calls, modelCalls)
	}
	if decision.Source == reviewer.SourceAutoAllow {
		assertAuditOutcome(t, stateDir, decision.AuditID, reviewer.AuditOutcomeDeterministic)
	}
}

func TestSafeShellShellEnvironment(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"BASHOPTS", "dotglob"}, {"BASHOPTS", "nocaseglob"},
		{"SHELLOPTS", "noglob"}, {"GLOBIGNORE", "ignored"},
		{"BASH_ENV", "./startup.sh"}, {"ENV", "./startup.sh"},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			request := testRequest(t, "cat *.md")
			request.Env[tc.key] = tc.value
			if err := os.WriteFile(filepath.Join(request.CWD, "visible.md"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/etc/passwd", filepath.Join(request.CWD, ".hidden.md")); err != nil {
				t.Fatal(err)
			}
			stateDir := t.TempDir()
			fake := &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":[]}`}}
			decision, err := reviewer.Check(request, reviewer.Options{
				StateDir: stateDir, ModelCall: fake,
				Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "test"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if decision.Source == reviewer.SourceAutoAllow || len(fake.requests) != 1 {
				t.Fatalf("source=%s calls=%d", decision.Source, len(fake.requests))
			}
			assertSafeShellAudit(t, stateDir, decision, len(fake.requests))
		})
	}
}
