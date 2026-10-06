package reviewer_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/supercode/auto-approval-reviewer/internal/reviewer"
)

func checkReadOnlyCommand(t *testing.T, command string, allow bool) {
	t.Helper()
	request := testRequest(t, command)
	checkReadOnlyRequest(t, request, allow)
}

func checkReadOnlyRequest(t *testing.T, request reviewer.Request, allow bool) {
	t.Helper()
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
	t.Logf("source=%s calls=%d", decision.Source, len(fake.requests))
	if (decision.Source == reviewer.SourceAutoAllow) != allow || (len(fake.requests) == 0) != allow {
		t.Fatalf("source=%s decision=%s model calls=%d want auto-allow=%v", decision.Source, decision.Decision, len(fake.requests), allow)
	}
	if decision.Decision != reviewer.DecisionAllow || (!allow && (decision.Source != reviewer.SourceAssessor || len(fake.requests) != 1)) {
		t.Fatalf("unexpected fallback: %#v calls=%d", decision, len(fake.requests))
	}
}

func TestReadOnlyCommandBoundaries(t *testing.T) {
	for _, command := range []string{
		"git merge-base --is-ancestor HEAD", "git merge-base --is-ancestor HEAD HEAD extra",
		"git merge-base --is-ancestor --octopus HEAD", "git merge-base HEAD HEAD",
		"git check-ignore", "git check-ignore --stdin", "git check-ignore --no-index file",
		"git check-ignore -v --delete file", "git check-ignore -v /etc/passwd",
		"git check-ignore protected", "git check-ignore -v protected/file",
		"git show-ref --heads --delete", "git show-ref --heads --verify HEAD",
		"git show-ref --heads --exclude-existing", "git show-ref --heads --output=file",
		"git branch new", "git branch --list -D old", "git branch --list -m old new",
		"git branch --list --copy old new", "git branch --list --force new",
		"git branch --list --edit-description", "git branch --list --set-upstream-to=origin/main",
		"git branch --list --track new", "git branch --list --unknown", "git branch -- new --list",
		"stat --format='%s' protected/file", "stat --format='%s' /etc/passwd",
		"stat --formatOops source", "stat --format='%s' --output=file source",
		"stat --format='%s' docs/{1..257}.png", "stat --format='%s' source; touch ./marker",
		"grep -A8x needle source", "rg -C8x needle source", "grep -B8 needle protected/file",
		"grep -A8 needle /etc/passwd", "grep -A8 needle source | touch ./marker",
		"systemctl start example.service", "systemctl stop example.service",
		"systemctl enable example.service", "systemctl mask example.service",
		"gsettings set org.example setting true",
	} {
		t.Run(command, func(t *testing.T) { checkReadOnlyCommand(t, command, false) })
	}
	for _, command := range []string{
		"git merge-base --is-ancestor HEAD HEAD", "git check-ignore -v docs/file",
		"git show-ref --heads", "git branch --list '*example*'",
	} {
		for _, prefix := range []string{"git -c core.pager=custom ", "git --config-env=core.pager=PAGER ", "git --git-dir=/etc ", "git -C /etc ", "./git "} {
			unsafe := prefix + strings.TrimPrefix(command, "git ")
			t.Run(unsafe, func(t *testing.T) { checkReadOnlyCommand(t, unsafe, false) })
		}
		for _, separator := range []string{";", "&&", "||", "|"} {
			unsafe := command + " " + separator + " touch ./marker"
			t.Run(unsafe, func(t *testing.T) { checkReadOnlyCommand(t, unsafe, false) })
		}
		for _, key := range []string{"GIT_CONFIG_COUNT", "GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_DIR"} {
			t.Run(command+key, func(t *testing.T) {
				request := testRequest(t, command)
				request.Env[key] = "unsafe"
				checkReadOnlyRequest(t, request, false)
			})
		}
	}
}

func TestReadOnlyScopedGlobBoundaries(t *testing.T) {
	for _, command := range []string{
		"cat node_modules/@scope/pkg/*.md", "stat --format='%s' node_modules/@scope/pkg/*.md",
	} {
		t.Run(command, func(t *testing.T) {
			request := testRequest(t, command)
			path := filepath.Join(request.CWD, "node_modules/@scope/pkg")
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/etc/passwd", filepath.Join(path, "escape.md")); err != nil {
				t.Fatal(err)
			}
			checkReadOnlyRequest(t, request, false)
		})
	}
}

func TestReadOnlyHistoricalCorpus(t *testing.T) {
	var corpus struct {
		Candidates, StatusQueries []struct {
			AuditID string `json:"auditId"`
			Command string `json:"command"`
			Allow   bool   `json:"allow"`
		}
	}
	data, err := os.ReadFile("testdata/read-only-corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range append(corpus.Candidates, corpus.StatusQueries...) {
		t.Run(tc.AuditID, func(t *testing.T) {
			request := testRequest(t, tc.Command)
			request.Command = strings.ReplaceAll(request.Command, "CWD", request.CWD)
			for _, path := range []string{
				"README.md", "docs/example.md", ".scratch/project-a-mvp/issues/01.md",
				"tmp/project-a-notes.md", "tmp/acceptance.md", "tests/checklist.spec.ts", "tests/lists.spec.ts",
				"node_modules/@opencode/plugin/dist/context.d.ts", "node_modules/@opencode/plugin/dist/tui/context.d.ts",
			} {
				full := filepath.Join(request.CWD, path)
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			checkReadOnlyRequest(t, request, tc.Allow)
		})
	}
}

func TestReadOnlyGitMergeBase(t *testing.T) {
	checkReadOnlyCommand(t, "git merge-base --is-ancestor 898abe6 d9fcad1", true)
}

func TestReadOnlyGitCheckIgnore(t *testing.T) {
	for _, command := range []string{"git check-ignore docs/research.md .scratch/feature/spec.md", "git check-ignore -v docs/backup-format.md"} {
		t.Run(command, func(t *testing.T) { checkReadOnlyCommand(t, command, true) })
	}
}

func TestReadOnlyGitShowRef(t *testing.T) {
	checkReadOnlyCommand(t, "git show-ref --heads", true)
}

func TestReadOnlyGitBranchList(t *testing.T) {
	for _, command := range []string{"git branch --list '*02*'", "git branch --list ticket/13-example", "git branch --list '*review*' && git show --stat --oneline HEAD && git status --porcelain=v1"} {
		t.Run(command, func(t *testing.T) { checkReadOnlyCommand(t, command, true) })
	}
}

func TestReadOnlyStatFormat(t *testing.T) {
	checkReadOnlyCommand(t, "stat --format='%F %s bytes %n' docs/data.csv docs/screenshots/{1..8}.png", true)
}

func TestReadOnlyRipgrepGlobOption(t *testing.T) {
	checkReadOnlyCommand(t, "rg -n status src -g '*.ts' | head -20", true)
}

func TestReadOnlyGrepAttachedContext(t *testing.T) {
	for _, command := range []string{
		"git remote -v; grep -A8 '\"scripts\"' package.json",
		"grep -B8 needle source", "grep -C8 needle source", "rg -A8 needle source",
	} {
		t.Run(command, func(t *testing.T) { checkReadOnlyCommand(t, command, true) })
	}
}
