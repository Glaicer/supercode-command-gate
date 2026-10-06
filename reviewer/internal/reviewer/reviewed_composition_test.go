package reviewer_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/supercode/auto-approval-reviewer/internal/reviewer"
)

func reviewedChainFixture(t *testing.T) (reviewer.Request, reviewer.Options, *fakeModelCall) {
	t.Helper()
	req, opts, fake := trustFixture(t)
	if err := os.WriteFile(filepath.Join(req.CWD, "node_modules/.bin/eslint"), []byte("#!/usr/bin/env node\nfixture eslint\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(req.CWD, "package.json"), []byte(`{"scripts":{"typecheck":"tsc --noEmit","lint":"eslint .","test":"vitest run"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(req.CWD, "node_modules/.bin/vitest"), []byte("#!/usr/bin/env node\nfixture vitest\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"pnpm typecheck", "pnpm lint"} {
		req.Command = command
		decision, err := reviewer.Check(req, opts)
		if err != nil || decision.Source != "assessor" {
			t.Fatalf("seed %s: %#v %v", command, decision, err)
		}
	}
	return req, opts, fake
}

func TestReviewedCompositionCoversEveryStaticSequenceBranch(t *testing.T) {
	for _, command := range []string{"pnpm typecheck; pnpm lint", "pnpm typecheck && pnpm lint", "pnpm typecheck || pnpm lint", "pnpm typecheck && git status --short", "printf ok | cat; pnpm typecheck"} {
		t.Run(command, func(t *testing.T) {
			req, opts, fake := reviewedChainFixture(t)
			req.Command = command
			req.Session.ID = "new-session"
			decision, err := reviewer.Check(req, opts)
			if err != nil || decision.Decision != "allow" || decision.Source != "reviewed-trust" || len(fake.requests) != 2 {
				t.Fatalf("%#v %v calls=%d", decision, err, len(fake.requests))
			}
		})
	}
}

func TestReviewedCompositionAllowsOnlySupportedOutputPipelines(t *testing.T) {
	for _, command := range []string{"pnpm test | tail -n 20", "pnpm test 2>&1 | tail -20", "pnpm test | head -n 10 | tail -n 5", "pnpm test 2>&1 | head -10; pnpm lint"} {
		t.Run(command, func(t *testing.T) {
			req, opts, fake := reviewedChainFixture(t)
			req.Command = "pnpm test"
			if _, err := reviewer.Check(req, opts); err != nil {
				t.Fatal(err)
			}
			req.Command = command
			req.Session.ID = "pipeline-session"
			decision, err := reviewer.Check(req, opts)
			if err != nil || decision.Source != "reviewed-trust" || len(fake.requests) != 3 {
				t.Fatalf("%#v %v calls=%d", decision, err, len(fake.requests))
			}
		})
	}
}

func TestReviewedCompositionUnknownElementsUseOneWholeProgramAssessment(t *testing.T) {
	for _, command := range []string{
		"pnpm typecheck && unknown-tool", "pnpm typecheck || unknown-tool", "pnpm typecheck | unknown-consumer",
		"pnpm typecheck -- --pretty false && pnpm lint", "pnpm typecheck > ./unknown-target && pnpm lint",
		"pnpm typecheck 2>&1 > ./output | tail -20", "pnpm typecheck > ./output 2>&1 | tail -20",
		"pnpm typecheck 1>&2 | tail -20", "pnpm typecheck | tail --follow", "pnpm typecheck 2>&1 2>&1 | tail -20", "pnpm typecheck < ./input && pnpm lint",
		"printf input | pnpm typecheck", "VALUE=1 pnpm typecheck && pnpm lint",
		"pnpm typecheck $(printf flag) && pnpm lint", "pnpm typecheck <(printf input) && pnpm lint",
		"cd .; pnpm typecheck", "cd . || pnpm typecheck", "pnpm typecheck && cd .; pnpm lint",
		"printf -v VAR changed; pnpm typecheck", "printf modified > ./package.json; pnpm typecheck",
	} {
		t.Run(command, func(t *testing.T) {
			req, opts, fake := reviewedChainFixture(t)
			if err := os.WriteFile(filepath.Join(req.CWD, "input"), []byte("input"), 0600); err != nil {
				t.Fatal(err)
			}
			req.Command = command
			decision, err := reviewer.Check(req, opts)
			if err != nil || decision.Source != "assessor" || len(fake.requests) != 3 {
				t.Fatalf("%#v %v calls=%d", decision, err, len(fake.requests))
			}
			var prompt struct {
				Command string `json:"command"`
			}
			if err := json.Unmarshal([]byte(fake.requests[2].UserPrompt), &prompt); err != nil || prompt.Command != command {
				t.Fatalf("Assessor received %q, want complete %q: %v", prompt.Command, command, err)
			}
		})
	}
}

func TestReviewedCompositionHardDenyCoversSuffixAndConditionalBranch(t *testing.T) {
	for _, operator := range []string{";", "&&", "||"} {
		t.Run(operator, func(t *testing.T) {
			req, opts, fake := reviewedChainFixture(t)
			req.Command = "pnpm typecheck " + operator + " rm -rf /"
			decision, err := reviewer.Check(req, opts)
			if err != nil || decision.Source != "hard-deny" || decision.Decision != "deny" || len(fake.requests) != 2 {
				t.Fatalf("%#v %v calls=%d", decision, err, len(fake.requests))
			}
		})
	}
}

func TestReviewedCompositionCwdChangesDoNotBorrowLaunchTrust(t *testing.T) {
	for _, command := range []string{"cd sub; pnpm typecheck", "cd sub && pnpm typecheck", "cd sub || pnpm typecheck", "pnpm typecheck || cd sub; pnpm lint"} {
		t.Run(command, func(t *testing.T) {
			req, opts, fake := reviewedChainFixture(t)
			if err := os.Mkdir(filepath.Join(req.CWD, "sub"), 0700); err != nil {
				t.Fatal(err)
			}
			req.Command = command
			decision, err := reviewer.Check(req, opts)
			if err != nil || decision.Source != "assessor" || len(fake.requests) != 3 {
				t.Fatalf("%#v %v calls=%d", decision, err, len(fake.requests))
			}
		})
	}
	req, opts, fake := reviewedChainFixture(t)
	if err := os.Mkdir(filepath.Join(req.CWD, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	req.Command = "cd sub | head -20; pnpm typecheck"
	decision, err := reviewer.Check(req, opts)
	if err != nil || decision.Source != "reviewed-trust" || len(fake.requests) != 2 {
		t.Fatalf("pipeline changed parent context: %#v %v calls=%d", decision, err, len(fake.requests))
	}
}

func TestReviewedCompositionQuotedSeparatorsStayInsideIndividualLaunch(t *testing.T) {
	req, opts, fake := reviewedChainFixture(t)
	individual := `pnpm typecheck -- --pretty 'false && ; |'`
	req.Command = individual
	if decision, err := reviewer.Check(req, opts); err != nil || decision.Source != "assessor" {
		t.Fatalf("%#v %v", decision, err)
	}
	req.Command = individual + " && pnpm lint"
	decision, err := reviewer.Check(req, opts)
	if err != nil || decision.Source != "reviewed-trust" || len(fake.requests) != 3 || len(decision.ReviewedCoverage) != 2 {
		t.Fatalf("%#v %v calls=%d", decision, err, len(fake.requests))
	}
}

func TestReviewedCompositionResetAndStaleNodeReturnEntireProgramToAssessor(t *testing.T) {
	for _, change := range []string{"reset", "lint-executable", "project"} {
		t.Run(change, func(t *testing.T) {
			req, opts, fake := reviewedChainFixture(t)
			switch change {
			case "reset":
				if err := reviewer.ResetReviewedTrust(req.CWD, opts); err != nil {
					t.Fatal(err)
				}
			case "lint-executable":
				if err := os.WriteFile(filepath.Join(req.CWD, "node_modules/.bin/eslint"), []byte("changed local eslint executable"), 0700); err != nil {
					t.Fatal(err)
				}
			case "project":
				other, _, _ := trustFixture(t)
				req.CWD = other.CWD
				req.WorkspaceRoot = other.WorkspaceRoot
				req.Env = other.Env
			}
			req.Command = "pnpm typecheck && pnpm lint"
			decision, err := reviewer.Check(req, opts)
			if err != nil || decision.Source != "assessor" || len(fake.requests) != 3 {
				t.Fatalf("%#v %v calls=%d", decision, err, len(fake.requests))
			}
			if change == "lint-executable" {
				req.Command = "pnpm typecheck"
				next, err := reviewer.Check(req, opts)
				if err != nil || next.Source != "reviewed-trust" || len(fake.requests) != 3 {
					t.Fatalf("unaffected node lost trust: %#v %v", next, err)
				}
			}
		})
	}
}

func TestReviewedCompositionWholeProgramAllowNeverCreatesIndividualTrust(t *testing.T) {
	req, opts, fake := trustFixture(t)
	req.Command = "pnpm typecheck && git status --short"
	if first, err := reviewer.Check(req, opts); err != nil || first.Source != "assessor" {
		t.Fatalf("%#v %v", first, err)
	}
	req.Command = "pnpm typecheck"
	next, err := reviewer.Check(req, opts)
	if err != nil || next.Source != "assessor" || len(fake.requests) != 2 {
		t.Fatalf("compound Allow authorized individual launch: %#v %v", next, err)
	}
	files, err := filepath.Glob(filepath.Join(opts.StateDir, "grants", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		contents, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(contents), `"grants"`) {
			t.Fatalf("compound trust created human grant: %s", contents)
		}
	}
}

func TestReviewedCompositionAuditAndTraceExposeNodeProvenanceWithoutLiterals(t *testing.T) {
	req, opts, fake := reviewedChainFixture(t)
	req.Command = "pnpm typecheck && git status --short"
	decision, err := reviewer.Check(req, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.ReviewedCoverage) != 2 || decision.ReviewedCoverage[0].Source != "reviewed-trust" || decision.ReviewedCoverage[0].OriginAuditID == "" || decision.ReviewedCoverage[1].Source != "auto-allow" || decision.ReviewedCoverage[1].Rule != "AA008" {
		t.Fatalf("coverage=%#v", decision.ReviewedCoverage)
	}
	audit, err := reviewer.Explain(decision.AuditID, opts)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Source           string                      `json:"source"`
		ReviewedCoverage []reviewer.ReviewedCoverage `json:"reviewedCoverage"`
	}
	if err := json.Unmarshal(audit, &record); err != nil {
		t.Fatal(err)
	}
	if record.Source != "reviewed-trust" || len(record.ReviewedCoverage) != 2 {
		t.Fatalf("audit=%s", audit)
	}
	req.Command = `pnpm typecheck && printf '%s' 'SECRET_TOKEN=do-not-retain'`
	next, err := reviewer.Check(req, opts)
	if err != nil || next.Source != "reviewed-trust" || len(fake.requests) != 2 {
		t.Fatalf("%#v %v", next, err)
	}
	records := readReviewLog(t, opts.StateDir)
	hits := 0
	for _, record := range records {
		if record["event"] == "reviewed-composition" && record["status"] == "hit" {
			hits++
			payload, err := json.Marshal(record["coverage"])
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(payload), "SECRET_TOKEN") || strings.Contains(string(payload), "pnpm") {
				t.Fatalf("literal in provenance: %s", payload)
			}
		}
	}
	if hits != 2 {
		t.Fatalf("trace hits=%d, want2", hits)
	}
	payload, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "do-not-retain") {
		t.Fatal("secret leaked into trace")
	}
}

func TestReviewedCompositionUsageCountsOneVerdictPerWholeProgram(t *testing.T) {
	req, opts, fake := reviewedChainFixture(t)
	req.Command = "pnpm typecheck && pnpm lint"
	decision, err := reviewer.Check(req, opts)
	if err != nil || decision.Source != "reviewed-trust" {
		t.Fatalf("%#v %v", decision, err)
	}
	stats, err := reviewer.Stats(opts)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Processed != 3 || stats.LLMFresh != 2 || stats.LLMReused != 1 || stats.Policy != 0 || len(fake.requests) != 2 {
		t.Fatalf("stats=%#v model calls=%d", stats, len(fake.requests))
	}
}
