package reviewer_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glaicer/supercode-command-gate/reviewer/internal/reviewer"
)

func trustFixture(t *testing.T) (reviewer.Request, reviewer.Options, *fakeModelCall) {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	local := filepath.Join(root, "node_modules", ".bin")
	for _, dir := range []string{bin, local} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(bin, "npm"), filepath.Join(bin, "pnpm"), filepath.Join(bin, "node"), filepath.Join(local, "tsc")} {
		if err := os.WriteFile(file, []byte("#!/usr/bin/env node\noriginal executable\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"scripts":{"typecheck":"tsc --noEmit"},"devDependencies":{"typescript":"5.0.0"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte("lockfileVersion: 9"), 0600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":[]}`, `{"risks":[],"uncertainties":[]}`, `{"risks":[],"uncertainties":[]}`}}
	req := reviewer.Request{ExecutionEnvDigest: strings.Repeat("a", 64), SchemaVersion: reviewer.RequestSchemaVersion, Command: "pnpm typecheck", CWD: root, WorkspaceRoot: &root, Env: map[string]string{"PATH": bin, "HOME": root}, Session: reviewer.Session{ID: "first", Host: "opencode"}}
	opts := reviewer.Options{StateDir: t.TempDir(), ModelCall: fake, Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "fake", OnUnavailable: "deny"}}}
	return req, opts, fake
}

func TestReviewedTrustSurvivesSessionAndSourceChanges(t *testing.T) {
	req, opts, fake := trustFixture(t)
	first, err := reviewer.Check(req, opts)
	if err != nil || first.Decision != "allow" {
		t.Fatalf("first: %#v %v", first, err)
	}
	if !strings.Contains(fake.requests[0].UserPrompt, "tsc --noEmit") {
		t.Fatal("assessor did not see package script")
	}
	if err := os.WriteFile(filepath.Join(req.CWD, "source.ts"), []byte("changed ordinary code"), 0600); err != nil {
		t.Fatal(err)
	}
	req.Session.ID = "new-session"
	req.Intent.AssistantRationale = "different rationale"
	second, err := reviewer.Check(req, opts)
	if err != nil || second.Source != "reviewed-trust" || len(fake.requests) != 1 {
		t.Fatalf("second: %#v %v calls=%d", second, err, len(fake.requests))
	}
}

func TestReviewedTrustLaunchChangesRequireFreshAssessment(t *testing.T) {
	for _, change := range []string{"args", "script", "hook", "lockfile", "executable", "config", "environment", "policy", "cwd", "composition", "incomplete"} {
		t.Run(change, func(t *testing.T) {
			req, opts, fake := trustFixture(t)
			if _, err := reviewer.Check(req, opts); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "args":
				req.Command += " -- --pretty false"
			case "script":
				os.WriteFile(filepath.Join(req.CWD, "package.json"), []byte(`{"scripts":{"typecheck":"tsc --noEmit --pretty false"}}`), 0600)
			case "hook":
				os.WriteFile(filepath.Join(req.CWD, "package.json"), []byte(`{"scripts":{"typecheck":"tsc --noEmit","pretypecheck":"tsc --noEmit"}}`), 0600)
			case "lockfile":
				os.WriteFile(filepath.Join(req.CWD, "pnpm-lock.yaml"), []byte("changed"), 0600)
			case "executable":
				os.WriteFile(filepath.Join(req.CWD, "node_modules/.bin/tsc"), []byte("changed executable"), 0700)
			case "config":
				os.WriteFile(filepath.Join(req.CWD, "tsconfig.json"), []byte(`{"compilerOptions":{"strict":true}}`), 0600)
			case "environment":
				req.ExecutionEnvDigest = strings.Repeat("b", 64)
			case "policy":
				opts.Config.Policy.CategoryOverrides = map[string]string{"network": "deny"}
			case "cwd":
				root := t.TempDir()
				req.CWD = root
				req.WorkspaceRoot = &root
			case "composition":
				req.Command += " && touch marker"
			case "incomplete":
				req.ExecutionEnvDigest = ""
			}
			req.Session.ID = "second"
			decision, err := reviewer.Check(req, opts)
			if err != nil || decision.Source == "reviewed-trust" || len(fake.requests) != 2 {
				t.Fatalf("decision=%#v err=%v calls=%d", decision, err, len(fake.requests))
			}
		})
	}
}

func TestResetReviewedTrustReturnsToAssessor(t *testing.T) {
	req, opts, fake := trustFixture(t)
	if _, err := reviewer.Check(req, opts); err != nil {
		t.Fatal(err)
	}
	if err := reviewer.ResetReviewedTrust(req.CWD, opts); err != nil {
		t.Fatal(err)
	}
	decision, err := reviewer.Check(req, opts)
	if err != nil || decision.Source != "assessor" || len(fake.requests) != 2 {
		t.Fatalf("%#v %v calls=%d", decision, err, len(fake.requests))
	}
}

type changingTrustModel struct {
	change func()
	calls  int
}

func (model *changingTrustModel) Call(_ context.Context, _ reviewer.ModelCallRequest) (string, error) {
	model.calls++
	if model.calls == 1 {
		model.change()
	}
	return `{"risks":[],"uncertainties":[]}`, nil
}

func TestReviewedTrustNeverSavesChangedAuditConditions(t *testing.T) {
	for _, change := range []string{"script", "reset"} {
		t.Run(change, func(t *testing.T) {
			req, opts, _ := trustFixture(t)
			model := &changingTrustModel{change: func() {
				if change == "script" {
					if err := os.WriteFile(filepath.Join(req.CWD, "package.json"), []byte(`{"scripts":{"typecheck":"tsc --noEmit --pretty false"}}`), 0600); err != nil {
						t.Fatal(err)
					}
				} else if err := reviewer.ResetReviewedTrust(req.CWD, opts); err != nil {
					t.Fatal(err)
				}
			}}
			opts.ModelCall = model
			if _, err := reviewer.Check(req, opts); err != nil {
				t.Fatal(err)
			}
			callsBefore := model.calls
			next, err := reviewer.Check(req, opts)
			if err != nil || next.Source == "reviewed-trust" || model.calls != callsBefore+1 {
				t.Fatalf("%#v %v calls=%d", next, err, model.calls)
			}
		})
	}
}

func TestReviewedTrustRejectsUnknownAndCorruptRecords(t *testing.T) {
	for _, content := range []string{"not json", `{"version":"unknown","entries":{}}`} {
		t.Run(content, func(t *testing.T) {
			req, opts, fake := trustFixture(t)
			if _, err := reviewer.Check(req, opts); err != nil {
				t.Fatal(err)
			}
			files, err := filepath.Glob(filepath.Join(opts.StateDir, "reviewed-trust", "*.json"))
			if err != nil || len(files) != 1 {
				t.Fatalf("files: %v %v", files, err)
			}
			if err := os.WriteFile(files[0], []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			next, err := reviewer.Check(req, opts)
			if err != nil || next.Source != "assessor" || len(fake.requests) != 2 {
				t.Fatalf("%#v %v calls=%d", next, err, len(fake.requests))
			}
		})
	}
}

func TestReviewedTrustDoesNotPersistAskDenyFailureOrUnknownActions(t *testing.T) {
	for _, scenario := range []string{"ask", "deny", "failure", "unknown-script", "install", "indirect-config", "dynamic-script"} {
		t.Run(scenario, func(t *testing.T) {
			req, opts, fake := trustFixture(t)
			switch scenario {
			case "ask":
				fake.responses = []string{`{"risks":[],"uncertainties":["external authorization is unclear"]}`}
			case "deny":
				opts.Config.Policy.Profile = "strict"
				fake.responses = []string{`{"risks":[{"category":"critical_data_loss","likelihood":"certain","severity":"critical","reversible":false,"affectsProtectedPaths":true,"evidence":"critical data loss"}],"uncertainties":[]}`}
			case "failure":
				fake.responses = nil
			case "unknown-script":
				os.WriteFile(filepath.Join(req.CWD, "package.json"), []byte(`{"scripts":{"typecheck":"arbitrary-tool"}}`), 0600)
			case "install":
				req.Command = "pnpm install"
			case "indirect-config":
				os.WriteFile(filepath.Join(req.CWD, "tsconfig.json"), []byte(`{"extends":"../shared.json"}`), 0600)
			case "dynamic-script":
				os.WriteFile(filepath.Join(req.CWD, "package.json"), []byte(`{"scripts":{"typecheck":"tsc --noEmit && touch marker"}}`), 0600)
			}
			if _, err := reviewer.Check(req, opts); err != nil {
				t.Fatal(err)
			}
			files, err := filepath.Glob(filepath.Join(opts.StateDir, "reviewed-trust", "*.json"))
			if err != nil || len(files) != 0 {
				t.Fatalf("persisted trust: %v %v", files, err)
			}
		})
	}
}

func TestReviewedTrustProcessHelper(t *testing.T) {
	if os.Getenv("AAR_TRUST_TEST_REQUEST") == "" {
		return
	}
	var req reviewer.Request
	if err := json.Unmarshal([]byte(os.Getenv("AAR_TRUST_TEST_REQUEST")), &req); err != nil {
		t.Fatal(err)
	}
	fake := &fakeModelCall{}
	decision, err := reviewer.Check(req, reviewer.Options{StateDir: os.Getenv("AAR_TRUST_TEST_STATE"), ModelCall: fake, Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{Model: "fake", OnUnavailable: "deny"}}})
	if err != nil || decision.Source != "reviewed-trust" || len(fake.requests) != 0 {
		t.Fatalf("%#v %v model calls=%d", decision, err, len(fake.requests))
	}
}

func TestReviewedTrustSurvivesFreshProcessWithoutHumanGrant(t *testing.T) {
	req, opts, _ := trustFixture(t)
	initial, err := reviewer.Check(req, opts)
	if err != nil {
		t.Fatal(err)
	}
	if initial.Source != "assessor" {
		t.Fatalf("initial=%#v", initial)
	}
	req.Session.ID = "different-process-session"
	req.Intent.LatestUserRequest = "new development context"
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(exe, "-test.run=^TestReviewedTrustProcessHelper$")
	command.Env = append(os.Environ(), "AAR_TRUST_TEST_REQUEST="+string(payload), "AAR_TRUST_TEST_STATE="+opts.StateDir)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fresh process: %v %s", err, output)
	}
	grants, err := filepath.Glob(filepath.Join(opts.StateDir, "grants", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range grants {
		contents, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(contents), `"grants"`) {
			t.Fatal("persistent assessor trust created human grant")
		}
	}
}

func TestReviewedTrustStaticScriptChainAndHooksAreDisclosed(t *testing.T) {
	req, opts, fake := trustFixture(t)
	if err := os.WriteFile(filepath.Join(req.CWD, "package.json"), []byte(`{"scripts":{"typecheck":"pnpm run check","check":"tsc --noEmit","pretypecheck":"tsc --noEmit --pretty false","posttypecheck":"tsc --noEmit"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := reviewer.Check(req, opts)
	if err != nil || first.Source != "assessor" {
		t.Fatalf("%#v %v", first, err)
	}
	for _, expected := range []string{"#pretypecheck", "#typecheck", "#check", "#posttypecheck", "tsc --noEmit --pretty false"} {
		if !strings.Contains(fake.requests[0].UserPrompt, expected) {
			t.Fatalf("missing script evidence %s", expected)
		}
	}
	next, err := reviewer.Check(req, opts)
	if err != nil || next.Source != "reviewed-trust" {
		t.Fatalf("%#v %v", next, err)
	}
	payload, err := reviewer.Explain(next.AuditID, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"originAuditId":"`+first.AuditID+`"`) {
		t.Fatalf("origin absent from audit: %s", payload)
	}
}

func TestReviewedTrustConcurrentCommandsKeepSeparateEntries(t *testing.T) {
	req, opts, _ := trustFixture(t)
	prime := req
	prime.Command = "pwd"
	if _, err := reviewer.Check(prime, opts); err != nil {
		t.Fatal(err)
	}
	failures := make(chan error, 2)
	for _, command := range []string{"pnpm typecheck", "pnpm typecheck -- --pretty false"} {
		go func(command string) {
			request := req
			request.Command = command
			request.Session.ID = command
			local := opts
			local.ModelCall = &fakeModelCall{responses: []string{`{"risks":[],"uncertainties":[]}`}}
			decision, err := reviewer.Check(request, local)
			if err == nil && decision.Source != "assessor" {
				err = fmt.Errorf("unexpected source %s", decision.Source)
			}
			failures <- err
		}(command)
	}
	for range 2 {
		if err := <-failures; err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{"pnpm typecheck", "pnpm typecheck -- --pretty false"} {
		req.Command = command
		fake := &fakeModelCall{}
		opts.ModelCall = fake
		decision, err := reviewer.Check(req, opts)
		if err != nil || decision.Source != "reviewed-trust" || len(fake.requests) != 0 {
			t.Fatalf("%#v %v", decision, err)
		}
	}
}

func TestReviewedTrustSupportedPackageAndLocalExecForms(t *testing.T) {
	for _, command := range []string{"npm run typecheck", "pnpm run typecheck", "pnpm exec tsc --noEmit", "./node_modules/.bin/tsc --noEmit"} {
		t.Run(command, func(t *testing.T) {
			req, opts, fake := trustFixture(t)
			req.Command = command
			first, err := reviewer.Check(req, opts)
			if err != nil || first.Source != "assessor" {
				t.Fatalf("%#v %v", first, err)
			}
			req.Session.ID = "later"
			next, err := reviewer.Check(req, opts)
			if err != nil || next.Source != "reviewed-trust" || len(fake.requests) != 1 {
				t.Fatalf("%#v %v calls=%d", next, err, len(fake.requests))
			}
		})
	}
}

func TestReviewedTrustDetectsChangedPnpmShimTarget(t *testing.T) {
	req, opts, fake := trustFixture(t)
	target := filepath.Join(req.CWD, "node_modules", "typescript", "bin", "tsc")
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("original target"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(req.CWD, "node_modules/.bin/tsc"), []byte("#!/bin/sh\nbasedir=$(dirname \"$0\")\nexec node \"$basedir/../typescript/bin/tsc\" \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := reviewer.Check(req, opts); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("locally replaced target"), 0700); err != nil {
		t.Fatal(err)
	}
	next, err := reviewer.Check(req, opts)
	if err != nil || next.Source != "assessor" || len(fake.requests) != 2 {
		t.Fatalf("%#v %v calls=%d", next, err, len(fake.requests))
	}
}
