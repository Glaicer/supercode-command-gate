package reviewer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

const reviewedTrustVersion = "reviewed-command-trust-v1"

type developmentLaunch struct {
	Project     string            `json:"project"`
	Generation  string            `json:"generation"`
	Command     string            `json:"command"`
	Environment string            `json:"environment"`
	Env         map[string]string `json:"env"`
	Policy      PolicyConfig      `json:"policy"`
	Versions    []string          `json:"versions"`
	Inputs      map[string]string `json:"inputs"`
	Evidence    []scriptEvidence  `json:"-"`
}

type reviewedCommandTrust struct {
	Version    string                        `json:"version"`
	Generation string                        `json:"generation"`
	Project    string                        `json:"project"`
	Entries    map[string]reviewedTrustEntry `json:"entries"`
}

type reviewedTrustEntry struct {
	Fingerprint string    `json:"fingerprint"`
	AuditID     string    `json:"auditId"`
	CreatedAt   time.Time `json:"createdAt"`
}

func launchDigest(value any) string {
	payload, _ := json.Marshal(value)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func singleDevelopmentCommand(text string) (IRCommand, bool) {
	ir := ParseShell(text)
	if ir.ParseError != "" || ir.Dynamic || len(ir.Commands) != 1 || len(ir.Redirections) != 0 || len(ir.Executions) != 1 || ir.Executions[0].Kind != "command" {
		return IRCommand{}, false
	}
	cmd := ir.Commands[0]
	if !cmd.Static || len(cmd.Arguments) == 0 || strings.TrimSpace(text) != strings.TrimSpace(text[cmd.Span.Start:cmd.Span.End]) {
		return IRCommand{}, false
	}
	return cmd, true
}

func developmentLaunchFor(request Request, config Config) (developmentLaunch, string) {
	launch := developmentLaunch{Command: request.Command, Environment: request.ExecutionEnvDigest, Env: request.Env, Policy: config.Policy, Versions: []string{reviewedTrustVersion, DeterministicPolicyVersion, AssessorMapperVersion, CatastrophicCatalogVersion, ShellIRSchemaVersion}, Inputs: map[string]string{}}
	if len(request.ExecutionEnvDigest) != 64 || request.Env["PATH"] == "" || request.Env["HOME"] == "" {
		return launch, "incomplete invocation environment"
	}
	for _, key := range []string{"NODE_OPTIONS", "NODE_PATH", "BASH_ENV", "ENV", "npm_config_script_shell", "NPM_CONFIG_SCRIPT_SHELL"} {
		if request.Env[key] != "" {
			return launch, "unsupported runtime override"
		}
	}
	absolute, err := filepath.Abs(request.CWD)
	if err != nil {
		return launch, "unresolved working package"
	}
	cwd, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return launch, "unresolved working package"
	}
	launch.Project = cwd
	// shortcut: workspace selectors and inherited parent packages need explicit resolution before extending this first slice.
	if request.WorkspaceRoot != nil && canonicalOrClean(*request.WorkspaceRoot, "") != cwd {
		return launch, "workspace package resolution unsupported"
	}
	cmd, ok := singleDevelopmentCommand(request.Command)
	if !ok {
		return launch, "unsupported whole program"
	}
	manifest, err := os.ReadFile(filepath.Join(cwd, "package.json"))
	if err != nil || len(manifest) > maxGrantEvidenceBytes {
		return launch, "missing working package manifest"
	}
	var pkg struct {
		Scripts    map[string]string `json:"scripts"`
		Workspaces any               `json:"workspaces"`
	}
	if json.Unmarshal(manifest, &pkg) != nil || pkg.Workspaces != nil {
		return launch, "unsupported working package"
	}
	launch.Inputs[filepath.Join(cwd, "package.json")] = digestScript(string(manifest))
	snapshot := func(path string, required bool) bool {
		resolved, err := filepath.EvalSymlinks(path)
		if errors.Is(err, os.ErrNotExist) && !required {
			launch.Inputs[path] = "absent"
			return true
		}
		if err != nil {
			return false
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
		file, err := os.Open(resolved)
		if err != nil {
			return false
		}
		digest := sha256.New()
		_, err = io.Copy(digest, file)
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return false
		}
		launch.Inputs[path] = resolved + ":" + info.Mode().String() + ":" + hex.EncodeToString(digest.Sum(nil))
		return true
	}
	snapshotExecutable := func(path string) bool {
		if !snapshot(path, true) {
			return false
		}
		file, err := os.Open(path)
		if err != nil {
			return false
		}
		content, err := io.ReadAll(io.LimitReader(file, 64<<10))
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return false
		}
		if strings.HasPrefix(string(content), "#!/bin/sh") || strings.HasPrefix(string(content), "#!/usr/bin/env sh") {
			matches := regexp.MustCompile(`"\$basedir/([^"$]+)"`).FindAllStringSubmatch(string(content), -1)
			if len(matches) == 0 {
				return false
			}
			base := filepath.Dir(path)
			if strings.Contains(string(content), "Resolve $0 through symlinks") {
				resolved, err := filepath.EvalSymlinks(path)
				if err != nil {
					return false
				}
				base = filepath.Dir(resolved)
			}
			for _, match := range matches {
				required := match[1] != "node" && match[1] != "node.exe"
				if !snapshot(filepath.Join(base, match[1]), required) {
					return false
				}
			}
			if !snapshot(filepath.Join(base, "node"), false) {
				return false
			}
		}
		return true
	}
	resolveExecutable := func(name string, local bool) bool {
		paths := filepath.SplitList(request.Env["PATH"])
		if local {
			paths = append([]string{filepath.Join(cwd, "node_modules", ".bin")}, paths...)
		}
		for _, dir := range paths {
			if !filepath.IsAbs(dir) {
				return false
			}
			path := filepath.Join(dir, name)
			info, err := os.Stat(path)
			if err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
				return snapshotExecutable(path)
			}
		}
		return false
	}
	if !resolveExecutable("node", false) {
		return launch, "unresolved node executable"
	}
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", "node_modules/.modules.yaml", "node_modules/.package-lock.json", ".npmrc", ".pnpmfile.cjs", "pnpmfile.cjs"} {
		if !snapshot(filepath.Join(cwd, name), false) {
			return launch, "unreadable dependency or manager input"
		}
	}
	for _, name := range []string{".pnpmfile.cjs", "pnpmfile.cjs"} {
		if launch.Inputs[filepath.Join(cwd, name)] != "absent" {
			return launch, "dynamic package manager hooks"
		}
	}
	if !snapshot(filepath.Join(request.Env["HOME"], ".npmrc"), false) {
		return launch, "unreadable user manager configuration"
	}
	if request.Env["npm_config_userconfig"] != "" || request.Env["NPM_CONFIG_USERCONFIG"] != "" || request.Env["npm_config_globalconfig"] != "" || request.Env["NPM_CONFIG_GLOBALCONFIG"] != "" {
		return launch, "external manager configuration"
	}
	for _, path := range []string{filepath.Join(cwd, ".npmrc"), filepath.Join(request.Env["HOME"], ".npmrc"), "/etc/npmrc", "/usr/local/etc/npmrc", filepath.Join(request.Env["HOME"], ".config", "pnpm", "rc")} {
		if !snapshot(path, false) {
			return launch, "unreadable manager configuration"
		}
		content, err := os.ReadFile(path)
		if err == nil && (strings.Contains(string(content), "${") || strings.Contains(string(content), "script-shell") || strings.Contains(string(content), "globalconfig") || strings.Contains(string(content), "userconfig") || strings.Contains(string(content), "node-options") || strings.Contains(string(content), "use-node-version")) {
			return launch, "indirect manager configuration"
		}
	}
	if launch.Inputs[filepath.Join(cwd, "pnpm-workspace.yaml")] != "absent" {
		return launch, "workspace configuration unsupported"
	}
	if strings.Contains(string(manifest), `"executionEnv"`) {
		return launch, "package runtime selection unsupported"
	}
	if !snapshot("/etc/npmrc", false) {
		return launch, "unreadable global manager configuration"
	}
	configs := []string{"tsconfig*.json", ".eslintrc*", "eslint.config.*", ".eslintignore", ".prettierrc*", "prettier.config.*", ".prettierignore", "vitest.config.*", "vite.config.*", "playwright.config.*"}
	for _, pattern := range configs {
		files, err := filepath.Glob(filepath.Join(cwd, pattern))
		if err != nil {
			return launch, "unresolved tool configuration"
		}
		launch.Inputs["glob:"+pattern] = launchDigest(files)
		for _, file := range files {
			if !snapshot(file, true) {
				return launch, "unreadable tool configuration"
			}
			content, err := os.ReadFile(file)
			if err != nil {
				return launch, "unreadable tool configuration"
			}
			if strings.HasSuffix(file, ".js") || strings.HasSuffix(file, ".cjs") || strings.HasSuffix(file, ".mjs") || strings.HasSuffix(file, ".ts") || strings.HasSuffix(file, ".cts") || strings.HasSuffix(file, ".mts") {
				return launch, "executable tool configuration"
			}
			if !strings.HasSuffix(file, "ignore") && !json.Valid(content) {
				return launch, "non-JSON tool configuration"
			}
			if strings.Contains(string(content), "plugins") || strings.Contains(string(content), "parser") || strings.Contains(string(content), "extends") || strings.Contains(string(content), "references") || strings.Contains(string(content), "import") || strings.Contains(string(content), "require") || strings.Contains(string(content), "process.") {
				return launch, "indirect tool configuration"
			}
		}
	}
	for parent := filepath.Dir(cwd); ; parent = filepath.Dir(parent) {
		for _, pattern := range append(configs, "package.json", "pnpm-workspace.yaml", ".npmrc") {
			files, err := filepath.Glob(filepath.Join(parent, pattern))
			if err != nil || len(files) != 0 {
				return launch, "inherited package or tool configuration"
			}
			launch.Inputs["parent:"+filepath.Join(parent, pattern)] = launchDigest(files)
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	if cmd.Name != "npm" && cmd.Name != "pnpm" && !strings.HasPrefix(cmd.Name, "./node_modules/.bin/") {
		return launch, "only package-manager and explicit local executable forms supported"
	}
	seen := map[string]bool{}
	var expand func(IRCommand, int) bool
	expand = func(command IRCommand, depth int) bool {
		if depth > 16 {
			return false
		}
		args := command.Arguments
		manager := command.Name == "npm" || command.Name == "pnpm"
		if manager {
			if !resolveExecutable(command.Name, false) || len(args) < 2 {
				return false
			}
			at := 1
			if args[at] == "exec" {
				if command.Name != "pnpm" || len(args) < 3 {
					return false
				}
				child := command
				child.Name = args[2]
				child.Arguments = args[2:]
				return expand(child, depth+1)
			}
			if args[at] == "run" {
				at++
				if len(args) <= at {
					return false
				}
			} else if command.Name == "npm" && args[at] != "test" {
				return false
			}
			name := args[at]
			if slices.Contains([]string{"install", "add", "remove", "publish", "push", "update", "deploy", "dlx", "start", "dev", "rebuild", "link", "unlink"}, name) {
				return false
			}
			body, exists := pkg.Scripts[name]
			if !exists || seen[name] {
				return false
			}
			seen[name] = true
			defer delete(seen, name)
			for _, script := range []string{"pre" + name, name, "post" + name} {
				body, exists = pkg.Scripts[script]
				if !exists {
					continue
				}
				launch.Evidence = append(launch.Evidence, scriptEvidence{Interpreter: command.Name, Kind: "package-script", Path: filepath.Join(cwd, "package.json") + "#" + script, Content: body, Digest: digestScript(body), Status: scriptStatusComplete})
				child, ok := singleDevelopmentCommand(body)
				if !ok {
					return false
				}
				if script == name && len(args) > at+1 {
					extra := args[at+1:]
					if extra[0] == "--" {
						extra = extra[1:]
					}
					child.Arguments = append(child.Arguments, extra...)
				}
				if !expand(child, depth+1) {
					return false
				}
			}
			return true
		}
		if strings.HasPrefix(command.Name, "./node_modules/.bin/") {
			if !snapshotExecutable(filepath.Join(cwd, command.Name)) {
				return false
			}
			command.Name = filepath.Base(command.Name)
		} else if !resolveExecutable(command.Name, true) {
			return false
		}
		for _, arg := range args[1:] {
			if strings.HasPrefix(arg, "-") && !slices.Contains([]string{"--noEmit", "--pretty", "--check", "--max-warnings", "--runInBand", "--no-file-parallelism", "--passWithNoTests"}, arg) {
				return false
			}
		}
		switch command.Name {
		case "tsc":
			return slices.Contains(args, "--noEmit") && !slices.Contains(args, "--build") && !slices.Contains(args, "-b")
		case "eslint":
			return !slices.Contains(args, "--fix") && !slices.Contains(args, "--fix-dry-run")
		case "prettier":
			return slices.Contains(args, "--check") && !slices.Contains(args, "--write") && !slices.Contains(args, "-w")
		case "vitest":
			return len(args) > 1 && args[1] == "run" && !slices.Contains(args, "--watch")
		case "playwright":
			return len(args) > 1 && args[1] == "test" && !slices.Contains(args, "--ui") && !slices.Contains(args, "--debug")
		}
		return false
	}
	if !expand(cmd, 0) {
		return launch, "unsupported development action or executable"
	}
	return launch, ""
}

func reviewedTrustPath(stateDir, project string) string {
	return filepath.Join(stateDir, "reviewed-trust", launchDigest(project)+".json")
}

func readReviewedTrust(path, project string) reviewedCommandTrust {
	state := reviewedCommandTrust{Version: reviewedTrustVersion, Project: project, Entries: map[string]reviewedTrustEntry{}}
	payload, err := os.ReadFile(path)
	if err != nil || len(payload) > maxGrantEvidenceBytes {
		return state
	}
	var stored reviewedCommandTrust
	if json.Unmarshal(payload, &stored) != nil || stored.Version != reviewedTrustVersion || stored.Project != project || len(stored.Entries) > 256 {
		return state
	}
	if stored.Entries != nil {
		return stored
	}
	return state
}

func mutateReviewedTrust(stateDir, project string, mutate func(*reviewedCommandTrust)) error {
	path := reviewedTrustPath(stateDir, project)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	unlock, err := acquireGrantLock(path)
	if err != nil {
		return err
	}
	defer unlock()
	state := readReviewedTrust(path, project)
	mutate(&state)
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".trust-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(payload)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(file.Name(), path)
}

func findReviewedTrust(stateDir string, launch developmentLaunch) (reviewedTrustEntry, bool) {
	key := launchDigest(launch)
	state := readReviewedTrust(reviewedTrustPath(stateDir, launch.Project), launch.Project)
	entry, ok := state.Entries[key]
	auditID, err := hex.DecodeString(entry.AuditID)
	return entry, ok && entry.Fingerprint == key && err == nil && len(auditID) == 16 && time.Since(entry.CreatedAt) < 30*24*time.Hour && !entry.CreatedAt.After(time.Now())
}

func saveReviewedTrust(stateDir string, launch developmentLaunch, auditID string) (bool, error) {
	saved := false
	err := mutateReviewedTrust(stateDir, launch.Project, func(state *reviewedCommandTrust) {
		if state.Generation != launch.Generation {
			return
		}
		key := launchDigest(launch)
		state.Entries[key] = reviewedTrustEntry{Fingerprint: key, AuditID: auditID, CreatedAt: time.Now().UTC()}
		saved = true
		if len(state.Entries) > 256 {
			keys := make([]string, 0, len(state.Entries))
			for key := range state.Entries {
				keys = append(keys, key)
			}
			sort.Slice(keys, func(i, j int) bool { return state.Entries[keys[i]].CreatedAt.Before(state.Entries[keys[j]].CreatedAt) })
			delete(state.Entries, keys[0])
		}
	})
	return saved, err
}

func ResetReviewedTrust(project string, options Options) error {
	absolute, err := filepath.Abs(project)
	if err != nil {
		return err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return err
	}
	req := Request{CWD: canonical, WorkspaceRoot: &canonical, Session: Session{ID: "trust-reset", Host: "aar"}}
	config, err := resolveReviewerConfig(req, options)
	if err != nil {
		return err
	}
	stateDir, err := reviewerStateDirectory(options, config)
	if err != nil {
		return err
	}
	return mutateReviewedTrust(stateDir, canonical, func(state *reviewedCommandTrust) {
		state.Entries = map[string]reviewedTrustEntry{}
		state.Generation, _ = randomID()
	})
}
