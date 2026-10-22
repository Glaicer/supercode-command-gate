package reviewer

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	pathExistencePresent = "present"
	pathExistenceAbsent  = "absent"
	pathExistenceUnknown = "unknown"
)

type assessorParserHints struct {
	Commands        []assessorCommandHint `json:"commands,omitempty"`
	Dynamic         bool                  `json:"dynamic"`
	DynamicFeatures []string              `json:"dynamicFeatures,omitempty"`
	ParseError      string                `json:"parseError,omitempty"`
}

type assessorCommandHint struct {
	Argv   []string `json:"argv,omitempty"`
	Source string   `json:"source,omitempty"`
}

type assessorPathHint struct {
	Source        string                  `json:"source"`
	Role          string                  `json:"role"`
	CommandIndex  *int                    `json:"commandIndex,omitempty"`
	ArgumentIndex *int                    `json:"argumentIndex,omitempty"`
	Resolution    *assessorPathResolution `json:"resolution,omitempty"`
}

type assessorPathResolution struct {
	Basis           string `json:"basis"`
	ResolvedPath    string `json:"resolvedPath"`
	Existence       string `json:"existence"`
	Protected       bool   `json:"protected"`
	InsideWorkspace bool   `json:"insideWorkspace"`
	InsideTemporary bool   `json:"insideTemporary"`
}

type pathCWD struct {
	cwd      string
	known    bool
	inferred bool
}

func compactParserHints(source string, ir ShellIR) assessorParserHints {
	hints := assessorParserHints{
		Dynamic:         ir.Dynamic,
		DynamicFeatures: append([]string(nil), ir.DynamicFeatures...),
		ParseError:      ir.ParseError,
	}
	for _, command := range ir.Commands {
		hint := assessorCommandHint{}
		if argv, ok := commandArgv(command); ok {
			hint.Argv = append([]string(nil), argv...)
		} else {
			hint.Source = sourceSpan(source, command.Span)
			if strings.TrimSpace(hint.Source) == strings.TrimSpace(source) {
				// The command field already carries the whole program verbatim.
				continue
			}
		}
		hints.Commands = append(hints.Commands, hint)
	}
	return hints
}

// commandArgv returns the exact argv of a dynamic command whose words are all
// static. Such words are intact no matter why the command as a whole is not
// static, except for alias expansion, which rewrites them.
func commandArgv(command IRCommand) ([]string, bool) {
	if command.Static {
		return command.Arguments, true
	}
	if command.Name == "alias" || command.Name == "unalias" {
		return nil, false
	}
	if len(command.ArgumentFacts) == 0 || len(command.Arguments) != len(command.ArgumentFacts) {
		return nil, false
	}
	for _, argument := range command.ArgumentFacts {
		if !argument.Static || argument.Value == "" {
			return nil, false
		}
	}
	return command.Arguments, true
}

// pathCWDBySpan maps each path candidate to the directory it is evaluated in.
// It tracks static cd commands in execution order and never guesses after a
// directory change it cannot follow.
func pathCWDBySpan(ir ShellIR, initial string, env map[string]string) map[IRSpan]pathCWD {
	contexts := map[IRSpan]pathCWD{}
	walkPathContexts(ir, ir.Executions, pathCWD{cwd: initial, known: true}, env, contexts)
	return contexts
}

func walkPathContexts(ir ShellIR, executions []IRExecution, state pathCWD, env map[string]string, contexts map[IRSpan]pathCWD) pathCWD {
	for _, execution := range executions {
		state = walkPathContext(ir, execution, state, env, contexts)
	}
	return state
}

func walkPathContext(ir ShellIR, execution IRExecution, state pathCWD, env map[string]string, contexts map[IRSpan]pathCWD) pathCWD {
	for _, index := range execution.RedirectionIndexes {
		if index < 0 || index >= len(ir.Redirections) {
			continue
		}
		redirection := ir.Redirections[index]
		if !redirection.HereDocument {
			contexts[redirection.TargetSpan] = state
		}
	}

	switch execution.Kind {
	case "command":
		if execution.CommandIndex < 0 || execution.CommandIndex >= len(ir.Commands) {
			return state
		}
		command := ir.Commands[execution.CommandIndex]
		for _, argument := range command.ArgumentFacts {
			contexts[argument.Span] = state
		}
		if command.Name == "cd" {
			return cdPathContext(command, state, env)
		}
		return state
	case "pipeline":
		// Pipeline stages run in subshells; a cd there cannot change the parent.
		for _, child := range execution.Children {
			walkPathContext(ir, child, state, env, contexts)
		}
		return state
	case "and":
		if len(execution.Children) != 2 {
			return pathCWD{}
		}
		left := walkPathContext(ir, execution.Children[0], state, env, contexts)
		return walkPathContext(ir, execution.Children[1], left, env, contexts)
	case "or":
		if len(execution.Children) != 2 {
			return pathCWD{}
		}
		left := walkPathContext(ir, execution.Children[0], state, env, contexts)
		// The right branch runs only when the left one failed, so it still
		// starts from the incoming directory.
		right := walkPathContext(ir, execution.Children[1], state, env, contexts)
		if left.sameDirectory(right) {
			return left
		}
		return pathCWD{}
	case "block":
		return walkPathContexts(ir, execution.Children, state, env, contexts)
	case "subshell":
		walkPathContexts(ir, execution.Children, state, env, contexts)
		return state
	default:
		// Conditional and loop constructs carry no child executions; their
		// nested commands remain in ir.Commands. Later commands keep the prior
		// directory only when nothing inside the construct can change it.
		if !directoryUnchanged(ir, execution.Span) {
			for _, child := range execution.Children {
				walkPathContext(ir, child, state, env, contexts)
			}
			return pathCWD{}
		}
		for _, command := range ir.Commands {
			if !spanContains(execution.Span, command.Span) {
				continue
			}
			for _, argument := range command.ArgumentFacts {
				contexts[argument.Span] = state
			}
		}
		for _, redirection := range ir.Redirections {
			if !redirection.HereDocument && spanContains(execution.Span, redirection.Span) {
				contexts[redirection.TargetSpan] = state
			}
		}
		for _, child := range execution.Children {
			walkPathContext(ir, child, state, env, contexts)
		}
		return state
	}
}

func (state pathCWD) sameDirectory(other pathCWD) bool {
	return state.known == other.known && state.inferred == other.inferred && state.cwd == other.cwd
}

// directoryUnchanged reports whether every command inside the construct is
// static and cannot change the working directory.
func directoryUnchanged(ir ShellIR, span IRSpan) bool {
	if span.Start >= span.End {
		return false
	}
	for _, command := range ir.Commands {
		if !spanContains(span, command.Span) {
			continue
		}
		if command.Name == "cd" || !command.Static {
			return false
		}
	}
	return true
}

func spanContains(outer, inner IRSpan) bool {
	return outer.Start < outer.End && outer.Start <= inner.Start && inner.End <= outer.End
}

func cdPathContext(command IRCommand, state pathCWD, env map[string]string) pathCWD {
	if !state.known || !command.Static {
		return pathCWD{}
	}
	operands := cdOperands(command.Arguments[1:])
	if len(operands) != 1 {
		return pathCWD{}
	}
	target := operands[0]
	if cdMayUseCDPath(target, env) {
		return pathCWD{}
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(state.cwd, target)
	}
	info, err := os.Stat(target)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// A failed cd leaves the current directory unchanged.
			return state
		}
		return pathCWD{}
	}
	if !info.IsDir() {
		return state
	}
	resolved, ok := resolveExistingPrefix(target)
	if !ok {
		return pathCWD{}
	}
	return pathCWD{cwd: resolved, known: true, inferred: true}
}

// cdMayUseCDPath reports whether a relative cd operand without an explicit
// ./ or ../ prefix can resolve through CDPATH instead of the current
// directory. Explicit relative paths bypass CDPATH.
func cdMayUseCDPath(target string, env map[string]string) bool {
	if env["CDPATH"] == "" || filepath.IsAbs(target) {
		return false
	}
	relative := "." + string(filepath.Separator)
	return !strings.HasPrefix(target, relative) && !strings.HasPrefix(target, relative+".")
}

func cdOperands(args []string) []string {
	operands := []string{}
	optionsEnded := false
	for _, argument := range args {
		if !optionsEnded && argument == "--" {
			optionsEnded = true
			continue
		}
		if !optionsEnded && strings.HasPrefix(argument, "-") {
			if argument == "-" {
				return nil
			}
			continue
		}
		operands = append(operands, argument)
	}
	return operands
}

func compactPathHint(source string, ir ShellIR, candidate IRPathCandidate, context pathCWD, evaluator *policyEvaluator) (assessorPathHint, bool) {
	hint := assessorPathHint{
		Source: sourceSpan(source, candidate.Span),
		Role:   candidate.Role,
	}
	recognized := false
	if candidate.Role == "redirection-target" {
		for _, redirection := range ir.Redirections {
			if redirection.TargetSpan == candidate.Span && !redirection.HereDocument && (redirection.WriteCapable || redirection.Operator == "<") {
				recognized = true
				break
			}
		}
	}
	if candidate.Role == "argument" && (candidate.AccessMode == "create" || candidate.AccessMode == "delete") {
		for commandIndex, command := range ir.Commands {
			if command.Name != "rm" && command.Name != "mkdir" {
				continue
			}
			for argumentIndex, argument := range command.ArgumentFacts {
				if argument.Span == candidate.Span {
					hint.Role = "file-operand"
					hint.CommandIndex = &commandIndex
					hint.ArgumentIndex = &argumentIndex
					recognized = true
					break
				}
			}
			if recognized {
				break
			}
		}
	}
	if !recognized {
		return assessorPathHint{}, false
	}
	if !context.known || context.cwd == "" || !candidate.Static || candidate.Value == "" {
		return hint, true
	}
	resolved, ok := evaluator.resolvePath(candidate.Value, context.cwd)
	if !ok {
		resolved, ok = danglingLinkPath(candidate.Value, context.cwd)
	}
	if !ok {
		return hint, true
	}
	basis := "initial-cwd"
	if context.inferred {
		basis = "inferred-cd"
	}
	hint.Resolution = &assessorPathResolution{
		Basis:           basis,
		ResolvedPath:    resolved,
		Existence:       pathExistence(resolved),
		Protected:       evaluator.isProtected(resolved),
		InsideWorkspace: evaluator.workspaceRoot != "" && pathWithin(resolved, evaluator.workspaceRoot),
		InsideTemporary: pathWithin(resolved, evaluator.tempRoot),
	}
	return hint, true
}

// danglingLinkPath locates a path whose final component is a symlink with a
// missing target. The link itself exists, and removing or overwriting it acts
// on the link, so its resolved parent still identifies the affected entry.
func danglingLinkPath(value, cwd string) (string, bool) {
	if cwd == "" || value == "" || strings.ContainsRune(value, '\x00') || strings.HasPrefix(value, "~") {
		return "", false
	}
	candidate := value
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(cwd, candidate)
	}
	candidate = filepath.Clean(candidate)
	if _, err := os.Lstat(candidate); err != nil {
		return "", false
	}
	parent, ok := resolveExistingPrefix(filepath.Dir(candidate))
	if !ok {
		return "", false
	}
	return filepath.Join(parent, filepath.Base(candidate)), true
}

func pathExistence(path string) string {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return pathExistencePresent
	case errors.Is(err, fs.ErrNotExist):
		return pathExistenceAbsent
	default:
		return pathExistenceUnknown
	}
}
