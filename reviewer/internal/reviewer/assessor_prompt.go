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
		if command.Static {
			hint.Argv = append([]string(nil), command.Arguments...)
		} else {
			hint.Source = sourceSpan(source, command.Span)
		}
		hints.Commands = append(hints.Commands, hint)
	}
	return hints
}

// pathCWDBySpan maps each path candidate to the directory it is evaluated in.
// It tracks static cd commands in execution order and never guesses after a
// directory change it cannot follow.
func pathCWDBySpan(ir ShellIR, initial string) map[IRSpan]pathCWD {
	contexts := map[IRSpan]pathCWD{}
	walkPathContexts(ir, ir.Executions, pathCWD{cwd: initial, known: true}, contexts)
	return contexts
}

func walkPathContexts(ir ShellIR, executions []IRExecution, state pathCWD, contexts map[IRSpan]pathCWD) pathCWD {
	for _, execution := range executions {
		state = walkPathContext(ir, execution, state, contexts)
	}
	return state
}

func walkPathContext(ir ShellIR, execution IRExecution, state pathCWD, contexts map[IRSpan]pathCWD) pathCWD {
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
			return cdPathContext(command, state)
		}
		return state
	case "pipeline":
		// Pipeline stages run in subshells; a cd there cannot change the parent.
		for _, child := range execution.Children {
			walkPathContext(ir, child, state, contexts)
		}
		return state
	case "and", "or":
		if len(execution.Children) != 2 {
			return pathCWD{}
		}
		left := walkPathContext(ir, execution.Children[0], state, contexts)
		return walkPathContext(ir, execution.Children[1], left, contexts)
	case "block":
		return walkPathContexts(ir, execution.Children, state, contexts)
	case "subshell":
		walkPathContexts(ir, execution.Children, state, contexts)
		return state
	default:
		// Conditional or unsupported constructs may or may not change the
		// directory, so later commands have no reliable execution context.
		for _, child := range execution.Children {
			walkPathContext(ir, child, state, contexts)
		}
		return pathCWD{}
	}
}

func cdPathContext(command IRCommand, state pathCWD) pathCWD {
	if !state.known || !command.Static {
		return pathCWD{}
	}
	operands := cdOperands(command.Arguments[1:])
	if len(operands) != 1 {
		return pathCWD{}
	}
	target := operands[0]
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

func pathExistence(path string) string {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return pathExistencePresent
	case errors.Is(err, fs.ErrNotExist):
		return pathExistenceAbsent
	default:
		return pathExistenceUnknown
	}
}
