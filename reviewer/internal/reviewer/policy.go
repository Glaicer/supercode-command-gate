package reviewer

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

type policyEvaluator struct {
	options       Options
	env           map[string]string
	originalCWD   string
	workspaceRoot string
	tempRoot      string
	protected     []string
	additionUsed  bool
}

type policyState struct {
	cwd string
}

func evaluateAutoAllow(request Request, ir ShellIR, options Options) (rule, reason string, ok bool) {
	if ir.ParseError != "" || ir.Dynamic && !onlyPathExpansions(ir.DynamicFeatures) || len(ir.Executions) == 0 {
		return "", "", false
	}
	evaluator := newPolicyEvaluator(request, options)
	state := policyState{cwd: evaluator.originalCWD}
	for _, execution := range ir.Executions {
		var safe bool
		safe, state = evaluator.evaluateExecution(ir, execution, state, false)
		if !safe {
			return "", "", false
		}
	}

	rule = autoAllowRule(ir, evaluator.additionUsed)
	if rule == "" {
		return "", "", false
	}
	return rule, autoAllowReason(rule), true
}

func newPolicyEvaluator(request Request, options Options) policyEvaluator {
	evaluator := policyEvaluator{
		options:  options,
		env:      request.Env,
		tempRoot: canonicalOrClean(os.TempDir(), ""),
	}
	evaluator.originalCWD = canonicalOrClean(request.CWD, "")
	if request.WorkspaceRoot != nil && *request.WorkspaceRoot != "" {
		evaluator.workspaceRoot = canonicalOrClean(*request.WorkspaceRoot, evaluator.originalCWD)
	}
	for _, configured := range options.ProtectedPaths {
		if root := canonicalOrClean(configured, evaluator.originalCWD); root != "" {
			evaluator.protected = appendUnique(evaluator.protected, root)
		}
	}
	return evaluator
}

func (e *policyEvaluator) evaluateExecution(ir ShellIR, execution IRExecution, state policyState, pipelineInput bool) (bool, policyState) {
	switch execution.Kind {
	case "command":
		if execution.CommandIndex < 0 || execution.CommandIndex >= len(ir.Commands) {
			return false, state
		}
		command := ir.Commands[execution.CommandIndex]
		redirectionsSafe, inputProvided := e.redirectionsSafe(ir, execution.RedirectionIndexes, state.cwd)
		if !redirectionsSafe {
			return false, state
		}
		if pipelineInput || inputProvided {
			return e.commandSafe(command, state, true)
		}
		return e.commandSafe(command, state, false)
	case "pipeline":
		if len(execution.Children) == 0 {
			return false, state
		}
		for index, child := range execution.Children {
			childSafe, _ := e.evaluateExecution(ir, child, state, index > 0)
			if !childSafe {
				return false, state
			}
		}
		// A cd in a pipeline runs in a subshell and cannot change the parent.
		return true, state
	case "and", "or":
		if len(execution.Children) != 2 {
			return false, state
		}
		leftSafe, next := e.evaluateExecution(ir, execution.Children[0], state, pipelineInput)
		if !leftSafe {
			return false, state
		}
		return e.evaluateExecution(ir, execution.Children[1], next, false)
	default:
		return false, state
	}
}

func (e *policyEvaluator) commandSafe(command IRCommand, state policyState, stdinSafe bool) (bool, policyState) {
	expanded := !command.Static
	if expanded {
		var ok bool
		command, ok = e.expandReadCommand(command, state.cwd)
		if !ok {
			return false, state
		}
	}
	if !command.Static || command.Name == "" || len(command.ArgumentFacts) == 0 {
		return false, state
	}
	for _, argument := range command.ArgumentFacts {
		if !argument.Static {
			return false, state
		}
	}

	if !expanded && e.matchesAddition(command, state.cwd) {
		e.additionUsed = true
		return true, state
	}
	if strings.Contains(command.Name, "/") {
		return false, state
	}

	args := command.Arguments[1:]
	switch command.Name {
	case "pwd":
		return onlyFlags(args, map[string]bool{"-L": true, "-P": true, "--logical": true, "--physical": true}), state
	case "cd":
		return e.safeCD(args, state)
	case "echo", "printf":
		return true, state
	case "true", "false":
		return len(args) == 0, state
	case "command":
		return safeCommandLookup(args), state
	case "type", "which":
		return safeLookup(args), state
	case "cat":
		return e.safePathReader(args, state.cwd, stdinSafe, catOptions)
	case "head", "tail":
		return e.safePathReader(args, state.cwd, stdinSafe, headTailOptions)
	case "ls":
		return e.safeDirectoryListing(args, state.cwd)
	case "tree":
		return e.safePathReader(args, state.cwd, true, treeOptions)
	case "file":
		return e.safePathReader(args, state.cwd, stdinSafe, fileOptions)
	case "stat":
		return e.safePathReader(args, state.cwd, stdinSafe, optionGrammar{values: map[string]bool{"--format=": true}})
	case "du", "wc", "uniq", "cut", "tr", "readlink", "realpath", "basename", "dirname":
		return e.safePathReader(args, state.cwd, stdinSafe, permissiveReadOptions)
	case "sort":
		return e.safePathReader(args, state.cwd, stdinSafe, sortOptions)
	case "diff", "cmp", "comm":
		return e.safePathReader(args, state.cwd, stdinSafe, diffOptions)
	case "grep", "rg", "ripgrep":
		return e.safeGrep(args, state.cwd, stdinSafe)
	case "find":
		return e.safeFind(args, state.cwd)
	case "sed":
		return e.safeSed(args, state.cwd, stdinSafe)
	case "awk":
		return e.safeAwk(args, state.cwd, stdinSafe)
	case "git":
		return e.safeGit(args, state.cwd)
	case "rm":
		return e.safeTemporaryRemoval(args, state.cwd), state
	default:
		return false, state
	}
}

func (e *policyEvaluator) safeTemporaryRemoval(args []string, cwd string) bool {
	operands := 0
	optionsEnded := false
	for _, arg := range args {
		if !optionsEnded && arg == "--" {
			optionsEnded = true
			continue
		}
		if !optionsEnded && strings.HasPrefix(arg, "-") {
			if strings.HasPrefix(arg, "--") {
				if arg != "--recursive" && arg != "--force" && arg != "--dir" && arg != "--verbose" && arg != "--one-file-system" && arg != "--preserve-root" {
					return false
				}
			} else if len(arg) < 2 || strings.Trim(arg[1:], "rfRdivI") != "" {
				return false
			}
			continue
		}
		resolved, ok := e.resolvePath(arg, cwd)
		if !ok || resolved == e.tempRoot || !pathWithin(resolved, e.tempRoot) || e.isProtected(resolved) || isHardDenyTarget(resolved) {
			return false
		}
		operands++
	}
	return operands > 0
}

type optionGrammar struct {
	values       map[string]bool
	flags        map[string]bool
	reject       map[string]bool
	allowUnknown bool
	numericCount bool
}

var (
	catOptions = optionGrammar{
		flags: map[string]bool{
			"--number": true, "--number-nonblank": true, "--squeeze-blank": true,
			"--show-nonprinting": true, "--show-ends": true, "--show-tabs": true,
		},
		allowUnknown: false,
	}
	headTailOptions = optionGrammar{
		numericCount: true,
		values:       map[string]bool{"-n": true, "--lines": true, "--lines=": true, "-c": true, "--bytes": true, "--bytes=": true},
		flags:        map[string]bool{"-q": true, "--quiet": true, "-v": true, "--verbose": true},
		allowUnknown: false,
	}
	permissiveReadOptions = optionGrammar{}
	fileOptions           = optionGrammar{
		reject: map[string]bool{"-C": true, "--compile": true, "--compile-only": true},
	}
	sortOptions = optionGrammar{
		reject: map[string]bool{"-o": true, "-o=": true, "--output": true, "--output=": true, "--compress-program": true, "--compress-program=": true},
	}
	treeOptions = optionGrammar{
		reject: map[string]bool{"-o": true, "-o=": true, "--output": true, "--output=": true},
	}
	diffOptions = optionGrammar{
		reject: map[string]bool{"-o": true, "--output": true, "--output=": true},
	}
)

func (e *policyEvaluator) safePathReader(args []string, cwd string, stdinSafe bool, grammar optionGrammar) (bool, policyState) {
	operands, ok := parseOptionOperands(args, grammar)
	if !ok {
		return false, policyState{cwd: cwd}
	}
	if len(operands) == 0 && !stdinSafe {
		return false, policyState{cwd: cwd}
	}
	for _, operand := range operands {
		if !e.safeReadPath(operand, cwd) {
			return false, policyState{cwd: cwd}
		}
	}
	return true, policyState{cwd: cwd}
}

func (e *policyEvaluator) safeDirectoryListing(args []string, cwd string) (bool, policyState) {
	operands, ok := parseOptionOperands(args, permissiveReadOptions)
	if !ok {
		return false, policyState{cwd: cwd}
	}
	if len(operands) == 0 {
		return e.safeReadPath(".", cwd), policyState{cwd: cwd}
	}
	for _, operand := range operands {
		if !e.safeReadPath(operand, cwd) {
			return false, policyState{cwd: cwd}
		}
	}
	return true, policyState{cwd: cwd}
}

func parseOptionOperands(args []string, grammar optionGrammar) ([]string, bool) {
	operands := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			operands = append(operands, args[index+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			operands = append(operands, arg)
			continue
		}
		if grammar.reject[arg] || hasOptionPrefix(grammar.reject, arg) || hasAttachedOptionValue(grammar.reject, arg) {
			return nil, false
		}
		if grammar.flags[arg] {
			continue
		}
		if grammar.numericCount && len(arg) > 1 && strings.Trim(arg[1:], "0123456789") == "" {
			continue
		}
		if grammar.numericCount && strings.HasPrefix(arg, "--") && !grammar.values[arg] && !hasOptionPrefix(grammar.values, arg) {
			return nil, false
		}
		if grammar.values[arg] {
			if index+1 >= len(args) {
				return nil, false
			}
			index++
			continue
		}
		if hasOptionPrefix(grammar.values, arg) || hasAttachedOptionValue(grammar.values, arg) {
			continue
		}
		if grammar.allowUnknown {
			continue
		}
		// The small, argument-free GNU/POSIX flag set used by these readers.
		if isCommonReadFlag(arg) && (!grammar.numericCount || strings.Trim(arg[1:], "qv") == "") {
			continue
		}
		return nil, false
	}
	return operands, true
}

func hasAttachedOptionValue(options map[string]bool, arg string) bool {
	for option := range options {
		if strings.HasSuffix(option, "=") {
			continue
		}
		if strings.HasPrefix(arg, option) && len(arg) > len(option) && strings.HasPrefix(option, "-") {
			return true
		}
	}
	return false
}

func hasOptionPrefix(options map[string]bool, arg string) bool {
	for option := range options {
		if strings.HasSuffix(option, "=") && strings.HasPrefix(arg, option) {
			return true
		}
	}
	return false
}

func isCommonReadFlag(arg string) bool {
	if arg == "-" || len(arg) < 2 || arg[0] != '-' || arg[1] == '-' {
		return false
	}
	for _, char := range arg[1:] {
		switch char {
		case 'A', 'B', 'C', 'E', 'F', 'G', 'H', 'I', 'L', 'M', 'N', 'P', 'R', 'S', 'T', 'U', 'V', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z':
		default:
			return false
		}
	}
	return true
}

func onlyFlags(args []string, allowed map[string]bool) bool {
	for _, arg := range args {
		if !allowed[arg] {
			return false
		}
	}
	return true
}

func safeCommandLookup(args []string) bool {
	if len(args) < 2 || (args[0] != "-v" && args[0] != "-V" && args[0] != "--verbose") {
		return false
	}
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") || strings.Contains(arg, "/") {
			return false
		}
	}
	return true
}

func safeLookup(args []string) bool {
	if len(args) == 0 {
		return false
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") || strings.ContainsAny(arg, "*$?[]{}") {
			return false
		}
	}
	return true
}

func (e *policyEvaluator) safeCD(args []string, state policyState) (bool, policyState) {
	if len(args) != 1 || args[0] == "-" || strings.HasPrefix(args[0], "-") {
		return false, state
	}
	if !filepath.IsAbs(args[0]) && !strings.HasPrefix(args[0], "."+string(filepath.Separator)) && !strings.HasPrefix(args[0], ".."+string(filepath.Separator)) && e.env["CDPATH"] != "" {
		return false, state
	}
	resolved, ok := e.resolvePath(args[0], state.cwd)
	if !ok {
		return false, state
	}
	if info, err := os.Stat(resolved); err != nil || !info.IsDir() {
		return false, state
	}
	return true, policyState{cwd: resolved}
}

func (e *policyEvaluator) safeGrep(args []string, cwd string, stdinSafe bool) (bool, policyState) {
	if len(args) == 0 {
		return false, policyState{cwd: cwd}
	}
	patternSeen := false
	filesMode := false
	pathOperands := []string{}
	optionsWithValues := map[string]bool{
		"-e": true, "--regexp": true, "-f": true, "--file": true,
		"-m": true, "--max-count": true, "-A": true, "-B": true, "-C": true,
		"--after-context": true, "--before-context": true, "--context": true,
		"--color": true, "--colour": true, "--include": true, "--exclude": true,
		"--glob": true, "--iglob": true, "--type": true, "--type-add": true,
		"--type-not": true, "--max-columns": true,
	}
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			if !patternSeen {
				return false, policyState{cwd: cwd}
			}
			pathOperands = append(pathOperands, args[index+1:]...)
			break
		}
		if arg == "--files" {
			patternSeen = true
			filesMode = true
			continue
		}
		if isUnsafeGrepFlag(arg) {
			return false, policyState{cwd: cwd}
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			if len(arg) > 2 && containsAny([]string{arg[:2]}, "-A", "-B", "-C") && strings.Trim(arg[2:], "0123456789") == "" {
				continue
			}
			if option, value, hasValue := splitOptionAssignment(arg, optionsWithValues); hasValue {
				if option == "-e" || option == "--regexp" || option == "-f" || option == "--file" {
					patternSeen = true
				}
				if option == "-f" || option == "--file" {
					if !e.safeReadPath(value, cwd) {
						return false, policyState{cwd: cwd}
					}
				}
				continue
			}
			if optionsWithValues[arg] {
				if index+1 >= len(args) {
					return false, policyState{cwd: cwd}
				}
				if arg == "-f" || arg == "--file" {
					if !e.safeReadPath(args[index+1], cwd) {
						return false, policyState{cwd: cwd}
					}
				}
				if arg == "-e" || arg == "--regexp" || arg == "-f" || arg == "--file" {
					patternSeen = true
				}
				index++
				continue
			}
			if !isCommonReadFlag(arg) {
				return false, policyState{cwd: cwd}
			}
			continue
		}
		if !patternSeen {
			patternSeen = true
			continue
		}
		pathOperands = append(pathOperands, arg)
	}
	if !patternSeen || (len(pathOperands) == 0 && !stdinSafe && !filesMode) {
		return false, policyState{cwd: cwd}
	}
	if len(pathOperands) == 0 && filesMode {
		pathOperands = append(pathOperands, ".")
	}
	for _, path := range pathOperands {
		if !e.safeReadPath(path, cwd) {
			return false, policyState{cwd: cwd}
		}
	}
	return true, policyState{cwd: cwd}
}

func splitOptionAssignment(arg string, options map[string]bool) (option, value string, ok bool) {
	separator := strings.IndexByte(arg, '=')
	if separator <= 0 {
		return "", "", false
	}
	option = arg[:separator]
	if !options[option] {
		return "", "", false
	}
	return option, arg[separator+1:], true
}

func isUnsafeGrepFlag(arg string) bool {
	if arg == "--follow" || arg == "--follow-links" || arg == "--recursive" || arg == "--dereference" || arg == "--dereference-recursive" {
		return true
	}
	if len(arg) < 2 || arg[0] != '-' || arg[1] == '-' {
		return false
	}
	return strings.ContainsAny(arg[1:], "rRL")
}

func (e *policyEvaluator) safeFind(args []string, cwd string) (bool, policyState) {
	paths := []string{}
	index := 0
	for index < len(args) {
		arg := args[index]
		if arg == "--" {
			index++
			break
		}
		switch arg {
		case "-P":
			index++
		case "-H", "-L", "-follow":
			return false, policyState{cwd: cwd}
		case "-xdev", "-mount", "-depth", "-ignore_readdir_race":
			index++
		default:
			if strings.HasPrefix(arg, "-") {
				return false, policyState{cwd: cwd}
			}
			paths = append(paths, arg)
			index++
			for index < len(args) && !findExpressionStart(args[index]) {
				paths = append(paths, args[index])
				index++
			}
		}
		if index < len(args) && findExpressionStart(args[index]) {
			break
		}
	}
	if len(paths) == 0 {
		paths = append(paths, ".")
	}
	for _, path := range paths {
		if !e.safeReadPath(path, cwd) {
			return false, policyState{cwd: cwd}
		}
	}
	for index < len(args) {
		arg := args[index]
		if findUnsafeAction(arg) {
			return false, policyState{cwd: cwd}
		}
		switch arg {
		case "!", "-not", "-a", "-and", "-o", "-or", ",", "(", ")",
			"-true", "-false", "-empty", "-prune", "-xdev", "-mount", "-depth",
			"-print", "-print0", "-printf", "-ls", "-quit", "-ignore_readdir_race":
			if arg == "-printf" {
				if index+1 >= len(args) {
					return false, policyState{cwd: cwd}
				}
				index++
			}
			index++
		case "-newer", "-samefile":
			if index+1 >= len(args) || !e.safeReadPath(args[index+1], cwd) {
				return false, policyState{cwd: cwd}
			}
			index += 2
		case "-maxdepth", "-mindepth", "-regextype", "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-type", "-user", "-group", "-perm", "-newermt", "-size", "-mmin", "-mtime", "-amin", "-atime", "-cmin", "-ctime", "-links", "-inum":
			if index+1 >= len(args) {
				return false, policyState{cwd: cwd}
			}
			index += 2
		default:
			return false, policyState{cwd: cwd}
		}
	}
	return true, policyState{cwd: cwd}
}

func findExpressionStart(arg string) bool {
	return arg == "!" || arg == "(" || arg == ")" || strings.HasPrefix(arg, "-")
}

func findUnsafeAction(arg string) bool {
	if arg == "-delete" || strings.HasPrefix(arg, "-exec") || strings.HasPrefix(arg, "-ok") {
		return true
	}
	return strings.HasPrefix(arg, "-fprint") || strings.HasPrefix(arg, "-fls")
}

func (e *policyEvaluator) safeSed(args []string, cwd string, stdinSafe bool) (bool, policyState) {
	scripts := []string{}
	files := []string{}
	index := 0
	for index < len(args) {
		arg := args[index]
		switch {
		case arg == "-i" || arg == "--in-place" || strings.HasPrefix(arg, "-i") || strings.HasPrefix(arg, "--in-place="):
			return false, policyState{cwd: cwd}
		case arg == "-e" || arg == "--expression":
			if index+1 >= len(args) {
				return false, policyState{cwd: cwd}
			}
			scripts = append(scripts, args[index+1])
			index += 2
		case strings.HasPrefix(arg, "-e") && len(arg) > 2:
			scripts = append(scripts, arg[2:])
			index++
		case arg == "-f" || arg == "--file":
			return false, policyState{cwd: cwd}
		case arg == "--":
			files = append(files, args[index+1:]...)
			index = len(args)
		case arg == "-n" || arg == "--quiet" || arg == "--silent" || arg == "--posix" || arg == "-r" || arg == "-E" || arg == "--regexp-extended" || arg == "--debug":
			index++
		case strings.HasPrefix(arg, "-"):
			return false, policyState{cwd: cwd}
		default:
			if len(scripts) == 0 {
				scripts = append(scripts, arg)
			} else {
				files = append(files, arg)
			}
			index++
		}
	}
	if len(scripts) == 0 {
		return false, policyState{cwd: cwd}
	}
	for _, script := range scripts {
		if !safeSedScript(script) {
			return false, policyState{cwd: cwd}
		}
	}
	if len(files) == 0 && !stdinSafe {
		return false, policyState{cwd: cwd}
	}
	for _, file := range files {
		if !e.safeReadPath(file, cwd) {
			return false, policyState{cwd: cwd}
		}
	}
	return true, policyState{cwd: cwd}
}

func safeSedScript(script string) bool {
	index := 0
	for index < len(script) {
		index = skipSedSpace(script, index)
		if index >= len(script) {
			break
		}
		if script[index] == '#' {
			index = skipToSedBoundary(script, index)
			continue
		}
		if script[index] == ':' {
			index = skipToSedBoundary(script, index+1)
			continue
		}
		if !skipSedAddress(script, &index) {
			return false
		}
		index = skipSedSpace(script, index)
		if index >= len(script) {
			break
		}
		command := script[index]
		index++
		switch command {
		case 'w', 'W', 'e', 'r', 'R':
			return false
		case 's':
			var ok bool
			index, ok = skipSedSubstitute(script, index)
			if !ok {
				return false
			}
		case 'y', 'Y', 't', 'T', 'b', 'B':
			index = skipToSedBoundary(script, index)
		case 'a', 'i', 'c':
			index = skipToSedBoundary(script, index)
		case 'q', 'Q', 'd', 'D', 'h', 'H', 'g', 'G', 'x', 'l', 'n', 'N', 'p', 'P', '=', 'z', '{', '}':
			if command == '{' || command == '}' {
				continue
			}
			index = skipToSedBoundary(script, index)
		default:
			return false
		}
	}
	return true
}

func skipSedSpace(source string, index int) int {
	for index < len(source) && (source[index] == ' ' || source[index] == '\t' || source[index] == '\n' || source[index] == ';') {
		index++
	}
	return index
}

func skipToSedBoundary(source string, index int) int {
	escaped := false
	for index < len(source) {
		if escaped {
			escaped = false
			index++
			continue
		}
		if source[index] == '\\' {
			escaped = true
			index++
			continue
		}
		if source[index] == ';' || source[index] == '\n' || source[index] == '}' {
			return index
		}
		index++
	}
	return index
}

func skipSedAddress(source string, index *int) bool {
	start := *index
	if *index < len(source) && (source[*index] == '$' || source[*index] >= '0' && source[*index] <= '9') {
		for *index < len(source) && ((source[*index] >= '0' && source[*index] <= '9') || source[*index] == '$') {
			(*index)++
		}
	} else if *index < len(source) && (source[*index] == '/' || source[*index] == '\\') {
		delimiter := source[*index]
		(*index)++
		escaped := false
		closed := false
		for *index < len(source) {
			if escaped {
				escaped = false
				(*index)++
				continue
			}
			if source[*index] == '\\' {
				escaped = true
				(*index)++
				continue
			}
			if source[*index] == delimiter {
				(*index)++
				closed = true
				break
			}
			(*index)++
		}
		if !closed {
			return false
		}
	}
	if *index == start {
		return true
	}
	if *index < len(source) && source[*index] == ',' {
		(*index)++
		return skipSedAddress(source, index)
	}
	return true
}

func skipSedSubstitute(source string, index int) (int, bool) {
	if index >= len(source) {
		return index, false
	}
	delimiter := source[index]
	index++
	for part := 0; part < 2; part++ {
		closed := false
		escaped := false
		for index < len(source) {
			if escaped {
				escaped = false
				index++
				continue
			}
			if source[index] == '\\' {
				escaped = true
				index++
				continue
			}
			if source[index] == delimiter {
				index++
				closed = true
				break
			}
			index++
		}
		if !closed {
			return index, false
		}
	}
	end := index
	for end < len(source) && source[end] != ';' && source[end] != '\n' && source[end] != '}' {
		if source[end] == 'w' || source[end] == 'e' {
			return end, false
		}
		end++
	}
	return end, true
}

func (e *policyEvaluator) safeAwk(args []string, cwd string, stdinSafe bool) (bool, policyState) {
	program := ""
	files := []string{}
	index := 0
	for index < len(args) {
		arg := args[index]
		switch {
		case arg == "-f" || arg == "--file":
			return false, policyState{cwd: cwd}
		case arg == "-v" || arg == "--assign" || arg == "-F" || arg == "--field-separator":
			if index+1 >= len(args) {
				return false, policyState{cwd: cwd}
			}
			index += 2
		case strings.HasPrefix(arg, "-v") && len(arg) > 2, strings.HasPrefix(arg, "-F") && len(arg) > 2, strings.HasPrefix(arg, "--assign="):
			index++
		case arg == "--":
			index++
			if index >= len(args) {
				return false, policyState{cwd: cwd}
			}
			program = args[index]
			index++
		case strings.HasPrefix(arg, "-"):
			return false, policyState{cwd: cwd}
		default:
			program = arg
			index++
		}
		if program != "" {
			break
		}
	}
	if program == "" || !safeAwkProgram(program) {
		return false, policyState{cwd: cwd}
	}
	for index < len(args) {
		arg := args[index]
		if strings.Contains(arg, "=") && !strings.Contains(arg, "/") && !strings.HasPrefix(arg, "./") {
			index++
			continue
		}
		files = append(files, arg)
		index++
	}
	if len(files) == 0 && !stdinSafe {
		return false, policyState{cwd: cwd}
	}
	for _, file := range files {
		if !e.safeReadPath(file, cwd) {
			return false, policyState{cwd: cwd}
		}
	}
	return true, policyState{cwd: cwd}
}

var (
	awkSystemPattern = regexp.MustCompile(`\bsystem\s*\(`)
	awkClosePattern  = regexp.MustCompile(`\bclose\s*\(`)
	awkPrintWrite    = regexp.MustCompile(`\b(print|printf)\b[\s\S]*(>>|>)`)
	awkGetline       = regexp.MustCompile(`\bgetline\b`)
	awkInclude       = regexp.MustCompile(`@\s*(include|load)\b`)
)

func safeAwkProgram(program string) bool {
	program = strings.ReplaceAll(program, "\\\r\n", "")
	program = strings.ReplaceAll(program, "\\\n", "")
	if awkSystemPattern.MatchString(program) || awkClosePattern.MatchString(program) || awkInclude.MatchString(program) || strings.Contains(program, "ENVIRON") || strings.Contains(program, "|") || awkPrintWrite.MatchString(program) || awkGetline.MatchString(program) {
		return false
	}
	return true
}

func (e *policyEvaluator) safeGit(args []string, cwd string) (bool, policyState) {
	if e.gitEnvironmentUnsafe() {
		return false, policyState{cwd: cwd}
	}
	index := 0
	effectiveCWD := cwd
	for index < len(args) {
		arg := args[index]
		switch {
		case arg == "-C":
			if index+1 >= len(args) || !e.safeReadPath(args[index+1], cwd) {
				return false, policyState{cwd: cwd}
			}
			resolved, resolvedOK := e.resolvePath(args[index+1], cwd)
			if !resolvedOK {
				return false, policyState{cwd: cwd}
			}
			effectiveCWD = resolved
			index += 2
		case strings.HasPrefix(arg, "--git-dir=") || strings.HasPrefix(arg, "--work-tree="):
			path := strings.SplitN(arg, "=", 2)[1]
			if !e.safeReadPath(path, cwd) {
				return false, policyState{cwd: cwd}
			}
			index++
		case arg == "--no-pager" || arg == "--paginate" || arg == "--no-replace-objects" || arg == "--literal-pathspecs" || arg == "--glob-pathspecs" || arg == "--noglob-pathspecs":
			index++
		case arg == "-c":
			return false, policyState{cwd: cwd}
		case strings.HasPrefix(arg, "-"):
			return false, policyState{cwd: cwd}
		default:
			goto subcommand
		}
	}

subcommand:
	if index >= len(args) {
		return false, policyState{cwd: cwd}
	}
	if !e.inSafeRoot(effectiveCWD) {
		return false, policyState{cwd: cwd}
	}
	subcommand := args[index]
	remaining := args[index+1:]
	if containsUnsafeGitPathFlag(remaining) {
		return false, policyState{cwd: cwd}
	}
	if !readOnlyGitSubcommand(subcommand, remaining) {
		return false, policyState{cwd: cwd}
	}
	for _, arg := range remaining {
		if subcommand == "check-ignore" && arg != "-v" && arg != "--" && !e.safeReadPath(arg, effectiveCWD) {
			return false, policyState{cwd: cwd}
		}
		if strings.HasPrefix(arg, "-") || arg == "--" || strings.Contains(arg, ":") {
			continue
		}
		if strings.Contains(arg, "/") || arg == "." || arg == ".." {
			if !e.safeReadPath(arg, effectiveCWD) {
				return false, policyState{cwd: cwd}
			}
		}
	}
	return true, policyState{cwd: cwd}
}

func readOnlyGitSubcommand(subcommand string, args []string) bool {
	switch subcommand {
	case "merge-base":
		return len(args) == 3 && args[0] == "--is-ancestor" && args[1] != "" && args[2] != "" && !strings.HasPrefix(args[1], "-") && !strings.HasPrefix(args[2], "-")
	case "check-ignore":
		if len(args) > 0 && args[0] == "-v" {
			args = args[1:]
		}
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		return len(args) > 0 && gitOperandsOnly(args)
	case "show-ref":
		return len(args) == 1 && args[0] == "--heads"
	case "status", "diff", "log", "show", "grep", "ls-files", "ls-tree", "rev-parse", "rev-list", "cat-file", "blame", "describe", "shortlog", "name-rev", "whatchanged", "count-objects", "fsck":
		return !containsAnyGitWriteFlag(args)
	case "branch":
		if containsAny(args, "--list") {
			return branchListingFlagsOnly(args)
		}
		return noGitOperands(args) && !containsAny(args, "-d", "-D", "-m", "-M", "-c", "-C", "-f", "--delete", "--move", "--copy", "--force", "--edit-description", "--set-upstream-to", "--unset-upstream", "--track") && !containsAnyPrefix(args, "--set-upstream-to=", "--unset-upstream=", "--track=")
	case "tag":
		return noGitOperands(args) && !containsAny(args, "-d", "-a", "-s", "-u", "-m", "-F", "-f", "--delete", "--annotate", "--sign", "--force")
	case "remote":
		return len(args) == 0 || (len(args) == 1 && args[0] == "-v") || (len(args) == 1 && args[0] == "--verbose")
	case "config":
		return containsAny(args, "--get", "--get-all", "--get-regexp", "--list", "-l", "--show-origin", "--show-scope") && !containsAnyGitWriteFlag(args) && !containsAny(args, "--global", "--system", "--worktree", "--file", "--blob", "--includes") && !containsAnyPrefix(args, "--file=")
	case "worktree":
		return len(args) >= 1 && args[0] == "list"
	case "reflog":
		return len(args) == 0 || (len(args) > 0 && args[0] == "show")
	case "stash":
		return len(args) > 0 && (args[0] == "list" || args[0] == "show")
	default:
		return false
	}
}

func branchListingFlagsOnly(args []string) bool {
	listing := false
	for _, arg := range args {
		if arg == "--" {
			return listing
		}
		if arg == "--list" {
			listing = true
		}
		if strings.HasPrefix(arg, "-") && !containsAny([]string{arg}, "--list", "--all", "--remotes", "-a", "-r") {
			return false
		}
	}
	return listing
}

func gitOperandsOnly(args []string) bool {
	for _, arg := range args {
		if arg == "" || strings.HasPrefix(arg, "-") {
			return false
		}
	}
	return true
}

func noGitOperands(args []string) bool {
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			return false
		}
	}
	return true
}

func containsAnyGitWriteFlag(args []string) bool {
	if containsAnyPrefix(args, "--output", "--ext-diff", "--textconv", "--lost-found") {
		return true
	}
	return containsAny(args, "--delete", "--force", "--amend", "--hard", "--mixed", "--soft", "--keep", "--merge")
}

func containsUnsafeGitPathFlag(args []string) bool {
	return containsAny(args, "-C", "--git-dir", "--work-tree", "--config-env") || containsAnyPrefix(args, "--git-dir=", "--work-tree=", "--config-env=")
}

func (e *policyEvaluator) gitEnvironmentUnsafe() bool {
	for key, value := range e.env {
		if strings.HasPrefix(key, "GIT_") && value != "" {
			return true
		}
	}
	return false
}

func containsAny(values []string, wanted ...string) bool {
	for _, value := range values {
		for _, target := range wanted {
			if value == target {
				return true
			}
		}
	}
	return false
}

func containsAnyPrefix(values []string, prefixes ...string) bool {
	for _, value := range values {
		for _, prefix := range prefixes {
			if strings.HasPrefix(value, prefix) {
				return true
			}
		}
	}
	return false
}

func (e *policyEvaluator) redirectionsSafe(ir ShellIR, indexes []int, cwd string) (safe bool, inputProvided bool) {
	for _, index := range indexes {
		if index < 0 || index >= len(ir.Redirections) {
			return false, false
		}
		redirection := ir.Redirections[index]
		if !redirection.Static || redirection.HereDocument || redirection.Target == "" {
			return false, false
		}
		if redirection.Operator == ">&" {
			if (redirection.FD != "" && redirection.FD != "1" && redirection.FD != "2") || (redirection.Target != "1" && redirection.Target != "2") {
				return false, false
			}
			continue
		}
		if redirection.WriteCapable {
			if redirection.Target == "/dev/null" {
				continue
			}
			resolved, ok := e.resolvePath(redirection.Target, cwd)
			if !ok || !e.inSafeRoot(resolved) || e.isProtected(resolved) || isHardDenyTarget(resolved) || !hasExplicitPathScope(redirection.Target) {
				return false, false
			}
			continue
		}
		if !e.safeReadPath(redirection.Target, cwd) {
			return false, false
		}
		inputProvided = true
	}
	return true, inputProvided
}

func hasExplicitPathScope(path string) bool {
	return filepath.IsAbs(path) || strings.HasPrefix(path, "."+string(filepath.Separator)) || strings.HasPrefix(path, ".."+string(filepath.Separator)) || strings.Contains(path, string(filepath.Separator))
}

func (e *policyEvaluator) safeReadPath(path, cwd string) bool {
	if path == "-" || path == "" || strings.HasPrefix(path, "~") || strings.ContainsRune(path, '\x00') {
		return false
	}
	resolved, ok := e.resolvePath(path, cwd)
	if !ok {
		return false
	}
	if resolved == "/dev/null" {
		return true
	}
	return e.inSafeRoot(resolved) && !e.isProtected(resolved)
}

func (e *policyEvaluator) resolvePath(path, cwd string) (string, bool) {
	if path == "" || strings.ContainsRune(path, '\x00') || strings.HasPrefix(path, "~") {
		return "", false
	}
	base := cwd
	if base == "" {
		base = e.originalCWD
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = base + string(filepath.Separator) + candidate
	}
	return resolveExistingPrefix(candidate)
}

func (e *policyEvaluator) inSafeRoot(path string) bool {
	roots := []string{e.originalCWD, e.workspaceRoot, e.tempRoot}
	for _, root := range roots {
		if root != "" && pathWithin(path, root) {
			return true
		}
	}
	return false
}

func (e *policyEvaluator) isProtected(path string) bool {
	for _, root := range e.protected {
		if pathWithin(path, root) {
			return true
		}
	}
	return false
}

func (e *policyEvaluator) matchesAddition(command IRCommand, cwd string) bool {
	argv := normalizeArgv(command.Arguments, cwd)
	for _, addition := range e.options.AutoAllowAdditions {
		if !equalStrings(argv, normalizeArgv(addition.Argv, cwd)) {
			continue
		}
		if len(argv) == 1 {
			return true
		}
		if len(addition.PathScope) == 0 {
			continue
		}
		allPathsSafe := true
		for _, arg := range argv[1:] {
			if !e.additionArgumentSafe(arg, cwd, addition.PathScope) {
				allPathsSafe = false
				break
			}
		}
		if allPathsSafe {
			return true
		}
	}
	return false
}

func (e *policyEvaluator) additionArgumentSafe(arg, cwd string, scopes []string) bool {
	pathValue := arg
	if strings.HasPrefix(arg, "-") {
		if separator := strings.IndexByte(arg, '='); separator > 0 {
			pathValue = arg[separator+1:]
			if pathValue == "" {
				return true
			}
		} else {
			return !strings.ContainsAny(arg[1:], `/\\`)
		}
	}
	resolved, ok := e.resolvePath(pathValue, cwd)
	return ok && !e.isProtected(resolved) && !isHardDenyTarget(resolved) && pathWithinAny(resolved, scopes, cwd)
}

func normalizeArgv(argv []string, cwd string) []string {
	normalized := make([]string, len(argv))
	for index, arg := range argv {
		if index > 0 && (filepath.IsAbs(arg) || strings.HasPrefix(arg, "."+string(filepath.Separator)) || strings.HasPrefix(arg, ".."+string(filepath.Separator))) {
			candidate := arg
			if !filepath.IsAbs(candidate) {
				candidate = filepath.Join(cwd, candidate)
			}
			if resolved, ok := resolveExistingPrefix(candidate); ok {
				normalized[index] = resolved
				continue
			}
			normalized[index] = filepath.Clean(candidate)
			continue
		}
		normalized[index] = arg
	}
	return normalized
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func pathWithin(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
		root = strings.ToLower(root)
	}
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

func pathWithinAny(path string, roots []string, cwd string) bool {
	for _, root := range roots {
		scope := root
		if !filepath.IsAbs(scope) {
			scope = filepath.Join(cwd, scope)
		}
		if resolved, ok := resolveExistingPrefix(scope); ok && pathWithin(path, resolved) {
			return true
		}
	}
	return false
}

func resolveExistingPrefix(path string) (string, bool) {
	missing := []string{}
	current := path
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", false
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Clean(resolved), true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", false
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func canonicalOrClean(path, base string) string {
	if path == "" {
		return ""
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(base, path)
	}
	path = filepath.Clean(path)
	if resolved, ok := resolveExistingPrefix(path); ok {
		return resolved
	}
	return path
}

func isHardDenyTarget(path string) bool {
	return isCatalogedHardDenyTarget(path)
}

func autoAllowRule(ir ShellIR, additionUsed bool) string {
	if additionUsed {
		return "AA009"
	}
	if len(ir.Commands) == 1 && ir.Commands[0].Name == "pwd" {
		return "AA001"
	}
	for _, command := range ir.Commands {
		if command.Name == "rm" {
			return "AA010"
		}
	}
	for _, command := range ir.Commands {
		switch command.Name {
		case "cd":
			return "AA002"
		case "find":
			return "AA005"
		case "sed":
			return "AA006"
		case "awk":
			return "AA007"
		case "git":
			return "AA008"
		case "grep", "rg", "ripgrep":
			return "AA004"
		}
	}
	return "AA003"
}

func autoAllowReason(rule string) string {
	switch rule {
	case "AA001":
		return "pwd only reads the current working directory"
	case "AA002":
		return "cd is a safe no-op and the complete program is read-only"
	case "AA004":
		return "the complete search program only reads and filters safe paths"
	case "AA005":
		return "find uses only read-only predicates over safe paths"
	case "AA006":
		return "sed uses a statically recovered read-only script"
	case "AA007":
		return "awk uses a statically recovered program without execution or output redirection"
	case "AA008":
		return "git uses a read-only operation over safe paths"
	case "AA009":
		return "the exact configured argv and path scope are safe"
	case "AA010":
		return "removal is confined to unprotected contents of the temporary directory and the complete program has been checked"
	default:
		return "the complete program uses only read-only primitives and safe paths"
	}
}
