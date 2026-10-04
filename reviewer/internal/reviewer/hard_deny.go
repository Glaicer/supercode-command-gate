package reviewer

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// CatastrophicCatalogVersion identifies the closed, built-in hard-deny catalog.
// It is deliberately not configurable: changing it is a policy change.
const CatastrophicCatalogVersion = "catastrophic-v1"

func hardDenyEffect(rule string) string {
	switch rule {
	case "HD001":
		return "whole-tree-destruction"
	case "HD002":
		return "immutable-root-mutation"
	case "HD003":
		return "raw-device-write"
	case "HD004":
		return "storage-format-or-discard"
	case "HD005":
		return "recursive-metadata-damage"
	case "HD006":
		return "immediate-host-crash"
	default:
		return "catastrophic-effect"
	}
}

type catastrophicPlatform string

const (
	platformLinux   catastrophicPlatform = "linux"
	platformDarwin  catastrophicPlatform = "darwin"
	platformWindows catastrophicPlatform = "windows"
)

type hardDenyContext struct {
	request  Request
	platform catastrophicPlatform
}

type hardDenyState struct {
	cwd string
}

type hardDenyValue struct {
	value string
	fixed bool
}

type hardDenyRedirection struct {
	value hardDenyValue
	write bool
}

type hardDenyStatus uint8

const (
	hardDenyStatusUnknown hardDenyStatus = iota
	hardDenyStatusTrue
	hardDenyStatusFalse
)

var canonicalForkBomb = regexp.MustCompile(`(?s)^\s*:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:\s*$`)
var linuxDiskDevice = regexp.MustCompile(`^/dev/(?:sd|hd|vd|xvd)[a-z]+[0-9]*$`)
var linuxNVMeDevice = regexp.MustCompile(`^/dev/nvme[0-9]+n[0-9]+(?:p[0-9]+)?$`)
var linuxMMCDevice = regexp.MustCompile(`^/dev/mmcblk[0-9]+(?:p[0-9]+|boot[0-9]+|rpmb)?$`)
var linuxMDDevice = regexp.MustCompile(`^/dev/md[A-Za-z0-9_-]+$`)
var linuxDMDevice = regexp.MustCompile(`^/dev/dm-[0-9]+$`)
var macDiskDevice = regexp.MustCompile(`^/dev/(?:r?disk)[0-9]+(?:s[0-9]+)*$`)
var windowsDriveRoot = regexp.MustCompile(`^[a-z]:/$`)
var windowsRawDevice = regexp.MustCompile(`^//[.?]/(?:physicaldrive[^/]+|harddisk[^/]+|volume\{[^/]+\})$`)

var linuxWholeTreeRoots = []string{
	"/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var",
}

var darwinWholeTreeRoots = []string{
	"/", "/Applications", "/Library", "/System", "/Users", "/Volumes", "/bin", "/cores", "/dev", "/etc", "/opt", "/private", "/sbin", "/tmp", "/usr", "/var",
}

// evaluateHardDeny is the first policy decision after parsing. A miss is not a
// safety result; it only means the closed catastrophic catalog did not match.
func evaluateHardDeny(request Request, ir ShellIR) (rule, reason string, ok bool) {
	platform := catastrophicPlatform(runtime.GOOS)
	if platform == platformWindows {
		// Windows execution is unsupported in V1. Keep reserved Windows facts in
		// the catalog helpers without enabling them on a Windows host by accident.
		return "", "", false
	}
	return evaluateHardDenyForPlatform(request, ir, platform)
}

func evaluateHardDenyForPlatform(request Request, ir ShellIR, platform catastrophicPlatform) (rule, reason string, ok bool) {
	context := hardDenyContext{request: request, platform: platform}
	if canonicalForkBomb.MatchString(request.Command) {
		return "HD006", "the command is a canonical fork bomb that can exhaust the host", true
	}

	state := hardDenyState{cwd: context.initialCWD()}
	for _, execution := range ir.Executions {
		matchedRule, matchedReason, matched, nextState, _ := context.walk(ir, execution, state)
		if matched {
			return matchedRule, matchedReason, true
		}
		state = nextState
	}
	return "", "", false
}

func (context hardDenyContext) initialCWD() string {
	if cwd := canonicalOrClean(context.request.CWD, ""); cwd != "" {
		return cwd
	}
	return canonicalOrClean(context.request.Env["PWD"], "")
}

func (context hardDenyContext) walk(ir ShellIR, execution IRExecution, state hardDenyState) (rule, reason string, matched bool, nextState hardDenyState, status hardDenyStatus) {
	if execution.Kind != "command" && len(execution.RedirectionIndexes) > 0 {
		if rule, reason, ok := context.matchStandaloneRedirections(ir, execution.RedirectionIndexes, state.cwd); ok {
			return rule, reason, true, state, hardDenyStatusUnknown
		}
	}
	if execution.Kind == "command" {
		if execution.CommandIndex < 0 || execution.CommandIndex >= len(ir.Commands) {
			return "", "", false, state, hardDenyStatusUnknown
		}
		command := ir.Commands[execution.CommandIndex]
		if rule, reason, ok := context.matchCommand(ir, command, execution.RedirectionIndexes, state); ok {
			return rule, reason, true, state, hardDenyStatusUnknown
		}
		nextState, status = context.commandState(command, state)
		return "", "", false, nextState, status
	}

	switch execution.Kind {
	case "pipeline":
		for _, child := range execution.Children {
			if rule, reason, ok, _, _ := context.walk(ir, child, state); ok {
				return rule, reason, true, state, hardDenyStatusUnknown
			}
		}
		return "", "", false, state, hardDenyStatusUnknown
	case "and":
		if len(execution.Children) != 2 {
			return "", "", false, state, hardDenyStatusUnknown
		}
		leftRule, leftReason, leftMatched, leftState, leftStatus := context.walk(ir, execution.Children[0], state)
		if leftMatched {
			return leftRule, leftReason, true, state, hardDenyStatusUnknown
		}
		if leftStatus == hardDenyStatusFalse {
			return "", "", false, leftState, hardDenyStatusFalse
		}
		rightRule, rightReason, rightMatched, rightState, rightStatus := context.walk(ir, execution.Children[1], leftState)
		if rightMatched {
			return rightRule, rightReason, true, state, hardDenyStatusUnknown
		}
		return "", "", false, rightState, combineHardDenyStatus(leftStatus, rightStatus)
	case "or":
		if len(execution.Children) != 2 {
			return "", "", false, state, hardDenyStatusUnknown
		}
		leftRule, leftReason, leftMatched, leftState, leftStatus := context.walk(ir, execution.Children[0], state)
		if leftMatched {
			return leftRule, leftReason, true, state, hardDenyStatusUnknown
		}
		if leftStatus == hardDenyStatusTrue {
			return "", "", false, leftState, hardDenyStatusTrue
		}
		rightRule, rightReason, rightMatched, rightState, rightStatus := context.walk(ir, execution.Children[1], leftState)
		if rightMatched {
			return rightRule, rightReason, true, state, hardDenyStatusUnknown
		}
		return "", "", false, rightState, combineHardDenyStatus(leftStatus, rightStatus)
	default:
		// Dynamic compound constructs are intentionally not traversed. A fact
		// inside an if/loop/function is not a statically established effect.
		return "", "", false, state, hardDenyStatusUnknown
	}
}

func (context hardDenyContext) matchStandaloneRedirections(ir ShellIR, indexes []int, cwd string) (rule, reason string, ok bool) {
	for _, redirection := range context.redirectionValues(ir, indexes, cwd) {
		if !redirection.write || !redirection.value.fixed {
			continue
		}
		resolved, resolvedOK := context.resolvePath(redirection.value.value, cwd)
		if !resolvedOK {
			continue
		}
		if context.isWholeTree(resolved) {
			return "HD002", "destructive mutation targets a cataloged platform root", true
		}
		if context.isRawDevice(resolved) {
			return "HD003", "a write operation targets a cataloged raw device", true
		}
	}
	return "", "", false
}

func combineHardDenyStatus(left, right hardDenyStatus) hardDenyStatus {
	if left == right {
		return left
	}
	return hardDenyStatusUnknown
}

func (context hardDenyContext) matchCommand(ir ShellIR, command IRCommand, redirectionIndexes []int, state hardDenyState) (rule, reason string, ok bool) {
	values, ok := context.commandValues(command, state.cwd)
	if !ok || len(values) == 0 || !values[0].fixed {
		return "", "", false
	}
	name, args, ok := unwrapHardDenyCommand(values)
	if !ok {
		return "", "", false
	}

	redirections := context.redirectionValues(ir, redirectionIndexes, state.cwd)
	if context.matchesImmediateCrash(name, args, redirections) {
		return "HD006", "the command is an immediate host or session crash primitive", true
	}
	if context.matchesWholeTreeDestruction(name, args, state.cwd) {
		return "HD001", "recursive or bulk destruction targets a cataloged platform root", true
	}
	if context.matchesImmutableRootMutation(name, args, redirections, state.cwd) {
		return "HD002", "destructive mutation targets a cataloged platform root", true
	}
	if context.matchesRawDeviceWrite(name, args, redirections, state.cwd) {
		return "HD003", "a write operation targets a cataloged raw device", true
	}
	if context.matchesStorageFormatOrDiscard(name, args, state.cwd) {
		return "HD004", "storage format or discard targets a cataloged raw device", true
	}
	if context.matchesRecursiveMetadataDamage(name, args, state.cwd) {
		return "HD005", "recursive metadata mutation covers a cataloged critical tree", true
	}
	return "", "", false
}

func (context hardDenyContext) commandState(command IRCommand, state hardDenyState) (hardDenyState, hardDenyStatus) {
	values, ok := context.commandValues(command, state.cwd)
	if !ok || len(values) == 0 || !values[0].fixed {
		return state, hardDenyStatusUnknown
	}
	name, args, ok := unwrapHardDenyCommand(values)
	if !ok {
		return state, hardDenyStatusUnknown
	}
	if name == "true" && len(args) == 0 {
		return state, hardDenyStatusTrue
	}
	if name == "false" && len(args) == 0 {
		return state, hardDenyStatusFalse
	}
	if name != "cd" {
		return state, hardDenyStatusUnknown
	}
	operands := hardDenyOperands(args, map[string]bool{})
	if len(operands) != 1 || !operands[0].fixed {
		return state, hardDenyStatusUnknown
	}
	pathValue, ok := context.resolvePath(operands[0].value, state.cwd)
	if !ok {
		return state, hardDenyStatusFalse
	}
	info, err := os.Stat(pathValue)
	if err != nil || !info.IsDir() {
		return state, hardDenyStatusFalse
	}
	return hardDenyState{cwd: pathValue}, hardDenyStatusTrue
}

func (context hardDenyContext) commandValues(command IRCommand, cwd string) ([]hardDenyValue, bool) {
	if len(command.ArgumentFacts) == 0 {
		return nil, false
	}
	values := make([]hardDenyValue, 0, len(command.ArgumentFacts))
	for index, fact := range command.ArgumentFacts {
		if fact.Static {
			value := fact.Value
			if index < len(command.Arguments) {
				value = command.Arguments[index]
			}
			values = append(values, hardDenyValue{value: value, fixed: true})
			continue
		}
		raw := sourceSpan(context.request.Command, fact.Span)
		if value, ok := trustedAnchorValue(raw, context.request, cwd, context.platform); ok {
			values = append(values, hardDenyValue{value: value, fixed: true})
			continue
		}
		values = append(values, hardDenyValue{fixed: false})
	}
	return values, true
}

func (context hardDenyContext) redirectionValues(ir ShellIR, indexes []int, cwd string) []hardDenyRedirection {
	values := make([]hardDenyRedirection, 0, len(indexes))
	for _, index := range indexes {
		if index < 0 || index >= len(ir.Redirections) {
			values = append(values, hardDenyRedirection{})
			continue
		}
		redirection := ir.Redirections[index]
		value := hardDenyValue{fixed: false}
		if redirection.Static {
			value = hardDenyValue{value: redirection.Target, fixed: redirection.Target != ""}
		} else if anchor, ok := trustedAnchorValue(sourceSpan(context.request.Command, redirection.TargetSpan), context.request, cwd, context.platform); ok {
			value = hardDenyValue{value: anchor, fixed: true}
		}
		values = append(values, hardDenyRedirection{value: value, write: redirection.WriteCapable})
	}
	return values
}

func sourceSpan(source string, span IRSpan) string {
	if span.Start < 0 || span.End <= span.Start || span.Start >= len(source) || span.End > len(source) {
		return ""
	}
	return source[span.Start:span.End]
}

func trustedAnchorValue(raw string, request Request, cwd string, platform catastrophicPlatform) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "'") || strings.Contains(raw, "`") || strings.Count(raw, `"`)%2 != 0 {
		return "", false
	}
	value := strings.ReplaceAll(raw, `"`, "")
	if strings.ContainsAny(value, `\\*?[]{};|&<>()`) {
		return "", false
	}

	anchor := ""
	suffix := ""
	switch {
	case strings.HasPrefix(value, "${HOME}"):
		anchor, suffix = "HOME", strings.TrimPrefix(value, "${HOME}")
	case strings.HasPrefix(value, "$HOME"):
		anchor, suffix = "HOME", strings.TrimPrefix(value, "$HOME")
	case strings.HasPrefix(value, "${PWD}"):
		anchor, suffix = "PWD", strings.TrimPrefix(value, "${PWD}")
	case strings.HasPrefix(value, "$PWD"):
		anchor, suffix = "PWD", strings.TrimPrefix(value, "$PWD")
	default:
		return "", false
	}
	if suffix != "" && !strings.HasPrefix(suffix, "/") {
		return "", false
	}
	base := ""
	if anchor == "HOME" {
		base = request.Env["HOME"]
	} else if anchor == "PWD" {
		base = cwd
		if base == "" {
			base = request.Env["PWD"]
		}
	}
	if !isAbsolutePlatformPath(base, platform) {
		return "", false
	}
	return base + suffix, true
}

func (context hardDenyContext) resolvePath(value, cwd string) (string, bool) {
	if value == "" || strings.ContainsRune(value, '\x00') || strings.ContainsAny(value, "$~*?[]{};|&<>()`'") {
		return "", false
	}
	if context.platform == platformWindows {
		candidate := normalizeCatalogPath(value, context.platform)
		if !isAbsolutePlatformPath(candidate, context.platform) {
			candidate = normalizeCatalogPath(path.Join(normalizeCatalogPath(cwd, context.platform), value), context.platform)
		}
		return candidate, true
	}
	base := cwd
	if base == "" {
		base = context.initialCWD()
	}
	candidate := value
	if !filepath.IsAbs(candidate) {
		candidate = base + string(filepath.Separator) + candidate
	}
	return resolveExistingPrefix(candidate)
}

func isAbsolutePlatformPath(value string, platform catastrophicPlatform) bool {
	if platform == platformWindows {
		value = normalizeCatalogPath(value, platform)
		return filepath.IsAbs(value) || windowsDriveRoot.MatchString(value) || (len(value) >= 3 && value[1] == ':' && value[2] == '/')
	}
	return filepath.IsAbs(value)
}

func unwrapHardDenyCommand(values []hardDenyValue) (name string, args []hardDenyValue, ok bool) {
	for depth := 0; depth < 6; depth++ {
		if len(values) == 0 || !values[0].fixed {
			return "", nil, false
		}
		name = filepath.Base(strings.ReplaceAll(values[0].value, `\`, `/`))
		args = values[1:]
		switch name {
		case "sudo", "doas":
			values, ok = skipWrapperOptions(args, map[string]bool{"-u": true, "--user": true, "-g": true, "--group": true, "-C": true, "--chdir": true})
		case "env":
			values, ok = skipEnvOptions(args)
		case "command", "builtin":
			values, ok = skipCommandOptions(args)
		case "exec":
			values, ok = skipWrapperOptions(args, map[string]bool{"-a": true})
		default:
			return name, args, true
		}
		if !ok {
			return "", nil, false
		}
	}
	return "", nil, false
}

func skipWrapperOptions(args []hardDenyValue, valueOptions map[string]bool) ([]hardDenyValue, bool) {
	for index := 0; index < len(args); index++ {
		if !args[index].fixed {
			return nil, false
		}
		value := args[index].value
		if value == "--" {
			return args[index+1:], true
		}
		if !strings.HasPrefix(value, "-") || value == "-" {
			return args[index:], true
		}
		if valueOptions[value] && !strings.Contains(value, "=") {
			index++
		}
	}
	return nil, false
}

func skipEnvOptions(args []hardDenyValue) ([]hardDenyValue, bool) {
	for index := 0; index < len(args); index++ {
		if !args[index].fixed {
			return nil, false
		}
		value := args[index].value
		if value == "--" {
			return args[index+1:], true
		}
		if strings.HasPrefix(value, "-") {
			if value == "-u" || value == "--unset" {
				index++
			}
			continue
		}
		if isEnvironmentAssignment(value) {
			continue
		}
		return args[index:], true
	}
	return nil, false
}

func skipCommandOptions(args []hardDenyValue) ([]hardDenyValue, bool) {
	for index := 0; index < len(args); index++ {
		if !args[index].fixed {
			return nil, false
		}
		value := args[index].value
		if value == "--" {
			return args[index+1:], true
		}
		if !strings.HasPrefix(value, "-") || value == "-" {
			return args[index:], true
		}
	}
	return nil, false
}

func isEnvironmentAssignment(value string) bool {
	separator := strings.IndexByte(value, '=')
	if separator <= 0 {
		return false
	}
	for _, char := range value[:separator] {
		if !(char == '_' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func hardDenyOperands(args []hardDenyValue, valueOptions map[string]bool) []hardDenyValue {
	operands := make([]hardDenyValue, 0, len(args))
	for index := 0; index < len(args); index++ {
		value := args[index].value
		if value == "--" {
			operands = append(operands, args[index+1:]...)
			break
		}
		if strings.HasPrefix(value, "-") && value != "-" {
			if valueOptions[value] && !strings.Contains(value, "=") {
				index++
			}
			continue
		}
		operands = append(operands, args[index])
	}
	return operands
}

func hasLongFlag(args []hardDenyValue, names ...string) bool {
	for _, arg := range args {
		if !arg.fixed {
			continue
		}
		for _, name := range names {
			if arg.value == name || strings.HasPrefix(arg.value, name+"=") {
				return true
			}
		}
	}
	return false
}

func hasShortFlag(args []hardDenyValue, wanted ...byte) bool {
	for _, arg := range args {
		if !arg.fixed || len(arg.value) < 2 || arg.value[0] != '-' || arg.value[1] == '-' {
			continue
		}
		for index := 1; index < len(arg.value); index++ {
			for _, flag := range wanted {
				if arg.value[index] == flag {
					return true
				}
			}
		}
	}
	return false
}

func (context hardDenyContext) resolvedTargets(values []hardDenyValue, cwd string) []string {
	targets := make([]string, 0, len(values))
	for _, value := range values {
		if !value.fixed {
			continue
		}
		if resolved, ok := context.resolvePath(value.value, cwd); ok {
			targets = append(targets, resolved)
		}
	}
	return targets
}

func (context hardDenyContext) isWholeTree(pathValue string) bool {
	return isWholeTreeCatalogPath(pathValue, context.platform, context.request)
}

func (context hardDenyContext) isRawDevice(pathValue string) bool {
	return isRawDeviceCatalogPath(pathValue, context.platform)
}

func (context hardDenyContext) matchesWholeTreeDestruction(name string, args []hardDenyValue, cwd string) bool {
	switch name {
	case "rm":
		if !hasShortFlag(args, 'r', 'R') && !hasLongFlag(args, "--recursive") {
			return false
		}
		preserveRoot := hasLongFlag(args, "--preserve-root") && !hasLongFlag(args, "--no-preserve-root")
		if hasShortFlag(args, 'i', 'I') && !hasShortFlag(args, 'f') && !hasLongFlag(args, "--force") {
			return false
		}
		for _, target := range context.resolvedTargets(hardDenyOperands(args, map[string]bool{}), cwd) {
			if context.isWholeTree(target) && !(preserveRoot && normalizeCatalogPath(target, context.platform) == "/") {
				return true
			}
		}
	case "shred":
		if !hasShortFlag(args, 'r', 'R') && !hasLongFlag(args, "--recursive") {
			return false
		}
		for _, target := range context.resolvedTargets(hardDenyOperands(args, map[string]bool{}), cwd) {
			if context.isWholeTree(target) {
				return true
			}
		}
	case "find":
		return context.findWholeTreeDestruction(args, cwd)
	}
	return false
}

func (context hardDenyContext) findWholeTreeDestruction(args []hardDenyValue, cwd string) bool {
	starts := findStartOperands(args)
	rootStart := false
	for _, start := range starts {
		if start.fixed {
			if resolved, ok := context.resolvePath(start.value, cwd); ok && context.isWholeTree(resolved) {
				rootStart = true
			}
		}
	}
	if !rootStart {
		return false
	}
	for index, arg := range args {
		if !arg.fixed {
			continue
		}
		switch arg.value {
		case "-delete":
			return true
		case "-exec", "-execdir", "-ok", "-okdir":
			if index+1 >= len(args) || !args[index+1].fixed {
				continue
			}
			name := filepath.Base(strings.ReplaceAll(args[index+1].value, `\`, `/`))
			if name == "rm" || name == "shred" || name == "unlink" || name == "rmdir" {
				return true
			}
		}
	}
	return false
}

func findStartOperands(args []hardDenyValue) []hardDenyValue {
	starts := make([]hardDenyValue, 0, 1)
	index := 0
	for index < len(args) && args[index].fixed && (args[index].value == "-H" || args[index].value == "-L" || args[index].value == "-P") {
		index++
	}
	for index < len(args) {
		arg := args[index]
		if !arg.fixed || strings.HasPrefix(arg.value, "-") || arg.value == "!" || arg.value == "(" {
			break
		}
		starts = append(starts, arg)
		index++
	}
	if len(starts) == 0 {
		starts = append(starts, hardDenyValue{value: ".", fixed: true})
	}
	return starts
}

func (context hardDenyContext) matchesImmutableRootMutation(name string, args []hardDenyValue, redirections []hardDenyRedirection, cwd string) bool {
	for _, redirection := range redirections {
		if redirection.write && redirection.value.fixed {
			if resolved, ok := context.resolvePath(redirection.value.value, cwd); ok && context.isWholeTree(resolved) {
				return true
			}
		}
	}

	switch name {
	case "rm":
		if hasShortFlag(args, 'r', 'R') || hasLongFlag(args, "--recursive") {
			return false
		}
		return context.anyWholeTreeTarget(hardDenyOperands(args, map[string]bool{}), cwd)
	case "rmdir":
		return context.anyWholeTreeTarget(hardDenyOperands(args, map[string]bool{}), cwd)
	case "truncate":
		return context.anyWholeTreeTarget(hardDenyOperands(args, map[string]bool{"-s": true, "--size": true}), cwd)
	case "dd":
		return context.anyWholeTreeTarget(ddOutputTargets(args), cwd)
	case "mv", "rename":
		operands := hardDenyOperands(args, map[string]bool{})
		if len(operands) < 2 {
			return false
		}
		if context.anyWholeTreeTarget(operands[:len(operands)-1], cwd) {
			return true
		}
		if (name == "mv" && (hasShortFlag(args, 'T') || hasLongFlag(args, "--no-target-directory"))) || name == "rename" {
			return context.anyWholeTreeTarget(operands[len(operands)-1:], cwd)
		}
		return false
	case "sed":
		if !hasShortFlag(args, 'i') && !hasLongFlag(args, "--in-place") {
			return false
		}
		return context.anyWholeTreeTarget(lastOperands(args), cwd)
	case "tee":
		return context.anyWholeTreeTarget(hardDenyOperands(args, map[string]bool{}), cwd)
	case "cp", "install", "ln":
		if !hasShortFlag(args, 'T') && !hasLongFlag(args, "--no-target-directory") {
			return false
		}
		operands := hardDenyOperands(args, map[string]bool{})
		if len(operands) == 0 {
			return false
		}
		return context.anyWholeTreeTarget(operands[len(operands)-1:], cwd)
	}
	return false
}

func (context hardDenyContext) anyWholeTreeTarget(values []hardDenyValue, cwd string) bool {
	for _, target := range context.resolvedTargets(values, cwd) {
		if context.isWholeTree(target) {
			return true
		}
	}
	return false
}

func lastOperands(args []hardDenyValue) []hardDenyValue {
	operands := hardDenyOperands(args, map[string]bool{"-e": true, "--expression": true})
	if len(operands) == 0 {
		return nil
	}
	return operands[len(operands)-1:]
}

func ddOutputTargets(args []hardDenyValue) []hardDenyValue {
	values := make([]hardDenyValue, 0, 1)
	for _, arg := range args {
		if !arg.fixed || !strings.HasPrefix(arg.value, "of=") {
			continue
		}
		values = append(values, hardDenyValue{value: strings.TrimPrefix(arg.value, "of="), fixed: true})
	}
	return values
}

func outputFlagTargets(commandName string, args []hardDenyValue) []hardDenyValue {
	values := make([]hardDenyValue, 0, 1)
	for index := 0; index < len(args); index++ {
		if !args[index].fixed {
			continue
		}
		value := args[index].value
		if isOutputFlag(commandName, value) {
			if index+1 < len(args) {
				values = append(values, args[index+1])
				index++
			}
			continue
		}
		for _, prefix := range outputFlagPrefixes(commandName) {
			if strings.HasPrefix(value, prefix) {
				values = append(values, hardDenyValue{value: strings.TrimPrefix(value, prefix), fixed: true})
				break
			}
		}
		if len(value) > 2 && value[0] == '-' && value[1] != '-' {
			for indexInCluster := 1; indexInCluster < len(value); indexInCluster++ {
				if !isOutputShortFlag(commandName, value[indexInCluster]) {
					continue
				}
				if indexInCluster+1 < len(value) {
					values = append(values, hardDenyValue{value: value[indexInCluster+1:], fixed: true})
				} else if index+1 < len(args) {
					values = append(values, args[index+1])
					index++
				}
				break
			}
		}
	}
	return values
}

func isOutputFlag(commandName, value string) bool {
	switch commandName {
	case "tar":
		return value == "-f" || value == "--file"
	case "curl":
		return value == "-o" || value == "--output"
	case "wget":
		return value == "-O" || value == "--output-document"
	case "git":
		return value == "-o" || value == "--output"
	default:
		return false
	}
}

func outputFlagPrefixes(commandName string) []string {
	switch commandName {
	case "tar":
		return []string{"--file="}
	case "curl", "git":
		return []string{"--output="}
	case "wget":
		return []string{"--output-document="}
	default:
		return nil
	}
}

func isOutputShortFlag(commandName string, flag byte) bool {
	switch commandName {
	case "tar":
		return flag == 'f'
	case "curl":
		return flag == 'o'
	case "wget":
		return flag == 'O'
	case "git":
		return flag == 'o'
	default:
		return false
	}
}

func (context hardDenyContext) matchesRawDeviceWrite(name string, args []hardDenyValue, redirections []hardDenyRedirection, cwd string) bool {
	for _, redirection := range redirections {
		if redirection.write && redirection.value.fixed {
			if resolved, ok := context.resolvePath(redirection.value.value, cwd); ok && context.isRawDevice(resolved) {
				return true
			}
		}
	}
	var targets []hardDenyValue
	switch name {
	case "dd":
		targets = ddOutputTargets(args)
	case "tee", "truncate", "shred":
		targets = hardDenyOperands(args, map[string]bool{"-s": true, "--size": true})
	case "cp", "mv", "install":
		operands := hardDenyOperands(args, map[string]bool{})
		if len(operands) > 0 {
			targets = operands[len(operands)-1:]
		}
	case "tar", "curl", "wget":
		targets = outputFlagTargets(name, args)
	case "git":
		if firstNonOption(args) == "archive" {
			targets = outputFlagTargets(name, args)
		}
	}
	for _, target := range context.resolvedTargets(targets, cwd) {
		if context.isRawDevice(target) {
			return true
		}
	}
	return false
}

func (context hardDenyContext) matchesStorageFormatOrDiscard(name string, args []hardDenyValue, cwd string) bool {
	if hasStorageNoOpFlag(name, args) || !storageOperationIsDestructive(name, args) {
		return false
	}
	for _, target := range context.resolvedTargets(storageTargetOperands(name, args), cwd) {
		if context.isRawDevice(target) {
			return true
		}
	}
	return false
}

func storageTargetOperands(name string, args []hardDenyValue) []hardDenyValue {
	valueOptions := map[string]bool{}
	switch {
	case name == "mkfs" || strings.HasPrefix(name, "mkfs."):
		valueOptions = map[string]bool{
			"-b": true, "-d": true, "-E": true, "-I": true, "-i": true, "-L": true, "-m": true,
			"-M": true, "-O": true, "-T": true, "-U": true, "--block-size": true,
			"--extended-options": true, "--label": true, "--inode-size": true,
			"--internal-journal-size": true, "--reserved-blocks-percentage": true,
			"--root-directory": true, "--test-features": true, "--type": true, "--uuid": true,
		}
	case name == "mkswap":
		valueOptions = map[string]bool{"-L": true, "-U": true, "--label": true, "--uuid": true, "--pagesize": true}
	}
	return hardDenyOperands(args, valueOptions)
}

func storageOperationIsDestructive(name string, args []hardDenyValue) bool {
	switch {
	case name == "mkfs" || strings.HasPrefix(name, "mkfs.") || name == "mkswap":
		return true
	case name == "wipefs":
		return hasShortFlag(args, 'a', 'f') || hasLongFlag(args, "--all", "--force")
	case name == "blkdiscard":
		return true
	case name == "badblocks":
		return hasShortFlag(args, 'w') || hasLongFlag(args, "--write-mode")
	case name == "hdparm":
		for _, arg := range args {
			if arg.fixed && (strings.HasPrefix(arg.value, "--security-erase") || strings.HasPrefix(arg.value, "--sanitize")) {
				return true
			}
		}
	case name == "sfdisk":
		return hasLongFlag(args, "--delete", "--wipe") || hasShortFlag(args, 'd')
	case name == "sgdisk":
		return hasLongFlag(args, "--zap-all", "--zap", "--clear", "--delete") || hasShortFlag(args, 'z', 'Z', 'd')
	case name == "mdadm":
		return hasLongFlag(args, "--zero-superblock", "--create", "--stop", "--remove")
	case name == "cryptsetup":
		for _, arg := range args {
			if arg.fixed && (arg.value == "luksFormat" || arg.value == "luksErase" || arg.value == "erase") {
				return true
			}
		}
	case name == "nvme":
		return firstNonOption(args) == "format" || firstNonOption(args) == "sanitize"
	case name == "parted":
		return containsAnyFixed(args, "mklabel", "mkpart", "rm", "resizepart", "set", "disk_set", "mkfs")
	case name == "diskutil":
		return containsAnyFixed(args, "eraseDisk", "eraseVolume", "partitionDisk", "zeroDisk")
	case name == "newfs":
		return true
	}
	return false
}

func hasStorageNoOpFlag(name string, args []hardDenyValue) bool {
	if hasLongFlag(args, "--dry-run", "--no-act", "--noaction") {
		return true
	}
	if name == "wipefs" && hasShortFlag(args, 'n') {
		return true
	}
	if name == "mkfs" || strings.HasPrefix(name, "mkfs.") {
		return hasShortFlag(args, 'n')
	}
	return false
}

func firstNonOption(args []hardDenyValue) string {
	for _, arg := range args {
		if arg.fixed && !strings.HasPrefix(arg.value, "-") {
			return arg.value
		}
	}
	return ""
}

func containsAnyFixed(args []hardDenyValue, wanted ...string) bool {
	for _, arg := range args {
		if !arg.fixed {
			continue
		}
		for _, value := range wanted {
			if arg.value == value {
				return true
			}
		}
	}
	return false
}

func (context hardDenyContext) matchesRecursiveMetadataDamage(name string, args []hardDenyValue, cwd string) bool {
	switch name {
	case "chmod", "chown", "chgrp", "setfacl":
		if !recursiveMetadataFlag(args) {
			return false
		}
		return context.anyMetadataTreeTarget(metadataOperands(name, args), args, cwd)
	case "find":
		return context.findRecursiveMetadataDamage(args, cwd)
	}
	return false
}

func recursiveMetadataFlag(args []hardDenyValue) bool {
	return hasLongFlag(args, "--recursive") || hasShortFlag(args, 'R')
}

func (context hardDenyContext) anyMetadataTreeTarget(values, args []hardDenyValue, cwd string) bool {
	preserveRoot := hasLongFlag(args, "--preserve-root") && !hasLongFlag(args, "--no-preserve-root")
	for _, target := range context.resolvedTargets(values, cwd) {
		if context.isWholeTree(target) && !(preserveRoot && normalizeCatalogPath(target, context.platform) == "/") {
			return true
		}
	}
	return false
}

func metadataOperands(name string, args []hardDenyValue) []hardDenyValue {
	valueOptions := map[string]bool{}
	skipLeading := 0
	switch name {
	case "chmod":
		valueOptions = map[string]bool{"--reference": true}
		nonOptions := hardDenyOperands(args, valueOptions)
		if hasLongFlag(args, "--reference") {
			return nonOptions
		}
		if len(nonOptions) > 0 {
			return nonOptions[1:]
		}
	case "chown":
		valueOptions = map[string]bool{"--from": true}
		skipLeading = 1
	case "chgrp":
		skipLeading = 1
	case "setfacl":
		valueOptions = map[string]bool{"-m": true, "--modify": true, "-x": true, "--remove": true, "--mask": true, "--set": true, "--set-file": true}
	}
	operands := hardDenyOperands(args, valueOptions)
	if skipLeading > len(operands) {
		return nil
	}
	return operands[skipLeading:]
}

func (context hardDenyContext) findRecursiveMetadataDamage(args []hardDenyValue, cwd string) bool {
	starts := findStartOperands(args)
	rootStart := false
	for _, start := range starts {
		if start.fixed {
			if resolved, ok := context.resolvePath(start.value, cwd); ok && context.isWholeTree(resolved) {
				rootStart = true
			}
		}
	}
	if !rootStart {
		return false
	}
	for index, arg := range args {
		if !arg.fixed || (arg.value != "-exec" && arg.value != "-execdir" && arg.value != "-ok" && arg.value != "-okdir") || index+1 >= len(args) || !args[index+1].fixed {
			continue
		}
		name := filepath.Base(strings.ReplaceAll(args[index+1].value, `\`, `/`))
		if name == "chmod" || name == "chown" || name == "chgrp" || name == "setfacl" {
			return true
		}
	}
	return false
}

func (context hardDenyContext) matchesImmediateCrash(name string, args []hardDenyValue, redirections []hardDenyRedirection) bool {
	if name == "echo" || name == "printf" {
		if context.matchesCriticalSysrq(args, redirections) {
			return true
		}
	}
	if name == "reboot" || name == "poweroff" || name == "halt" {
		return !hasLongFlag(args, "--help", "--version", "--dry-run", "--no-act")
	}
	if name == "shutdown" {
		return !hasLongFlag(args, "--help", "--version", "--cancel", "--dry-run", "--no-act") && !hasShortFlag(args, 'k') && !containsAnyFixed(args, "-c")
	}
	if name == "systemctl" {
		subcommand := firstNonOption(hardDenyOperands(args, map[string]bool{
			"--host": true, "--machine": true, "--root": true, "--state": true,
		}))
		return (subcommand == "reboot" || subcommand == "poweroff" || subcommand == "halt" || subcommand == "kexec") && !hasShortFlag(args, 'h') && !hasLongFlag(args, "--help", "--version", "--dry-run", "--no-act")
	}
	if name == "init" || name == "telinit" {
		return containsAnyFixed(args, "0", "6")
	}
	if name == "kill" || name == "pkill" || name == "killall" {
		return matchesFatalKill(name, args)
	}
	return false
}

func (context hardDenyContext) matchesCriticalSysrq(args []hardDenyValue, redirections []hardDenyRedirection) bool {
	if context.platform != platformLinux {
		return false
	}
	criticalTarget := false
	for _, redirection := range redirections {
		if !redirection.write || !redirection.value.fixed {
			continue
		}
		if target, ok := context.resolvePath(redirection.value.value, ""); ok && normalizeCatalogPath(target, context.platform) == "/proc/sysrq-trigger" {
			criticalTarget = true
		}
	}
	if !criticalTarget {
		return false
	}
	for _, arg := range args {
		if arg.fixed && (arg.value == "b" || arg.value == "c" || arg.value == "o") {
			return true
		}
	}
	return false
}

func matchesFatalKill(name string, args []hardDenyValue) bool {
	if name != "kill" {
		// pkill/killall can target all processes only with an explicit negative
		// process-group operand after `--`; named patterns are not fixed targets.
		signal := "TERM"
		for index := 0; index < len(args); index++ {
			if !args[index].fixed {
				return false
			}
			value := args[index].value
			if value == "--" {
				return index+1 < len(args) && args[index+1].fixed && args[index+1].value == "-1" && !isNoopSignal(signal)
			}
			if value == "-s" || value == "--signal" {
				if index+1 >= len(args) || !args[index+1].fixed {
					return false
				}
				signal = args[index+1].value
				index++
				continue
			}
			if strings.HasPrefix(value, "--signal=") {
				signal = strings.TrimPrefix(value, "--signal=")
				continue
			}
			if strings.HasPrefix(value, "-") && value != "-1" {
				signal = strings.TrimPrefix(value, "-")
			}
		}
		return false
	}

	signal := "TERM"
	signalNoop := false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !arg.fixed {
			return false
		}
		value := arg.value
		if value == "--" {
			return fatalKillTargets(args[index+1:], signal, signalNoop)
		}
		if value == "-s" || value == "--signal" {
			if index+1 >= len(args) || !args[index+1].fixed {
				return false
			}
			signal = args[index+1].value
			signalNoop = isNoopSignal(signal)
			index++
			continue
		}
		if strings.HasPrefix(value, "--signal=") {
			signal = strings.TrimPrefix(value, "--signal=")
			signalNoop = isNoopSignal(signal)
			continue
		}
		if value == "-l" || value == "-L" || value == "--list" || value == "--table" || value == "--help" || value == "--version" {
			return false
		}
		if strings.HasPrefix(value, "-") && value != "-1" {
			signal = strings.TrimPrefix(value, "-")
			signalNoop = isNoopSignal(signal)
			continue
		}
		if value == "-1" {
			return !signalNoop
		}
		if value == "1" {
			return !signalNoop
		}
	}
	return false
}

func fatalKillTargets(args []hardDenyValue, signal string, signalNoop bool) bool {
	if signalNoop || isNoopSignal(signal) {
		return false
	}
	for _, arg := range args {
		if arg.fixed && (arg.value == "1" || arg.value == "-1") {
			return true
		}
	}
	return false
}

func isNoopSignal(signal string) bool {
	signal = strings.ToLower(strings.TrimPrefix(signal, "sig"))
	return signal == "0"
}

func isCatalogedHardDenyTarget(pathValue string) bool {
	platform := catastrophicPlatform(runtime.GOOS)
	if platform == platformWindows {
		return false
	}
	return isWholeTreeCatalogPath(pathValue, platform, Request{}) || isRawDeviceCatalogPath(pathValue, platform)
}

func normalizeCatalogPath(pathValue string, platform catastrophicPlatform) string {
	if platform != platformWindows {
		return filepath.Clean(pathValue)
	}
	pathValue = strings.ToLower(strings.ReplaceAll(pathValue, `\`, "/"))
	for _, prefix := range []string{"//./", "//?/"} {
		if strings.HasPrefix(pathValue, prefix) {
			return prefix + strings.TrimPrefix(path.Clean(strings.TrimPrefix(pathValue, prefix)), "/")
		}
	}
	if len(pathValue) >= 2 && pathValue[1] == ':' {
		drive := pathValue[:2]
		rest := pathValue[2:]
		if rest == "" {
			return drive + "/"
		}
		if !strings.HasPrefix(rest, "/") {
			rest = "/" + rest
		}
		return drive + path.Clean(rest)
	}
	return path.Clean(pathValue)
}

func isWholeTreeCatalogPath(pathValue string, platform catastrophicPlatform, request Request) bool {
	pathValue = normalizeCatalogPath(pathValue, platform)
	if platform == platformWindows {
		return isWindowsWholeTreePath(pathValue, request)
	}
	roots := linuxWholeTreeRoots
	if platform == platformDarwin {
		roots = darwinWholeTreeRoots
	}
	for _, root := range roots {
		if pathValue == normalizeCatalogPath(root, platform) {
			return true
		}
		if platform != platformWindows {
			if resolved, ok := resolveExistingPrefix(root); ok && pathValue == normalizeCatalogPath(resolved, platform) {
				return true
			}
		}
	}
	return false
}

func isWindowsWholeTreePath(pathValue string, request Request) bool {
	if windowsDriveRoot.MatchString(pathValue) {
		return true
	}
	for _, envName := range []string{"SystemRoot", "USERPROFILE", "HOME"} {
		if value := request.Env[envName]; value != "" && pathValue == normalizeCatalogPath(value, platformWindows) {
			return true
		}
	}
	if len(pathValue) < 4 || !windowsDriveRoot.MatchString(pathValue[:3]) {
		return false
	}
	base := pathValue[2:]
	for _, root := range []string{"/program files", "/program files (x86)", "/programdata", "/users", "/recovery", "/system volume information"} {
		if base == root {
			return true
		}
	}
	return false
}

func isRawDeviceCatalogPath(pathValue string, platform catastrophicPlatform) bool {
	pathValue = normalizeCatalogPath(pathValue, platform)
	switch platform {
	case platformLinux:
		if pathValue == "/proc/sysrq-trigger" || pathValue == "/dev/mem" || pathValue == "/dev/kmem" {
			return true
		}
		if linuxDiskDevice.MatchString(pathValue) || linuxNVMeDevice.MatchString(pathValue) || linuxMMCDevice.MatchString(pathValue) || linuxMDDevice.MatchString(pathValue) || linuxDMDevice.MatchString(pathValue) {
			return true
		}
		if strings.HasPrefix(pathValue, "/dev/mapper/") {
			mapperName := strings.TrimPrefix(pathValue, "/dev/mapper/")
			return mapperName != "" && !strings.Contains(mapperName, "/")
		}
	case platformDarwin:
		return macDiskDevice.MatchString(pathValue)
	case platformWindows:
		return windowsRawDevice.MatchString(pathValue)
	}
	return false
}
