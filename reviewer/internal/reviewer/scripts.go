package reviewer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	scriptStatusComplete       = "complete"
	scriptStatusMissing        = "missing"
	scriptStatusUnreadable     = "unreadable"
	scriptStatusDynamic        = "dynamic"
	scriptStatusOutside        = "outside-workspace"
	scriptStatusUnsupported    = "unsupported"
	scriptStatusChanged        = "changed"
	scriptStatusUnknown        = "unknown"
	scriptKindInline           = "inline"
	scriptKindHeredoc          = "heredoc"
	scriptKindEntrypoint       = "entrypoint"
	scriptKindDependency       = "dependency"
	scriptKindInterpreter      = "interpreter"
	scriptKindDependencyStatus = "dependency-status"
)

// scriptEvidence is serialized into the assessor prompt as evidence only. It
// is never copied into the audit record, which keeps source literals out of
// ordinary audit storage while allowing the assessor to inspect their effects.
type scriptEvidence struct {
	Interpreter string `json:"interpreter"`
	Kind        string `json:"kind"`
	Path        string `json:"path,omitempty"`
	Digest      string `json:"digest,omitempty"`
	Status      string `json:"status"`
	Content     string `json:"content,omitempty"`
}

type scriptSnapshot struct {
	Path    string
	Digest  string
	Size    int64
	Mode    os.FileMode
	ModTime int64
}

type scriptCollection struct {
	Evidence            []scriptEvidence
	Snapshots           []scriptSnapshot
	SourceSpans         []IRSpan
	Uncertainties       []string
	AllHeredocsComplete bool
}

type dependencySpec struct {
	Value    string
	Relative bool
}

var (
	pythonImportPattern   = regexp.MustCompile(`(?m)^\s*(?:from\s+([.A-Za-z_][.A-Za-z0-9_.]*)\s+import\s+([^#\n]+)|import\s+([^#\n]+))`)
	pythonDynamicPattern  = regexp.MustCompile(`(?m)\b(?:__import__|importlib\.(?:import_module|util)|exec|eval)\s*\(`)
	jsImportPattern       = regexp.MustCompile(`(?m)(?:\b(?:require|import)\s*\(\s*|\b(?:from|import)\s+)["']([^"']+)["']`)
	jsDynamicPattern      = regexp.MustCompile(`(?m)\b(?:require|import)\s*\(\s*[^"'\s]`)
	shellSourcePattern    = regexp.MustCompile(`(?m)(?:^|[;&|]\s*)(?:source|\.)\s+([^\s;&|]+)`)
	shellDynamicPattern   = regexp.MustCompile(`(?m)(?:^|[;&|]\s*)(?:source|\.)\s+[$"']`)
	rubyRequirePattern    = regexp.MustCompile(`(?m)\brequire_relative\s*["']([^"']+)["']`)
	genericRequirePattern = regexp.MustCompile(`(?m)\b(?:require|include|do|require_once|include_once)\s*["']([^"']+)["']`)
)

func defaultInterpreterForms() map[string]InterpreterForm {
	return map[string]InterpreterForm{
		"bash":    {InlineFlags: []string{"-c", "--command"}, FileExtensions: []string{".sh", ".bash"}},
		"sh":      {InlineFlags: []string{"-c", "--command"}, FileExtensions: []string{".sh"}},
		"dash":    {InlineFlags: []string{"-c", "--command"}, FileExtensions: []string{".sh"}},
		"zsh":     {InlineFlags: []string{"-c", "--command"}, FileExtensions: []string{".sh", ".zsh"}},
		"python":  {InlineFlags: []string{"-c", "--command"}, FileExtensions: []string{".py", ".pyw"}},
		"python3": {InlineFlags: []string{"-c", "--command"}, FileExtensions: []string{".py", ".pyw"}},
		"node":    {InlineFlags: []string{"-e", "--eval"}, FileExtensions: []string{".js", ".mjs", ".cjs"}},
	}
}

func interpreterForm(name string, config AssessorConfig) (InterpreterForm, bool) {
	defaults := defaultInterpreterForms()
	form, known := defaults[name]
	if configured, ok := config.Interpreters[name]; ok {
		known = true
		if configured.InlineFlags != nil {
			form.InlineFlags = append([]string(nil), configured.InlineFlags...)
		}
		if configured.FileExtensions != nil {
			form.FileExtensions = append([]string(nil), configured.FileExtensions...)
		}
	}
	if !known && opaqueInterpreterCommands[name] {
		return InterpreterForm{}, true
	}
	return form, known
}

func collectScriptEvidence(request Request, ir ShellIR, config AssessorConfig) scriptCollection {
	collection := scriptCollection{AllHeredocsComplete: true}
	visited := map[string]bool{}
	seenCommands := map[int]bool{}
	var walk func(IRExecution)
	walk = func(execution IRExecution) {
		if execution.Kind == "command" && execution.CommandIndex >= 0 && execution.CommandIndex < len(ir.Commands) {
			seenCommands[execution.CommandIndex] = true
			collection.collectCommand(request, ir, ir.Commands[execution.CommandIndex], execution.RedirectionIndexes, config, visited)
		}
		for _, child := range execution.Children {
			walk(child)
		}
	}
	for _, execution := range ir.Executions {
		walk(execution)
	}
	// Compound ShellIR nodes preserve their nested commands in the flat
	// Commands list even when policy deliberately treats their execution as
	// dynamic. Collect those commands too so the assessor still sees complete
	// interpreter evidence.
	for index, command := range ir.Commands {
		if seenCommands[index] {
			continue
		}
		collection.collectCommand(request, ir, command, redirectionsForCommand(ir, command), config, visited)
	}
	return collection
}

func redirectionsForCommand(ir ShellIR, command IRCommand) []int {
	indexes := []int{}
	for index, redirection := range ir.Redirections {
		if redirection.Span.Start >= command.Span.Start && redirection.Span.End <= command.Span.End {
			indexes = append(indexes, index)
		}
	}
	return indexes
}

func scriptSourceSpan(spans []IRSpan, candidate IRSpan) bool {
	for _, span := range spans {
		if span.Start == candidate.Start && span.End == candidate.End {
			return true
		}
	}
	return false
}

func dynamicEvidenceComplete(ir ShellIR, scripts scriptCollection) bool {
	if !ir.Dynamic {
		return true
	}
	if len(ir.DynamicFeatures) == 0 {
		return false
	}
	for _, feature := range ir.DynamicFeatures {
		if feature != "heredoc" || !scripts.AllHeredocsComplete {
			return false
		}
	}
	return true
}

func (collection *scriptCollection) collectCommand(request Request, ir ShellIR, command IRCommand, redirectionIndexes []int, config AssessorConfig, visited map[string]bool) {
	form, known := interpreterForm(command.Name, config)
	if !known {
		return
	}
	if _, builtinForm := defaultInterpreterForms()[command.Name]; !builtinForm {
		if _, configuredForm := config.Interpreters[command.Name]; !configuredForm {
			collection.addStatus(command.Name, scriptKindInterpreter, "", scriptStatusUnsupported, "interpreter source and local dependencies are not fully evidenced")
			return
		}
	}
	if len(command.ArgumentFacts) == 0 || !command.ArgumentFacts[0].Static {
		collection.addStatus(command.Name, scriptKindInterpreter, "", scriptStatusDynamic, "the interpreter executable is not statically recoverable")
		return
	}
	if !command.Static {
		collection.addStatus(command.Name, scriptKindInterpreter, "", scriptStatusDynamic, "interpreter arguments are not statically recoverable")
	}

	foundSource := false
	if source, index, ok := inlineInterpreterSource(command, form); ok {
		foundSource = true
		collection.SourceSpans = append(collection.SourceSpans, command.ArgumentFacts[index].Span)
		collection.addContent(command.Name, scriptKindInline, "", source, scriptStatusComplete, "")
		collection.collectInlineDependencies(request, command.Name, source, request.CWD, visited)
	} else if index, dynamic := inlineInterpreterSourceIndex(command, form); dynamic {
		foundSource = true
		collection.SourceSpans = append(collection.SourceSpans, command.ArgumentFacts[index].Span)
		collection.addStatus(command.Name, scriptKindInline, "", scriptStatusDynamic, "inline interpreter source is dynamic or unsupported")
	}

	hasHeredoc := collection.collectRedirections(request, ir, command, redirectionIndexes, config, visited)

	if !foundSource {
		if index, ok := fileInterpreterArgument(command, form, request); ok {
			foundSource = true
			collection.collectFile(request, command.Name, scriptKindEntrypoint, command.Arguments[index], request.CWD, config, visited)
		} else if fileInterpreterArgumentDynamic(command, form) {
			foundSource = true
			collection.addStatus(command.Name, scriptKindEntrypoint, "", scriptStatusDynamic, "interpreter entrypoint is dynamic or unsupported")
		}
	}

	if !foundSource && !hasHeredoc {
		collection.addStatus(command.Name, scriptKindInterpreter, "", scriptStatusUnsupported, "interpreter source and local dependencies are not fully evidenced")
	}
}

func (collection *scriptCollection) collectRedirections(request Request, ir ShellIR, command IRCommand, redirectionIndexes []int, config AssessorConfig, visited map[string]bool) bool {
	_, known := interpreterForm(command.Name, config)
	if !known {
		return false
	}
	found := false
	for _, redirectionIndex := range redirectionIndexes {
		if redirectionIndex < 0 || redirectionIndex >= len(ir.Redirections) {
			collection.addStatus(command.Name, scriptKindHeredoc, "", scriptStatusUnreadable, "heredoc redirection is not recoverable")
			collection.AllHeredocsComplete = false
			found = true
			continue
		}
		redirection := ir.Redirections[redirectionIndex]
		if !redirection.HereDocument {
			continue
		}
		found = true
		body := redirection.HereDocumentBody
		if body == "" {
			body, _ = recoverHeredocBody(request.Command, redirection.Span)
		}
		if body == "" {
			collection.addStatus(command.Name, scriptKindHeredoc, "", scriptStatusMissing, "heredoc body is missing")
			collection.AllHeredocsComplete = false
			continue
		}
		quoted := heredocDelimiterQuoted(request.Command, redirection)
		status := scriptStatusComplete
		uncertainty := ""
		if !quoted {
			status = scriptStatusDynamic
			uncertainty = "heredoc body may be changed by shell expansion"
			collection.AllHeredocsComplete = false
		}
		collection.addContent(command.Name, scriptKindHeredoc, "", body, status, uncertainty)
		if status == scriptStatusComplete {
			collection.collectInlineDependencies(request, command.Name, body, request.CWD, visited)
		}
	}
	return found
}

func (collection *scriptCollection) addContent(interpreter, kind, path, content, status, uncertainty string) {
	evidence := scriptEvidence{Interpreter: interpreter, Kind: kind, Path: path, Status: status, Content: content}
	if status == scriptStatusComplete {
		evidence.Digest = digestScript(content)
	}
	collection.Evidence = append(collection.Evidence, evidence)
	if uncertainty != "" {
		collection.addUncertainty(uncertainty)
	}
}

func (collection *scriptCollection) addStatus(interpreter, kind, path, status, uncertainty string) {
	collection.Evidence = append(collection.Evidence, scriptEvidence{Interpreter: interpreter, Kind: kind, Path: path, Status: status})
	collection.addUncertainty(uncertainty)
}

func (collection *scriptCollection) addUncertainty(value string) {
	if value == "" {
		return
	}
	for _, existing := range collection.Uncertainties {
		if existing == value {
			return
		}
	}
	collection.Uncertainties = append(collection.Uncertainties, value)
}

func inlineInterpreterSource(command IRCommand, form InterpreterForm) (string, int, bool) {
	index, dynamic := inlineInterpreterSourceIndex(command, form)
	if dynamic || index < 0 || index >= len(command.Arguments) || index >= len(command.ArgumentFacts) {
		return "", index, false
	}
	if !command.ArgumentFacts[index].Static {
		return "", index, false
	}
	argument := command.Arguments[index]
	for _, flag := range form.InlineFlags {
		if strings.HasPrefix(argument, flag+"=") {
			return strings.TrimPrefix(argument, flag+"="), index, true
		}
	}
	return argument, index, true
}

func inlineInterpreterSourceIndex(command IRCommand, form InterpreterForm) (int, bool) {
	for index := 1; index < len(command.Arguments); index++ {
		argument := command.Arguments[index]
		for _, flag := range form.InlineFlags {
			if argument == flag {
				if index+1 >= len(command.Arguments) || index+1 >= len(command.ArgumentFacts) {
					return index, true
				}
				return index + 1, !command.ArgumentFacts[index+1].Static
			}
			if strings.HasPrefix(argument, flag+"=") {
				return index, !command.ArgumentFacts[index].Static
			}
		}
	}
	return -1, false
}

func fileInterpreterArgument(command IRCommand, form InterpreterForm, request Request) (int, bool) {
	skipNext := false
	for index := 1; index < len(command.Arguments); index++ {
		argument := command.Arguments[index]
		if skipNext {
			skipNext = false
			continue
		}
		for _, flag := range form.InlineFlags {
			if argument == flag {
				skipNext = true
				break
			}
		}
		if skipNext || strings.HasPrefix(argument, "-") {
			continue
		}
		if argument == "-" {
			return index, false
		}
		if len(form.FileExtensions) == 0 || hasAnySuffix(argument, form.FileExtensions) || scriptPathLooksLocal(argument, request.CWD) {
			return index, true
		}
	}
	return -1, false
}

func fileInterpreterArgumentDynamic(command IRCommand, form InterpreterForm) bool {
	for index := 1; index < len(command.ArgumentFacts); index++ {
		if !command.ArgumentFacts[index].Static {
			argument := ""
			if index < len(command.Arguments) {
				argument = command.Arguments[index]
			}
			if argument == "" || strings.HasPrefix(argument, "-") {
				return true
			}
		}
	}
	_ = form
	return false
}

func scriptPathLooksLocal(value, base string) bool {
	if strings.ContainsRune(value, filepath.Separator) || strings.HasPrefix(value, ".") {
		return true
	}
	_, err := os.Stat(filepath.Join(base, value))
	return err == nil
}

func hasAnySuffix(value string, suffixes []string) bool {
	lower := strings.ToLower(value)
	for _, suffix := range suffixes {
		if strings.HasSuffix(lower, strings.ToLower(suffix)) {
			return true
		}
	}
	return false
}

func (collection *scriptCollection) collectFile(request Request, interpreter, kind, candidate, baseDir string, config AssessorConfig, visited map[string]bool) {
	candidates := []string{candidate}
	if kind == scriptKindDependency {
		candidates = dependencyCandidates(candidate, baseDir, interpreter, true)
	}
	resolved := ""
	status := scriptStatusMissing
	for _, pathCandidate := range candidates {
		candidatePath, candidateStatus := resolveWorkspaceScriptPath(request, pathCandidate, baseDir)
		if candidateStatus == scriptStatusComplete || candidateStatus == scriptStatusOutside || candidateStatus == scriptStatusUnreadable {
			resolved, status = candidatePath, candidateStatus
			if candidateStatus == scriptStatusComplete {
				break
			}
		}
		if resolved == "" {
			resolved, status = candidatePath, candidateStatus
		}
	}
	if status != scriptStatusComplete {
		collection.addStatus(interpreter, kind, resolved, status, scriptPathUncertainty(kind, status))
		return
	}
	if visited[resolved] {
		return
	}
	visited[resolved] = true
	content, snapshot, err := readScriptSnapshot(resolved)
	if err != nil {
		status := scriptStatusUnreadable
		if errors.Is(err, os.ErrNotExist) {
			status = scriptStatusMissing
		}
		collection.addStatus(interpreter, kind, resolved, status, scriptPathUncertainty(kind, status))
		return
	}
	collection.Snapshots = append(collection.Snapshots, snapshot)
	collection.Evidence = append(collection.Evidence, scriptEvidence{
		Interpreter: interpreter,
		Kind:        kind,
		Path:        resolved,
		Digest:      snapshot.Digest,
		Status:      scriptStatusComplete,
		Content:     content,
	})
	collection.collectDependencies(request, interpreter, resolved, content, config, visited)
}

func (collection *scriptCollection) collectInlineDependencies(request Request, interpreter, content, baseDir string, visited map[string]bool) {
	collection.collectDependencyEvidence(request, interpreter, content, baseDir, AssessorConfig{}, visited)
}

func (collection *scriptCollection) collectDependencies(request Request, interpreter, path, content string, config AssessorConfig, visited map[string]bool) {
	collection.collectDependencyEvidence(request, interpreter, content, filepath.Dir(path), config, visited)
}

func (collection *scriptCollection) collectDependencyEvidence(request Request, interpreter, content, baseDir string, config AssessorConfig, visited map[string]bool) {
	for _, dependency := range discoverDependencies(interpreter, content) {
		if dependency.Value == "" {
			continue
		}
		if dependency.Relative || dependencyIsLocalCandidate(request, dependency.Value, baseDir, interpreter) {
			collection.collectFile(request, interpreter, scriptKindDependency, dependency.Value, baseDir, config, visited)
		}
	}
	if dependenciesDynamic(interpreter, content) {
		collection.addStatus(interpreter, scriptKindDependencyStatus, "", scriptStatusDynamic, "a relevant script dependency is dynamically selected")
	}
}

func discoverDependencies(interpreter, content string) []dependencySpec {
	lower := strings.ToLower(interpreter)
	seen := map[string]bool{}
	dependencies := []dependencySpec{}
	add := func(value string, relative bool) {
		value = strings.TrimSpace(value)
		value = strings.Trim(value, "\"'")
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		dependencies = append(dependencies, dependencySpec{Value: value, Relative: relative})
	}
	switch lower {
	case "python", "python3":
		for _, match := range pythonImportPattern.FindAllStringSubmatch(content, -1) {
			if match[1] != "" {
				if match[1] == "." && match[2] != "" {
					for _, item := range strings.Split(match[2], ",") {
						fields := strings.Fields(item)
						if len(fields) > 0 {
							add("."+fields[0], true)
						}
					}
				} else {
					add(match[1], strings.HasPrefix(match[1], "."))
				}
				continue
			}
			for _, item := range strings.Split(match[3], ",") {
				fields := strings.Fields(item)
				if len(fields) > 0 {
					add(fields[0], strings.HasPrefix(fields[0], "."))
				}
			}
		}
	case "node", "deno", "bun":
		for _, match := range jsImportPattern.FindAllStringSubmatch(content, -1) {
			add(match[1], strings.HasPrefix(match[1], ".") || strings.HasPrefix(match[1], "/"))
		}
	case "bash", "sh", "dash", "zsh":
		for _, match := range shellSourcePattern.FindAllStringSubmatch(content, -1) {
			add(match[1], true)
		}
	case "ruby":
		for _, match := range rubyRequirePattern.FindAllStringSubmatch(content, -1) {
			add(match[1], true)
		}
		for _, match := range genericRequirePattern.FindAllStringSubmatch(content, -1) {
			add(match[1], strings.HasPrefix(match[1], ".") || strings.HasPrefix(match[1], "/"))
		}
	default:
		for _, match := range genericRequirePattern.FindAllStringSubmatch(content, -1) {
			add(match[1], strings.HasPrefix(match[1], ".") || strings.HasPrefix(match[1], "/"))
		}
	}
	return dependencies
}

func dependenciesDynamic(interpreter, content string) bool {
	switch strings.ToLower(interpreter) {
	case "python", "python3":
		return pythonDynamicPattern.MatchString(content)
	case "node", "deno", "bun":
		return jsDynamicPattern.MatchString(content)
	case "bash", "sh", "dash", "zsh":
		return shellDynamicPattern.MatchString(content)
	default:
		return false
	}
}

func dependencyIsLocalCandidate(request Request, value, baseDir, interpreter string) bool {
	if strings.HasPrefix(value, ".") || strings.HasPrefix(value, "/") {
		return true
	}
	if strings.Contains(value, "/") {
		return true
	}
	candidates := dependencyCandidates(value, baseDir, interpreter, false)
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return true
		}
	}
	root := workspaceRoot(request)
	for _, candidate := range dependencyCandidates(value, root, interpreter, false) {
		if _, err := os.Stat(candidate); err == nil {
			return true
		}
	}
	return false
}

func dependencyCandidates(value, baseDir, interpreter string, relative bool) []string {
	module := strings.TrimSpace(value)
	if strings.HasPrefix(module, ".") && (strings.EqualFold(interpreter, "python") || strings.EqualFold(interpreter, "python3")) {
		dots := 0
		for dots < len(module) && module[dots] == '.' {
			dots++
		}
		base := baseDir
		for index := 1; index < dots; index++ {
			base = filepath.Dir(base)
		}
		module = strings.TrimPrefix(module[dots:], ".")
		baseDir = base
		relative = true
	}
	if strings.EqualFold(interpreter, "python") || strings.EqualFold(interpreter, "python3") {
		module = strings.ReplaceAll(module, ".", string(filepath.Separator))
	}
	if relative || strings.HasPrefix(value, ".") || strings.HasPrefix(value, "/") {
		module = filepath.FromSlash(module)
	}
	if !filepath.IsAbs(module) {
		module = filepath.Join(baseDir, module)
	}
	module = filepath.Clean(module)
	candidates := []string{module}
	if filepath.Ext(module) == "" {
		switch strings.ToLower(interpreter) {
		case "python", "python3":
			candidates = append(candidates, module+".py", filepath.Join(module, "__init__.py"))
		case "node", "deno", "bun":
			candidates = append(candidates, module+".js", module+".mjs", module+".cjs", module+".json", filepath.Join(module, "index.js"))
		case "ruby":
			candidates = append(candidates, module+".rb")
		case "perl":
			candidates = append(candidates, module+".pl", module+".pm")
		case "php":
			candidates = append(candidates, module+".php")
		}
	}
	return candidates
}

func resolveWorkspaceScriptPath(request Request, candidate, baseDir string) (string, string) {
	if strings.TrimSpace(candidate) == "" {
		return "", scriptStatusMissing
	}
	pathValue := candidate
	if !filepath.IsAbs(pathValue) {
		pathValue = filepath.Join(baseDir, pathValue)
	}
	pathValue = filepath.Clean(pathValue)
	root := workspaceRoot(request)
	if !pathInsideRoot(pathValue, root) {
		return pathValue, scriptStatusOutside
	}
	info, err := os.Stat(pathValue)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return pathValue, scriptStatusMissing
		}
		return pathValue, scriptStatusUnreadable
	}
	if info.IsDir() {
		return pathValue, scriptStatusUnreadable
	}
	resolved, err := filepath.EvalSymlinks(pathValue)
	if err != nil {
		return pathValue, scriptStatusUnreadable
	}
	resolved = filepath.Clean(resolved)
	if !pathInsideRoot(resolved, root) {
		return resolved, scriptStatusOutside
	}
	return resolved, scriptStatusComplete
}

func workspaceRoot(request Request) string {
	root := request.CWD
	if request.WorkspaceRoot != nil && *request.WorkspaceRoot != "" {
		root = *request.WorkspaceRoot
	}
	if root == "" {
		root = "."
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return filepath.Clean(root)
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		return filepath.Clean(resolved)
	}
	return filepath.Clean(absolute)
}

func pathInsideRoot(pathValue, root string) bool {
	relative, err := filepath.Rel(root, pathValue)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && relative != string(filepath.Separator)
}

func readScriptSnapshot(pathValue string) (string, scriptSnapshot, error) {
	content, err := os.ReadFile(pathValue)
	if err != nil {
		return "", scriptSnapshot{}, err
	}
	info, err := os.Stat(pathValue)
	if err != nil {
		return "", scriptSnapshot{}, err
	}
	return string(content), scriptSnapshot{
		Path:    pathValue,
		Digest:  digestScript(string(content)),
		Size:    info.Size(),
		Mode:    info.Mode(),
		ModTime: info.ModTime().UnixNano(),
	}, nil
}

func digestScript(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func scriptPathUncertainty(kind, status string) string {
	if kind == scriptKindDependency {
		return "a relevant script dependency is " + status
	}
	return "the interpreter " + kind + " source is " + status
}

func verifyScriptSnapshots(snapshots []scriptSnapshot) (bool, string) {
	for _, snapshot := range snapshots {
		_, current, err := readScriptSnapshot(snapshot.Path)
		if err != nil {
			return true, fmt.Sprintf("relevant script source changed or became unreadable: %s", snapshot.Path)
		}
		if current.Digest != snapshot.Digest || current.Size != snapshot.Size || current.Mode != snapshot.Mode || current.ModTime != snapshot.ModTime {
			return true, fmt.Sprintf("relevant script source changed during assessment: %s", snapshot.Path)
		}
	}
	return false, ""
}

func recoverHeredocBody(source string, span IRSpan) (string, bool) {
	raw := sourceSpan(source, span)
	if raw == "" {
		return "", false
	}
	operator := strings.Index(raw, "<<")
	if operator < 0 {
		return "", false
	}
	rest := strings.TrimSpace(raw[operator+2:])
	dash := strings.HasPrefix(rest, "-")
	if dash {
		rest = strings.TrimSpace(rest[1:])
	}
	if rest == "" {
		return "", false
	}
	delimiter := rest
	if space := strings.IndexAny(delimiter, " \t\r\n"); space >= 0 {
		delimiter = delimiter[:space]
	}
	delimiter = strings.Trim(delimiter, "\"'")
	newline := strings.IndexByte(rest, '\n')
	if newline < 0 {
		return "", false
	}
	body := rest[newline+1:]
	lines := strings.SplitAfter(body, "\n")
	var builder strings.Builder
	for _, line := range lines {
		check := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if dash {
			check = strings.TrimLeft(check, "\t")
		}
		if check == delimiter {
			return builder.String(), true
		}
		builder.WriteString(line)
	}
	return builder.String(), false
}

func heredocDelimiterQuoted(source string, redirection IRRedirection) bool {
	raw := sourceSpan(source, redirection.Span)
	operator := strings.Index(raw, "<<")
	if operator < 0 {
		return false
	}
	rest := strings.TrimSpace(raw[operator+2:])
	rest = strings.TrimPrefix(rest, "-")
	rest = strings.TrimSpace(rest)
	return strings.HasPrefix(rest, "\"") || strings.HasPrefix(rest, "'")
}
