package reviewer

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const maxPathExpansion = 256

var numericBrace = regexp.MustCompile(`\{(0|[1-9][0-9]*)\.\.(0|[1-9][0-9]*)\}`)
var expansionWord = regexp.MustCompile(`^[a-zA-Z0-9_./*?{}-]+$`)

func onlyPathExpansions(features []string) bool {
	if len(features) == 0 {
		return false
	}
	for _, feature := range features {
		if feature != "globbing" && feature != "brace-expansion" {
			return false
		}
	}
	return true
}

func (e *policyEvaluator) expandReadCommand(command IRCommand, cwd string) (IRCommand, bool) {
	switch command.Name {
	case "cat", "head", "tail", "ls", "tree", "file", "stat", "du", "wc", "uniq", "cut", "tr", "readlink", "realpath", "basename", "dirname", "sort", "diff", "cmp", "comm", "grep", "rg", "ripgrep":
	default:
		return command, false
	}
	if len(command.ArgumentFacts) == 0 || !command.ArgumentFacts[0].Static || !onlyPathExpansions(command.DynamicFeatures) {
		return command, false
	}
	for _, key := range []string{"BASHOPTS", "SHELLOPTS", "GLOBIGNORE", "BASH_ENV", "ENV"} {
		if e.env[key] != "" {
			return command, false
		}
	}
	args := make([]string, 0, len(command.Arguments))
	facts := make([]IRArgument, 0, len(command.ArgumentFacts))
	for _, argument := range command.ArgumentFacts {
		values := []string{argument.Value}
		if !argument.Static {
			if !onlyPathExpansions(argument.DynamicFeatures) {
				return command, false
			}
			var ok bool
			values, ok = e.expandReadWord(argument.Raw, cwd)
			if !ok {
				return command, false
			}
		}
		if len(args)+len(values)-1 > maxPathExpansion {
			return command, false
		}
		for _, value := range values {
			args = append(args, value)
			facts = append(facts, IRArgument{Value: value, Static: true, Span: argument.Span})
		}
	}
	command.Arguments, command.ArgumentFacts, command.Static = args, facts, true
	return command, true
}

func (e *policyEvaluator) expandReadWord(raw, cwd string) ([]string, bool) {
	if !expansionWord.MatchString(raw) || strings.HasPrefix(raw, "-") || strings.Contains(raw, "**") {
		return nil, false
	}
	for _, part := range strings.Split(raw, "/") {
		if part == ".." {
			return nil, false
		}
	}
	patterns := []string{raw}
	if strings.ContainsAny(raw, "{}") {
		match := numericBrace.FindStringSubmatchIndex(raw)
		if match == nil || strings.ContainsAny(raw[:match[0]]+raw[match[1]:], "{}") {
			return nil, false
		}
		start, err1 := strconv.Atoi(raw[match[2]:match[3]])
		end, err2 := strconv.Atoi(raw[match[4]:match[5]])
		if err1 != nil || err2 != nil || start > end && start-end >= maxPathExpansion || end > start && end-start >= maxPathExpansion {
			return nil, false
		}
		step := 1
		if start > end {
			step = -1
		}
		patterns = nil
		for number := start; ; number += step {
			patterns = append(patterns, raw[:match[0]]+strconv.Itoa(number)+raw[match[1]:])
			if number == end {
				break
			}
		}
	}
	var result []string
	for _, pattern := range patterns {
		values := []string{pattern}
		if strings.ContainsAny(pattern, "*?") {
			var ok bool
			values, ok = e.expandGlob(pattern, cwd)
			if !ok {
				return nil, false
			}
		}
		if len(result)+len(values) > maxPathExpansion {
			return nil, false
		}
		for _, value := range values {
			if strings.HasPrefix(value, "-") || !e.safeReadPath(value, cwd) {
				return nil, false
			}
		}
		result = append(result, values...)
	}
	return result, len(result) > 0
}

func (e *policyEvaluator) expandGlob(pattern, cwd string) ([]string, bool) {
	prefix := ""
	if filepath.IsAbs(pattern) {
		prefix = string(filepath.Separator)
	}
	paths := []string{prefix}
	entriesRead := 0
	for _, part := range strings.Split(pattern, "/") {
		if part == "" {
			continue
		}
		var next []string
		for _, base := range paths {
			if !strings.ContainsAny(part, "*?") {
				next = append(next, filepath.Join(base, part))
				continue
			}
			directory := base
			if directory == "" {
				directory = "."
			}
			if !e.safeReadPath(directory, cwd) {
				return nil, false
			}
			if !filepath.IsAbs(directory) {
				directory = filepath.Join(cwd, directory)
			}
			info, err := os.Stat(directory)
			if err != nil || !info.IsDir() {
				continue
			}
			file, err := os.Open(directory)
			if err != nil {
				continue
			}
			entries, err := file.ReadDir(4097 - entriesRead)
			file.Close()
			entriesRead += len(entries)
			if err != nil && err != io.EOF || entriesRead > 4096 {
				return nil, false
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".") && !strings.HasPrefix(part, ".") {
					continue
				}
				matched, err := filepath.Match(part, entry.Name())
				if err != nil {
					return nil, false
				}
				if matched {
					next = append(next, filepath.Join(base, entry.Name()))
					if len(next) > maxPathExpansion {
						return nil, false
					}
				}
			}
		}
		paths = next
	}
	var matches []string
	for _, path := range paths {
		full := path
		if !filepath.IsAbs(full) {
			full = filepath.Join(cwd, full)
		}
		if _, err := os.Lstat(full); err == nil {
			matches = append(matches, path)
		}
	}
	sort.Strings(matches)
	return matches, len(matches) > 0
}
