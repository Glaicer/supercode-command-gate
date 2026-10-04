package reviewer

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	defaultRiskProfile                = "data-loss"
	defaultUnavailableAction          = DecisionDeny
	defaultAssessorTimeoutMs          = 5000
	defaultGrantMaxAgeSeconds         = 24 * 60 * 60
	defaultGrantReservationTTLSeconds = 10 * 60
)

var riskCategories = []string{
	"critical_data_loss",
	"credential_access",
	"external_side_effect",
	"network",
	"privilege",
	"persistence",
	"process_control",
	"resource_exhaustion",
	"opaque_execution",
	"goal_mismatch",
}

var riskCategorySet = make(map[string]bool)

func init() {
	for _, category := range riskCategories {
		riskCategorySet[category] = true
	}
}

func defaultConfig() Config {
	return Config{
		Assessor: AssessorConfig{
			TotalTimeoutMs: defaultAssessorTimeoutMs,
			OnUnavailable:  defaultUnavailableAction,
			Options:        map[string]any{},
		},
		Policy: PolicyConfig{
			Profile:           defaultRiskProfile,
			CategoryOverrides: map[string]string{},
		},
		Grants: GrantsConfig{
			SessionTrust:          true,
			MaxAgeSeconds:         defaultGrantMaxAgeSeconds,
			ReservationTTLSeconds: defaultGrantReservationTTLSeconds,
		},
	}
}

// ResolveConfig resolves the Reviewer's process and project configuration.
// Check uses the same function with its test/embedding options applied.
func ResolveConfig(request Request) (Config, error) {
	return resolveReviewerConfig(request, Options{})
}

func resolveReviewerConfig(request Request, options Options) (Config, error) {
	config := defaultConfig()
	if options.Config != nil {
		config = cloneConfig(*options.Config)
	} else {
		basePath, found, err := reviewerConfigPath(options.ConfigPath)
		if err != nil {
			return Config{}, err
		}
		if found {
			values, err := readTOMLFile(basePath)
			if err != nil {
				return Config{}, fmt.Errorf("read reviewer config %s: %w", basePath, err)
			}
			if err := applyConfigValues(&config, values); err != nil {
				return Config{}, fmt.Errorf("decode reviewer config %s: %w", basePath, err)
			}
		}

		projectPath := projectConfigPath(request)
		if projectPath != "" {
			if _, err := os.Stat(projectPath); err == nil {
				values, err := readTOMLFile(projectPath)
				if err != nil {
					return Config{}, fmt.Errorf("read project reviewer config %s: %w", projectPath, err)
				}
				if err := applyConfigValues(&config, values); err != nil {
					return Config{}, fmt.Errorf("decode project reviewer config %s: %w", projectPath, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return Config{}, fmt.Errorf("stat project reviewer config %s: %w", projectPath, err)
			}
		}
	}

	if options.ProtectedPaths != nil {
		config.Policy.ProtectedPaths = append([]string(nil), options.ProtectedPaths...)
	}
	if options.AutoAllowAdditions != nil {
		config.Policy.AutoAllowAdditions = append([]AutoAllowAddition(nil), options.AutoAllowAdditions...)
	}
	if options.StateDir != "" {
		config.Audit.Dir = options.StateDir
	}
	return normalizeConfig(config)
}

func reviewerConfigPath(explicit string) (path string, found bool, err error) {
	if explicit != "" {
		if _, statErr := os.Stat(explicit); statErr == nil {
			return explicit, true, nil
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return "", false, statErr
		}
		return "", false, nil
	}

	candidates := make([]string, 0, 3)
	if configured := os.Getenv("AAR_CONFIG"); configured != "" {
		candidates = append(candidates, configured)
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		candidates = append(candidates, filepath.Join(xdg, "aar", "config.toml"))
	}
	if platformPath := platformConfigPath(); platformPath != "" {
		candidates = append(candidates, platformPath)
	}
	for _, candidate := range candidates {
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate, true, nil
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return "", false, statErr
		}
	}
	return "", false, nil
}

func platformConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "aar", "config.toml")
	case "windows":
		if appData := os.Getenv("AppData"); appData != "" {
			return filepath.Join(appData, "aar", "config.toml")
		}
		return filepath.Join(home, "AppData", "Roaming", "aar", "config.toml")
	default:
		return filepath.Join(home, ".config", "aar", "config.toml")
	}
}

func projectConfigPath(request Request) string {
	root := request.CWD
	if request.WorkspaceRoot != nil && *request.WorkspaceRoot != "" {
		root = *request.WorkspaceRoot
	}
	if root == "" {
		return ""
	}
	return filepath.Join(root, ".aar.toml")
}

func normalizeConfig(config Config) (Config, error) {
	defaults := defaultConfig()
	if config.Policy.Profile == "" {
		config.Policy.Profile = defaults.Policy.Profile
	}
	if config.Assessor.TotalTimeoutMs <= 0 {
		config.Assessor.TotalTimeoutMs = defaults.Assessor.TotalTimeoutMs
	}
	if config.Assessor.OnUnavailable == "" {
		config.Assessor.OnUnavailable = defaults.Assessor.OnUnavailable
	}
	if config.Assessor.Options == nil {
		config.Assessor.Options = map[string]any{}
	}
	for model, window := range config.Assessor.ContextWindows {
		if strings.TrimSpace(model) == "" || window <= 0 {
			return Config{}, fmt.Errorf("assessor.contextWindows.%s must be a positive integer", model)
		}
	}
	for key := range config.Assessor.Options {
		lower := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", ""), "_", ""))
		if strings.Contains(lower, "apikey") || strings.Contains(lower, "authorization") || strings.Contains(lower, "password") || strings.Contains(lower, "secret") || lower == "token" {
			return Config{}, fmt.Errorf("assessor.options.%s cannot contain credential material", key)
		}
	}
	if config.Policy.CategoryOverrides == nil {
		config.Policy.CategoryOverrides = map[string]string{}
	}
	if config.Policy.Profile != "data-loss" && config.Policy.Profile != "balanced" && config.Policy.Profile != "strict" {
		return Config{}, fmt.Errorf("policy.profile must be data-loss, balanced, or strict")
	}
	if config.Assessor.OnUnavailable != DecisionAsk && config.Assessor.OnUnavailable != DecisionDeny {
		return Config{}, fmt.Errorf("assessor.onUnavailable must be ask or deny")
	}
	if config.Grants.MaxAgeSeconds <= 0 {
		config.Grants.MaxAgeSeconds = defaults.Grants.MaxAgeSeconds
	}
	if config.Grants.ReservationTTLSeconds <= 0 {
		config.Grants.ReservationTTLSeconds = defaults.Grants.ReservationTTLSeconds
	}
	for category, override := range config.Policy.CategoryOverrides {
		if !riskCategorySet[category] {
			return Config{}, fmt.Errorf("policy.categoryOverrides contains unsupported category %q", category)
		}
		if override != "inherit" && override != "ignore" && override != DecisionAsk && override != DecisionDeny {
			return Config{}, fmt.Errorf("policy.categoryOverrides.%s must be inherit, ignore, ask, or deny", category)
		}
	}
	return config, nil
}

func cloneConfig(config Config) Config {
	clone := config
	clone.Assessor.FallbackModels = append([]string(nil), config.Assessor.FallbackModels...)
	clone.Assessor.Options = cloneMap(config.Assessor.Options)
	clone.Assessor.ContextWindows = cloneIntMap(config.Assessor.ContextWindows)
	clone.Assessor.Interpreters = cloneInterpreterForms(config.Assessor.Interpreters)
	clone.Policy.CategoryOverrides = cloneStringMap(config.Policy.CategoryOverrides)
	clone.Policy.ProtectedPaths = append([]string(nil), config.Policy.ProtectedPaths...)
	clone.Policy.AutoAllowAdditions = append([]AutoAllowAddition(nil), config.Policy.AutoAllowAdditions...)
	for index := range clone.Policy.AutoAllowAdditions {
		clone.Policy.AutoAllowAdditions[index].Argv = append([]string(nil), config.Policy.AutoAllowAdditions[index].Argv...)
		clone.Policy.AutoAllowAdditions[index].PathScope = append([]string(nil), config.Policy.AutoAllowAdditions[index].PathScope...)
	}
	return clone
}

func cloneIntMap(values map[string]int) map[string]int {
	clone := make(map[string]int, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func cloneInterpreterForms(values map[string]InterpreterForm) map[string]InterpreterForm {
	clone := make(map[string]InterpreterForm, len(values))
	for key, value := range values {
		clone[key] = InterpreterForm{
			InlineFlags:    append([]string(nil), value.InlineFlags...),
			FileExtensions: append([]string(nil), value.FileExtensions...),
		}
	}
	return clone
}

func cloneMap(values map[string]any) map[string]any {
	clone := make(map[string]any, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func cloneStringMap(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func applyConfigValues(config *Config, values map[string]any) error {
	for _, sectionName := range []string{"assessor", "policy", "grants", "audit"} {
		if raw, present := values[sectionName]; present {
			if _, ok := raw.(map[string]any); !ok {
				return fmt.Errorf("%s must be a table", sectionName)
			}
		}
	}
	if section, ok := mapValue(values, "assessor"); ok {
		if raw, present := section["model"]; present {
			value, ok := raw.(string)
			if !ok {
				return errors.New("assessor.model must be a string")
			}
			config.Assessor.Model = value
		}
		if _, present := section["fallbackModels"]; present {
			value, ok := stringSliceValue(section, "fallbackModels")
			if !ok {
				return errors.New("assessor.fallbackModels must be an array of strings")
			}
			config.Assessor.FallbackModels = value
		}
		if raw, present := section["baseUrl"]; present {
			value, ok := raw.(string)
			if !ok {
				return errors.New("assessor.baseUrl must be a string")
			}
			config.Assessor.BaseURL = value
		}
		if raw, present := section["apiKeyEnv"]; present {
			value, ok := raw.(string)
			if !ok {
				return errors.New("assessor.apiKeyEnv must be a string")
			}
			config.Assessor.APIKeyEnv = value
		}
		if _, present := section["totalTimeoutMs"]; present {
			value, ok := intValue(section, "totalTimeoutMs")
			if !ok {
				return errors.New("assessor.totalTimeoutMs must be an integer")
			}
			config.Assessor.TotalTimeoutMs = value
		}
		if raw, present := section["onUnavailable"]; present {
			value, ok := raw.(string)
			if !ok {
				return errors.New("assessor.onUnavailable must be a string")
			}
			config.Assessor.OnUnavailable = value
		}
		if raw, present := section["options"]; present {
			options, ok := raw.(map[string]any)
			if !ok {
				return errors.New("assessor.options must be a table")
			}
			config.Assessor.Options = mergeValueMaps(config.Assessor.Options, options)
		}
		if raw, present := section["contextWindows"]; present {
			windows, ok := raw.(map[string]any)
			if !ok {
				return errors.New("assessor.contextWindows must be a table")
			}
			if config.Assessor.ContextWindows == nil {
				config.Assessor.ContextWindows = map[string]int{}
			}
			for model, rawWindow := range windows {
				window, ok := intValue(map[string]any{"window": rawWindow}, "window")
				if !ok {
					return fmt.Errorf("assessor.contextWindows.%s must be an integer", model)
				}
				config.Assessor.ContextWindows[model] = window
			}
		}
		if raw, present := section["interpreters"]; present {
			interpreters, ok := raw.(map[string]any)
			if !ok {
				return errors.New("assessor.interpreters must be a table")
			}
			if config.Assessor.Interpreters == nil {
				config.Assessor.Interpreters = map[string]InterpreterForm{}
			}
			for name, rawForm := range interpreters {
				formValues, ok := rawForm.(map[string]any)
				if !ok {
					return fmt.Errorf("assessor.interpreters.%s must be a table", name)
				}
				form := config.Assessor.Interpreters[name]
				if _, present := formValues["inlineFlags"]; present {
					flags, ok := stringSliceValue(formValues, "inlineFlags")
					if !ok {
						return fmt.Errorf("assessor.interpreters.%s.inlineFlags must be an array of strings", name)
					}
					form.InlineFlags = flags
				}
				if _, present := formValues["fileExtensions"]; present {
					extensions, ok := stringSliceValue(formValues, "fileExtensions")
					if !ok {
						return fmt.Errorf("assessor.interpreters.%s.fileExtensions must be an array of strings", name)
					}
					form.FileExtensions = extensions
				}
				config.Assessor.Interpreters[name] = form
			}
		}
	}
	if section, ok := mapValue(values, "policy"); ok {
		if raw, present := section["profile"]; present {
			value, ok := raw.(string)
			if !ok {
				return errors.New("policy.profile must be a string")
			}
			config.Policy.Profile = value
		}
		if _, present := section["protectedPaths"]; present {
			value, ok := stringSliceValue(section, "protectedPaths")
			if !ok {
				return errors.New("policy.protectedPaths must be an array of strings")
			}
			config.Policy.ProtectedPaths = value
		}
		if raw, present := section["categoryOverrides"]; present {
			overrides, ok := raw.(map[string]any)
			if !ok {
				return errors.New("policy.categoryOverrides must be a table")
			}
			if config.Policy.CategoryOverrides == nil {
				config.Policy.CategoryOverrides = map[string]string{}
			}
			for key, value := range overrides {
				stringValue, ok := value.(string)
				if !ok {
					return fmt.Errorf("policy.categoryOverrides.%s must be a string", key)
				}
				config.Policy.CategoryOverrides[key] = stringValue
			}
		}
		if raw, present := section["autoAllowAdditions"]; present {
			additions, ok := raw.([]any)
			if !ok {
				return errors.New("policy.autoAllowAdditions must be an array of tables")
			}
			parsed := make([]AutoAllowAddition, 0, len(additions))
			for index, raw := range additions {
				item, ok := raw.(map[string]any)
				if !ok {
					return fmt.Errorf("policy.autoAllowAdditions[%d] must be a table", index)
				}
				argv, ok := stringSliceValue(item, "argv")
				if !ok {
					return fmt.Errorf("policy.autoAllowAdditions[%d].argv must be an array of strings", index)
				}
				pathScope := []string(nil)
				if _, present := item["pathScope"]; present {
					pathScope, ok = stringSliceValue(item, "pathScope")
					if !ok {
						return fmt.Errorf("policy.autoAllowAdditions[%d].pathScope must be an array of strings", index)
					}
				}
				parsed = append(parsed, AutoAllowAddition{Argv: argv, PathScope: pathScope})
			}
			config.Policy.AutoAllowAdditions = parsed
		}
	}
	if section, ok := mapValue(values, "grants"); ok {
		if raw, present := section["sessionTrust"]; present {
			value, ok := raw.(bool)
			if !ok {
				return errors.New("grants.sessionTrust must be a boolean")
			}
			config.Grants.SessionTrust = value
		}
		if _, present := section["maxAgeSeconds"]; present {
			value, ok := intValue(section, "maxAgeSeconds")
			if !ok {
				return errors.New("grants.maxAgeSeconds must be an integer")
			}
			config.Grants.MaxAgeSeconds = value
		}
		if _, present := section["reservationTTLSeconds"]; present {
			value, ok := intValue(section, "reservationTTLSeconds")
			if !ok {
				return errors.New("grants.reservationTTLSeconds must be an integer")
			}
			config.Grants.ReservationTTLSeconds = value
		}
	}
	if section, ok := mapValue(values, "audit"); ok {
		if raw, present := section["dir"]; present {
			value, ok := raw.(string)
			if !ok {
				return errors.New("audit.dir must be a string")
			}
			config.Audit.Dir = value
		}
	}
	return nil
}

func mapValue(values map[string]any, key string) (map[string]any, bool) {
	value, ok := values[key]
	if !ok {
		return nil, false
	}
	result, ok := value.(map[string]any)
	return result, ok
}

func intValue(values map[string]any, key string) (int, bool) {
	switch value := values[key].(type) {
	case int64:
		return int(value), true
	case int:
		return value, true
	case float64:
		return int(value), value == float64(int(value))
	default:
		return 0, false
	}
}

func stringSliceValue(values map[string]any, key string) ([]string, bool) {
	items, ok := values[key].([]any)
	if !ok {
		if strings, ok := values[key].([]string); ok {
			return append([]string(nil), strings...), true
		}
		return nil, false
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		value, ok := item.(string)
		if !ok {
			return nil, false
		}
		result = append(result, value)
	}
	return result, true
}

func mergeValueMaps(base, overlay map[string]any) map[string]any {
	merged := cloneMap(base)
	for key, value := range overlay {
		if baseMap, ok := merged[key].(map[string]any); ok {
			if overlayMap, ok := value.(map[string]any); ok {
				merged[key] = mergeValueMaps(baseMap, overlayMap)
				continue
			}
		}
		merged[key] = value
	}
	return merged
}

func readTOMLFile(path string) (map[string]any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	root := map[string]any{}
	section := []string{}
	var currentTable map[string]any = root
	currentTableIsRoot := true
	var pending string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = stripTOMLComment(line)
		if line == "" {
			continue
		}
		if pending != "" {
			line = pending + " " + line
			pending = ""
		}
		if key, value, ok := splitTOMLAssignment(line); ok {
			if !balancedTOMLValue(value) {
				pending = line
				continue
			}
			parsed, err := parseTOMLValue(value)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			if currentTableIsRoot && len(section) > 0 {
				setTOMLValue(root, append(append([]string(nil), section...), key), parsed)
			} else {
				setTOMLValue(currentTable, []string{key}, parsed)
			}
			continue
		}
		if strings.HasPrefix(line, "[[") && strings.HasSuffix(line, "]]") {
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "[["), "]]"))
			path := splitDottedKey(name)
			if len(path) == 0 {
				return nil, errors.New("empty array table name")
			}
			parent := ensureTOMLMap(root, path[:len(path)-1])
			key := path[len(path)-1]
			items, _ := parent[key].([]any)
			item := map[string]any{}
			parent[key] = append(items, item)
			section = nil
			currentTable = item
			currentTableIsRoot = false
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if name == "" {
				return nil, errors.New("empty table name")
			}
			section = splitDottedKey(name)
			ensureTOMLMap(root, section)
			currentTable = ensureTOMLMap(root, section)
			currentTableIsRoot = false
			continue
		}
		return nil, fmt.Errorf("unsupported TOML line %q", line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if pending != "" {
		return nil, errors.New("unterminated TOML value")
	}
	return root, nil
}

func splitTOMLAssignment(line string) (key, value string, ok bool) {
	quote := rune(0)
	depth := 0
	for index, current := range line {
		if current == '\\' && quote == '"' {
			continue
		}
		if (current == '"' || current == '\'') && (quote == 0 || quote == current) {
			if quote == 0 {
				quote = current
			} else {
				quote = 0
			}
		}
		if quote != 0 {
			continue
		}
		switch current {
		case '[', '{':
			depth++
		case ']', '}':
			depth--
		case '=':
			if depth == 0 {
				return strings.TrimSpace(line[:index]), strings.TrimSpace(line[index+1:]), true
			}
		}
	}
	return "", "", false
}

func stripTOMLComment(line string) string {
	quote := rune(0)
	for index, current := range line {
		if current == '"' || current == '\'' {
			if quote == 0 {
				quote = current
			} else if quote == current {
				quote = 0
			}
		}
		if current == '#' && quote == 0 {
			return strings.TrimSpace(line[:index])
		}
	}
	return strings.TrimSpace(line)
}

func balancedTOMLValue(value string) bool {
	quote := rune(0)
	depth := 0
	for _, current := range value {
		if current == '"' || current == '\'' {
			if quote == 0 {
				quote = current
			} else if quote == current {
				quote = 0
			}
			continue
		}
		if quote != 0 {
			continue
		}
		if current == '[' || current == '{' {
			depth++
		} else if current == ']' || current == '}' {
			depth--
		}
	}
	return quote == 0 && depth == 0
}

func parseTOMLValue(value string) (any, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty value")
	}
	if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
		decoded, err := strconv.Unquote(value)
		if err != nil {
			return nil, fmt.Errorf("invalid string: %w", err)
		}
		return decoded, nil
	}
	if strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") {
		return strings.TrimSuffix(strings.TrimPrefix(value, "'"), "'"), nil
	}
	if value == "true" || value == "false" {
		return value == "true", nil
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		parts := splitTOMLList(strings.TrimSpace(value[1 : len(value)-1]))
		items := make([]any, 0, len(parts))
		for _, part := range parts {
			item, err := parseTOMLValue(part)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, nil
	}
	if strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}") {
		result := map[string]any{}
		for _, part := range splitTOMLList(strings.TrimSpace(value[1 : len(value)-1])) {
			key, itemValue, ok := splitTOMLAssignment(part)
			if !ok {
				return nil, fmt.Errorf("invalid inline table item %q", part)
			}
			item, err := parseTOMLValue(itemValue)
			if err != nil {
				return nil, err
			}
			result[strings.TrimSpace(key)] = item
		}
		return result, nil
	}
	if integer, err := strconv.ParseInt(value, 10, 64); err == nil {
		return integer, nil
	}
	if floating, err := strconv.ParseFloat(value, 64); err == nil {
		return floating, nil
	}
	return nil, fmt.Errorf("unsupported value %q", value)
}

func splitTOMLList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := []string{}
	start := 0
	quote := rune(0)
	depth := 0
	for index, current := range value {
		if current == '"' || current == '\'' {
			if quote == 0 {
				quote = current
			} else if quote == current {
				quote = 0
			}
		}
		if quote != 0 {
			continue
		}
		switch current {
		case '[', '{':
			depth++
		case ']', '}':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(value[start:index]))
				start = index + 1
			}
		}
	}
	parts = append(parts, strings.TrimSpace(value[start:]))
	return parts
}

func splitDottedKey(value string) []string {
	parts := strings.Split(value, ".")
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
		parts[index] = strings.Trim(parts[index], "\"")
	}
	return parts
}

func ensureTOMLMap(root map[string]any, path []string) map[string]any {
	current := root
	for _, key := range path {
		if nested, ok := current[key].(map[string]any); ok {
			current = nested
			continue
		}
		nested := map[string]any{}
		current[key] = nested
		current = nested
	}
	return current
}

func setTOMLValue(root map[string]any, path []string, value any) {
	if len(path) == 0 {
		return
	}
	parent := ensureTOMLMap(root, path[:len(path)-1])
	parent[path[len(path)-1]] = value
}
