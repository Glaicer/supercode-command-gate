package reviewer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"
)

// DoctorReport is the startup contract consumed by the OpenCode Command Gate.
// It deliberately reports contract versions and operational deadlines without
// exposing configuration values or credential material.
type DoctorReport struct {
	LoggingEnabled             bool               `json:"loggingEnabled"`
	SchemaVersion              string             `json:"schemaVersion"`
	ContractVersion            string             `json:"contractVersion"`
	Status                     string             `json:"status"`
	RequestSchemaVersion       string             `json:"requestSchemaVersion"`
	DecisionSchemaVersion      string             `json:"decisionSchemaVersion"`
	ReviewerTimeoutMs          int                `json:"reviewerTimeoutMs"`
	ShellIRSchemaVersion       string             `json:"shellIRSchemaVersion"`
	HardDenyCatalogVersion     string             `json:"hardDenyCatalogVersion"`
	DeterministicPolicyVersion string             `json:"deterministicPolicyVersion"`
	AssessorSchemaVersion      string             `json:"assessorSchemaVersion"`
	AssessorMapperVersion      string             `json:"assessorMapperVersion"`
	Connections                []DoctorConnection `json:"connections,omitempty"`
	AssessorPromptDigest       string             `json:"assessorPromptDigest"`
}

type DoctorConnection struct {
	Connection          string `json:"connection"`
	CredentialAvailable bool   `json:"credentialAvailable"`
}

func doctorConnections(config AssessorConfig) []DoctorConnection {
	if config.Model == "" {
		return nil
	}
	result := []DoctorConnection{}
	for index, connection := range assessorConnections(config) {
		_, err := assessorAPIKey(AssessorConfig{APIKeyEnv: connection.APIKeyEnv})
		if connection.AuthMode == "codex" || connection.AuthMode == "opencode" {
			err = validateSubscriptionCredentials(config)
		}
		result = append(result, DoctorConnection{Connection: connectionLabel(index), CredentialAvailable: err == nil})
	}
	return result
}

// Doctor validates the Reviewer's configuration and state directory without
// evaluating or executing a command. Deterministic-only installations may
// omit an assessor model; those commands still have a healthy local reviewer.
func Doctor(request Request, options Options) (DoctorReport, error) {
	if request.CWD == "" {
		request.CWD = currentWorkingDirectory()
	}
	config, err := resolveReviewerConfig(request, options)
	if err != nil {
		return DoctorReport{}, err
	}
	if err := validateAssessorConfiguration(config); err != nil {
		return DoctorReport{}, err
	}
	stateDir, err := reviewerStateDirectory(options, config)
	if err != nil {
		return DoctorReport{}, err
	}
	if err := ensureDoctorStateDirectory(stateDir); err != nil {
		return DoctorReport{}, err
	}

	return DoctorReport{
		Connections:                doctorConnections(config.Assessor),
		LoggingEnabled:             config.Audit.IsEnabled(),
		SchemaVersion:              "aar-doctor-v1",
		ContractVersion:            "aar-contract-v1",
		Status:                     "ok",
		RequestSchemaVersion:       RequestSchemaVersion,
		DecisionSchemaVersion:      DecisionSchemaVersion,
		ReviewerTimeoutMs:          config.Assessor.TotalTimeoutMs,
		ShellIRSchemaVersion:       ShellIRSchemaVersion,
		HardDenyCatalogVersion:     CatastrophicCatalogVersion,
		DeterministicPolicyVersion: DeterministicPolicyVersion,
		AssessorSchemaVersion:      AssessorSchemaVersion,
		AssessorMapperVersion:      AssessorMapperVersion,
		AssessorPromptDigest:       assessorPromptDigest(),
	}, nil
}

func validateAssessorConfiguration(config Config) error {
	// Deterministic-only installs remain useful without an assessor. When an
	// assessor is configured, fail at startup for missing credentials or an
	// unusable endpoint instead of discovering the problem on the first command.
	if config.Assessor.Model == "" {
		if config.Assessor.BaseURL != "" || config.Assessor.APIKeyEnv != "" || len(config.Assessor.FallbackModels) > 0 || len(config.Assessor.Fallbacks) > 0 || config.Assessor.OnUnavailable != defaultUnavailableAction || len(config.Assessor.Options) > 0 || len(config.Assessor.ContextWindows) > 0 || len(config.Assessor.Interpreters) > 0 {
			return errors.New("assessor.model is required when assessor configuration is present")
		}
		return nil
	}
	if config.Assessor.AuthMode == "codex" || config.Assessor.AuthMode == "opencode" {
		return validateSubscriptionCredentials(config.Assessor)
	}
	available := false
	for index, connection := range assessorConnections(config.Assessor) {
		if _, err := chatCompletionsURL(connection.BaseURL); err != nil {
			return fmt.Errorf("%s: %w", connectionLabel(index), err)
		}
		if _, err := assessorAPIKey(AssessorConfig{APIKeyEnv: connection.APIKeyEnv}); err == nil {
			available = true
		}
	}
	if !available {
		return errors.New("all assessor connection credentials are unavailable")
	}

	return nil
}

func validateSubscriptionCredentials(config AssessorConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.TotalTimeoutMs)*time.Millisecond)
	defer cancel()
	_, err := loadSubscriptionCredentials(ctx, config.AuthMode, config.AuthJSONPath)
	return err
}

func assessorPromptDigest() string {
	digest := sha256.Sum256([]byte(assessorSystemPrompt))
	return hex.EncodeToString(digest[:])
}

func ensureDoctorStateDirectory(stateDir string) error {
	if stateDir == "" {
		return errors.New("reviewer state directory is empty")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create reviewer state directory: %w", err)
	}
	info, err := os.Stat(stateDir)
	if err != nil {
		return fmt.Errorf("stat reviewer state directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("reviewer state path %s is not a directory", stateDir)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return fmt.Errorf("secure reviewer state directory: %w", err)
	}
	probe, err := os.CreateTemp(stateDir, ".doctor-*")
	if err != nil {
		return fmt.Errorf("write reviewer state directory: %w", err)
	}
	probePath := probe.Name()
	defer os.Remove(probePath)
	if err := probe.Chmod(0o600); err != nil {
		_ = probe.Close()
		return fmt.Errorf("secure reviewer state probe: %w", err)
	}
	if _, err := probe.WriteString("aar doctor\n"); err != nil {
		_ = probe.Close()
		return fmt.Errorf("write reviewer state probe: %w", err)
	}
	if err := probe.Close(); err != nil {
		return fmt.Errorf("close reviewer state probe: %w", err)
	}
	return nil
}
