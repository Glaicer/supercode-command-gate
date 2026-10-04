package reviewer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// DoctorReport is the startup contract consumed by the OpenCode Command Gate.
// It deliberately reports contract versions and operational deadlines without
// exposing configuration values or credential material.
type DoctorReport struct {
	SchemaVersion              string `json:"schemaVersion"`
	ContractVersion            string `json:"contractVersion"`
	Status                     string `json:"status"`
	RequestSchemaVersion       string `json:"requestSchemaVersion"`
	DecisionSchemaVersion      string `json:"decisionSchemaVersion"`
	ReviewerTimeoutMs          int    `json:"reviewerTimeoutMs"`
	ShellIRSchemaVersion       string `json:"shellIRSchemaVersion"`
	HardDenyCatalogVersion     string `json:"hardDenyCatalogVersion"`
	DeterministicPolicyVersion string `json:"deterministicPolicyVersion"`
	AssessorSchemaVersion      string `json:"assessorSchemaVersion"`
	AssessorMapperVersion      string `json:"assessorMapperVersion"`
	AssessorPromptDigest       string `json:"assessorPromptDigest"`
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
		if config.Assessor.BaseURL != "" || config.Assessor.APIKeyEnv != "" || len(config.Assessor.FallbackModels) > 0 || config.Assessor.OnUnavailable != defaultUnavailableAction || len(config.Assessor.Options) > 0 || len(config.Assessor.ContextWindows) > 0 || len(config.Assessor.Interpreters) > 0 {
			return errors.New("assessor.model is required when assessor configuration is present")
		}
		return nil
	}
	if _, err := chatCompletionsURL(config.Assessor.BaseURL); err != nil {
		return err
	}
	if _, err := assessorAPIKey(config.Assessor); err != nil {
		return err
	}
	return nil
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
