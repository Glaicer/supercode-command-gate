package reviewer_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/supercode/auto-approval-reviewer/internal/reviewer"
)

func TestDoctorReportsSupportedContractsAndSecuresStateDirectory(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	cwd := t.TempDir()
	report, err := reviewer.Doctor(reviewer.Request{CWD: cwd, WorkspaceRoot: &cwd}, reviewer.Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Doctor() error = %v", err)
	}
	if report.SchemaVersion != "aar-doctor-v1" || report.ContractVersion != "aar-contract-v1" || report.Status != "ok" {
		t.Fatalf("report = %#v, want healthy doctor report", report)
	}
	if report.RequestSchemaVersion != reviewer.RequestSchemaVersion || report.DecisionSchemaVersion != reviewer.DecisionSchemaVersion {
		t.Fatalf("report contracts = %#v, want supported request and decision versions", report)
	}
	if report.ReviewerTimeoutMs <= 0 {
		t.Fatalf("reviewer timeout = %d, want positive timeout", report.ReviewerTimeoutMs)
	}
	if report.ShellIRSchemaVersion != reviewer.ShellIRSchemaVersion {
		t.Fatalf("ShellIR schema = %q, want %q", report.ShellIRSchemaVersion, reviewer.ShellIRSchemaVersion)
	}
	if report.HardDenyCatalogVersion == "" || report.DeterministicPolicyVersion == "" || report.AssessorSchemaVersion != reviewer.AssessorSchemaVersion || report.AssessorMapperVersion != reviewer.AssessorMapperVersion || len(report.AssessorPromptDigest) != 64 {
		t.Fatalf("version report = %#v, want supported policy, assessor schema/mapper, and 64-character prompt digest", report)
	}
	info, err := os.Stat(stateDir)
	if err != nil {
		t.Fatalf("stat state directory: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("state directory mode = %o, want 700", got)
	}
}

func TestDoctorRejectsInvalidReviewerConfiguration(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "invalid.toml")
	if err := os.WriteFile(configPath, []byte("[assessor]\nonUnavailable = \"allow\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := reviewer.Doctor(
		reviewer.Request{CWD: t.TempDir()},
		reviewer.Options{ConfigPath: configPath, StateDir: t.TempDir()},
	)
	if err == nil {
		t.Fatal("Doctor() error = nil, want invalid configuration error")
	}
}

func TestDoctorRejectsUnavailableConfiguredAssessor(t *testing.T) {
	t.Setenv("AAR_MISSING_KEY", "")
	_, err := reviewer.Doctor(
		reviewer.Request{CWD: t.TempDir()},
		reviewer.Options{Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{
			Model: "test-model", BaseURL: "https://model.example.test/v1", APIKeyEnv: "AAR_MISSING_KEY",
		}}, StateDir: t.TempDir()},
	)
	if err == nil {
		t.Fatal("Doctor() error = nil, want missing assessor credential error")
	}
}

func TestDoctorRejectsPartialAssessorConfiguration(t *testing.T) {
	_, err := reviewer.Doctor(
		reviewer.Request{CWD: t.TempDir()},
		reviewer.Options{Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{BaseURL: "https://model.example.test/v1"}}, StateDir: t.TempDir()},
	)
	if err == nil {
		t.Fatal("Doctor() error = nil, want missing assessor model error")
	}
}

func TestDoctorRejectsAssessorPolicyWithoutModel(t *testing.T) {
	_, err := reviewer.Doctor(
		reviewer.Request{CWD: t.TempDir()},
		reviewer.Options{Config: &reviewer.Config{Assessor: reviewer.AssessorConfig{OnUnavailable: reviewer.DecisionAsk}}, StateDir: t.TempDir()},
	)
	if err == nil {
		t.Fatal("Doctor() error = nil, want missing assessor model error")
	}
}
