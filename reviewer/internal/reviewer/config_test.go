package reviewer_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/supercode/auto-approval-reviewer/internal/reviewer"
)

func TestReviewerConfigUsesExplicitSourceThenProjectOverlay(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "base.toml")
	if err := os.WriteFile(base, []byte(`
[assessor]
model = "base-model"
fallbackModels = ["base-fallback"]
baseUrl = "https://example.test/v1"
apiKeyEnv = "AAR_TEST_API_KEY"
totalTimeoutMs = 3210
onUnavailable = "ask"

[assessor.options]
temperature = 0

[policy]
profile = "balanced"
protectedPaths = ["protected"]

[policy.categoryOverrides]
credential_access = "ask"

[grants]
sessionTrust = false

[audit]
dir = "base-audit"
`), 0o600); err != nil {
		t.Fatalf("write base config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".aar.toml"), []byte(`
[assessor]
model = "project-model"
fallbackModels = ["project-fallback"]

[policy]
profile = "strict"
protectedPaths = ["project-protected"]

[audit]
dir = "project-audit"
`), 0o600); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	t.Setenv("AAR_CONFIG", base)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "xdg"))
	cwd := root
	config, err := reviewer.ResolveConfig(reviewer.Request{CWD: cwd, WorkspaceRoot: &cwd})
	if err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}
	if config.Assessor.Model != "project-model" || len(config.Assessor.FallbackModels) != 1 || config.Assessor.FallbackModels[0] != "project-fallback" {
		t.Fatalf("assessor config = %#v, want project overlay", config.Assessor)
	}
	if config.Assessor.BaseURL != "https://example.test/v1" || config.Assessor.APIKeyEnv != "AAR_TEST_API_KEY" || config.Assessor.TotalTimeoutMs != 3210 || config.Assessor.OnUnavailable != "ask" {
		t.Fatalf("assessor base fields = %#v", config.Assessor)
	}
	if config.Policy.Profile != "strict" || len(config.Policy.ProtectedPaths) != 1 || config.Policy.ProtectedPaths[0] != "project-protected" {
		t.Fatalf("policy config = %#v", config.Policy)
	}
	if config.Policy.CategoryOverrides["credential_access"] != "ask" || config.Grants.SessionTrust {
		t.Fatalf("policy/grants overlay lost base values: %#v %#v", config.Policy, config.Grants)
	}
	if config.Assessor.Options["temperature"] != int64(0) {
		t.Fatalf("assessor options = %#v, want temperature preserved", config.Assessor.Options)
	}
	if config.Audit.Dir != "project-audit" {
		t.Fatalf("audit dir = %q, want project-audit", config.Audit.Dir)
	}
}

func TestInvalidUnavailableActionIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[assessor]\nmodel = \"primary\"\nonUnavailable = \"allow\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAR_CONFIG", path)
	_, err := reviewer.ResolveConfig(reviewer.Request{CWD: t.TempDir()})
	if err == nil {
		t.Fatal("ResolveConfig() error = nil, want invalid onUnavailable error")
	}
}

func TestReviewerConfigParsesExactAdditionTablesAndRejectsCredentialOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(`
[assessor]
model = "primary"

[assessor.options]
reasoning_effort = "low"

[policy]
profile = "data-loss"

[[policy.autoAllowAdditions]]
argv = ["my-reader", "source"]
pathScope = ["."]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAR_CONFIG", path)
	config, err := reviewer.ResolveConfig(reviewer.Request{CWD: t.TempDir()})
	if err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}
	if len(config.Policy.AutoAllowAdditions) != 1 || config.Policy.AutoAllowAdditions[0].Argv[0] != "my-reader" {
		t.Fatalf("auto-allow additions = %#v", config.Policy.AutoAllowAdditions)
	}

	credentialPath := filepath.Join(t.TempDir(), "credential-options.toml")
	if err := os.WriteFile(credentialPath, []byte("[assessor]\nmodel = \"primary\"\n[assessor.options]\napiKey = \"must-reject\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAR_CONFIG", credentialPath)
	if _, err := reviewer.ResolveConfig(reviewer.Request{CWD: t.TempDir()}); err == nil {
		t.Fatal("ResolveConfig() error = nil, want credential option rejection")
	}
}

func TestMissingPrimaryModelDoesNotUseFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[assessor]\nfallbackModels = [\"fallback\"]\nonUnavailable = \"ask\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAR_CONFIG", path)
	config, err := reviewer.ResolveConfig(reviewer.Request{CWD: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if config.Assessor.Model != "" || len(config.Assessor.FallbackModels) != 1 {
		t.Fatalf("config = %#v, want missing primary preserved", config.Assessor)
	}
}

func TestReviewerConfigParsesContextWindowsAndInterpreterForms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(`
[assessor]
model = "primary"

[assessor.contextWindows]
primary = 4096
fallback = 32768

[assessor.interpreters.custom-runner]
inlineFlags = ["--run"]
fileExtensions = [".runner"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAR_CONFIG", path)
	config, err := reviewer.ResolveConfig(reviewer.Request{CWD: t.TempDir()})
	if err != nil {
		t.Fatalf("ResolveConfig() error = %v", err)
	}
	if config.Assessor.ContextWindows["primary"] != 4096 || config.Assessor.ContextWindows["fallback"] != 32768 {
		t.Fatalf("context windows = %#v", config.Assessor.ContextWindows)
	}
	form, ok := config.Assessor.Interpreters["custom-runner"]
	if !ok || len(form.InlineFlags) != 1 || form.InlineFlags[0] != "--run" || len(form.FileExtensions) != 1 || form.FileExtensions[0] != ".runner" {
		t.Fatalf("interpreter form = %#v, want configured form", form)
	}
}
