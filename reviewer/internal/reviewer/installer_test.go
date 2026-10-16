package reviewer

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type installerConnection struct {
	AuthMode, Model, BaseUrl, ApiKeyEnv string
}

type installerAnswers struct {
	Connections           []installerConnection
	Profile               string
	ProtectedPaths        []string
	TimeoutMs             int
	Unavailable           string
	History, SessionTrust bool
}

func installerShellSource(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	marker := "\nrun_wizard \"$@\"; exit\n"
	if !strings.HasSuffix(text, marker) {
		t.Fatal("installer entrypoint changed; update the isolated function harness")
	}
	return strings.TrimSuffix(text, marker)
}

func installerPowerShell(t *testing.T) string {
	t.Helper()
	if binary := os.Getenv("AAR_TEST_PWSH"); binary != "" {
		return binary
	}
	for _, name := range []string{"pwsh", "powershell"} {
		if binary, err := exec.LookPath(name); err == nil {
			return binary
		}
	}
	t.Skip("PowerShell unavailable; set AAR_TEST_PWSH to check install.ps1")
	return ""
}

func shellInstallerConfig(t *testing.T, answers installerAnswers) []byte {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	var input strings.Builder
	input.WriteString(installerShellSource(t))
	input.WriteString("\nconnection_count=" + strconv.Itoa(len(answers.Connections)) + "\n")
	input.WriteString("connection_modes=(); models=(); urls=(); key_envs=(); protected_paths=()\n")
	for index, connection := range answers.Connections {
		for key, value := range map[string]string{"connection_modes": connection.AuthMode, "models": connection.Model, "urls": connection.BaseUrl, "key_envs": connection.ApiKeyEnv} {
			input.WriteString(key + "[" + strconv.Itoa(index) + "]=" + quote(value) + "\n")
		}
	}
	for _, path := range answers.ProtectedPaths {
		input.WriteString("protected_paths+=(" + quote(path) + ")\n")
	}
	input.WriteString("profile=" + quote(answers.Profile) + "\ntimeout_ms=" + strconv.Itoa(answers.TimeoutMs) + "\nunavailable=" + quote(answers.Unavailable) + "\n")
	input.WriteString("history=" + strconv.FormatBool(answers.History) + "\nsession_trust=" + strconv.FormatBool(answers.SessionTrust) + "\nwrite_config\n")
	command := exec.Command("bash", "-s")
	command.Stdin = strings.NewReader(input.String())
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Bash config generation: %v\n%s", err, output)
	}
	return output
}

func powerShellInstallerConfig(t *testing.T, answers installerAnswers) []byte {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "..", "install.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(answers)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(installerPowerShell(t), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
$tokens = $null; $errors = $null
[void][Management.Automation.Language.Parser]::ParseFile($env:AAR_TEST_SCRIPT, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors -join "\n") }
. $env:AAR_TEST_SCRIPT
$data = ConvertFrom-Json $env:AAR_TEST_INPUT
New-AarConfig -Connections @($data.Connections) -Profile $data.Profile -ProtectedPaths @($data.ProtectedPaths) -TimeoutMs $data.TimeoutMs -Unavailable $data.Unavailable -History $data.History -SessionTrust $data.SessionTrust
`)
	command.Env = append(os.Environ(), "AAR_TEST_SCRIPT="+path, "AAR_TEST_INPUT="+string(input))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("PowerShell config generation: %v\n%s", err, output)
	}
	return output
}

func TestInstallerGeneratedConfigs(t *testing.T) {
	api := installerConnection{AuthMode: "api-key", Model: "provider/model", BaseUrl: "https://api.example.com/v1", ApiKeyEnv: "ASSESSOR_API_KEY"}
	subscription := installerConnection{AuthMode: "opencode", Model: "subscription-model"}
	cases := []struct {
		name    string
		answers installerAnswers
	}{
		{"local-only", installerAnswers{Connections: []installerConnection{}, Profile: "data-loss", ProtectedPaths: []string{}, TimeoutMs: 5000, Unavailable: "deny", History: true, SessionTrust: true}},
		{"api-with-escaped-values", installerAnswers{Connections: []installerConnection{{AuthMode: "api-key", Model: "model\"\\quoted", BaseUrl: "http://127.0.0.1:8123/v1", ApiKeyEnv: "LOCAL_MODEL_KEY"}}, Profile: "strict", ProtectedPaths: []string{"/data/O'Neil/quote\" # important", `C:\Users\Tester\Documents`, "/данные/важное"}, TimeoutMs: 600000, Unavailable: "ask"}},
		{"subscription", installerAnswers{Connections: []installerConnection{subscription}, Profile: "balanced", ProtectedPaths: []string{}, TimeoutMs: 20000, Unavailable: "deny", History: true, SessionTrust: true}},
		{"ordered-api-fallbacks", installerAnswers{Connections: []installerConnection{api, {AuthMode: "api-key", Model: "backup", BaseUrl: "https://backup.example.com/v1", ApiKeyEnv: "BACKUP_KEY"}, subscription}, Profile: "data-loss", ProtectedPaths: []string{}, TimeoutMs: 10000, Unavailable: "ask", History: true}},
		{"subscription-api-fallback", installerAnswers{Connections: []installerConnection{subscription, api}, Profile: "balanced", ProtectedPaths: []string{"/valuable"}, TimeoutMs: 5000, Unavailable: "deny", SessionTrust: true}},
	}
	for _, generator := range []struct {
		name string
		run  func(*testing.T, installerAnswers) []byte
	}{{"bash", shellInstallerConfig}, {"powershell", powerShellInstallerConfig}} {
		t.Run(generator.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					payload := generator.run(t, tc.answers)
					directory := t.TempDir()
					path := filepath.Join(directory, "config.toml")
					if err := os.WriteFile(path, payload, 0600); err != nil {
						t.Fatal(err)
					}
					config, err := resolveReviewerConfig(Request{CWD: directory}, Options{ConfigPath: path})
					if err != nil {
						t.Fatalf("generated config rejected: %v\n%s", err, payload)
					}
					if config.Policy.Profile != tc.answers.Profile || !slices.Equal(config.Policy.ProtectedPaths, tc.answers.ProtectedPaths) || config.Grants.SessionTrust != tc.answers.SessionTrust || config.Audit.IsEnabled() != tc.answers.History {
						t.Fatalf("answers not preserved: %+v\n%s", config, payload)
					}
					if len(tc.answers.Connections) == 0 {
						if err := validateAssessorConfiguration(config); err != nil {
							t.Fatalf("deterministic config is not usable: %v", err)
						}
						return
					}
					connections := assessorConnections(config.Assessor)
					if len(connections) != len(tc.answers.Connections) || config.Assessor.TotalTimeoutMs != tc.answers.TimeoutMs || config.Assessor.OnUnavailable != tc.answers.Unavailable {
						t.Fatalf("connection/behavior answers not preserved: %+v", config.Assessor)
					}
					for index, got := range connections {
						want := tc.answers.Connections[index]
						if got.AuthMode != want.AuthMode || got.Model != want.Model || got.BaseURL != want.BaseUrl || got.APIKeyEnv != want.ApiKeyEnv {
							t.Fatalf("connection %d = %+v, want %+v", index, got, want)
						}
					}
				})
			}
		})
	}
}
