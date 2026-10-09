package reviewer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type authExportOutput struct{ bytes.Buffer }

func (output *authExportOutput) Write(data []byte) (int, error) {
	if output.Len()+len(data) > 1024*1024 {
		return 0, errors.New("credential export exceeds limit")
	}
	return output.Buffer.Write(data)
}

func loadSubscriptionCredentials(ctx context.Context, authMode, authJSONPath string) (codexCredentials, error) {
	if authMode != "opencode" {
		return loadCodexCredentials(authJSONPath)
	}
	var result codexCredentials
	binary := os.Getenv("OPENCODE_BIN")
	if binary == "" {
		binary = "opencode"
	}
	// shortcut: targeted auth export boots a location; use the global read-only export to avoid recursive Gate startup until a filtered credential endpoint exists.
	command := exec.CommandContext(ctx, binary, "auth", "export")
	output := &authExportOutput{}
	command.Stdout = output
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		return result, errors.New("OpenCode credentials unavailable; check the CLI connection and sign in with OpenCode")
	}
	var entries []struct {
		IntegrationID string `json:"integrationID"`
		Active        bool   `json:"active"`
		Value         struct {
			Type     string `json:"type"`
			MethodID string `json:"methodID"`
			Access   string `json:"access"`
			Refresh  string `json:"refresh"`
			Expires  int64  `json:"expires"`
			Metadata struct {
				AccountID string `json:"accountID"`
			} `json:"metadata"`
		} `json:"value"`
	}
	if json.Unmarshal(output.Bytes(), &entries) != nil {
		return result, errors.New("OpenCode credential export is malformed")
	}
	found := false
	for _, entry := range entries {
		if entry.IntegrationID != "openai" || !entry.Active {
			continue
		}
		if found {
			return codexCredentials{}, errors.New("OpenCode has ambiguous active OpenAI credentials")
		}
		found = true
		value := entry.Value
		if value.Type != "oauth" || (value.MethodID != "chatgpt-browser" && value.MethodID != "chatgpt-headless") {
			return result, errors.New("OpenCode active OpenAI connection must use ChatGPT subscription login")
		}
		if value.Expires <= time.Now().UnixMilli() {
			return result, errors.New("OpenCode subscription access token expired; refresh or sign in with OpenCode, then retry")
		}
		if value.Access == "" || strings.ContainsAny(value.Access, "\r\n") || strings.TrimSpace(value.Metadata.AccountID) == "" || strings.ContainsAny(value.Metadata.AccountID, "\r\n") {
			return result, errors.New("OpenCode subscription credentials require an access token and account ID")
		}
		result.Tokens.AccessToken = value.Access
		result.Tokens.RefreshToken = value.Refresh
		result.Tokens.AccountID = value.Metadata.AccountID
	}
	if !found {
		return result, errors.New("OpenCode has no active OpenAI credential; sign in to ChatGPT subscription with OpenCode")
	}
	return result, nil
}
