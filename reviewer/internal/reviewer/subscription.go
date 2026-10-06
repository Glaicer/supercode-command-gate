package reviewer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const codexResponsesURL = "https://chatgpt.com/backend-api/codex/responses"

type codexCredentials struct {
	AuthMode string `json:"auth_mode"`
	Tokens   struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		AccountID    string `json:"account_id"`
	} `json:"tokens"`
}

func loadCodexCredentials(filename string) (codexCredentials, error) {
	var credentials codexCredentials
	file, err := os.Open(filename)
	if err != nil {
		return credentials, errors.New("Codex Auth JSON unavailable; select a readable file from Codex ChatGPT sign-in")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1024*1024 || info.Mode().Perm()&0077 != 0 {
		return credentials, errors.New("Codex Auth JSON must be a private regular file (0600), at most 1 MiB")
	}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&credentials); err != nil {
		return codexCredentials{}, errors.New("Codex Auth JSON is malformed")
	}
	if (credentials.AuthMode != "" && credentials.AuthMode != "chatgpt") || strings.TrimSpace(credentials.Tokens.AccountID) == "" || strings.ContainsAny(credentials.Tokens.AccountID, "\r\n") {
		return codexCredentials{}, errors.New("Codex Auth JSON requires ChatGPT sign-in tokens and an account ID; OpenCode credentials and API keys are unsupported")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return codexCredentials{}, errors.New("Codex Auth JSON contains trailing data")
	}
	parts := strings.Split(credentials.Tokens.AccessToken, ".")
	if len(parts) != 3 {
		return codexCredentials{}, errors.New("Codex Auth JSON access token is malformed")
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	var expiry struct {
		Exp int64 `json:"exp"`
	}
	if err != nil || json.Unmarshal(claims, &expiry) != nil || expiry.Exp <= 0 {
		return codexCredentials{}, errors.New("Codex Auth JSON access token expiry is missing or malformed")
	}
	if expiry.Exp <= time.Now().Unix() {
		return codexCredentials{}, errors.New("Codex access token expired; refresh or sign in with Codex, then retry; AAR reloads the file without changing it")
	}
	return credentials, nil
}

type codexModelCall struct {
	authJSONPath string
	client       *http.Client
}

func (call *codexModelCall) Call(ctx context.Context, request ModelCallRequest) (string, error) {
	credentials, err := loadCodexCredentials(call.authJSONPath)
	if err != nil {
		return "", err
	}
	payload := cloneMap(request.Options)
	payload["model"] = request.Model
	payload["instructions"] = request.SystemPrompt
	payload["input"] = []map[string]any{{"role": "user", "content": []map[string]string{{"type": "input_text", "text": request.UserPrompt}}}}
	payload["tools"] = []any{}
	payload["tool_choice"] = "none"
	payload["parallel_tool_calls"] = false
	payload["store"] = false
	payload["stream"] = true
	payload["include"] = []string{}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", errors.New("cannot encode Codex subscription assessment")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, codexResponsesURL, bytes.NewReader(body))
	if err != nil {
		return "", errors.New("cannot create Codex subscription assessment")
	}
	httpRequest.Header.Set("Authorization", "Bearer "+credentials.Tokens.AccessToken)
	httpRequest.Header.Set("ChatGPT-Account-ID", credentials.Tokens.AccountID)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "text/event-stream")
	httpRequest.Header.Set("originator", "codex_cli_rs")
	client := call.client
	if client == nil {
		client = http.DefaultClient
	}
	safeClient := *client
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := safeClient.Do(httpRequest)
	if err != nil {
		return "", errors.New("Codex subscription request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		switch response.StatusCode {
		case 401:
			return "", errors.New("Codex subscription authentication rejected; refresh or sign in with Codex, then retry")
		case 403:
			return "", errors.New("Codex subscription access denied; check account/model entitlement")
		case 429:
			return "", errors.New("Codex subscription usage limit reached; retry after the account limit resets")
		default:
			return "", fmt.Errorf("Codex subscription endpoint returned HTTP %d", response.StatusCode)
		}
	}
	text, err := readCodexAssessment(response.Body)
	if err != nil {
		return "", err
	}
	for _, secret := range []string{credentials.Tokens.AccessToken, credentials.Tokens.RefreshToken, credentials.Tokens.IDToken, credentials.Tokens.AccountID} {
		if secret != "" && strings.Contains(text, secret) {
			return "", errors.New("Codex subscription response contained credential material")
		}
	}
	return text, nil
}

func readCodexAssessment(reader io.Reader) (string, error) {
	scanner := bufio.NewScanner(io.LimitReader(reader, 4*1024*1024))
	scanner.Buffer(make([]byte, 4096), 2*1024*1024)
	var delta strings.Builder
	var data []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			continue
		}
		if line != "" || len(data) == 0 {
			continue
		}
		raw := strings.Join(data, "\n")
		data = nil
		if raw == "[DONE]" {
			continue
		}
		var event struct {
			Type     string `json:"type"`
			Delta    string `json:"delta"`
			Response struct {
				Status string `json:"status"`
				Output []struct {
					Type    string `json:"type"`
					Content []struct {
						Type string `json:"type"`
						Text string `json:"text"`
					} `json:"content"`
				} `json:"output"`
			} `json:"response"`
		}
		if json.Unmarshal([]byte(raw), &event) != nil {
			return "", errors.New("Codex subscription stream contains malformed JSON")
		}
		switch event.Type {
		case "response.output_text.delta":
			delta.WriteString(event.Delta)
		case "error", "response.failed", "response.incomplete":
			return "", errors.New("Codex subscription assessment failed or was incomplete")
		case "response.completed":
			if event.Response.Status != "completed" {
				return "", errors.New("Codex subscription response did not complete")
			}
			var text strings.Builder
			for _, item := range event.Response.Output {
				if item.Type != "message" && item.Type != "reasoning" {
					return "", errors.New("Codex subscription returned unsupported non-text output")
				}
				for _, part := range item.Content {
					if part.Type == "output_text" {
						text.WriteString(part.Text)
					}
				}
			}
			if text.Len() > 0 {
				return text.String(), nil
			}
			if delta.Len() > 0 {
				return delta.String(), nil
			}
			return "", errors.New("Codex subscription response contained no assessment text")
		}
	}
	return "", errors.New("Codex subscription stream ended without a completed assessment")
}
