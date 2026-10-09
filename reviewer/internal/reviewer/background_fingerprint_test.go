package reviewer

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func backgroundGoldenRequest() Request {
	return Request{
		SchemaVersion: RequestSchemaVersion,
		Command:       "pwd",
		CWD:           "/workspace/project",
		WorkspaceRoot: nil,
		Env:           map[string]string{"PWD": "/workspace/project"},
		Session:       Session{ID: "golden-session", Host: "opencode", IntentID: "intent-1"},
		Intent:        Intent{Goal: "inspect the workspace", LatestUserRequest: "show me the current directory", Purpose: "read-only inspection"},
	}
}

func fingerprintOfPayload(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func TestForegroundFingerprintPayloadsAreUnchanged(t *testing.T) {
	t.Parallel()

	request := backgroundGoldenRequest()
	basePayload := `{"command":"pwd","cwd":"/workspace/project","workspaceRoot":null,"sessionId":"golden-session","intentId":"intent-1","policyVersion":"deterministic-v2","shellIR":"shellir-v1"}`
	if got := fingerprintFor(request); got != fingerprintOfPayload(basePayload) {
		t.Fatalf("fingerprintFor() = %s, want the sha256 of the pre-background payload %s", got, basePayload)
	}

	factsPayload := `{"fingerprintSchema":"request-fingerprint-v2","command":"pwd","cwd":"/workspace/project","workspaceRoot":null,"sessionId":"golden-session","intentId":"intent-1","goal":"inspect the workspace","latestUserRequest":"show me the current directory","purpose":"read-only inspection","trustedEnv":{"PWD":"/workspace/project"},"requestSchema":"aar-request-v1","decisionSchema":"aar-decision-v1","shellIRSchema":"shellir-v1","policyVersion":"deterministic-v2","hardDenyCatalog":"catastrophic-v2","policy":{"Profile":"","CategoryOverrides":null,"ProtectedPaths":null,"AutoAllowAdditions":null},"paths":[],"scripts":[]}`
	if got := fingerprintForFacts(request, localAssessmentContext{}, Config{}); got != fingerprintOfPayload(factsPayload) {
		t.Fatalf("fingerprintForFacts() = %s, want the sha256 of the pre-background payload %s", got, factsPayload)
	}
}

func TestBackgroundFeedsBothFingerprints(t *testing.T) {
	t.Parallel()

	foreground := backgroundGoldenRequest()
	background := foreground
	background.Background = true

	if fingerprintFor(foreground) == fingerprintFor(background) {
		t.Fatal("fingerprintFor() ignored the background fact")
	}
	if fingerprintForFacts(foreground, localAssessmentContext{}, Config{}) == fingerprintForFacts(background, localAssessmentContext{}, Config{}) {
		t.Fatal("fingerprintForFacts() ignored the background fact")
	}
}
