package reviewer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	grantStateDirectory = "grants"
	grantStateVersion   = "aar-session-grants-v1"
	grantLockTimeout    = 2 * time.Second
)

type grantReservation struct {
	Fingerprint string    `json:"fingerprint"`
	IntentID    string    `json:"intentId"`
	Eligible    bool      `json:"eligible"`
	Decision    string    `json:"decision"`
	Source      string    `json:"source"`
	CreatedAt   time.Time `json:"createdAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

type approvalGrant struct {
	Fingerprint string    `json:"fingerprint"`
	SessionID   string    `json:"sessionId"`
	IntentID    string    `json:"intentId"`
	Scope       string    `json:"scope"`
	Eligible    bool      `json:"eligible"`
	CreatedAt   time.Time `json:"createdAt"`
}

type denyNote struct {
	Fingerprint string    `json:"fingerprint"`
	IntentID    string    `json:"intentId"`
	CreatedAt   time.Time `json:"createdAt"`
}

type sessionGrantState struct {
	SchemaVersion string                      `json:"schemaVersion"`
	SessionID     string                      `json:"sessionId"`
	UpdatedAt     time.Time                   `json:"updatedAt"`
	Reservations  map[string]grantReservation `json:"reservations,omitempty"`
	Grants        map[string]approvalGrant    `json:"grants,omitempty"`
	Denials       map[string]denyNote         `json:"denials,omitempty"`
}

var grantStateMutex sync.Mutex

// Grant records a grant only for a fingerprint reserved by a recent ask.
// It never evaluates or executes the command represented by the fingerprint.
func Grant(sessionID, fingerprint, scope string, options Options) error {
	if strings.TrimSpace(sessionID) == "" {
		return errors.New("grant session is required")
	}
	if strings.TrimSpace(fingerprint) == "" {
		return errors.New("grant fingerprint is required")
	}
	scope = normalizeGrantScope(scope)
	if scope == "" {
		return errors.New("grant scope must be once or session")
	}
	request := Request{
		SchemaVersion: RequestSchemaVersion,
		CWD:           currentWorkingDirectory(),
		WorkspaceRoot: workspaceRootFromEnvironment(),
		Session:       Session{ID: sessionID, Host: "opencode"},
	}
	config, err := resolveReviewerConfig(request, options)
	if err != nil {
		return err
	}
	stateDir, err := reviewerStateDirectory(options, config)
	if err != nil {
		return err
	}
	if err := garbageCollectGrantFiles(stateDir, time.Duration(config.Grants.MaxAgeSeconds)*time.Second); err != nil {
		return err
	}
	return mutateSessionGrantState(stateDir, sessionID, func(state *sessionGrantState) error {
		reservation, ok := state.Reservations[fingerprint]
		if !ok || time.Now().After(reservation.ExpiresAt) {
			delete(state.Reservations, fingerprint)
			return errors.New("grant fingerprint was not reserved by a recent ask")
		}
		if reservation.Decision != DecisionAsk {
			return errors.New("grant fingerprint was not reserved for an ask decision")
		}
		if scope == GrantScopeSession && (!config.Grants.SessionTrust || !reservation.Eligible) {
			return errors.New("session trust is not eligible for this request")
		}
		state.Grants[fingerprint] = approvalGrant{
			Fingerprint: fingerprint,
			SessionID:   sessionID,
			IntentID:    reservation.IntentID,
			Scope:       scope,
			Eligible:    reservation.Eligible,
			CreatedAt:   time.Now().UTC(),
		}
		delete(state.Reservations, fingerprint)
		return nil
	})
}

// DenyNote records the negative result of a human approval prompt. It is
// intentionally tied to the exact fingerprint and current intent.
func DenyNote(sessionID, fingerprint string, options Options) error {
	if strings.TrimSpace(sessionID) == "" {
		return errors.New("deny-note session is required")
	}
	if strings.TrimSpace(fingerprint) == "" {
		return errors.New("deny-note fingerprint is required")
	}
	request := Request{
		SchemaVersion: RequestSchemaVersion,
		CWD:           currentWorkingDirectory(),
		WorkspaceRoot: workspaceRootFromEnvironment(),
		Session:       Session{ID: sessionID, Host: "opencode"},
	}
	config, err := resolveReviewerConfig(request, options)
	if err != nil {
		return err
	}
	stateDir, err := reviewerStateDirectory(options, config)
	if err != nil {
		return err
	}
	if err := garbageCollectGrantFiles(stateDir, time.Duration(config.Grants.MaxAgeSeconds)*time.Second); err != nil {
		return err
	}
	return mutateSessionGrantState(stateDir, sessionID, func(state *sessionGrantState) error {
		reservation, ok := state.Reservations[fingerprint]
		if !ok || time.Now().After(reservation.ExpiresAt) {
			delete(state.Reservations, fingerprint)
			return errors.New("deny-note fingerprint was not reserved by a recent ask")
		}
		if reservation.Decision != DecisionAsk {
			return errors.New("deny-note fingerprint was not reserved for an ask decision")
		}
		state.Denials[fingerprint] = denyNote{
			Fingerprint: fingerprint,
			IntentID:    reservation.IntentID,
			CreatedAt:   time.Now().UTC(),
		}
		delete(state.Reservations, fingerprint)
		return nil
	})
}

// SessionEvent invalidates every capability associated with a session. The
// event is deliberately destructive because missing an event must never widen
// the set of commands that can be reused.
func SessionEvent(sessionID, event string, options Options) error {
	if strings.TrimSpace(sessionID) == "" {
		return errors.New("session-event session is required")
	}
	switch event {
	case "end", "clear", "new-intent", "goal-change":
	default:
		return errors.New("session-event event must be end, clear, new-intent, or goal-change")
	}
	request := Request{
		SchemaVersion: RequestSchemaVersion,
		CWD:           currentWorkingDirectory(),
		WorkspaceRoot: workspaceRootFromEnvironment(),
		Session:       Session{ID: sessionID, Host: "opencode"},
	}
	config, err := resolveReviewerConfig(request, options)
	if err != nil {
		return err
	}
	stateDir, err := reviewerStateDirectory(options, config)
	if err != nil {
		return err
	}
	if err := garbageCollectGrantFiles(stateDir, time.Duration(config.Grants.MaxAgeSeconds)*time.Second); err != nil {
		return err
	}
	return mutateSessionGrantState(stateDir, sessionID, func(state *sessionGrantState) error {
		state.Reservations = map[string]grantReservation{}
		state.Grants = map[string]approvalGrant{}
		state.Denials = map[string]denyNote{}
		return nil
	})
}

func normalizeGrantScope(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "once":
		return GrantScopeOnce
	case "session":
		return GrantScopeSession
	default:
		return ""
	}
}

func currentWorkingDirectory() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return cwd
}

func workspaceRootFromEnvironment() *string {
	root := strings.TrimSpace(os.Getenv("AAR_WORKSPACE_ROOT"))
	if root == "" {
		return nil
	}
	return &root
}

func reviewerStateDirectory(options Options, config Config) (string, error) {
	configured := options.StateDir
	if configured == "" {
		configured = config.Audit.Dir
	}
	return resolveStateDir(configured)
}

func reserveAsk(request Request, fingerprint string, eligible bool, source string, options Options, config Config) error {
	stateDir, err := reviewerStateDirectory(options, config)
	if err != nil {
		return err
	}
	if err := garbageCollectGrantFiles(stateDir, time.Duration(config.Grants.MaxAgeSeconds)*time.Second); err != nil {
		return err
	}
	now := time.Now().UTC()
	return mutateSessionGrantState(stateDir, request.Session.ID, func(state *sessionGrantState) error {
		state.Reservations[fingerprint] = grantReservation{
			Fingerprint: fingerprint,
			IntentID:    request.Session.IntentID,
			Eligible:    eligible,
			Decision:    DecisionAsk,
			Source:      source,
			CreatedAt:   now,
			ExpiresAt:   now.Add(time.Duration(config.Grants.ReservationTTLSeconds) * time.Second),
		}
		delete(state.Denials, fingerprint)
		return nil
	})
}

func consumeGrant(request Request, fingerprint string, eligible bool, options Options, config Config) (approvalGrant, bool, error) {
	stateDir, err := reviewerStateDirectory(options, config)
	if err != nil {
		return approvalGrant{}, false, err
	}
	if err := garbageCollectGrantFiles(stateDir, time.Duration(config.Grants.MaxAgeSeconds)*time.Second); err != nil {
		return approvalGrant{}, false, err
	}
	var matched approvalGrant
	var found bool
	err = mutateSessionGrantState(stateDir, request.Session.ID, func(state *sessionGrantState) error {
		invalidateMismatchedIntent(state, request.Session.IntentID)
		grant, ok := state.Grants[fingerprint]
		if !ok || grant.SessionID != request.Session.ID {
			return nil
		}
		if grant.Scope == GrantScopeSession && (!config.Grants.SessionTrust || !eligible) {
			delete(state.Grants, fingerprint)
			return nil
		}
		if grant.Scope == GrantScopeSession && !grant.Eligible {
			delete(state.Grants, fingerprint)
			return nil
		}
		matched = grant
		found = true
		if grant.Scope == GrantScopeOnce {
			delete(state.Grants, fingerprint)
		}
		return nil
	})
	return matched, found, err
}

func matchingDenyNote(request Request, fingerprint string, options Options, config Config) (bool, error) {
	stateDir, err := reviewerStateDirectory(options, config)
	if err != nil {
		return false, err
	}
	if err := garbageCollectGrantFiles(stateDir, time.Duration(config.Grants.MaxAgeSeconds)*time.Second); err != nil {
		return false, err
	}
	var found bool
	err = mutateSessionGrantState(stateDir, request.Session.ID, func(state *sessionGrantState) error {
		invalidateMismatchedIntent(state, request.Session.IntentID)
		note, ok := state.Denials[fingerprint]
		if ok && note.IntentID == request.Session.IntentID {
			found = true
		}
		return nil
	})
	return found, err
}

func invalidateMismatchedIntent(state *sessionGrantState, intentID string) {
	for fingerprint, grant := range state.Grants {
		if grant.IntentID != intentID {
			delete(state.Grants, fingerprint)
		}
	}
	for fingerprint, note := range state.Denials {
		if note.IntentID != intentID {
			delete(state.Denials, fingerprint)
		}
	}
	for fingerprint, reservation := range state.Reservations {
		if reservation.IntentID != intentID {
			delete(state.Reservations, fingerprint)
		}
	}
}

func newSessionGrantState(sessionID string) sessionGrantState {
	return sessionGrantState{
		SchemaVersion: grantStateVersion,
		SessionID:     sessionID,
		Reservations:  map[string]grantReservation{},
		Grants:        map[string]approvalGrant{},
		Denials:       map[string]denyNote{},
	}
}

func mutateSessionGrantState(stateDir, sessionID string, mutate func(*sessionGrantState) error) error {
	grantStateMutex.Lock()
	defer grantStateMutex.Unlock()

	grantsDir := filepath.Join(stateDir, grantStateDirectory)
	if err := os.MkdirAll(grantsDir, 0o700); err != nil {
		return fmt.Errorf("create grants directory: %w", err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return fmt.Errorf("secure state directory: %w", err)
	}
	if err := os.Chmod(grantsDir, 0o700); err != nil {
		return fmt.Errorf("secure grants directory: %w", err)
	}
	path := sessionGrantPath(grantsDir, sessionID)
	unlock, err := acquireGrantLock(path)
	if err != nil {
		return err
	}
	defer unlock()

	state, err := readSessionGrantState(path, sessionID)
	if err != nil {
		return err
	}
	if err := mutate(&state); err != nil {
		return err
	}
	state.UpdatedAt = time.Now().UTC()
	return writeSessionGrantState(path, state)
}

func sessionGrantPath(grantsDir, sessionID string) string {
	name := safeSessionFileName(sessionID)
	return filepath.Join(grantsDir, name+".json")
}

func safeSessionFileName(sessionID string) string {
	var builder strings.Builder
	for _, char := range sessionID {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' {
			builder.WriteRune(char)
		} else {
			builder.WriteByte('_')
		}
	}
	name := builder.String()
	if name == "" {
		name = "session"
	}
	if name != sessionID {
		sum := sha256.Sum256([]byte(sessionID))
		name += "-" + hex.EncodeToString(sum[:6])
	}
	return name
}

func acquireGrantLock(statePath string) (func(), error) {
	lockPath := statePath + ".lock"
	deadline := time.Now().Add(grantLockTimeout)
	for {
		file, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			_ = file.Close()
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("create grant lock: %w", err)
		}
		if time.Now().After(deadline) {
			return nil, errors.New("timed out waiting for grant state lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func readSessionGrantState(path, sessionID string) (sessionGrantState, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return newSessionGrantState(sessionID), nil
	}
	if err != nil {
		return sessionGrantState{}, fmt.Errorf("read session grant state: %w", err)
	}
	var state sessionGrantState
	if err := json.Unmarshal(contents, &state); err != nil {
		return sessionGrantState{}, fmt.Errorf("decode session grant state: %w", err)
	}
	if state.SchemaVersion != grantStateVersion || state.SessionID != sessionID {
		return sessionGrantState{}, errors.New("unsupported or mismatched session grant state")
	}
	if state.Reservations == nil {
		state.Reservations = map[string]grantReservation{}
	}
	if state.Grants == nil {
		state.Grants = map[string]approvalGrant{}
	}
	if state.Denials == nil {
		state.Denials = map[string]denyNote{}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return sessionGrantState{}, fmt.Errorf("secure session grant state: %w", err)
	}
	return state, nil
}

func writeSessionGrantState(path string, state sessionGrantState) error {
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode session grant state: %w", err)
	}
	payload = append(payload, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".grant-*.tmp")
	if err != nil {
		return fmt.Errorf("create session grant state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary grant state: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write session grant state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync session grant state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close session grant state: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace session grant state: %w", err)
	}
	return os.Chmod(path, 0o600)
}

func garbageCollectGrantFiles(stateDir string, maxAge time.Duration) error {
	if maxAge <= 0 {
		maxAge = time.Duration(defaultGrantMaxAgeSeconds) * time.Second
	}
	grantsDir := filepath.Join(stateDir, grantStateDirectory)
	entries, err := os.ReadDir(grantsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read grants directory: %w", err)
	}
	cutoff := time.Now().Add(-maxAge)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(grantsDir, entry.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("remove stale grant state %s: %w", entry.Name(), err)
			}
		}
	}
	return nil
}
