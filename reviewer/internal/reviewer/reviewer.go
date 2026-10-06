package reviewer

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var secretLike = regexp.MustCompile(`(?i)(bearer\s+|[a-z0-9_]*(?:token|password|secret|api[_-]?key|access[_-]?key)[a-z0-9_-]*\s*(?:=|:)\s*)(?:"[^"]*"|'[^']*'|[^\s'"` + "`" + `]+)`)
var secretFlag = regexp.MustCompile(`(?i)(--?[a-z0-9_-]*(?:token|password|secret|api[_-]?key|access[_-]?key)(?:=|\s+))(?:"[^"]*"|'[^']*'|[^\s'"` + "`" + `]+)`)
var awsAccessKeyID = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
var urlCredential = regexp.MustCompile(`(?i)(https?://[^/\s:@]+:)[^@\s]+(@)`)

type auditRecord struct {
	SchemaVersion      string          `json:"schemaVersion"`
	AuditID            string          `json:"auditId"`
	RecordedAt         string          `json:"recordedAt"`
	Command            string          `json:"command"`
	CWD                string          `json:"cwd"`
	Decision           string          `json:"decision"`
	Outcome            string          `json:"outcome"`
	Source             string          `json:"source"`
	Rule               *string         `json:"rule"`
	RequestFingerprint string          `json:"requestFingerprint"`
	Effects            []string        `json:"effects"`
	Profile            string          `json:"profile"`
	AssessorModel      string          `json:"assessorModel,omitempty"`
	AssessorAttempts   int             `json:"assessorAttempts,omitempty"`
	FailureKind        string          `json:"failureKind,omitempty"`
	DurationMs         int64           `json:"durationMs"`
	Assessment         *RiskAssessment `json:"assessment,omitempty"`
}

// Check records audit and review logs without executing Request.Command.
func Check(request Request, options Options) (result Decision, resultErr error) {
	started := time.Now()
	config, configErr := resolveReviewerConfig(request, options)
	logOptions := options
	if configErr == nil && logOptions.StateDir == "" {
		logOptions.StateDir = config.Audit.Dir
	}
	log, err := newReviewLog(logOptions.StateDir)
	if err != nil {
		return Decision{}, err
	}
	defer func() {
		log.record("verdict", map[string]any{
			"decision": result.Decision, "source": result.Source, "rule": result.Rule,
			"reason": result.Reason, "auditId": result.AuditID,
			"durationMs": time.Since(started).Milliseconds(), "error": errorText(resultErr),
		})
		if err := log.close(); err != nil && resultErr == nil {
			result, resultErr = Decision{}, err
		}
	}()
	log.record("received", map[string]any{
		"command": request.Command, "cwd": request.CWD,
		"sessionId": request.Session.ID, "intentId": request.Session.IntentID,
	})
	if err := validateRequest(request); err != nil {
		return Decision{}, err
	}
	if configErr != nil {
		return Decision{}, configErr
	}
	request.Env = cloneStringMap(request.Env)
	policyOptions := options
	policyOptions.ProtectedPaths = append([]string(nil), config.Policy.ProtectedPaths...)
	policyOptions.AutoAllowAdditions = append([]AutoAllowAddition(nil), config.Policy.AutoAllowAdditions...)
	if policyOptions.StateDir == "" && config.Audit.Dir != "" {
		policyOptions.StateDir = config.Audit.Dir
	}
	grantOptions := policyOptions
	grantStateDir, err := reviewerStateDirectory(grantOptions, config)
	if err != nil {
		return Decision{}, err
	}
	if err := garbageCollectGrantFiles(grantStateDir, time.Duration(config.Grants.MaxAgeSeconds)*time.Second); err != nil {
		return Decision{}, err
	}

	ir := ParseShell(request.Command)
	log.record("parsed", map[string]any{
		"shellIR":    ParseShell(redact(request.Command)),
		"parseError": ir.ParseError, "dynamic": ir.Dynamic,
		"profile": config.Policy.Profile,
	})
	fingerprint := fingerprintFor(request)
	decision := Decision{
		SchemaVersion:      DecisionSchemaVersion,
		Decision:           DecisionDeny,
		Reason:             "command effect is not proven safe; the command was not executed",
		Source:             SourceUnavailable,
		RequestFingerprint: fingerprint,
		GrantEligible:      false,
		Dynamic:            ir.Dynamic,
		AssessorModel:      config.Assessor.Model,
		PolicyProfile:      config.Policy.Profile,
	}

	if rule, reason, ok := evaluateHardDeny(request, ir); ok {
		decision.Reason = reason
		decision.Source = SourceHardDeny
		decision.Rule = &rule
	} else if rule, reason, ok := evaluateAutoAllow(request, ir, policyOptions); ok {
		decision.Decision = DecisionAllow
		decision.Reason = reason
		decision.Source = SourceAutoAllow
		decision.Rule = &rule
	} else {
		_, initialLocal := buildModelCallRequest(request, ir, policyOptions, config)
		decision.RequestFingerprint = fingerprintForFacts(request, initialLocal, config)
		decision.RequestFingerprintBase = fingerprint

		denied, err := matchingDenyNote(request, decision.RequestFingerprint, grantOptions, config)
		if err != nil {
			return Decision{}, err
		}
		if denied {
			decision.Decision = DecisionDeny
			decision.Reason = "a human denied this exact command; a new genuine user request is required before it can be asked again"
			decision.Source = SourceDenyNote
		} else {
			grant, found, err := consumeGrant(request, decision.RequestFingerprint, grantFactsEligible(initialLocal), grantOptions, config)
			if err != nil {
				return Decision{}, err
			}
			if found {
				decision.Decision = DecisionAllow
				decision.Reason = "a human approved this exact command for the current session"
				decision.Source = SourceGrant
				decision.GrantScope = grant.Scope
				decision.GrantEligible = false
			} else {
				log.record("assessor-required", map[string]any{"model": config.Assessor.Model})
				assessment, local, trace, assessorErr := assessCommand(request, ir, policyOptions, config, log)
				log.record("assessor-result", map[string]any{
					"model": trace.Model, "attempts": trace.Attempts,
					"assessment": redactedAssessment(assessment), "error": errorText(assessorErr),
				})
				decision.AssessorModel = trace.Model
				decision.AssessorAttempts = trace.Attempts
				if assessorErr != nil {
					decision.Decision = config.Assessor.OnUnavailable
					decision.Reason = "the Command Risk Assessor was unavailable; the command was not proven safe and was not executed"
					decision.Source = SourceUnavailable
					var failure *assessorFailure
					if errors.As(assessorErr, &failure) {
						decision.FailureKind = failure.kind
					}
					if decision.FailureKind == "" {
						decision.FailureKind = AssessorFailureProvider
					}
					decision.GrantEligible = false
					if local.EvidenceBytes == 0 {
						local = initialLocal
					}
					if decision.Decision == DecisionAsk {
						if err := reserveAsk(request, decision.RequestFingerprint, false, decision.Source, grantOptions, config); err != nil {
							return Decision{}, err
						}
					}
				} else {
					if fingerprintForFacts(request, local, config) != decision.RequestFingerprint {
						local.Uncertainties = appendUnique(local.Uncertainties, "a material target or script source changed during assessment")
						local.EvidenceChanged = true
					}
					mapped := mapRiskAssessment(assessment, config.Policy, local)
					decision.Decision = mapped.Decision
					decision.Reason = mapped.Reason
					decision.Source = SourceAssessor
					decision.Assessment = assessment
					decision.GrantEligible = config.Grants.SessionTrust && decision.Decision == DecisionAsk && grantFactsEligible(local) && !assessmentHasMaterialUncertainty(assessment, config.Policy)
					if decision.Decision == DecisionAsk {
						if err := reserveAsk(request, decision.RequestFingerprint, decision.GrantEligible, decision.Source, grantOptions, config); err != nil {
							return Decision{}, err
						}
					}
				}
			}
		}
	}
	if ir.ParseError != "" && decision.Source != SourceHardDeny {
		if decision.Source == SourceUnavailable {
			decision.Reason = "the Command Risk Assessor was unavailable for a command with a parse failure; the command was not proven safe and was not executed"
		}
	}

	decision.DurationMs = time.Since(started).Milliseconds()
	log.record("policy-result", map[string]any{
		"decision": decision.Decision, "source": decision.Source, "rule": decision.Rule,
		"reason": decision.Reason, "profile": config.Policy.Profile,
		"failureKind": decision.FailureKind, "grantScope": decision.GrantScope,
		"grantEligible": decision.GrantEligible,
	})
	auditID, err := writeAudit(request, decision, policyOptions, config)
	if err != nil {
		return Decision{}, err
	}
	decision.AuditID = auditID
	return decision, nil
}

func validateRequest(request Request) error {
	if request.SchemaVersion != RequestSchemaVersion {
		return fmt.Errorf("unsupported request schemaVersion %q", request.SchemaVersion)
	}
	if request.Session.ID == "" {
		return errors.New("session.id is required")
	}
	if request.Session.Host == "" {
		return errors.New("session.host is required")
	}
	return nil
}

type fingerprintInput struct {
	Command       string  `json:"command"`
	CWD           string  `json:"cwd"`
	WorkspaceRoot *string `json:"workspaceRoot"`
	SessionID     string  `json:"sessionId"`
	IntentID      string  `json:"intentId"`
	PolicyVersion string  `json:"policyVersion"`
	ShellIR       string  `json:"shellIR"`
}

func fingerprintFor(request Request) string {
	input := fingerprintInput{
		Command:       request.Command,
		CWD:           request.CWD,
		WorkspaceRoot: request.WorkspaceRoot,
		SessionID:     request.Session.ID,
		IntentID:      request.Session.IntentID,
		PolicyVersion: DeterministicPolicyVersion,
		ShellIR:       ShellIRSchemaVersion,
	}
	payload, _ := json.Marshal(input)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

const maxGrantEvidenceBytes = 1 << 20

type fingerprintPath struct {
	Value            string `json:"value"`
	Role             string `json:"role"`
	AccessMode       string `json:"accessMode"`
	Resolved         string `json:"resolved,omitempty"`
	ResolvedExisting bool   `json:"resolvedExisting"`
	Protected        bool   `json:"protected"`
	InsideSafeRoot   bool   `json:"insideSafeRoot"`
	Unresolved       bool   `json:"unresolved"`
}

type fingerprintScript struct {
	Interpreter string `json:"interpreter"`
	Kind        string `json:"kind"`
	Path        string `json:"path,omitempty"`
	Digest      string `json:"digest,omitempty"`
	Status      string `json:"status"`
}

type factFingerprintInput struct {
	FingerprintSchema  string              `json:"fingerprintSchema"`
	Command            string              `json:"command"`
	CanonicalCWD       string              `json:"cwd"`
	WorkspaceRoot      *string             `json:"workspaceRoot"`
	SessionID          string              `json:"sessionId"`
	IntentID           string              `json:"intentId"`
	Goal               string              `json:"goal"`
	LatestUserRequest  string              `json:"latestUserRequest"`
	Purpose            string              `json:"purpose"`
	AssistantRationale string              `json:"assistantRationale,omitempty"`
	TrustedEnv         map[string]string   `json:"trustedEnv"`
	RequestSchema      string              `json:"requestSchema"`
	DecisionSchema     string              `json:"decisionSchema"`
	ShellIRSchema      string              `json:"shellIRSchema"`
	PolicyVersion      string              `json:"policyVersion"`
	HardDenyCatalog    string              `json:"hardDenyCatalog"`
	Policy             PolicyConfig        `json:"policy"`
	Paths              []fingerprintPath   `json:"paths"`
	Scripts            []fingerprintScript `json:"scripts"`
	Uncertainties      []string            `json:"uncertainties,omitempty"`
}

func fingerprintForFacts(request Request, local localAssessmentContext, config Config) string {
	cwd := canonicalOrClean(request.CWD, "")
	workspaceRoot := cloneStringPointer(request.WorkspaceRoot)
	if workspaceRoot != nil {
		canonical := canonicalOrClean(*workspaceRoot, cwd)
		workspaceRoot = &canonical
	}
	paths := make([]fingerprintPath, 0, len(local.PathFacts))
	for _, fact := range local.PathFacts {
		paths = append(paths, fingerprintPath{
			Value:            fact.Value,
			Role:             fact.Role,
			AccessMode:       fact.AccessMode,
			Resolved:         fact.Resolved,
			ResolvedExisting: fact.ResolvedExisting,
			Protected:        fact.Protected,
			InsideSafeRoot:   fact.InsideSafeRoot,
			Unresolved:       fact.Unresolved,
		})
	}
	scripts := make([]fingerprintScript, 0, len(local.Scripts))
	for _, script := range local.Scripts {
		scripts = append(scripts, fingerprintScript{
			Interpreter: script.Interpreter,
			Kind:        script.Kind,
			Path:        script.Path,
			Digest:      script.Digest,
			Status:      script.Status,
		})
	}
	input := factFingerprintInput{
		FingerprintSchema:  FingerprintSchemaVersion,
		Command:            request.Command,
		CanonicalCWD:       cwd,
		WorkspaceRoot:      workspaceRoot,
		SessionID:          request.Session.ID,
		IntentID:           request.Session.IntentID,
		Goal:               request.Intent.Goal,
		LatestUserRequest:  request.Intent.LatestUserRequest,
		Purpose:            request.Intent.Purpose,
		AssistantRationale: request.Intent.AssistantRationale,
		TrustedEnv:         trustedEnvSnapshot(request.Env),
		RequestSchema:      request.SchemaVersion,
		DecisionSchema:     DecisionSchemaVersion,
		ShellIRSchema:      ShellIRSchemaVersion,
		PolicyVersion:      DeterministicPolicyVersion,
		HardDenyCatalog:    CatastrophicCatalogVersion,
		Policy:             config.Policy,
		Paths:              paths,
		Scripts:            scripts,
		Uncertainties:      append([]string(nil), local.Uncertainties...),
	}
	payload, _ := json.Marshal(input)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func grantFactsEligible(local localAssessmentContext) bool {
	if local.Dynamic {
		return false
	}
	if local.EvidenceBytes > maxGrantEvidenceBytes {
		return false
	}
	if len(local.Uncertainties) != 0 {
		return false
	}
	for _, script := range local.Scripts {
		if script.Status != scriptStatusComplete {
			return false
		}
	}
	return true
}

func writeAudit(request Request, decision Decision, options Options, config Config) (string, error) {
	stateDir, err := resolveStateDir(options.StateDir)
	if err != nil {
		return "", err
	}
	auditDir := filepath.Join(stateDir, "audit")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		return "", fmt.Errorf("create audit directory: %w", err)
	}
	_ = os.Chmod(stateDir, 0o700)
	_ = os.Chmod(auditDir, 0o700)

	auditID, err := randomID()
	if err != nil {
		return "", fmt.Errorf("create audit id: %w", err)
	}
	record := auditRecord{
		SchemaVersion:      AuditSchemaVersion,
		AuditID:            auditID,
		RecordedAt:         time.Now().UTC().Format(time.RFC3339Nano),
		Command:            redact(request.Command),
		CWD:                redact(request.CWD),
		Decision:           decision.Decision,
		Outcome:            auditOutcome(decision.Source),
		Source:             decision.Source,
		Rule:               decision.Rule,
		RequestFingerprint: decision.RequestFingerprint,
		Effects:            effectsFor(decision),
		Profile:            config.Policy.Profile,
		AssessorModel:      decision.AssessorModel,
		AssessorAttempts:   decision.AssessorAttempts,
		FailureKind:        decision.FailureKind,
		DurationMs:         decision.DurationMs,
		Assessment:         redactedAssessment(decision.Assessment),
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("encode audit record: %w", err)
	}
	payload = append(payload, '\n')
	path := filepath.Join(auditDir, auditID+".json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create audit record: %w", err)
	}
	if _, writeErr := file.Write(payload); writeErr != nil {
		_ = file.Close()
		return "", fmt.Errorf("write audit record: %w", writeErr)
	}
	if closeErr := file.Close(); closeErr != nil {
		return "", fmt.Errorf("close audit record: %w", closeErr)
	}
	return auditID, nil
}

// Explain returns one stored, secret-safe audit record. The audit ID is
// treated as an opaque capability and is never interpolated from arbitrary
// path text.
func Explain(auditID string, options Options) ([]byte, error) {
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(auditID) {
		return nil, errors.New("audit id must be a 32-character lowercase hexadecimal value")
	}
	stateDir := options.StateDir
	if stateDir == "" {
		request := Request{
			SchemaVersion: RequestSchemaVersion,
			CWD:           currentWorkingDirectory(),
			WorkspaceRoot: workspaceRootFromEnvironment(),
			Session:       Session{ID: "explain", Host: "aar"},
		}
		config, err := resolveReviewerConfig(request, options)
		if err != nil {
			return nil, err
		}
		stateDir, err = reviewerStateDirectory(options, config)
		if err != nil {
			return nil, err
		}
	}
	if stateDir == "" {
		return nil, errors.New("reviewer state directory is empty")
	}
	path := filepath.Join(stateDir, "audit", auditID+".json")
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read audit record %s: %w", auditID, err)
	}
	var record auditRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil, fmt.Errorf("decode audit record %s: %w", auditID, err)
	}
	if record.SchemaVersion != AuditSchemaVersion || record.AuditID != auditID {
		return nil, fmt.Errorf("audit record %s has an unsupported schema or identity", auditID)
	}
	return append(bytes.TrimSpace(payload), '\n'), nil
}

func resolveStateDir(configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	if fromEnv := os.Getenv("AAR_STATE_DIR"); fromEnv != "" {
		return fromEnv, nil
	}
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "aar"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve state directory: %w", err)
	}
	return filepath.Join(home, ".local", "state", "aar"), nil
}

func redact(command string) string {
	redacted := secretLike.ReplaceAllString(command, `$1[REDACTED]`)
	redacted = secretFlag.ReplaceAllString(redacted, `$1[REDACTED]`)
	redacted = urlCredential.ReplaceAllString(redacted, `$1[REDACTED]$2`)
	if strings.Contains(redacted, "sk-") {
		redacted = regexp.MustCompile(`sk-[A-Za-z0-9_-]+`).ReplaceAllString(redacted, "sk-[REDACTED]")
	}
	return awsAccessKeyID.ReplaceAllString(redacted, "AKIA[REDACTED]")
}

func effectsFor(decision Decision) []string {
	switch decision.Source {
	case SourceGrant:
		return []string{"human-approved-exact-command"}
	case SourceDenyNote:
		return []string{"human-denied-exact-command"}
	case SourceHardDeny:
		if decision.Rule != nil {
			return []string{hardDenyEffect(*decision.Rule)}
		}
		return []string{"hard-deny"}
	case SourceAutoAllow:
		if decision.Rule != nil {
			return []string{"deterministic-rule-" + *decision.Rule}
		}
		return []string{"deterministic-auto-allow"}
	case SourceAssessor:
		if assessment, ok := decision.Assessment.(RiskAssessment); ok && len(assessment.Risks) > 0 {
			effects := make([]string, 0, len(assessment.Risks))
			for _, risk := range assessment.Risks {
				effects = appendUnique(effects, risk.Category)
			}
			return effects
		}
		return []string{"model-assessed-command"}
	case SourceUnavailable:
		return []string{"reviewer-unavailable"}
	}
	if assessment, ok := decision.Assessment.(RiskAssessment); ok && len(assessment.Risks) > 0 {
		effects := make([]string, 0, len(assessment.Risks))
		for _, risk := range assessment.Risks {
			effects = appendUnique(effects, risk.Category)
		}
		return effects
	}
	return []string{"unassessed-command"}
}

func auditOutcome(source string) string {
	switch source {
	case SourceHardDeny, SourceAutoAllow:
		return AuditOutcomeDeterministic
	case SourceAssessor:
		return AuditOutcomeModel
	case SourceGrant:
		return AuditOutcomeGrant
	default:
		return AuditOutcomeFailure
	}
}

func redactedAssessment(value any) *RiskAssessment {
	var assessment RiskAssessment
	switch typed := value.(type) {
	case RiskAssessment:
		assessment = typed
	case *RiskAssessment:
		if typed == nil {
			return nil
		}
		assessment = *typed
	default:
		return nil
	}
	assessment.Risks = append([]Risk(nil), assessment.Risks...)
	for index := range assessment.Risks {
		assessment.Risks[index].Evidence = redact(assessment.Risks[index].Evidence)
		if detail := assessment.Risks[index].DataLoss; detail != nil {
			copy := &DataLossEvidence{ValueReason: redact(detail.ValueReason), Targets: make([]string, len(detail.Targets))}
			for index, target := range detail.Targets {
				copy.Targets[index] = redact(target)
			}
			assessment.Risks[index].DataLoss = copy
		}
	}
	assessment.Uncertainties = append([]string(nil), assessment.Uncertainties...)
	for index := range assessment.Uncertainties {
		assessment.Uncertainties[index] = redact(assessment.Uncertainties[index])
	}
	return &assessment
}

func randomID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}
