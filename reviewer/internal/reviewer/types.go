package reviewer

import "context"

// Request is the versioned stdin contract for `aar check`.
type Request struct {
	SchemaVersion string            `json:"schemaVersion"`
	Command       string            `json:"command"`
	CWD           string            `json:"cwd"`
	WorkspaceRoot *string           `json:"workspaceRoot"`
	Env           map[string]string `json:"env"`
	Session       Session           `json:"session"`
	Intent        Intent            `json:"intent"`
}

type Session struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	IntentID string `json:"intentId"`
}

type Intent struct {
	Goal               string `json:"goal"`
	LatestUserRequest  string `json:"latestUserRequest"`
	Purpose            string `json:"purpose"`
	AssistantRationale string `json:"assistantRationale,omitempty"`
}

type Options struct {
	StateDir           string
	AutoAllowAdditions []AutoAllowAddition
	ProtectedPaths     []string
	ConfigPath         string
	Config             *Config
	ModelCall          ModelCall
}

// AutoAllowAddition is an exact, local policy extension. Argv is matched as a
// complete normalized argument vector; PathScope is required when the vector
// contains path operands. There is deliberately no wildcard or prefix syntax.
type AutoAllowAddition struct {
	Argv      []string `json:"argv"`
	PathScope []string `json:"pathScope"`
}

// Config is the Command Reviewer's configuration surface. It is deliberately
// separate from the host plugin configuration.
type Config struct {
	Assessor AssessorConfig
	Policy   PolicyConfig
	Grants   GrantsConfig
	Audit    AuditConfig
}

type AssessorConfig struct {
	Model          string
	FallbackModels []string
	Fallbacks      []AssessorConnection
	BaseURL        string
	APIKeyEnv      string
	TotalTimeoutMs int
	OnUnavailable  string
	Options        map[string]any
	// ContextWindows optionally declares approximate token capacities by model.
	// A missing entry means that capacity is unknown and the model is attempted.
	ContextWindows map[string]int
	// Interpreters extends the built-in interpreter forms used for script
	// evidence extraction. It is intentionally data-only; it cannot authorize a
	// command or change the local policy mapper.
	Interpreters map[string]InterpreterForm
}

type AssessorConnection struct {
	Model         string
	BaseURL       string
	APIKeyEnv     string
	Options       map[string]any
	ContextWindow int
}

type InterpreterForm struct {
	InlineFlags    []string
	FileExtensions []string
}

type PolicyConfig struct {
	Profile            string
	CategoryOverrides  map[string]string
	ProtectedPaths     []string
	AutoAllowAdditions []AutoAllowAddition
}

type GrantsConfig struct {
	SessionTrust          bool
	MaxAgeSeconds         int
	ReservationTTLSeconds int
}

type AuditConfig struct {
	Enabled *bool
	Dir     string
}

// ModelCall is the only transport seam between policy and a model provider.
// Implementations receive a fresh request for every stateless attempt.
type ModelCall interface {
	Call(context.Context, ModelCallRequest) (string, error)
}

type ModelCallRequest struct {
	Model        string
	Connection   string
	SystemPrompt string
	UserPrompt   string
	Options      map[string]any
}

type RiskAssessment struct {
	Risks         []Risk   `json:"risks"`
	Uncertainties []string `json:"uncertainties"`
}

type Risk struct {
	Category              string            `json:"category"`
	Likelihood            string            `json:"likelihood"`
	Severity              string            `json:"severity"`
	Reversible            bool              `json:"reversible"`
	AffectsProtectedPaths bool              `json:"affectsProtectedPaths"`
	Evidence              string            `json:"evidence"`
	DataLoss              *DataLossEvidence `json:"dataLoss,omitempty"`
}

type DataLossEvidence struct {
	Targets     []string `json:"targets"`
	ValueReason string   `json:"valueReason"`
}

type Decision struct {
	SchemaVersion          string  `json:"schemaVersion"`
	Decision               string  `json:"decision"`
	Reason                 string  `json:"reason"`
	Source                 string  `json:"source"`
	FailureKind            string  `json:"failureKind,omitempty"`
	Rule                   *string `json:"rule"`
	Assessment             any     `json:"assessment"`
	RequestFingerprint     string  `json:"requestFingerprint"`
	RequestFingerprintBase string  `json:"requestFingerprintBase,omitempty"`
	GrantEligible          bool    `json:"grantEligible"`
	GrantScope             string  `json:"grantScope,omitempty"`
	AuditID                string  `json:"auditId"`

	// Dynamic is an internal observation used by callers and tests. It never
	// crosses the aar-decision-v1 wire contract.
	Dynamic bool `json:"-"`

	// Audit metadata is deliberately kept off the wire. It lets the Reviewer
	// explain the outcome without exposing operational details to the Gate.
	AssessorConnection string `json:"-"`
	AssessorModel      string `json:"-"`
	AssessorAttempts   int    `json:"-"`
	PolicyProfile      string `json:"-"`
	DurationMs         int64  `json:"-"`
}

const (
	RequestSchemaVersion  = "aar-request-v1"
	DecisionSchemaVersion = "aar-decision-v1"
	AssessorSchemaVersion = "assessor-risk-v1"
	ShellIRSchemaVersion  = "shellir-v1"

	DecisionAllow = "allow"
	DecisionDeny  = "deny"
	DecisionAsk   = "ask"

	GrantScopeOnce    = "once"
	GrantScopeSession = "session"

	SourceHardDeny    = "hard-deny"
	SourceAutoAllow   = "auto-allow"
	SourceGrant       = "grant"
	SourceAssessor    = "assessor"
	SourceUnavailable = "unavailable"
	SourceDenyNote    = "deny-note"
)

const (
	GrantSchemaVersion         = "aar-grant-v1"
	DenyNoteSchemaVersion      = "aar-deny-note-v1"
	SessionEventSchemaVersion  = "aar-session-event-v1"
	FingerprintSchemaVersion   = "request-fingerprint-v2"
	DeterministicPolicyVersion = "deterministic-v2"
	AssessorMapperVersion      = "assessor-mapper-v2"
	AuditSchemaVersion         = "aar-audit-v1"

	AuditOutcomeDeterministic = "deterministic"
	AuditOutcomeModel         = "model"
	AuditOutcomeGrant         = "grant"
	AuditOutcomeFailure       = "failure"
)

const (
	AssessorFailureProvider = "provider-outage"
	AssessorFailureJSON     = "invalid-json"
	AssessorFailureSchema   = "schema-invalid"
)
