# Command Reviewer (`aar`)

The Reviewer and V2 Command Gate share one repository. See the
[root README](../README.md) for installation, shell compatibility, command dump
results, parse-failure behavior, verification, and the complete
[Reviewer configuration reference](../README.md#reviewer-configuration).

`plugin/` contains the historical OpenCode V1 Gate; current V2 installation
and approval instructions are in the root README.

## Safe shell syntax

The complete program must satisfy the existing policy, including every pipeline
stage and every command after `;`, `&&`, or `||`. No new command families or read
scopes are introduced.

- `head -60` and `tail -20` accept decimal count shortcuts alongside existing
  `-n 60`, `-n60`, and `--lines=60` forms. Unknown flags fall back to the Assessor;
  this does not authorize follow mode.
- Output duplication between descriptors 1 and 2 is supported (`2>&1`, `1>&2`,
  `>&2`). Redirections retain source order. File writes still require the existing
  explicit safe target policy; duplication is not a file operand or safe stdin.
  Input duplication, other descriptors, closing and moving descriptors fall back.
- Unquoted path words support `*` and `?` in relative, nested and absolute paths.
  Pattern source characters are limited to ASCII letters, digits, `_`, `@`, `.`, `/`,
  `-`, `*`, `?` and supported braces. Matching filenames may contain other
  characters. Hidden names require an explicit leading dot in the component.
  Fully quoted words remain literal; mixed quoting, escapes, bracket patterns,
  `**`, extglob, tilde and `..` components in expansion words fall back.
- One numeric brace range per word supports `{1..8}` and `{8..1}`, including a
  range combined with a glob. Endpoints are nonnegative decimal integers without
  zero padding. Lists, letters, steps, nested or multiple ranges fall back.
  Plain brace expansion can name missing files, just like literal path operands.
  A glob with no matches always falls back, including inside a brace range.
- Expansion is limited to 256 resulting arguments per command (excluding the
  executable), 256 intermediate glob candidates, and 4096 inspected directory
  entries per glob pattern. Every result and every enumerated directory passes
  existing canonical path/protected path checks. Leading option-like results
  fall back. Patterns are inspected without executing a shell.

Expansion is available only for existing `cat`, `head`, `tail`, `ls`, `tree`,
`file`, `stat`, `du`, `wc`, `uniq`, `cut`, `tr`, `readlink`, `realpath`, `basename`,
`dirname`, `sort`, `diff`, `cmp`, `comm`, `grep`, `rg`, and `ripgrep` rules. Their
existing option and operand restrictions still apply.
Expansion does not authorize `rm`, custom executables, scripts, or exact configured
additions. Parameter/command/process substitution, loops and assignments retain
existing fallback. ShellIR retains dynamic glob/brace facts; only the policy
resolves this bounded subset.

Gate carries `BASHOPTS`, `SHELLOPTS`, `GLOBIGNORE`, `BASH_ENV`, and `ENV` from the
actual invocation environment. Any nonempty value makes expansion commands fall
back, since shell options or startup scripts can change expansion semantics.
This is Bash syntax policy, not support for arbitrary shells or containment of
filesystem changes between checking and execution.

Validation and fixed before/after fixtures are recorded in
[ticket 11 evidence](../../../.scratch/029-command-gate-v2/11-evidence.md).

## Read-only command forms

The whole-program, environment, canonical path and protected path checks also
apply to these forms:

- `git merge-base --is-ancestor <commit> <commit>` accepts exactly two non-option
  operands. Other merge-base modes and extra flags fall back.
- `git check-ignore [-v] [--] <path>...` checks every pathname against the read
  scope, including plain filenames. Stdin mode and other options fall back.
- `git show-ref --heads` accepts exactly that argument vector.
- `git branch --list [--all|--remotes|-a|-r] [<pattern>...]` requires `--list`
  before any `--` separator and validates every option. Creation, deletion, move,
  copy, force, tracking and description edits do not gain auto-allow.
- `stat --format=<format> <path>...` consumes the format as an option value;
  existing supported path expansions also apply. Unknown long options fall back.
- `grep`, `rg` and `ripgrep` accept attached decimal context counts such as
  `-A8`, `-B8`, `-C8` alongside existing separated context options.
- Glob paths may include `@`, for example `node_modules/@scope/pkg/*.d.ts`.
  Expansion limits, no-match fallback and symlink/protected-path checks remain.

Git configuration overrides, nonempty `GIT_*` environment facts, external
executables and an unsafe second command still prevent deterministic approval.
External reference checkouts, system directories and credential-related reads
receive no additional read scope. `systemctl`, `gsettings` and `ps` retain
Assessor fallback, including their read-only status queries; their mutation modes
are not added to this policy.

The fixed corpus, classification and measured results are in
[ticket 12 evidence](../../../.scratch/029-command-gate-v2/12-evidence.md).

## Independent Assessor providers

AAR TOML can use independent ordered fallback connections:

```toml
[assessor]
model = "primary-model"
baseUrl = "https://provider-a.example/v1"
apiKeyEnv = "PROVIDER_A_KEY"
totalTimeoutMs = 5000
options = { temperature = 0.1 }

[[assessor.fallbacks]]
model = "fallback-model"
baseUrl = "https://provider-b.example/v1"
apiKeyEnv = "PROVIDER_B_KEY"
options = { temperature = 0.2 }
contextWindow = 32768
```

Each fallback requires its own `model`, `baseUrl`, and `apiKeyEnv`; these fields
and its `options` do not inherit primary values. Omitted `options` means an empty
map. Optional `contextWindow` overrides the shared model-keyed `contextWindows`
capacity hint for that connection. Evidence is never truncated. Keep credentials
in environment variables, never TOML. URLs must use HTTPS except loopback test
servers, and cannot contain userinfo, query parameters or fragments. Redirects
are rejected so credentials cannot be forwarded to another endpoint.

The existing `fallbackModels` retains model-only switching on the primary URL,
key and options; configuring both nonempty `fallbackModels` and `fallbacks` is
an error. The project `.aar.toml` overlays primary scalars and merges primary
options as before. A project `fallbacks` array replaces the entire global array;
an omitted array inherits it, and `fallbacks = []` clears it. Inline table arrays
are also supported:

```toml
fallbacks = [{ model = "m", baseUrl = "https://provider-b.example/v1", apiKeyEnv = "PROVIDER_B_KEY" }]
```
The Gate forwards the union of explicitly declared credential environment names
from global and project TOML to the trusted AAR process; only the selected
connection's key is sent in each HTTP request.

The primary connection runs first. Each connection gets the remaining overall
`totalTimeoutMs` divided by the number of remaining connections, with at most
two sequential attempts sharing that connection's allocation. Timeouts cancel
the HTTP request. Missing credentials, exhausted transport/JSON/schema retries,
or insufficient context capacity advance to the next connection. A validated
RiskAssessment ends the chain even when local policy maps it to ask or deny.
Exhaustion uses `onUnavailable`, preserving Hard Deny and approval policy.

`aar doctor` checks all URL shapes and credential availability without calling
providers. Its `connections` diagnostics and the audit `assessorConnection`
field identify `primary` and `fallback[0]`, `fallback[1]`, etc., including identical
model IDs, without exposing endpoints or keys. Doctor succeeds when at least
one configured connection has an available credential, so a missing primary
key does not prevent a usable fallback. Structural errors always fail validation.

## ChatGPT subscription authentication

Use the **OpenCode** harness as the credential owner. Sign in there:

```sh
opencode auth login openai --method chatgpt-browser
```

Configure the Assessor to read its active ChatGPT subscription connection:

```toml
[assessor]
model = "gpt-6-luna"
authMode = "opencode"
totalTimeoutMs = 20000
options = { reasoning = { effort = "none" } }
```

In OpenCode v2.0.24, `auth.json` is a legacy migration input; credentials and
subsequent updates live in its database. AAR reads current entries through the
public `opencode auth export` CLI, selecting exactly one active `openai` OAuth
credential with method `chatgpt-browser` or `chatgpt-headless`, an access token,
account ID and unexpired millisecond expiry. Inactive credentials and unrelated
providers are ignored; API-key connections, malformed output and ambiguous active
connections fail closed. Export output stays in memory and is bounded to 1 MiB;
credentials never enter Reviewer requests, audit, trace or diagnostics.

The CLI defaults to `opencode` on PATH; `OPENCODE_BIN` selects the harness binary.
Gate forwards `OPENCODE_CONFIG_DIR`, `XDG_DATA_HOME` and `XDG_CACHE_HOME` along with
its existing HOME/config environment. Use the same namespace as the harness where
you logged in. Global export avoids booting a project location and recursively
loading Gate. It uses the normal OpenCode CLI server connection, which may start
the managed service if absent. `aar doctor` queries credentials through this
connection, but performs no provider/LLM call and starts no login flow.

AAR reloads credentials on each attempt, including authentication retries. It
never writes the owner store, rotates tokens, calls an OAuth refresh endpoint or
starts login. OpenCode refreshes credentials through its own provider lifecycle;
export itself does not refresh them. If expired or revoked, refresh or sign in
through OpenCode and retry. CLI execution shares the assessment deadline.

Subscription authentication is separate from default `authMode = "api-key"` and
paid OpenAI API billing. Account entitlement, model availability and usage limits
still apply; a readable token does not prove access to the requested model.

### Legacy Codex file mode

The previous reader remains available with `authMode = "codex"` and an explicit
absolute `authJsonPath = "/absolute/path/to/.codex/auth.json"`. It supports Codex
`auth.json`, optional `auth_mode = "chatgpt"`, `tokens.access_token` as a JWT with
`exp`, and `tokens.account_id`. The private regular file must have permissions
0600 and be at most 1 MiB. Other Codex auth modes, keyrings and provider-keyed
OpenCode legacy JSON are unsupported. This mode performs no credential search;
Codex owns refresh and AAR reloads its file on each attempt. Doctor checks this
file locally without a network call.

[Official Codex authentication documentation](https://learn.chatgpt.com/docs/auth)
describes this legacy owner/file mode. JWT expiry is a local readiness hint;
the subscription server verifies credentials and account/model access.

Subscription requests go only to
`https://chatgpt.com/backend-api/codex/responses`; redirects are rejected.
Configuration of `baseUrl`, `apiKeyEnv` or independent API `fallbacks` in this
mode is rejected, so OAuth credentials cannot reach another host and no paid API
fallback occurs. Explicit `fallbackModels` stay on the subscription transport.
Project overlays keep the existing scalar inheritance rules; when switching modes,
explicitly clear incompatible inherited fields (for example `baseUrl = ""`,
`apiKeyEnv = ""`, `fallbacks = []`, or `authJsonPath = ""` for API-key or OpenCode mode).
Only subscription `options.reasoning`, `options.text`, and `options.service_tier`
are accepted; state, tools and saved-prompt options are rejected. Each request
has complete Assessor evidence, no history/previous response, no tools, and
`store = false`; SSE text is accepted only after a completed response and then
validated by the existing RiskAssessment parser and local policy mapper.
The existing deadline and retry budget applies. Authentication, limit and stream
failures use `onUnavailable`; an expired/failed response cannot authorize a command.
Provider errors are sanitized, and reflected credential material is refused
before reaching audit or trace.

Compatibility was checked against
[Codex source revision 551bd409](https://github.com/openai/codex/tree/551bd409ebf03fc6ea0dcad0915368d8a493f012/codex-rs):
`login/src/auth/storage.rs` and `login/src/token_data.rs` define the credential
format, `login/src/auth/manager.rs` defines bearer/owner-refresh handling, and
`model-provider-info/src/lib.rs` plus `codex-api/src/endpoint/responses.rs`
define the subscription origin and Responses stream transport. On 2026-10-06,
an explicitly authorized minimal live probe with read-only Codex credentials
and exact model `gpt-6-luna` returned a locally validated RiskAssessment through
this subscription transport. No credentials were changed and no paid API was used.
This confirms the tested account/model at that time; other account entitlements
and future transport changes remain provider-controlled.

The OpenCode owner mode was checked against v2.0.24 source, synthetic CLI/HTTP
fixtures and the real CLI against an isolated mock credential API. Global export
called only `/api/info` and `/api/credential`, without loading a project location. The historical live probe above used Codex credentials; it does not
prove a live OpenCode owner-mode call.
