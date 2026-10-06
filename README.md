# Command Gate V2

Native Bash review for OpenCode **2.0.22**, using the separate `aar` Command Reviewer. The **1.0.0** breaking release line is V2-only; the historical Gate **0.1.0** remains V1-only. No dual-API factory or runtime emulation is shipped. Release acceptance remains incomplete until the genuine human TUI smoke passes.

## Security limitations

**AAR is a safeguard against agent mistakes, not a security boundary against a deliberately harmful agent.** It reviews command safety, but does not verify the safety of executable files, package scripts or their dependencies. It may inspect some script sources as evidence; this is not a comprehensive security audit, and an `allow` decision does not guarantee that the executed code is safe.

An agent deliberately attempting destructive actions is likely to succeed, for example by placing harmful code in a file and running it through an otherwise ordinary command. AAR does not sandbox execution or restrict the launched process's filesystem and network access. Execution isolation, such as bubblewrap (`bwrap`), is a separate protection layer and is outside this project's scope.

Successful Assessor Allow for a supported development launch may be reused across sessions in the **same canonical working package** (`reviewed-trust`), separately from human grants. This is an optimization of the safeguard above. Ordinary source and test edits intentionally preserve this trust; it does not prove executable code safe. Only assessments with no risks or uncertainties are recorded. Human approval, Ask, Deny, unavailable Assessor and passthrough never populate it.

The first slice supports `npm run <script>`, `npm test`, `pnpm [run] <script>`, `pnpm exec <tool> …`, and explicit `./node_modules/.bin/<tool> …`: TypeScript `tsc --noEmit`, ESLint without fixes, Prettier `--check`, `vitest run`, and `playwright test`. Static single-command package script chains and applicable pre/post scripts are disclosed to the Assessor. Script names never produce an initial Allow. Only supported static arguments are eligible; install/publish/dev commands, shell composition, workspace selectors/inherited packages, alternate config flags, executable or indirect tool configurations, custom Node startup, manager hook files and unknown actions take the ordinary review path. Workspace roots different from the working package are currently unsupported. The compositions below reuse only individually reviewed records; a whole-program Assessor Allow never creates records for its component commands.

Static `;`, `&&` and `||` compositions can reuse individual launch records alongside commands covered by deterministic policy, for example `pnpm typecheck && pnpm lint` or `pnpm typecheck && git status --short`. Both conditional branches must be covered. Supported development producers can pipe output through policy-checked `head`/`tail`; one literal `2>&1` can merge stderr into stdout without changing the producer's argv, environment, cwd or stdin. Output truncation may close the pipe early; this is output handling, not a new guarantee about executable behavior. Pipe/file input to a development launch, other descriptor changes or file output, unknown consumers, mutating policy actions and operator additions take the ordinary whole-program Assessor path. Policy-only pipelines retain their policy semantics.

Parent `cd` changes cwd and potentially `PWD`/`OLDPWD`, so later launch reuse conservatively falls back even when a path appears unchanged. Branch-dependent cwd also falls back. A `cd` producer inside a policy-covered pipeline cannot change the parent's launch context. Coverage is checked through the existing ShellIR evaluator, preserving quoted separators and exact individual command bytes; commands are never split by string separators. A composition verdict includes `reviewedCoverage` node indexes, policy rules and original audit IDs without copying command literals into provenance. Resetting or invalidating any required record restores whole-program review; composed Allow never creates human grants.

Every lookup checks current Hard Deny and whole-program policy before reuse, and Gate still applies native permissions. Exact command bytes, canonical cwd, scripts/hooks and manifest, lockfiles and installed manager metadata, local selected executable bytes and resolved paths, Node/package-manager executable bytes, root configuration/ignore files and their existence, manager rc inputs, and Reviewer policy/semantics participate in invalidation. The Gate includes PATH and supported runtime override indicators as secret-safe evidence; a SHA-256 digest of the complete invocation environment catches changes to undisclosed settings without forwarding their values. Requests lacking that digest or PATH/HOME are reviewed normally. Config references/imports, executable configs, parent package/tool configs and dynamic manager overrides remain unsupported until their resolution is implemented.

Trust lives under the Reviewer state directory in `reviewed-trust/`, as atomic versioned files with per-project locking, at most 256 entries per project, and a 30-day lifetime. Hits carry `originAuditId`; audit/review events distinguish hits, new saves and misses (including changed/reset/expired/invalid inputs). Missing, corrupt or unknown-version records never authorize. To reset the current project's persistent trust without changing human grants, use the same Reviewer state/config environment as Gate:

```sh
aar trust-reset --project /absolute/path/to/project
```

Reset is scoped to that canonical working directory and prevents a review already in flight from restoring the previous generation. Different worktrees and projects never share trust.

## Approval

**Approval mode.** The server option `approvalMode` defaults to **`never-ask`**: every Reviewer `ask` is deterministically denied as a policy refusal — no pending request is created, no adapter is awaited and no dialog opens, with or without a connected TUI. The model-visible tool error carries the original Reviewer reason, the readable risks/uncertainties and the fixed explanation "Human approval is required by Reviewer policy, but prompts are disabled. The command was not executed." Ask-to-Deny is a policy refusal, never an operational failure: neither `onReviewerFailure: "passthrough"` nor a connected approval client can bypass it, and no severity threshold, implicit approval or automatic grant exists. The human approval flow described below is opt-in via the explicit `"approvalMode": "interactive"` server option — the mode for users who want **Allow once** or **Trust exact for session**:

```jsonc
{
  "plugins": [
    {
      "package": "@supercode/command-gate",
      "options": {
        "binaryPath": "/absolute/path/to/aar",
        "approvalMode": "interactive",
      },
    },
  ],
}
```

Never-ask suppresses **Gate** approval prompts only. Native permission prompts and any other host/plugin prompts are separate mechanisms and stay exactly as configured.

The server owns location/session/message/call-bound pending requests. The TUI receives them through public RPC, not a model-visible tool. Its paginated summary leads with the highest-severity risk and its evidence, remaining risk/uncertainty counts, and canonical working directory, followed by a masked command preview labelled **shortened** when truncated. Details presents every risk and uncertainty before the compact masked preview; it never puts the complete script ahead of the assessment. **Full command** separately displays the original unmasked command with its original line breaks and whitespace, wrapped into numbered pages for the terminal dimensions. Pipes, semicolons, quoted punctuation and embedded scripts are not split into different commands or reformatted. Non-ASCII graphemes stay intact, with a conservative two-cell width budget. Diagnostics holds identifiers, fingerprint and raw assessment JSON. All three expanded views warn that they may contain secrets. Actions are Deny, Allow once, eligible Trust exact for session, Details, Full command and Diagnostics. Reading pages or opening any view is **not** approval; dismissal refuses the call.

Later pages show **Previous** to the left of Next/Actions. The first page retains Dismiss; Escape dismisses from any page, never navigates backward. Terminal resizing reflows the current page from the original source position without acknowledging it or skipping unread content.

Only an explicit, matching human reply can create `aar grant --scope once` or `aar grant --scope session`. The server then performs fresh `aar check` and requires that exact grant before returning to the existing native executor. Once is consumed; session trust permits subsequent exact matches in the owning session, with fresh parse/facts/Hard Deny and no repeated assessor or approval. Changed command bytes, cwd, material paths/symlinks, scripts/dependencies, intent or policy cannot reuse the grant. Reviewer `grantEligible` controls the trust action; use a Reviewer that includes `grants.sessionTrust` in eligibility. Native permission deny remains authoritative. Neither RPC nor TUI executes commands or creates saved permission patterns.

Deny records `aar deny-note` and retains the exact denial in memory until intent/Goal changes. This remains authoritative if the CLI fails, a later assessor allows, or another command's failed approval resets Reviewer state. No working adapter, disconnect, expiry, cancellation, stale/duplicate reply or failed grant means no execution.

## Command Reviewer (`aar`)

The Reviewer source lives in this repository at `reviewer/`; the upstream GitHub repository is archived and no longer published. The vendored tree contains the Go module (`cmd/aar`, `internal/reviewer`), the historical V1 Gate sources (`reviewer/plugin/`). The V1 Gate is retained as historical source; this README documents the current V2 Gate and the shared Reviewer. npm packaging excludes it: the package `files` whitelist ships only `README.md`, the root forwarders and `dist/`.

Build and install (Go 1.27 toolchain):

```sh
cd reviewer
go test ./...
AAR_RELEASE_VERSION=<version> ./scripts/release.sh
install dist/reviewer-v<version>/aar-v<version>-<os>-<arch> ~/.local/bin/aar
aar doctor
```

`release.sh` emits static binaries for linux-amd64, linux-arm64, darwin-amd64 and darwin-arm64 plus `SHA256SUMS`. For a single local binary, `go build -o aar ./cmd/aar` is enough. The release binary embeds the pinned Bash parser and has no runtime download or provider SDK dependency. The Reviewer parses and assesses commands, returns a Decision, and writes a redacted audit record; it never executes the command under review. Reviewer configuration is documented below.

## Reviewer configuration

The Reviewer uses the first existing file from `$AAR_CONFIG`,
`$XDG_CONFIG_HOME/aar/config.toml`, and the platform config path:
`~/.config/aar/config.toml` on Linux or
`~/Library/Application Support/aar/config.toml` on macOS. A `.aar.toml` at the
workspace root (or current working directory when no workspace root is supplied)
overlays the selected global file. Tables merge their entries; supplied arrays
replace the corresponding global arrays.

This file owns assessor, policy, grants, and audit settings. Gate settings such
as `binaryPath`, `timeoutMs`, and `commandRewriter` belong in OpenCode config,
not this TOML file. Example:

```toml
[assessor] # Model connection and assessment behavior.
model = "provider/model-id" # Primary model identifier accepted by your endpoint.
fallbackModels = ["provider/fallback-model"] # Backup models for subsequent attempts.
baseUrl = "https://api.example.test/v1" # API base URL; AAR appends /chat/completions.
apiKeyEnv = "PROVIDER_API_KEY" # Name of the exported variable holding the key, not the key itself.
totalTimeoutMs = 5000 # Total assessment deadline in milliseconds, including fallback attempts.
onUnavailable = "deny" # Failed assessment: deny, or ask (V2 dialogs require interactive approvalMode).

[assessor.options] # Additional API request fields supported by your endpoint.
temperature = 0 # Requests less random model output; omit if the endpoint does not support it.

[policy] # Local rules that map evidence and model risks to decisions.
profile = "data-loss" # Risk profile: data-loss, balanced, or strict; descriptions below.
protectedPaths = ["/important/data"] # Paths that need protection during review.

[policy.categoryOverrides] # Override model risk handling for individual categories.
network = "inherit" # Use the profile's network rule; alternatives: ignore, ask, deny.

[grants] # Human approval records and session trust.
sessionTrust = true # Offer Trust exact for session only when the command is eligible.
maxAgeSeconds = 86400 # Clean up grant records older than 24 hours.
reservationTTLSeconds = 600 # Pending approval reservation expires after 10 minutes.

[audit] # History and state directory.
enabled = true # Set false to skip audit JSON and SQLite review history.
dir = "/path/to/aar-state" # State directory; omit to use the environment/default path.
```

`assessor.apiKeyEnv` names the environment variable holding the credential;
the key itself is never stored in configuration, requests, or audit records.
Export that variable before starting OpenCode. Run `aar doctor` from the
project directory to check the configuration and state directory; this does
not test a live model response.

### Assessor settings

| Key in `[assessor]` | Default  | Meaning                                                                                                            |
| ------------------- | -------- | ------------------------------------------------------------------------------------------------------------------ |
| `model`             | Unset    | Primary model identifier sent to the endpoint.                                                                     |
| `fallbackModels`    | `[]`     | Backup model identifiers for subsequent attempts.                                                                  |
| `baseUrl`           | Unset    | OpenAI-compatible API URL; `/chat/completions` is appended unless already present. Remote endpoints require HTTPS. |
| `apiKeyEnv`         | Unset    | Environment variable name containing the API credential.                                                           |
| `totalTimeoutMs`    | `5000`   | Total assessment time budget in milliseconds, including fallback attempts.                                         |
| `onUnavailable`     | `"deny"` | `"deny"` or `"ask"` when assessment cannot be completed, including invalid model responses.                        |

Without an assessor model, deterministic review remains available. Commands
requiring model assessment use the unavailable action. When configuring a
model, provide its endpoint and credential environment variable.

`[assessor.options]` passes additional fields to the API request, such as
`temperature`; support depends on the endpoint. AAR supplies `model` and
`messages` itself. Credential-bearing option names are rejected; use
`apiKeyEnv` instead.

`[assessor.contextWindows]` optionally maps model identifiers to positive
integer token capacities. A model without an entry is still attempted.
`[assessor.interpreters.<name>]` accepts `inlineFlags` and `fileExtensions`,
both arrays of strings, to extend script evidence collection. This does not
change the Bash parser or authorize the interpreter's commands.

```toml
[assessor.contextWindows] # Optional context capacities, keyed by model identifier.
"provider/model-id" = 128000 # Approximate token capacity used to check whether evidence fits.

[assessor.interpreters.bun] # Recognize Bun script sources for evidence collection.
inlineFlags = ["-e", "--eval"] # Flags whose following argument contains inline source code.
fileExtensions = [".js", ".ts"] # Script filename extensions recognized for this interpreter.
```

### Policy settings

| Key in `[policy]`    | Default       | Meaning                                                                                              |
| -------------------- | ------------- | ---------------------------------------------------------------------------------------------------- |
| `profile`            | `"data-loss"` | `"data-loss"`, `"balanced"`, or `"strict"`.                                                          |
| `protectedPaths`     | `[]`          | Paths treated as protected during review.                                                            |
| `categoryOverrides`  | `{}`          | Per-category model risk handling, configured as a table below.                                       |
| `autoAllowAdditions` | `[]`          | Exact additional argument vectors and their permitted path scopes, configured as array tables below. |

`data-loss` requires a concrete `critical_data_loss` risk with high or critical
severity, irreversible effects, and either a protected target or structured
`dataLoss.targets` plus a nonempty `dataLoss.valueReason` explaining which
valuable data would be lost. Likely/certain risks deny; possible risks ask.
Recursion, `rm`, unknown file contents, parser limitations, and free-text
uncertainties alone do not block. Ordinary project cleanup is expected work.
Static `rm` confined to unprotected temporary-directory contents is allowed
without the assessor after checking the complete program and canonical paths.
Deleting a cataloged system root or the actual `HOME` tree still hard-denies.

`balanced` also considers credential access, privilege,
persistence, and high-impact external, network, process, or resource risks.
`strict` considers all risk categories. Enabled risks still pass through the
severity and likelihood rules; a profile does not reject every reported risk.

`[policy.categoryOverrides]` accepts `"inherit"`, `"ignore"`, `"ask"`, or
`"deny"` for these categories:

```text
critical_data_loss, credential_access, external_side_effect, network,
privilege, persistence, process_control, resource_exhaustion,
opaque_execution, goal_mismatch
```

Overrides affect model risk mapping, not Hard Deny rules. `balanced` and
`strict` retain the conservative uncertainty checks. Changed executable
sources/targets during assessment require a fresh review in every profile.
`autoAllowAdditions` matches the complete `argv`, with
no wildcard or prefix matching. Commands with path operands need `pathScope`;
these additions do not override Hard Deny or dynamic-syntax checks.

```toml
[[policy.autoAllowAdditions]] # One additional exact command allowed by deterministic review.
argv = ["my-tool", "--version"] # Complete argument vector; no wildcard or prefix matching.
```

### Grants and audit settings

| Key                            | Default   | Meaning                                                                 |
| ------------------------------ | --------- | ----------------------------------------------------------------------- |
| `grants.sessionTrust`          | `true`    | Offer session trust for an exact command when its evidence is eligible. |
| `grants.maxAgeSeconds`         | `86400`   | Age threshold for cleaning up grant records.                            |
| `grants.reservationTTLSeconds` | `600`     | Lifetime of a pending approval reservation.                             |
| `audit.enabled`                | `true`    | Save audit JSON and SQLite review history; false leaves working state intact. |
| `audit.dir`                    | Automatic | State directory containing audit and approval records.                  |

When `audit.dir` is unset, the state directory is selected from `$AAR_STATE_DIR`,
`$XDG_STATE_HOME/aar`, then `~/.local/state/aar`. Use an absolute path when
setting it explicitly. Nonpositive timeout and grant lifetime values fall
back to their defaults; they do not disable time limits.

Inspect a stored audit record without exposing raw secret-like values:

```sh
aar explain --audit-id <AUDIT_ID>
```

Audit records classify outcomes as `deterministic`, `model`, `grant`, or
`failure`, and include the selected profile, assessor attempt metadata, and
redacted RiskAssessment evidence when one exists.

With `[audit] enabled = false`, checks keep the same Decision and permissions
without creating or opening audit/log files, including retries and failures.
Existing history remains. `auditId` remains a correlation ID and does not promise
a saved record; `aar explain` reports that an unsaved or cleaned record is absent.
Grants and trust remain available. `aar doctor` reports effective `loggingEnabled`.

Clear saved history explicitly from the project whose `.aar.toml` should apply:

```sh
aar cleanup
```

Cleanup uses the same effective configuration and state directory as checks. It
removes audit JSON and clears `review_events`, including SQLite WAL history,
while retaining the database file, grants, deny notes, trust, aggregate counters,
and configuration. It works with logging disabled or absent history and is safe
to repeat. It rejects symlink history paths and reports active checks or SQLite
writers/readers as busy; retry after they finish. Future enabled checks can
record new history. If cleanup fails, its error is explicit and some trace data
may already have been cleared.

When `audit.enabled` is true, `aar check` also writes events to
`<state-dir>/logs/reviews.sqlite`. Logging uses the same state directory as audit and grants;
by default, the database is `~/.local/state/aar/logs/reviews.sqlite`.
The `review_events` table stores `id` (event order), `review_id` (groups one check),
`recorded_at` (UTC), `event`, and `detail` (masked event fields as JSON).
A check records `received` (command, cwd, session/intent),
`parsed` (ShellIR, parse error, dynamic syntax, policy profile), and
`policy-result` and `verdict` (allow/ask/deny, source, matched rule and reason).
The final verdict links to the existing audit record via `auditId`.

Commands requiring assessment additionally record `assessor-required`, every
`assessor-call` and `assessor-response` (model, attempt, response or error),
and `assessor-result` (validated risks, uncertainties, total attempts or failure).
Automatic rules and exact grants do not call the LLM. Request/configuration
errors are recorded as a verdict with an error instead of a decision. Events
are committed individually as processing proceeds, so an interrupted check
retains its completed stages even if no final verdict is available.

Logs mask the same recognized secret patterns as audit; parsed command arguments
are derived from the masked command, while top-level parse error and dynamic
status come from the original parse. The database has mode `0600`, and newly
created log directories have mode `0700`. Environment variables, API request headers and
provider credentials are not logged. Failure to create/write a log fails the
check rather than returning approval. SQLite uses WAL mode and a one-second
busy timeout for concurrent checks.
Log retention is manual. Existing JSONL files are left in place; new checks
write only to SQLite.

For example, inspect recent verdicts with an optional installed SQLite CLI:

```sh
sqlite3 ~/.local/state/aar/logs/reviews.sqlite \
  "SELECT review_id, recorded_at, json_extract(detail, '$.decision'), json_extract(detail, '$.source'), json_extract(detail, '$.reason') FROM review_events WHERE event = 'verdict' ORDER BY id DESC LIMIT 20;"
```

The driver is pinned to [modernc.org/sqlite v1.60.1](https://pkg.go.dev/modernc.org/sqlite@v1.60.1), verified against the Go module registry.
It embeds SQLite in pure Go, so the Reviewer needs no system SQLite
installation and keeps `CGO_ENABLED=0` release builds.

## Shell compatibility

The Reviewer always parses commands using Bash grammar; the request does not
select a shell. Bash-compatible syntax can also be valid in zsh, and script evidence
collection recognizes `zsh -c` and `.zsh` files, but this is not full zsh syntax
support. The V2 Gate accepts only Bash as the native execution shell;
sh/zsh/fish/PowerShell invocations are refused before execution. Successful Bash parsing does not
guarantee identical execution semantics in another shell.

Ordinary `python3 script.py`, `node script.js`, and quoted `python3 -c '...'`
or `node -e '...'` invocations use shared shell syntax. Their embedded code is
Python or JavaScript; surrounding expansions and globbing still belong to the
shell. The Reviewer leaves execution and shell selection to OpenCode.

### Real command dump results

On 2026-10-05, all 7,179 JSON-encoded command strings in
`../../.scratch/029-auto-approval-reviewer/cmds.txt` were decoded and passed
to the Reviewer's actual `ParseShell` function. No dumped command was executed.

| Result                          |        Commands |
| ------------------------------- | --------------: |
| Parsed successfully             | 7,177 (99.972%) |
| Parsed without dynamic features |           3,541 |
| Parsed with dynamic features    |           3,636 |
| Parse failures                  |               2 |

Dump line 5302 failed because `${(P)v:-—}` uses zsh parameter expansion flags.
Line 7117 failed because of an unclosed double quote. Among successful parses,
1,207 commands contained recognized Python or Node invocations. These results
describe this dump, not a guarantee for future commands. Dynamic features
include variables, heredocs, loops, and redirections; successful parsing alone
does not imply automatic approval.

### Parse-failure behavior

For a fresh request, a parse failure skips deterministic auto-allow and goes to
the Command Risk Assessor with the failure recorded as local uncertainty.
In `data-loss`, the uncertainty alone does not block; the assessor must identify
a concrete material data-loss risk. In `balanced` and `strict`, it forces an
otherwise allowed assessment to `ask`. If the assessor is unavailable, the
default is `deny`, or `ask` when `assessor.onUnavailable = "ask"` is configured.

The V2 Gate defaults to `approvalMode: "never-ask"`, so a Reviewer `ask`
becomes a policy refusal without a dialog. With `approvalMode: "interactive"`,
the Gate waits for an explicit human reply through its TUI adapter. Allow once
records a grant, then the Gate rechecks the exact command before continuing
the original native call. Session trust is unavailable for parse failures.
Approval does not repair malformed syntax or change the execution shell.

## Installation and migration from V1

Build the separate Reviewer from the source vendored in `reviewer/` for Linux amd64/arm64 or macOS amd64/arm64 — or reuse an already released binary — and make `aar doctor` pass. The Gate neither embeds, builds nor downloads `aar` at runtime. Windows and non-Bash execution are unsupported. Reviewer policy/provider/profile/grant settings remain in the Reviewer configuration; plugin options below configure only the Gate.

After the V2 package is published, use the native flow (this ticket does **not** publish it or install into your real setup):

```sh
opencode plugin add @supercode/command-gate
```

Replace the V1 plugin registration; do not run both Gates. Manually copy values from the legacy JSONC `gate` section into the V2 package entry in global `~/.config/opencode/opencode.jsonc`; the V2 Gate never reads that section itself:

```jsonc
{
  "plugins": [
    {
      "package": "@supercode/command-gate",
      "options": {
        "binaryPath": "/absolute/path/to/aar",
        "timeoutMs": 5500,
        "approvalTimeoutMs": 600000,
      },
    },
  ],
}
```

Native `plugin add` also registers the bare package in global `cli.json`. Server inventory discovers its TUI half; operational settings come from RPC, not duplicated client options. Both registrations resolve to one TUI instance. Config changes require a **fresh location/service boot**; already-active locations can retain the old inventory/options. Do not restart the service hosting an active agent. A directory target must be an installed package directory with dependencies; standalone JS paths are not supported. Root `index.js`, `tui.js` and `rpc.js` forward to compiled JavaScript. The UI uses host dialogs and host Solid; there is no raw JSX/TSX or bundled renderer.

| Server option       | Default             | Explicit environment override      |
| ------------------- | ------------------- | ---------------------------------- |
| `enabled`           | `true`              | —                                  |
| `binaryPath`        | `aar`               | `AAR_BINARY_PATH`                  |
| `tools`             | `["bash", "shell"]` | `AAR_GATE_TOOLS` (comma-separated) |
| `timeoutMs`         | `5500`              | `AAR_GATE_TIMEOUT_MS`              |
| `commandRewriter`   | `none`              | `AAR_GATE_COMMAND_REWRITER`        |
| `rewriterPath`      | `rtk`               | `AAR_GATE_REWRITER_PATH`           |
| `onReviewerFailure` | `deny`              | `AAR_GATE_ON_REVIEWER_FAILURE`     |
| `approvalMode`      | `never-ask`         | —                                  |

Explicit package options take precedence over environment overrides. `approvalTimeoutMs` is a server-only option, default `600000`. There is no environment override for `approvalMode`; it accepts only `never-ask` and `interactive` (matched case-insensitively like the other enum options), and any other value is an invalid setting that denies — including invalid settings combined with passthrough.

To disable Command Gate while keeping both registrations, use the same entry
in the `plugins` array of **both** `opencode.jsonc` (or `opencode.json`) and
`cli.json`:

```jsonc
{
  "package": "@supercode/command-gate",
  "options": { "enabled": false },
}
```

`enabled` defaults to `true` and accepts only booleans. With `false`, the server
skips doctor, Reviewer/RTK calls, hooks and RPC registration; the TUI skips
commands, dialogs, timers and RPC connections. OpenCode still loads the package,
but both halves do no work. TUI options must be set in `cli.json` because server
inventory does not forward them. To re-enable, remove this option or set it to
`true` in both files. As with other plugin options, a fresh location/service boot
is required; changing configuration does not disable an already running instance.

Use **Command Gate: health** in the palette, or `/gate-health`, for server doctor health/reason, failure mode, effective settings and approval-adapter availability. An active inventory item is only proof of loading, not successful review. Missing/incompatible Reviewer, explicit **UNREVIEWED** passthrough and unavailable approval adapter have separate diagnostics.

## Native permission backstop

Keep native shell allow with the minimal deny backstop. Native **Always** saves project/prefix permissions; it is not **Trust exact for session** and cannot replace a fresh Reviewer check. Broad native ask rules can introduce a second prompt after review.

```jsonc
{
  "permissions": [
    { "action": "shell", "resource": "*", "effect": "allow" },
    { "action": "shell", "resource": "mkfs*", "effect": "deny" },
    { "action": "shell", "resource": "dd *", "effect": "deny" },
    { "action": "shell", "resource": "shutdown *", "effect": "deny" },
    { "action": "shell", "resource": "reboot*", "effect": "deny" },
  ],
}
```

| Deadline            | Default    | Meaning                                                                                                                                |
| ------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `timeoutMs`         | 5,500 ms   | Each Reviewer CLI operation; must exceed the doctor-reported check deadline (normally 5,000 ms).                                       |
| `approvalTimeoutMs` | 600,000 ms | Separate finite human-wait deadline; positive server option. Expiration denies, never allows.                                          |
| TUI heartbeat       | 5,000 ms   | Reconcile list and renew the approval adapter lease.                                                                                   |
| Adapter lease       | 15,000 ms  | Missing renewals invalidate replies; pending waits detect lease loss within another 1,000 ms. Explicit disconnect refuses immediately. |

Reviewer reservation expiry still applies: a response arriving before the human deadline can nevertheless fail `aar grant` if the reservation has expired. Grants remain in the Reviewer-owned state directory; the Gate does not add a grant store.

## Failures and cancellation

The default `onReviewerFailure: "deny"` keeps interception loaded when doctor is unhealthy or the binary is missing/incompatible. Invalid options always deny. Explicit `"passthrough"` permits operational Reviewer failures only, labelled **UNREVIEWED** in server diagnostics and a TUI warning fetched through public status RPC. Reviewer deny/ask (including never-ask Ask-to-Deny), stale context, failed approval/grant, native deny, unsupported Bash/background invocation and invalid configuration never become passthrough.

Gate-owned Reviewer and RTK operations are deadline-bound. On cancellation/deadline, POSIX subprocess groups receive SIGKILL (including descendants); the Effect finalizer joins subprocess close before releasing review state. Native command execution and its supervision remain entirely with OpenCode. Unload interrupts the wrapped native Effect, including pre-spawn permission waits; any already-running native process is cancelled by host supervision, never by a Gate spawner. Pending human waits remove timers/abort listeners on every terminal response, and plugin unload closes them and signals outstanding reviews. Captured old tool wrappers refuse after unload instead of executing without their removed shell hook. Restart/reload still resets persisted human session grants before first review.

**Accepted fail-open gap:** an absent, disabled or failed-to-load plugin cannot intercept native commands. Inventory alone does not prove protection; inspect doctor/operational diagnostics. This is distinct from a loaded-but-unhealthy Gate, which denies by default.

Same-session reviews and once consumption use a per-session permit over existing Reviewer locking. Invalidation advances context generation before resetting Reviewer state; reconciliation after review/grant refuses stale authorization. Main/child sessions and locations retain independent approval identities. RPC notifications are hints, not consent: list/get reconciliation and explicit matching replies are required.

## Intent and lifecycle

Every public user admission, including plugin/subagent `session.prompt`, is authoritative. The Gate reconciles typed admitted messages and durable inbox events; an early prompt hook invalidates trust but does not supply the final text. Synthetic continuation, compaction summaries and tool output never become admitted user text. Child sessions inherit available parent intent until their own admission; grants still belong only to the owning session/location.

New admission, canonical Goal replacement/clear, native `/clear` and session deletion invalidate grants, pending approvals and deny suppression. Parent changes conservatively invalidate known descendants. Native `/clear` uses a public TUI keymap bridge: Reviewer invalidation must succeed before dispatching the native command; an unavailable bridge disables the approval adapter. Tab close and turn idle do not end the session. Server restart/location reload resets persisted Reviewer authorization before first review; a new or expired client connection conservatively resets known sessions. Live-event notifications are not the sole source of authorization: context generation is reconciled before review, reply and continuation.

## Review context

The Reviewer receives the active Goal, latest user request, canonical working
directory, workspace root, protected paths, and temporary-directory boundary.
When OpenCode exposes the owning assistant message in session context, the Gate
also sends up to 8,192 characters of its text/reasoning preceding the exact tool
call as `intent.assistantRationale`. Other tool outputs, provider state, later
reasoning, and messages from other calls are excluded. Missing rationale does
not block; provided rationale is contextual evidence and cannot bypass Hard
Deny. It is bound to the assessment fingerprint and checked for changes during
review and approval. It is sent to the configured assessor provider.

## RTK and invocation integrity

Server options `commandRewriter: "none" | "rtk"` (default `"none"`) and `rewriterPath` (default `"rtk"`) also accept `AAR_GATE_COMMAND_REWRITER` and `AAR_GATE_REWRITER_PATH`; explicit options win. RTK is a trusted optimizer, not a safety dependency. Gate invokes the binary as `rtk rewrite <whole-command>` with `shell: false`, actual cwd and an allowlisted optimizer environment (PATH/HOME/PWD, no provider keys or session secrets). It never executes the submitted command during rewriting. Successful non-empty trimmed stdout becomes the Verbatim review subject and native command. Missing RTK, empty output, non-zero exit, oversized output or deadline failure keep the original command and still require the ordinary Reviewer Decision. Cancellation stops the call, not a fallback execution.

**Installation requirements:** disable every other RTK/rewrite plugin for covered native tools; Gate alone owns their rewrite. Keep its native execute wrapper intact. Tool-input edits before that wrapper and shell edits before Gate's shell review are reviewed as final facts, not as the model's initial arguments. Actual canonical cwd, session material env (HOME/CDPATH/PWD when present) and Bash come from shell creation, not the plugin process environment. The checked native composition retains the host's permission checks, scanner, streaming and executor.

After review, Gate guards the same shell invocation's command/cwd/shell/env properties and a copied environment against controlled late mutations. Changed writes refuse before start with a model-facing error rather than reuse allow. The host may reassign identical top-level properties, canonicalize cwd to the already-reviewed canonical directory, and add its four native metadata values (`AGENT=1`, `OPENCODE=1`, default `AI_AGENT=opencode`, owning `OPENCODE_SESSION_ID`); these are not material Reviewer facts. Other env-property writes refuse even when assigning the existing value. The guards also apply to explicit UNREVIEWED passthrough. Background is checked both in tool-before and at wrapped native execute, so a later tool-before hook cannot enable it.

**Unsupported composition:** late shell command/cwd/env/shell mutators, second RTK rewrite, removal/replacement of the Gate wrapper, custom executors, and plugins that replace the hook payload, suppress guard failures or dispatch outside the native tool seam. Known late mutation fixtures refuse; arbitrary malicious/unknown plugin compositions are not contained or proven safe. Configured list order alone is not proof of registration order or compatibility: validate a new composition with native marker/output traces. No claim that Gate is always the final hook is made.

Reviewer remains Bash-only; sh/zsh/fish/PowerShell and explicit native background mode refuse before start, without changing the selected shell after allow. Background syntax and hidden long-lived effects inside a program remain existing Reviewer policy, not a new Gate parser or containment guarantee. Human `!command` is neither reviewed nor rewritten (tests exercise its server shell API, not typed TUI input). Non-shell tools, MCP, arbitrary Code Mode code and other plugin processes are outside coverage. Child native shell calls are covered at the proven common seam; not every nested dispatch form has been demonstrated.

## Verification

```sh
pnpm install --frozen-lockfile
pnpm compile
pnpm typecheck
pnpm format:check
pnpm test:package
pnpm test:all
AAR_PREBUILT=/absolute/path/to/existing/aar pnpm test:packed
AAR_PREBUILT=/absolute/path/to/existing/aar pnpm test:human:packed
GATE_PACKED=1 GATE_LONG_HUMAN=1 AAR_PREBUILT=/absolute/path/to/existing/aar node --test test/long-command-human.test.mjs
```

Run Reviewer tests from its module directory:

```sh
cd reviewer
go test ./...
```

The frozen assessor smoke corpus is advisory and must be run with an explicit
model/configuration:

```sh
AAR_BINARY_PATH=/path/to/aar \
AAR_SMOKE_CONFIG=/path/to/aar/config.toml \
AAR_SMOKE_MODEL=provider/model-id \
AAR_SMOKE_API_KEY_ENV=PROVIDER_API_KEY \
npm run test:smoke
```

The smoke command above runs from `reviewer/`; it contacts the explicitly configured model endpoint.

`compile` emits server/TUI/RPC and excludes test sources; `prepack` regenerates compiled output. Build/runtime dependency pins were rechecked against registry.npmjs.org for host 2.0.22; its plugin package pins client 2.0.22 and Effect 4.0.0-rc.112. Solid is build-time/types-only: the host supplies its own runtime instance, and this dialog-only UI needs no JSX transform.

Packed tests use **native plugin add through a loopback registry** in isolated HOME/XDG/config, then activate the location and require package-source inventory, TUI discovery and working RPC. The registry proxies only dependency requests to npm. Installed JS is compared byte-for-byte against the extracted tarball; artifact integrity, exact host version, Reviewer SHA256, inventory, settings, audit and native effects are saved below `/tmp/opencode`. `AAR_PREBUILT` is required for packed checks, so the separate existing Reviewer is never built by that path. Workspace tests may build the Reviewer from `AAR_SOURCE`. Python 3 drives real target TUI actions/layout; the 64×24 layout check uses the installed `pyte` terminal emulator to assert actual screen contents and retains page screenshots. These are automated regression evidence, **not human approval**.

Full commands serialize test files to bound installation/host resources. Boots within one packed run reuse its isolated dependency cache; the first boot proves cold native installation, later boots prove activation/reuse. The harness removes only that run-owned cache after servers stop, retaining tarball, extracted artifact, logs and installation evidence. Regenerate a live launcher by rerunning the human command rather than using a completed run's stale launcher.

TUI keymap registration must occur under the rendered app slot, not directly in plugin setup: setup has no host `Keymap.Provider`. The real-TUI diagnostics test covers this boundary.

The opt-in human command prints an isolated TUI launcher: inspect summary/details, manually Allow once twice for `human-once`, Trust exact for session for `human-session`, Deny for `human-deny`, then exit the temporary TUI. It must be run while the test server is alive; the harness stops its processes on completion/failure. Personal config/service/credentials are not connected or changed. Genuine human approval, macOS/arm64 execution and release-download checksum verification are not implied by Linux automated smoke. No publication, push, real installation or service restart is performed.

The long-command human check prints its own isolated launcher. Use a terminal where Full command spans multiple pages: inspect the immediately visible risk, read Details without traversing the script, read Full command through `FINAL_COMMAND_LINE`, return to actions, then explicitly Allow once. Repeat with Deny for the next call and exit the temporary TUI. Record terminal dimensions and human feedback beside the run's retained `results.json`, packed artifact and host version; the automated result alone does not complete this acceptance.
