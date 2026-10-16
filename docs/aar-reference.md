# Command Reviewer (`aar`): reference

The [root README](https://github.com/Glaicer/supercode-command-gate/blob/main/README.md)
covers installing and configuring Command Gate. This document is the deep
reference for the reviewer binary itself.

## Building the reviewer

With Go 1.27+ installed, run from this repository:

```sh
cd reviewer
AAR_RELEASE_VERSION=0.1.0 sh scripts/release.sh
```

The script cross-compiles Linux, macOS and Windows binaries for amd64 and arm64
into `reviewer/dist/reviewer-v0.1.0/`, together with `SHA256SUMS`. Windows
artifacts end in `.exe`. Windows builds are cross-compilation checked, but have
had no Windows runtime or plugin-integration testing. AAR still reviews Bash
syntax, not PowerShell or cmd.exe; the shell installer (`install.sh` in the
repository root) remains Linux/macOS-only, while Windows uses `install.ps1`.

## Deterministic policy

The deterministic checks run with no model call. The whole program must
qualify, including every pipeline stage and every command after `;`, `&&`, or
`||`:

- **Read-only commands:** `cat`, `head`, `tail`, `ls`, `tree`, `file`,
  `stat`, `du`, `wc`, `uniq`, `cut`, `tr`, `readlink`, `realpath`,
  `basename`, `dirname`, `sort`, `diff`, `cmp`, `comm`, `grep`/`rg`,
  plus read-only `git` forms (`git branch --list`, `git check-ignore`,
  `git merge-base --is-ancestor`, `git show-ref --heads`) and
  `stat --format=<format> <path>...`.
- **Bounded path expansion:** `*` / `?` globs and one numeric brace range
  (`{1..8}`) per unquoted word, up to 256 resulting arguments and 4096
  inspected directory entries per pattern. Every result still passes the
  canonical-path and protected-path checks; a glob with no matches always
  falls back.
- **Descriptor duplication** such as `2>&1`, `1>&2`, `>&2`. File writes
  still require the explicit safe-target policy.

Everything outside this subset (writes, `rm`, custom executables, scripts,
loops, substitutions, unknown flags, hidden-name globs without a leading
dot, and the mutation modes of `systemctl`/`gsettings`/`ps`) falls back to
the assessor. Nonempty `BASHOPTS`, `SHELLOPTS`, `GLOBIGNORE`, `BASH_ENV` or
`ENV` disables expansion auto-allow, since shell options and startup scripts
can change expansion semantics. This is Bash syntax policy, not support for
other shells, and it does not contain filesystem changes between checking
and execution.

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

Each API-key fallback requires its own `model`, `baseUrl`, and `apiKeyEnv`;
these fields and its `options` do not inherit primary values. A fallback can
instead set `authMode = "opencode"` and a `model` to use the active OpenCode
subscription; omit `baseUrl` and `apiKeyEnv` for that connection. The
`fallbacks` array can also be written inline. The top-level `onUnavailable`
applies to the entire assessor chain. Omitted `options` means an empty map.
Optional `contextWindow` overrides the shared model-keyed `contextWindows`
capacity hint for that connection. Evidence is never truncated. Keep
credentials in environment variables, never in TOML. URLs must use HTTPS
except loopback test servers, and cannot contain userinfo, query parameters
or fragments. AAR rejects redirects, so credentials cannot be forwarded to
another endpoint.

`fallbackModels` switches only the model, reusing the primary URL, key and
options; configuring both nonempty `fallbackModels` and `fallbacks` is an
error. The project `.aar.toml` overlays primary scalars and merges primary
options. A project `fallbacks` array replaces the entire global array; an
omitted array inherits it, and `fallbacks = []` clears it. These inheritance
rules also hold when switching modes, so explicitly clear incompatible
inherited fields (for example `baseUrl = ""`, `apiKeyEnv = ""`,
`fallbacks = []`, or `authJsonPath = ""` for API-key or OpenCode mode).

The Gate forwards the union of explicitly declared credential environment names
from global and project TOML to the trusted AAR process; each HTTP request
carries only the selected connection's key.

The primary connection runs first. Each connection gets the remaining overall
`totalTimeoutMs` divided by the number of remaining connections, with at most
two sequential attempts sharing that connection's allocation. Timeouts cancel
the HTTP request. Missing credentials, exhausted transport/JSON/schema retries,
or insufficient context capacity advance to the next connection. A validated
RiskAssessment ends the chain even when local policy maps it to ask or deny.
Exhaustion uses `onUnavailable`, preserving Hard Deny and approval policy.

`aar doctor` checks all URL shapes and credential availability without calling
providers. Its `connections` diagnostics and the audit `assessorConnection`
field identify `primary` and `fallback[0]`, `fallback[1]`, etc., including
identical model IDs, without exposing endpoints or keys. Doctor succeeds when
at least one configured connection has an available credential, so a missing
primary key does not prevent a usable fallback. Structural errors always fail
validation.

## ChatGPT subscription authentication

Use the OpenCode harness as the credential owner. Sign in there:

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
credential with method `chatgpt-browser` or `chatgpt-headless`, an access
token, account ID and unexpired millisecond expiry. It ignores inactive
credentials and unrelated providers; API-key connections, malformed output and
ambiguous active connections fail closed. Export output stays in memory, capped
at 1 MiB; credentials never enter Reviewer requests, audit, trace or
diagnostics.

The CLI defaults to `opencode` on PATH; `OPENCODE_BIN` selects the harness
binary. Gate forwards `OPENCODE_CONFIG_DIR`, `XDG_DATA_HOME` and
`XDG_CACHE_HOME` along with the HOME/config environment it already forwards.
Use the same namespace as the harness where you logged in. Global export avoids
booting a project location and recursively loading Gate. It uses the normal
OpenCode CLI server connection, which may start the managed service if absent.
`aar doctor` queries credentials through this connection, but performs no
provider/LLM call and starts no login flow.

AAR reloads credentials on each attempt, including authentication retries. It
never writes the owner store, rotates tokens, calls an OAuth refresh endpoint
or starts login. OpenCode refreshes credentials through its own provider
lifecycle; export itself does not refresh them. If the token is expired or
revoked, refresh or sign in through OpenCode and retry. CLI execution shares
the assessment deadline.

Subscription authentication is separate from the default
`authMode = "api-key"` and paid OpenAI API billing. API-key connections can
incur separate API billing; without explicit configuration there is no paid
API fallback. Account entitlement, model availability and usage limits still
apply; a readable token does not prove access to the requested model.

### Subscription request behavior

AAR sends subscription requests only to
`https://chatgpt.com/backend-api/codex/responses` and rejects redirects; it
also rejects primary `baseUrl` and `apiKeyEnv`, so OAuth credentials cannot
reach another host. Explicit `fallbackModels` stay on the primary subscription
transport.

AAR accepts only the subscription options `options.reasoning`, `options.text`,
and `options.service_tier`; it rejects state, tools and saved-prompt options.
Each request carries no history or previous response, no tools, and
`store = false`. AAR accepts SSE text only after a completed response and
validates it with the RiskAssessment parser and local policy mapper. The same
deadline and retry budget apply. Authentication, limit and stream failures use
`onUnavailable`; an expired or failed response cannot authorize a command. AAR
sanitizes provider errors and refuses reflected credential material before it
reaches audit or trace.

### Legacy Codex file mode

`authMode = "codex"` selects a file reader with an explicit absolute
`authJsonPath = "/absolute/path/to/.codex/auth.json"`. It supports Codex
`auth.json`, optional `auth_mode = "chatgpt"`, `tokens.access_token` as a JWT
with `exp`, and `tokens.account_id`. The private regular file must have
permissions 0600 and be at most 1 MiB. Other Codex auth modes, keyrings and
provider-keyed OpenCode legacy JSON are unsupported. This mode performs no
credential search; Codex owns refresh and AAR reloads its file on each attempt.
Legacy Codex mode rejects independent API fallbacks. Doctor checks this file
locally without a network call.

[Official Codex authentication documentation](https://learn.chatgpt.com/docs/auth)
describes this legacy owner/file mode. JWT expiry is a local readiness hint;
the subscription server verifies credentials and account/model access.
