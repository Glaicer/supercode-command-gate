<div align="center">

<img src="https://raw.githubusercontent.com/Glaicer/supercode-command-gate/main/public/command-gate.jpg" alt="Command Gate" width="512">

# Command Gate

**Control, handed over. You can relax.**

</div>

Coding agents execute dozens of shell commands per session. OpenCode's
permissions are coarse: you either approve every `ls` by hand, or allow
everything and hope the agent never hallucinates a destructive one.

Command Gate sits in between. It reads each command in full, decides whether
it's safe, and only stops you when it matters.

> Inspired by the auto-review idea from
> Codex and Claude Code:
> low-risk actions proceed on their own; suspicious ones stop for human
> review.

## How it works

Command Gate is two pieces working together:

- **The plugin** (`@glaicer/supercode-command-gate`): runs inside OpenCode. It
  intercepts every shell call, passes it to the reviewer, enforces the
  verdict, and shows the approval dialog when a command needs you.
- **The reviewer** (`aar`): a small standalone binary, installed separately.
  It never executes anything itself. It parses the full command, applies a
  deterministic safety policy to it, and, when a command is unclear, asks
  an LLM assessor for a verdict.

With both in place, every command goes through the same path:

1. The agent calls a shell tool.
2. Command Gate intercepts the call and hands the full command to `aar`, the
   command reviewer.
3. `aar` parses the command and applies its safety policy. Clearly safe or
   clearly dangerous commands are decided automatically; everything in
   between goes to an LLM assessor, which reviews the command together
   with the session context it runs in.
4. The verdict: **allow**: the command runs, exactly as reviewed. **deny**:
   it's blocked, with a reason. **ask**: it needs your approval.

<p>
  <img src="https://raw.githubusercontent.com/Glaicer/supercode-command-gate/main/public/how-it-works.jpg" alt="How Command Gate reviews a command" width="1000">
</p>

- **Simple commands pass instantly.** Reads, listings, and `git status` are
  allowed by deterministic rules, with no model call and no delay.
- **Complex commands go to an LLM.** The assessor sees the whole command,
  the bodies of the scripts it would run, and the session context: your
  goal, your latest request, and the agent's own reasoning.
- **Approvals are remembered.** An approved command isn't re-assessed or
  re-asked next time, until your intent or the project's scripts change.
- **OpenCode's permission rules still apply.** The Gate adds a layer, it
  doesn't replace them: a rule that asks or denies still fires regardless
  of the Gate's verdict. Review your rules after installing: with the
  Gate in place, setting shell commands to `allow` leaves the Gate as the
  only thing that asks.

**This is a safeguard against agent mistakes, not a security boundary.** It
will not contain a deliberately malicious agent, it doesn't audit every file
or dependency a command may touch, and it doesn't sandbox execution. For real
isolation, pair it with a sandbox such as bubblewrap.

Background invocations are refused by default. With `allowBackground` on, they
are reviewed like any other command, but the Gate does not contain, supervise
or clean up background processes once the host starts them.

## Installation

**1. Install the reviewer:** pick your terminal:

```sh
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/Glaicer/supercode-command-gate/main/install.sh | bash
```

```powershell
# Windows PowerShell
Invoke-RestMethod https://raw.githubusercontent.com/Glaicer/supercode-command-gate/main/install.ps1 | Invoke-Expression
```

The installer is an interactive wizard: it downloads the binary from GitHub
Releases, verifies its SHA-256 checksum, and writes `config.toml` together
with you: model, auth mode, safety profile. It never asks for the API key
itself, only the name of the environment variable holding it.

Run `aar doctor` to verify the setup.

**2. Register the plugin in OpenCode:**

```sh
opencode plugin add @glaicer/supercode-command-gate
```

Restart OpenCode after installing. The first load may take a moment while
OpenCode downloads the package. To pass options (approval mode, timeouts),
register it in `~/.config/opencode/opencode.jsonc` instead; see
[Configuration](#configuration).

## Sandbox mode

Command Gate supports sandboxed OpenCode launches. Inside a sandbox,
commands are already contained by the sandbox itself, so there is nothing
left to review. Skipping the Gate saves tokens and keeps your costs down.

To activate it, set the environment variable when launching OpenCode:

```sh
OPENCODE_SANDBOX_MODE=sandboxed opencode
```

In practice, set the variable in the settings of the sandbox you use, so it
is inherited by the OpenCode process.

With the variable set, the plugin assumes it runs in a sandbox and switches
itself off entirely: no command reviews, no approval dialogs, and no model
calls. Any other value (or no variable at all) keeps the Gate active.

The plugin trusts the variable and does not check whether a real sandbox is
behind it. Set it yourself, or know who launches OpenCode for you.

## Configuration

Two separate places: the plugin is configured in OpenCode's config, the
reviewer in its own TOML file.

| OS      | Binary                           | Config                                          |
| ------- | -------------------------------- | ----------------------------------------------- |
| Linux   | `~/.local/bin/aar`               | `~/.config/aar/config.toml`                     |
| macOS   | `~/.local/bin/aar`               | `~/Library/Application Support/aar/config.toml` |
| Windows | `%LOCALAPPDATA%\aar\bin\aar.exe` | `%APPDATA%\aar\config.toml`                     |

### Plugin: OpenCode config

```jsonc
// ~/.config/opencode/opencode.jsonc
{
  "plugins": [
    {
      "package": "@glaicer/supercode-command-gate",
      "options": {
        "binaryPath": "/home/you/.local/bin/aar",
        "approvalMode": "interactive",
      },
    },
  ],
}
```

| Option              | Default         | Meaning                                                                                        |
| ------------------- | --------------- | ---------------------------------------------------------------------------------------------- |
| `binaryPath`        | `aar` in PATH   | Where to find the reviewer binary.                                                             |
| `approvalMode`      | `never-ask`     | `interactive` shows an approval dialog in the TUI; `never-ask` refuses such commands outright. |
| `approvalTimeoutMs` | `600000`        | How long the approval dialog waits for your answer.                                            |
| `timeoutMs`         | `5500`          | Deadline for one review.                                                                       |
| `onReviewerFailure` | `deny`          | If the reviewer itself fails: `deny`, or let the command through unreviewed (`passthrough`).   |
| `allowBackground`   | `false`         | Review invocations with `background: true` instead of refusing them upfront.                   |
| `tools`             | `bash`, `shell` | Which shell tools to intercept.                                                                |
| `commandRewriter`   | `none`          | `rtk` rewrites commands through `rtk` (path in `rewriterPath`) before review.                  |
| `enabled`           | `true`          | Set `false` to keep the plugin installed but off.                                              |

Every option can also come from an environment variable (`AAR_BINARY_PATH`,
`AAR_GATE_TOOLS`, `AAR_GATE_TIMEOUT_MS`, `AAR_GATE_ON_REVIEWER_FAILURE`,
`AAR_GATE_COMMAND_REWRITER`, `AAR_GATE_REWRITER_PATH`); the config file wins.

By default there are no popups: a command that would need your approval is
simply refused. If you'd rather decide yourself, set `approvalMode` to
`interactive`: you get a dialog with the risks, the full command, and
**Allow once**, **Trust for this session**, or **Deny**.

### Reviewer: `~/.config/aar/config.toml`

```toml
[assessor]                              # the LLM that assesses unclear commands
model = "provider/model-id"             # model id
baseUrl = "https://api.example.com/v1"  # OpenAI-compatible endpoint (HTTPS)
apiKeyEnv = "ASSESSOR_API_KEY"          # env var holding the key — never the key itself
totalTimeoutMs = 5000                   # budget for one assessment (default 5000)
onUnavailable = "deny"                  # when no assessor is reachable: deny · ask
authMode = "api-key"                    # api-key (default) · opencode · codex
authJsonPath = ""                       # codex mode only: absolute path to auth.json
options = { temperature = 0.1 }         # raw request options for the provider
contextWindows = { "provider/model-id" = 128000 }  # token capacity hints per model
fallbackModels = []                     # model-only fallbacks on the primary connection
interpreters.python = { inlineFlags = ["-c"], fileExtensions = ["py"] }  # script evidence extraction

[[assessor.fallbacks]]                  # ordered fallback connections
model = "fallback-model"                # each has its own endpoint, key and options
baseUrl = "https://provider-b.example/v1"
apiKeyEnv = "PROVIDER_B_KEY"
options = { temperature = 0.2 }
contextWindow = 32768                   # per-connection capacity override
# authMode = "opencode"                 # or reuse the OpenCode subscription

[policy]
profile = "data-loss"                   # data-loss (default) · balanced · strict
protectedPaths = ["/important/data"]    # paths to protect during review
categoryOverrides = { network = "ask" } # per risk category: inherit · ignore · ask · deny
autoAllowAdditions = [                  # exact additional commands to auto-allow
  { argv = ["./scripts/report.sh"], pathScope = ["./reports"] },
]

[grants]                                # remembered approvals
sessionTrust = true                     # allow "Trust for this session" (default true)
maxAgeSeconds = 86400                   # how long approvals are remembered (default 24h)
reservationTTLSeconds = 600             # approval reservation window (default 10 min)

[audit]
enabled = true                          # audit trail of every decision (default on)
dir = "~/.local/state/aar"              # state dir: audit trail, history, approvals
```

- **Profiles:** `data-loss` only stops real threats to your data, the
  recommended default for everyday agent work. `balanced` also weighs
  credentials, privilege and network effects. `strict` weighs everything.
- **Risk categories:** `categoryOverrides` tunes the ten built-in categories
  (`critical_data_loss`, `credential_access`, `external_side_effect`,
  `network`, `privilege`, `persistence`, `process_control`,
  `resource_exhaustion`, `opaque_execution`, `goal_mismatch`), each set to
  `inherit`, `ignore`, `ask` or `deny`.
- **No assessor configured?** Deterministic rules still work; commands that
  would need a model are denied rather than guessed.
- A `.aar.toml` in your project root overlays the global config.
- You can also assess through your ChatGPT subscription via OpenCode instead
  of an API key (`authMode = "opencode"`); see
  [ChatGPT subscription authentication](#chatgpt-subscription-authentication).
- Assessor connections can have ordered fallbacks; see
  [Independent Assessor providers](#independent-assessor-providers).
- The audit trail and remembered approvals live in the state directory
  (`~/.local/state/aar`, overridable with `AAR_STATE_DIR`).
- Run `aar doctor` to check your setup.

### Everyday commands

```sh
aar doctor                          # check binary, config and credentials
aar stats                           # how many commands were allowed / denied / asked
aar trust-reset --project <path>    # forget remembered approvals for a project
aar cleanup                         # clear review history (approvals are kept)
```

## Deep dive

The full reference for the `aar` reviewer lives in
[docs/aar-reference.md](https://github.com/Glaicer/supercode-command-gate/blob/main/docs/aar-reference.md):

- **Building the reviewer:** cross-compiling release binaries from source.
- **Deterministic policy:** exactly which command forms pass without a model call.
- **Independent Assessor providers:** ordered fallback connections, their
  budget and timeout rules.
- **ChatGPT subscription authentication:** using your OpenCode/ChatGPT
  subscription as the assessor, plus the legacy Codex file mode.
