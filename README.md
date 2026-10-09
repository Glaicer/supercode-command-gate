# Command Gate

**Every shell command your AI agent runs — reviewed before it runs.**

Coding agents execute dozens of shell commands per session. OpenCode's
permissions are coarse: you either approve every `ls` by hand, or allow
everything and hope the agent never hallucinates a destructive one.

Command Gate sits in between. It reads each command in full, decides whether
it's safe, and only stops you when it matters.

> Inspired by the auto-review idea from
> [Codex](https://openai.com/index/running-codex-safely/) and Claude Code:
> low-risk actions proceed on their own; suspicious ones stop for human
> review.

## How it works

1. The agent calls a shell tool.
2. Command Gate intercepts the call and hands the full command to `aar`, the
   command reviewer.
3. `aar` parses the command and applies its safety policy. Obvious reads and
   development commands (`pnpm test`, typecheck, lint) pass on their own;
   catastrophic ones are hard-denied. Everything else goes to an LLM assessor
   that sees the whole command, the scripts it would run, and what you asked
   the agent to do.
4. The verdict: **allow** — the command runs, exactly as reviewed. **deny** —
   it's blocked, with a reason. **ask** — it needs your approval.

Approvals are remembered: a command that was safe yesterday is not re-assessed
today, as long as nothing around it changed.

**This is a safeguard against agent mistakes, not a security boundary.** It
will not contain a deliberately malicious agent, it doesn't audit every file
or dependency a command may touch, and it doesn't sandbox execution. For real
isolation, pair it with a sandbox such as bubblewrap.

Background invocations are refused by default. With `allowBackground` on, they
are reviewed like any other command — but the Gate does not contain, supervise
or clean up background processes once the host starts them.

## Two parts

| Part                      | What it is                                                                                                                                                               |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `aar`                     | The command reviewer. A small static binary (Linux/macOS) that parses and assesses commands. It never executes anything itself. Source lives in [`reviewer/`](reviewer). |
| `@supercode/command-gate` | The OpenCode plugin. Intercepts shell calls, talks to `aar`, enforces the verdict, and shows the approval dialog in the TUI.                                             |

Requires OpenCode 2.0.22+ and Bash.

## Installation

_Coming soon — instructions will be added once the package is published._

You will need two things: the `aar` binary on your machine, and the plugin
registered in OpenCode.

## Configuration

Two separate places: the reviewer has its own TOML file, the plugin is
configured through OpenCode's config.

### Reviewer: `~/.config/aar/config.toml`

```toml
[assessor]
model = "provider/model-id"              # model used to assess unclear commands
baseUrl = "https://api.example.com/v1"   # OpenAI-compatible endpoint (HTTPS)
apiKeyEnv = "ASSESSOR_API_KEY"           # name of the env var holding the key — never the key itself
totalTimeoutMs = 20000                   # time budget for one assessment

[policy]
profile = "data-loss"                    # data-loss (default) · balanced · strict
protectedPaths = ["/important/data"]     # paths to protect during review
```

- **Profiles:** `data-loss` only stops real threats to your data — the
  recommended default for everyday agent work. `balanced` also weighs
  credentials, privilege and network effects. `strict` weighs everything.
- **No assessor configured?** Deterministic rules still work; commands that
  would need a model are denied rather than guessed.
- A `.aar.toml` in your project root overlays the global config.
- You can also assess through your ChatGPT subscription via OpenCode instead
  of an API key (`authMode = "opencode"`).
- Run `aar doctor` to check your setup.

### Plugin: OpenCode config

```jsonc
// ~/.config/opencode/opencode.jsonc
{
  "plugins": [
    {
      "package": "@supercode/command-gate",
      "options": {
        "binaryPath": "/home/you/.local/bin/aar",
        "approvalMode": "interactive",
      },
    },
  ],
}
```

| Option              | Default       | Meaning                                                                                        |
| ------------------- | ------------- | ---------------------------------------------------------------------------------------------- |
| `binaryPath`        | `aar` in PATH | Where to find the reviewer binary.                                                             |
| `approvalMode`      | `never-ask`   | `interactive` shows an approval dialog in the TUI; `never-ask` refuses such commands outright. |
| `timeoutMs`         | `5500`        | Deadline for one review, in milliseconds.                                                      |
| `onReviewerFailure` | `deny`        | If the reviewer itself fails: `deny`, or let the command through unreviewed (`passthrough`).   |
| `enabled`           | `true`        | Set `false` to keep the plugin installed but off.                                              |
| `allowBackground`   | `false`       | Review invocations with `background: true` instead of refusing them upfront.                   |

By default there are no popups: a command that would need your approval is
simply refused. If you'd rather decide yourself, set `approvalMode` to
`interactive` — you get a dialog with the risks, the full command, and
**Allow once**, **Trust for this session**, or **Deny**.

### Everyday commands

```sh
aar doctor                          # check binary, config and credentials
aar stats                           # how many commands were allowed / denied / asked
aar trust-reset --project <path>    # forget remembered approvals for a project
aar cleanup                         # clear review history (approvals are kept)
```
