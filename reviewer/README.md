# Auto Approve Permissions

Auto Approve Permissions ships as two separate artifacts:

- **Command Reviewer** — the standalone `aar` binary. It parses and assesses a
  command, returns a Decision, writes a secret-safe audit record, and never
  executes the command under review.
- **Command Gate** — the `@supercode/command-gate` npm package. It intercepts
  OpenCode's native `bash` and `shell` tools and leaves execution to OpenCode.

The supported runtime is OpenCode `1.18.21` on Linux or macOS. Windows command
execution is unsupported in V1; Windows policy catalog facts remain reserved
and unit-tested for a future host.

## Install the Command Reviewer

Download one release binary and its checksum file from the GitHub release:

```text
aar-v<VERSION>-linux-amd64
aar-v<VERSION>-linux-arm64
aar-v<VERSION>-darwin-amd64
aar-v<VERSION>-darwin-arm64
SHA256SUMS
```

Install the selected binary as `aar` on `PATH`, verify it against `SHA256SUMS`,
then run:

```sh
aar doctor
```

The release binary is static, embeds the pinned Bash parser, and has no runtime
download or provider SDK dependency. The Reviewer never spawns the command it
checks.

## Install the Command Gate

Install the normal npm package and list it in OpenCode configuration:

```sh
npm install @supercode/command-gate@0.1.0
```

```jsonc
{
  "plugin": ["@supercode/command-gate"]
}
```

The package contains TypeScript source only. It does not embed, download, or
build `aar`; it resolves the binary from `gate.binaryPath` or `PATH`.

## Reviewer configuration

The Reviewer reads `$AAR_CONFIG`, then `$XDG_CONFIG_HOME/aar/config.toml`, then
the platform config path. A project `.aar.toml` overlays the selected global
file. This file owns assessor, policy, grants, and audit settings:

```toml
[assessor]
model = "provider/model-id"
fallbackModels = ["provider/fallback-model"]
baseUrl = "https://api.example.test/v1"
apiKeyEnv = "PROVIDER_API_KEY"
totalTimeoutMs = 5000
onUnavailable = "deny" # or "ask"

[assessor.options]
temperature = 0

[policy]
profile = "data-loss" # data-loss, balanced, or strict
protectedPaths = ["/important/data"]

[policy.categoryOverrides]
network = "inherit" # inherit, ignore, ask, or deny

[grants]
sessionTrust = true

[audit]
dir = "/path/to/aar-state"
```

`assessor.apiKeyEnv` names the environment variable holding the credential;
the key itself is never stored in configuration, requests, or audit records.
The default profile is `data-loss`, and the default unavailable action is
`deny`.

Inspect a stored audit record without exposing raw secret-like values:

```sh
aar explain --audit-id <AUDIT_ID>
```

Audit records classify outcomes as `deterministic`, `model`, `grant`, or
`failure`, and include the selected profile, assessor attempt metadata, and
redacted RiskAssessment evidence when one exists.

## Gate configuration

Gate settings live under the ordinary OpenCode `gate` object. Project settings
overlay global settings:

```jsonc
{
  "gate": {
    "binaryPath": "/home/me/.local/bin/aar",
    "tools": ["bash", "shell"],
    "timeoutMs": 5500,
    "commandRewriter": "none",
    "onReviewerFailure": "deny"
  }
}
```

Safe defaults are `bash` and `shell`, `commandRewriter: "none"`, and
`onReviewerFailure: "deny"`. A missing binary, failed `aar doctor`, unsupported
contract, invalid output, non-zero exit, or timeout produces a short actionable
diagnostic and denies the command. `passthrough` is available only when an
operator explicitly accepts unreviewed execution.

The Gate checks the exact `@opencode-ai/plugin` and `@opencode-ai/sdk`
`1.18.21` runtime contract. A missing or mismatched runtime is Gate
unavailability, never permission to execute.

## Recommended OpenCode permissions

Allow the Gate to make the fine-grained decision, and keep only a minimal native
deny backstop for the accepted fail-open boundary:

```jsonc
{
  "permission": {
    "bash": {
      "*": "allow",
      "mkfs*": "deny",
      "dd *": "deny",
      "shutdown *": "deny",
      "reboot*": "deny"
    }
  }
}
```

OpenCode permission rules are order-sensitive: the later matching rule wins,
so the narrow deny entries must follow the broad allow. Do not add broad native
`ask` rules such as `rm *`; they can fire after the Gate allows a command and
reintroduce approval fatigue.

## RTK coexistence

With `commandRewriter: "none"`, RTK is not required and the Gate behaves the
same when RTK is absent. With `commandRewriter: "rtk"`, the Gate invokes
`rtk rewrite` before `aar check`, reviews those exact bytes, and never rewrites
after the Decision. Empty, failed, or timed-out rewrites leave the original
command unchanged.

Remove RTK's own Bash-rewrite plugin from the global plugin directory before
using `commandRewriter: "rtk"`. Two rewriters on the same native tool are
unsafe regardless of plugin order.

## Coverage and failure boundary

The Gate covers model-issued `bash` and `shell` calls, including subagent
sessions. Human-typed `!command` input in the TUI bypasses
`tool.execute.before` by design; it is not claimed as covered. Other tools,
MCP tools, Code Mode, and unrelated plugins are outside this feature.

The interception design has an explicit fail-open boundary: if the plugin is
not loaded, native Bash may run without review. Startup diagnostics, the
denying Gate, and the minimal native deny list make that state loud but cannot
remove it. Feature 027 is the hard execution boundary for that requirement.

## Verification

Run the local package and reviewer checks:

```sh
npm test
npm run test:packaging
go test ./...
```

The real OpenCode integration harness covers deterministic read allow, Hard
Deny, model-derived allow and deny, allow-once and session grants, reviewer
outages, malformed output, schema mismatch, timeout, missing `aar`, both RTK
rewrite modes, and the no-RTK path. It uses only local fake services.

The frozen assessor smoke corpus is advisory and must be run with an explicit
model/configuration:

```sh
AAR_BINARY_PATH=/path/to/aar \
AAR_SMOKE_CONFIG=/path/to/aar/config.toml \
AAR_SMOKE_MODEL=provider/model-id \
AAR_SMOKE_API_KEY_ENV=PROVIDER_API_KEY \
npm run test:smoke
```
