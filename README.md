# Command Gate V2

Native Bash review for OpenCode **2.0.22**, using the existing `aar` Command Reviewer. This implementation supports automatic allow/deny and same-call **Deny / Allow once**. Session trust, full lifecycle handling, RTK composition and packed-release verification remain separate tickets.

## Approval

The server owns location/session/message/call-bound pending requests. The TUI receives them through public RPC, not a model-visible tool. It shows paginated effect summary, canonical cwd and masked preview, followed by Deny, Allow once and Full details. Full command and RiskAssessment may contain secrets and are revealed only in details. Summary-page acknowledgement is **not** approval; dismissal refuses the call.

Only an explicit, matching human reply can create `aar grant --scope once`. The server then performs fresh `aar check` and requires consumption of that exact once grant before returning to the existing native executor. Changed evidence, intent or Goal cannot reuse the reply. Native permission deny remains authoritative. Neither RPC nor TUI executes commands or creates saved permission patterns.

Deny records `aar deny-note` and retains the exact denial in memory until intent/Goal changes. This remains authoritative if the CLI fails, a later assessor allows, or another command's failed approval resets Reviewer state. No working adapter, disconnect, expiry, cancellation, stale/duplicate reply or failed grant means no execution.

## Local setup and options

```sh
pnpm install --frozen-lockfile
pnpm compile:tui
```

The root `tui.js` entry loads compiled JS from `dist/`; the UI uses the host's built-in dialogs and does not ship another Solid/OpenTUI renderer. Regenerate it after source changes. No raw npm TSX is loaded.

Configure the plugin directory in the V2 server `plugins` array, with options on the server entry:

```jsonc
{
  "plugins": [
    {
      "package": "/absolute/path/to/command-gate-v2",
      "options": {
        "binaryPath": "/absolute/path/to/aar",
        "timeoutMs": 5500,
        "approvalTimeoutMs": 600000,
      },
    },
  ],
}
```

The TUI half is discoverable through the server inventory; its operational settings come from server RPC, not duplicated client options. Isolated tests additionally register the same directory in their temporary `cli.json`. This slice is not a verified packed release; do not publish or change a personal service/config as part of testing it.

| Deadline            | Default    | Meaning                                                                                                                                |
| ------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `timeoutMs`         | 5,500 ms   | Each Reviewer CLI operation; must exceed the doctor-reported check deadline (normally 5,000 ms).                                       |
| `approvalTimeoutMs` | 600,000 ms | Separate finite human-wait deadline; positive server option. Expiration denies, never allows.                                          |
| TUI heartbeat       | 5,000 ms   | Reconcile list and renew the approval adapter lease.                                                                                   |
| Adapter lease       | 15,000 ms  | Missing renewals invalidate replies; pending waits detect lease loss within another 1,000 ms. Explicit disconnect refuses immediately. |

Reviewer reservation expiry still applies: a response arriving before the human deadline can nevertheless fail `aar grant` if the reservation has expired. First check in a server instance and changed intent/Goal reset Reviewer authorization state. Broader clear/deletion/reconnect lifecycle and session trust belong to ticket 04; failure/concurrency stress and bounded long-lived state belong to 05.

**Supported composition:** native Bash tool execution with the Gate wrapper intact and no later material command/cwd/env/shell mutator. Human `!command` bypasses review; non-shell tools are untouched. Background mode and non-Bash shells refuse. A missing/disabled/unloaded Gate does not protect the host's shell.

## Verification

```sh
pnpm typecheck
pnpm format:check
pnpm test
pnpm test:seam
pnpm test:approval
node --test test/tui-layout.test.mjs
GATE_HUMAN=1 node --test test/human.test.mjs
```

Integration tests use an isolated real target host, real `aar`, loopback fake model/assessor, temporary HOME/XDG/config and marker effects. Artifacts are printed below `/tmp/opencode`; personal configuration and service are untouched. Python 3 drives the 64×24 PTY layout regression and never approves execution. The separate human test prints a launcher: inspect summary/details, manually Allow once for `human-once`, Deny for `human-deny`, then exit the temporary TUI. Automated replies and PTY input are not human-approval evidence.
