# Command Gate V2

Native Bash review for OpenCode **2.0.22**, using the existing `aar` Command Reviewer. This implementation supports automatic allow/deny and same-call **Deny / Allow once / Trust exact for session**. Failure/concurrency stress, RTK composition and packed-release verification remain separate tickets.

## Approval

The server owns location/session/message/call-bound pending requests. The TUI receives them through public RPC, not a model-visible tool. It shows paginated effect summary, canonical cwd and masked preview, followed by Deny, Allow once, eligible Trust exact for session, and Full details. Full command and RiskAssessment may contain secrets and are revealed only in details. Summary-page acknowledgement is **not** approval; dismissal refuses the call.

Only an explicit, matching human reply can create `aar grant --scope once` or `aar grant --scope session`. The server then performs fresh `aar check` and requires that exact grant before returning to the existing native executor. Once is consumed; session trust permits subsequent exact matches in the owning session, with fresh parse/facts/Hard Deny and no repeated assessor or approval. Changed command bytes, cwd, material paths/symlinks, scripts/dependencies, intent or policy cannot reuse the grant. Reviewer `grantEligible` controls the trust action; use a Reviewer that includes `grants.sessionTrust` in eligibility. Native permission deny remains authoritative. Neither RPC nor TUI executes commands or creates saved permission patterns.

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

Reviewer reservation expiry still applies: a response arriving before the human deadline can nevertheless fail `aar grant` if the reservation has expired. Grants remain in the Reviewer-owned state directory; the Gate does not add a grant store. Failure/concurrency stress and bounded long-lived state belong to ticket 05.

## Intent and lifecycle

Every public user admission, including plugin/subagent `session.prompt`, is authoritative. The Gate reconciles typed admitted messages and durable inbox events; an early prompt hook invalidates trust but does not supply the final text. Synthetic continuation, compaction summaries and tool output never become admitted user text. Child sessions inherit available parent intent until their own admission; grants still belong only to the owning session/location.

New admission, canonical Goal replacement/clear, native `/clear` and session deletion invalidate grants, pending approvals and deny suppression. Parent changes conservatively invalidate known descendants. Native `/clear` uses a public TUI keymap bridge: Reviewer invalidation must succeed before dispatching the native command; an unavailable bridge disables the approval adapter. Tab close and turn idle do not end the session. Server restart/location reload resets persisted Reviewer authorization before first review; a new or expired client connection conservatively resets known sessions. Live-event notifications are not the sole source of authorization: context generation is reconciled before review, reply and continuation.

**Supported composition:** native Bash tool execution with the Gate wrapper intact and no later material command/cwd/env/shell mutator. Human `!command` bypasses review; non-shell tools are untouched. Background mode and non-Bash shells refuse. A missing/disabled/unloaded Gate does not protect the host's shell.

## Verification

```sh
pnpm typecheck
pnpm format:check
pnpm test
pnpm test:seam
pnpm test:approval
node --test test/lifecycle.test.mjs test/tui-actions.test.mjs
node --test test/tui-layout.test.mjs
GATE_HUMAN=1 node --test test/human.test.mjs
```

Integration tests use an isolated real target host, real `aar`, loopback fake model/assessor, temporary HOME/XDG/config and marker effects. Artifacts are printed below `/tmp/opencode`; personal configuration and service are untouched. Python 3 drives the 64×24 PTY layout regression without approving execution. The separate automated TUI-actions test presses once/session/deny actions and checks real native effects; it is **not human-approval evidence**. The opt-in human test prints a launcher: inspect summary/details, manually Allow once twice for `human-once`, Trust exact for session for `human-session`, Deny for `human-deny`, then exit the temporary TUI. Automated replies and PTY input are not human-approval evidence.
