# Command Gate V2

Native Bash review for OpenCode **2.0.22**, using the existing `aar` Command Reviewer. This implementation supports automatic allow/deny, optional pre-review RTK rewriting and same-call **Deny / Allow once / Trust exact for session**, with failure/cancellation/concurrency and invocation-integrity regression coverage. Packed-release verification remains a separate ticket.

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

Reviewer reservation expiry still applies: a response arriving before the human deadline can nevertheless fail `aar grant` if the reservation has expired. Grants remain in the Reviewer-owned state directory; the Gate does not add a grant store.

## Failures and cancellation

The default `onReviewerFailure: "deny"` keeps interception loaded when doctor is unhealthy or the binary is missing/incompatible. Invalid options always deny. Explicit `"passthrough"` permits operational Reviewer failures only, labelled **UNREVIEWED** in server diagnostics and a TUI warning fetched through public status RPC. Reviewer deny/ask, stale context, failed approval/grant, native deny, unsupported Bash/background invocation and invalid configuration never become passthrough.

Gate-owned Reviewer and RTK operations are deadline-bound. On cancellation/deadline, POSIX subprocess groups receive SIGKILL (including descendants); the Effect finalizer joins subprocess close before releasing review state. Native command execution and its supervision remain entirely with OpenCode. Unload interrupts the wrapped native Effect, including pre-spawn permission waits; any already-running native process is cancelled by host supervision, never by a Gate spawner. Pending human waits remove timers/abort listeners on every terminal response, and plugin unload closes them and signals outstanding reviews. Captured old tool wrappers refuse after unload instead of executing without their removed shell hook. Restart/reload still resets persisted trust before first review.

**Accepted fail-open gap:** an absent, disabled or failed-to-load plugin cannot intercept native commands. Inventory alone does not prove protection; inspect doctor/operational diagnostics. This is distinct from a loaded-but-unhealthy Gate, which denies by default.

Same-session reviews and once consumption use a per-session permit over existing Reviewer locking. Invalidation advances context generation before resetting Reviewer state; reconciliation after review/grant refuses stale authorization. Main/child sessions and locations retain independent approval identities. RPC notifications are hints, not consent: list/get reconciliation and explicit matching replies are required.

## Intent and lifecycle

Every public user admission, including plugin/subagent `session.prompt`, is authoritative. The Gate reconciles typed admitted messages and durable inbox events; an early prompt hook invalidates trust but does not supply the final text. Synthetic continuation, compaction summaries and tool output never become admitted user text. Child sessions inherit available parent intent until their own admission; grants still belong only to the owning session/location.

New admission, canonical Goal replacement/clear, native `/clear` and session deletion invalidate grants, pending approvals and deny suppression. Parent changes conservatively invalidate known descendants. Native `/clear` uses a public TUI keymap bridge: Reviewer invalidation must succeed before dispatching the native command; an unavailable bridge disables the approval adapter. Tab close and turn idle do not end the session. Server restart/location reload resets persisted Reviewer authorization before first review; a new or expired client connection conservatively resets known sessions. Live-event notifications are not the sole source of authorization: context generation is reconciled before review, reply and continuation.

## RTK and invocation integrity

Server options `commandRewriter: "none" | "rtk"` (default `"none"`) and `rewriterPath` (default `"rtk"`) also accept `AAR_GATE_COMMAND_REWRITER` and `AAR_GATE_REWRITER_PATH`; explicit options win. RTK is a trusted optimizer, not a safety dependency. Gate invokes the binary as `rtk rewrite <whole-command>` with `shell: false`, actual cwd and an allowlisted optimizer environment (PATH/HOME/PWD, no provider keys or session secrets). It never executes the submitted command during rewriting. Successful non-empty trimmed stdout becomes the Verbatim review subject and native command. Missing RTK, empty output, non-zero exit, oversized output or deadline failure keep the original command and still require the ordinary Reviewer Decision. Cancellation stops the call, not a fallback execution.

**Installation requirements:** disable every other RTK/rewrite plugin for covered native tools; Gate alone owns their rewrite. Keep its native execute wrapper intact. Tool-input edits before that wrapper and shell edits before Gate's shell review are reviewed as final facts, not as the model's initial arguments. Actual canonical cwd, session material env (HOME/CDPATH/PWD when present) and Bash come from shell creation, not the plugin process environment. The checked native composition retains the host's permission checks, scanner, streaming and executor.

After review, Gate guards the same shell invocation's command/cwd/shell/env properties and a copied environment against controlled late mutations. Changed writes refuse before start with a model-facing error rather than reuse allow. The host may reassign identical top-level properties, canonicalize cwd to the already-reviewed canonical directory, and add its four native metadata values (`AGENT=1`, `OPENCODE=1`, default `AI_AGENT=opencode`, owning `OPENCODE_SESSION_ID`); these are not material Reviewer facts. Other env-property writes refuse even when assigning the existing value. The guards also apply to explicit UNREVIEWED passthrough. Background is checked both in tool-before and at wrapped native execute, so a later tool-before hook cannot enable it.

**Unsupported composition:** late shell command/cwd/env/shell mutators, second RTK rewrite, removal/replacement of the Gate wrapper, custom executors, and plugins that replace the hook payload, suppress guard failures or dispatch outside the native tool seam. Known late mutation fixtures refuse; arbitrary malicious/unknown plugin compositions are not contained or proven safe. Configured list order alone is not proof of registration order or compatibility: validate a new composition with native marker/output traces. No claim that Gate is always the final hook is made.

Reviewer remains Bash-only; sh/zsh/fish/PowerShell and explicit native background mode refuse before start, without changing the selected shell after allow. Background syntax and hidden long-lived effects inside a program remain existing Reviewer policy, not a new Gate parser or containment guarantee. Human `!command` is neither reviewed nor rewritten (tests exercise its server shell API, not typed TUI input). Non-shell tools, MCP, arbitrary Code Mode code and other plugin processes are outside coverage. Child native shell calls are covered at the proven common seam; not every nested dispatch form has been demonstrated.

## Verification

```sh
pnpm typecheck
pnpm format:check
pnpm test
pnpm test:seam
pnpm test:approval
node --test test/lifecycle.test.mjs test/tui-actions.test.mjs
node --test test/tui-layout.test.mjs
node --test test/failures.test.mjs test/cancellation.test.mjs test/concurrency.test.mjs
node --test test/rtk.test.mjs test/integrity.test.mjs
GATE_HUMAN=1 node --test test/human.test.mjs
```

Integration tests use an isolated real target host, real `aar`, loopback fake model/assessor, temporary HOME/XDG/config and marker effects. Artifacts are printed below `/tmp/opencode`; personal configuration and service are untouched. Python 3 drives the 64×24 PTY layout regression without approving execution. The separate automated TUI-actions test presses once/session/deny actions and checks real native effects; it is **not human-approval evidence**. The opt-in human test prints a launcher: inspect summary/details, manually Allow once twice for `human-once`, Trust exact for session for `human-session`, Deny for `human-deny`, then exit the temporary TUI. Automated replies and PTY input are not human-approval evidence.
