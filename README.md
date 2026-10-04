# Command Gate V2

Native Bash review for OpenCode **2.0.22**, using the separate `aar` Command Reviewer. The **1.0.0** breaking release line is V2-only; the historical Gate **0.1.0** remains V1-only. No dual-API factory or runtime emulation is shipped. Release acceptance remains incomplete until the genuine human TUI smoke passes.

## Approval

The server owns location/session/message/call-bound pending requests. The TUI receives them through public RPC, not a model-visible tool. Its paginated summary shows a masked command preview, the highest-severity risk and its evidence, remaining risk/uncertainty counts, and canonical working directory. Full details presents every risk and uncertainty in readable form; Technical details holds identifiers, fingerprint and raw assessment JSON. Both details views may contain secrets. Actions are Deny, Allow once, eligible Trust exact for session, Full details and Technical details. Summary-page acknowledgement is **not** approval; dismissal refuses the call.

Only an explicit, matching human reply can create `aar grant --scope once` or `aar grant --scope session`. The server then performs fresh `aar check` and requires that exact grant before returning to the existing native executor. Once is consumed; session trust permits subsequent exact matches in the owning session, with fresh parse/facts/Hard Deny and no repeated assessor or approval. Changed command bytes, cwd, material paths/symlinks, scripts/dependencies, intent or policy cannot reuse the grant. Reviewer `grantEligible` controls the trust action; use a Reviewer that includes `grants.sessionTrust` in eligibility. Native permission deny remains authoritative. Neither RPC nor TUI executes commands or creates saved permission patterns.

Deny records `aar deny-note` and retains the exact denial in memory until intent/Goal changes. This remains authoritative if the CLI fails, a later assessor allows, or another command's failed approval resets Reviewer state. No working adapter, disconnect, expiry, cancellation, stale/duplicate reply or failed grant means no execution.

## Installation and migration from V1

Install the existing separate Reviewer binary for Linux amd64/arm64 or macOS amd64/arm64, verify its release checksum, and make `aar doctor` pass. The Gate neither embeds, builds nor downloads `aar`. Windows and non-Bash execution are unsupported. Reviewer policy/provider/profile/grant settings remain in the Reviewer configuration; plugin options below configure only the Gate.

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

| Server option | Default | Explicit environment override |
| --- | --- | --- |
| `binaryPath` | `aar` | `AAR_BINARY_PATH` |
| `tools` | `["bash", "shell"]` | `AAR_GATE_TOOLS` (comma-separated) |
| `timeoutMs` | `5500` | `AAR_GATE_TIMEOUT_MS` |
| `commandRewriter` | `none` | `AAR_GATE_COMMAND_REWRITER` |
| `rewriterPath` | `rtk` | `AAR_GATE_REWRITER_PATH` |
| `onReviewerFailure` | `deny` | `AAR_GATE_ON_REVIEWER_FAILURE` |

Explicit package options take precedence over environment overrides. `approvalTimeoutMs` is a server-only option, default `600000`. Invalid settings deny, including invalid settings combined with passthrough.

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
pnpm install --frozen-lockfile
pnpm compile
pnpm typecheck
pnpm format:check
pnpm test:package
pnpm test:all
AAR_PREBUILT=/absolute/path/to/existing/aar pnpm test:packed
AAR_PREBUILT=/absolute/path/to/existing/aar pnpm test:human:packed
```

`compile` emits server/TUI/RPC and excludes test sources; `prepack` regenerates compiled output. Build/runtime dependency pins were rechecked against registry.npmjs.org for host 2.0.22; its plugin package pins client 2.0.22 and Effect 4.0.0-rc.112. Solid is build-time/types-only: the host supplies its own runtime instance, and this dialog-only UI needs no JSX transform.

Packed tests use **native plugin add through a loopback registry** in isolated HOME/XDG/config, then activate the location and require package-source inventory, TUI discovery and working RPC. The registry proxies only dependency requests to npm. Installed JS is compared byte-for-byte against the extracted tarball; artifact integrity, exact host version, Reviewer SHA256, inventory, settings, audit and native effects are saved below `/tmp/opencode`. `AAR_PREBUILT` is required for packed checks, so the separate existing Reviewer is never built by that path. Workspace tests may build the Reviewer from `AAR_SOURCE`. Python 3 drives real target TUI actions/layout; these are automated regression evidence, **not human approval**.

Full commands serialize test files to bound installation/host resources. Boots within one packed run reuse its isolated dependency cache; the first boot proves cold native installation, later boots prove activation/reuse. The harness removes only that run-owned cache after servers stop, retaining tarball, extracted artifact, logs and installation evidence. Regenerate a live launcher by rerunning the human command rather than using a completed run's stale launcher.

TUI keymap registration must occur under the rendered app slot, not directly in plugin setup: setup has no host `Keymap.Provider`. The real-TUI diagnostics test covers this boundary.

The opt-in human command prints an isolated TUI launcher: inspect summary/details, manually Allow once twice for `human-once`, Trust exact for session for `human-session`, Deny for `human-deny`, then exit the temporary TUI. It must be run while the test server is alive; the harness stops its processes on completion/failure. Personal config/service/credentials are not connected or changed. Genuine human approval, macOS/arm64 execution and release-download checksum verification are not implied by Linux automated smoke. No publication, push, real installation or service restart is performed.
