# Command Gate V2 public-contract proof

Disposable proof for ticket `../docs/.scratch/issues/01-v2-contract-proof.md`, not a production Gate. Target: OpenCode **2.0.22** only. Do not install this plugin into a personal service: it intentionally contains observational bypasses and late-mutator fixtures.

## Reproduce

Requirements: target OpenCode binary, Node, Go, Python 3, pnpm, and the existing Reviewer source. Dependencies are exact-pinned in `package.json` and `pnpm-lock.yaml`; installation and live/TUI checks require operator approval.

From this directory:

```sh
pnpm install --frozen-lockfile
pnpm typecheck
pnpm format:check
PROOF_HUMAN=1 pnpm test
```

`OPENCODE_BIN` overrides `/home/glaicer/.opencode/bin/opencode`; `AAR_SOURCE` overrides the sibling `auto-approval-reviewer` source path. `PROOF_ROOT` must name a **new**, nonexistent directory below `/tmp/opencode`; otherwise the driver creates one automatically. The driver compiles the real `aar` there, never modifies Reviewer sources, and records their commit.

At the printed `Human TUI:` instruction, run the generated launcher in a separate real terminal. Run `/proof-approve`, inspect the effect/cwd/session/call/command/fingerprint dialog, close the details dialog, and select **Allow once** in the action dialog. Confirm that Deny and Trust exact for session are also visible. **Exit the test TUI before lifecycle smoke can start**: the launcher records an exit notice and the driver waits for it. Otherwise a still-open client hot-reloads the temporary smoke options and runs an additional clear. The suite explicitly fails if the human scenario or human response is absent; an HTTP reply is not a substitute for this observation. The approval wait deadline is ten minutes; expiration denies. Client-close wait is also finite and fails the run if it expires.

An unattended subset, intentionally excluding human UI evidence:

```sh
node --test --test-skip-pattern='human TUI' contract.test.mjs
```

The driver uses an allowlisted child environment with fresh HOME, XDG directories, OPENCODE_CONFIG_DIR, DB and Reviewer state. Only dummy loopback provider credentials are supplied. It checks activated inventory before running cases. Own servers/providers are stopped in `finally`; PTY smoke terminates its own TUI. Nothing changes user config or restarts the personal service.

## Chosen public binding

- Effect `Plugin.define({ effect })`; `ctx.tool.hook("execute.before")` receives `{ tool, input, sessionID, messageID, id }` and permits typed `Tool.Error` denial. The scanner-empty denial is deliberately an error-channel fixture, not a fabricated normal Reviewer Decision.
- `ctx.tool.transform` wraps **the existing native** `shell.execute(input, call)`, providing an Effect `Context.Reference` with call identity. It does not implement shell execution. Native shell creation inherits that reference.
- `ctx.shell.hook("create.before")` receives `{ command, cwd, env, shell, timeout }`, but no direct session/call identity. The inherited reference supplies identity; `realpathSync(cwd)` supplies canonical cwd. Non-default workdir/session HOME/CDPATH and Bash are observed against native marker output, and actual facts go through real `aar check`.
- Shell hooks have an infallible callback channel. A deliberate `Effect.die(Tool.Error)` is converted to typed failure by the public native-executor wrapper. Real assessor denial proves a curated model-facing error before command substitution and continued session execution. This is not evidence that an ordinary Promise throw has equivalent behavior.
- For Reviewer ask, the shell-before hook waits on custom public RPC. TUI `Plugin.define({ setup })`, `ctx.client.rpc(Proof)` and public dialogs deliver the actual human response. Server calls real `aar grant`, then fresh `aar check`, then returns to the same native invocation. No model reissue or Runner is involved.
- RPC 2.0.22 needs explicit `events: {}` and an input schema even for the no-argument list method. RPC is location-scoped; schemas here are deliberately minimal proof schemas, not production validation.
- `ctx.session.hook("prompt")` observes public user admissions, including plugin `ctx.session.prompt`. Per the accepted 2026-10-03 policy, all such admissions count as human intent; no provenance inference is attempted. Separate synthetic/compaction/tool output do not replace admitted text.
- `ctx.session.get` exposes location, `parentID` and metadata. Active Goal is reconciled before each check. Child ownership, inherited parent intent, parent-triggered child invalidation and foreign-location refusal are exercised separately.
- `/clear` has no required invented server event: a public TUI keymap layer bridges the native clear command to RPC invalidation, then temporarily withdraws its override while redispatching native clear. The smoke asserts exactly one report and a native transition to home. Public keymap command `run` dispatches by ID; calling it while the override remains installed recursively invokes the bridge. The entire app-slot setup is untracked to prevent reactive registration feedback.
- Public `ctx.event.subscribe()` supplies `session.deleted` with `data.sessionID` and **without location** in the live envelope. Previously reconciled session IDs establish ownership; the stream invalidates only owned sessions. Turn idle is not deletion.
- Restart/reload use first-check reset, not unload cleanup. Distinct real TUI connect IDs trigger conservative reset. Lost admitted text stays explicitly null, never reconstructed from summaries. A public native interrupt aborts the Effect-backed wait, removes pending state and prevents execution/grant.

## Evidence and limits

Each run retains `results.json`, `events.jsonl`, `openapi.json`, `provider-requests.json`, `server.log`, isolated host logs and TUI PTY captures in the printed proof root. Assertions cover:

| Case | Required external observation |
| --- | --- |
| Assessor/tool-before deny and scanner-empty typed denial | No marker/substitution, curated tool error, model receives result and finishes |
| Effective shell-before assessor deny | No substitution marker, model-facing error through the native wrapper, session finishes |
| Auto-allow/assessor allow | Real Reviewer source, one model shell call, one native shell-before observation, expected marker/output |
| Effective invocation | Non-default canonical cwd, session HOME/CDPATH/PROOF_ENV, Bash and owning call agree with native output |
| Human Allow once | Real TUI response → real grant → fresh Reviewer grant hit → one native continuation |
| Native interruption | Pending ask observed, wait cancelled, no marker/fresh check/human reply |
| Idle/synthetic/compaction | Seeded real session grant and admitted Verbatim text preserved |
| Admission/plugin admission/Goal/clear/reconnect/reload/restart/end | Seeded grant becomes real assessor ask; clear native route becomes home |
| Parent/child/two locations | Parent grant not shared, child inherited intent explicit, changed parent intent invalidates child, foreign location refused |
| Late tool/shell mutators | Different execution marker proves the composition is **unsupported**, not integrity-safe |
| Human shell API | Native marker executes without bound tool identity or Reviewer review |

Lifecycle grants are explicitly seeded through a real reserved ask and CLI `aar grant --scope session` as test preconditions. They are **not** claimed to be human UI approvals. The one actual human UI case independently proves that exchange.

The supported composition is Bash native tool execution with the public wrapper intact and **no later material command/cwd/env/shell mutator**. The deliberately injected late-mutator fixtures execute changed bytes; they expose a limitation, not a successful safety path. Plugin-list order alone does not prove finality. RTK compatibility, configured native deny, full cancellation/failure/concurrency stress, exact-session UI behavior, masking/expandable production details, packaging and operational diagnostics remain downstream work. The human shell HTTP endpoint proves the server path used for the accepted `!command` bypass, not independent evidence of typing `!command` in the TUI. Public `parentID` fixtures prove child binding, not that every built-in subagent dispatch form is covered.

The proof does not port complete Gate logic or reimplement Reviewer policy. Source-only v2.0.16 findings and earlier v2.0.22 audit fixtures are background, **not** fresh proof results. The prior regression baseline was 202 Go Reviewer/CLI tests and 36 Gate/packaging tests; Reviewer/V1 files remain unchanged.

## Latest verification

**2026-10-03: PASS — 9/9**, including the genuine human TUI Allow once and all lifecycle checks. Runtime 2.0.22; Reviewer source commit `a8baa2245b2932fe22cba212fe9b99dc575aee26`. Full artifacts: `/tmp/opencode/command-gate-final-02/results.json` and sibling traces/OpenAPI/logs/captures. The user confirmed the details and three actions, selected Allow once, and exited the test TUI; the driver observed its exit notice. No own server/provider/TUI process remained afterward. Typecheck, Prettier, JS/Python syntax checks and `git diff --check` passed.

Standards review: zero hard violations; one optional duplicated-subprocess-helper smell, left alone for this disposable proof. Spec review: its only blocker was pending final human verification, now resolved by the full run; the client-exit barrier received a separate follow-up review with no substantive issue.

Failed runs are not hidden: `/tmp/opencode/command-gate-final-01` passed human approval but failed 8/9 because the still-open human TUI hot-reloaded smoke options and produced a second native-clear report. Waiting for launcher exit fixes that harness isolation bug without weakening the single-clear assertion. `/tmp/opencode/command-gate-proof-4T7W35` passed the eight unattended assertions only; earlier `/tmp/opencode/command-gate-human-04` predates lifecycle fixes. Ticket01 is proven under the conditions above; no downstream production implementation was started. Per operator choice, ignored local spec/tickets are not part of the proof commit.
