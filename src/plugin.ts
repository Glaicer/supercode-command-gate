import path from "node:path";
import { createHash } from "node:crypto";
import { Context, Effect, Semaphore } from "effect";
import { Plugin } from "@opencode/plugin/effect";
import { Error as ToolError } from "@opencode/plugin/promise/tool";
import type { ShellCreateBefore } from "@opencode/plugin/effect/shell";
import { resolveConfig } from "./config.ts";
import {
  blockedMessage,
  errorMessage,
  startupDiagnostic,
  unavailableReason,
} from "./messages.ts";
import { buildRequest, type Request } from "./request.ts";
import {
  callAction,
  callCheck,
  callDoctor,
  fingerprintFor,
  normalizeDoctorResult,
  validateDecision,
  type Decision,
  type StartupStatus,
} from "./reviewer.ts";
import {
  GateState,
  goalFromMetadata,
  type AuthorizingRecord,
  type CallIdentity,
} from "./state.ts";
import { ApprovalQueue, type ApprovalReply } from "./approval.ts";
import { Approvals } from "./rpc.ts";

const BoundCallRef = Context.Reference<CallIdentity | null>(
  "command-gate/call",
  { defaultValue: () => null },
);

type ReviewOutcome =
  | { kind: "allow"; request: Request; decision: Decision }
  | { kind: "deny"; message: string };

const deny = (reason: string): ReviewOutcome => ({
  kind: "deny",
  message: blockedMessage(reason),
});
const allow = (request: Request, decision: Decision): ReviewOutcome => ({
  kind: "allow",
  request,
  decision,
});

type Attempt<A> = { ok: true; value: A } | { ok: false; reason: string };

const attempt = <A>(
  effect: Effect.Effect<A, unknown>,
): Effect.Effect<Attempt<A>> =>
  effect.pipe(
    Effect.map((value): Attempt<A> => ({ ok: true, value })),
    Effect.catch((error) =>
      Effect.succeed({ ok: false as const, reason: errorMessage(error) }),
    ),
    Effect.catchDefect((defect) =>
      Effect.succeed({ ok: false as const, reason: errorMessage(defect) }),
    ),
  );

const attemptPromise = <A>(
  try_: (signal: AbortSignal) => PromiseLike<A>,
): Effect.Effect<Attempt<A>> =>
  attempt(
    Effect.tryPromise({
      try: try_,
      catch: (error): string => errorMessage(error),
    }),
  );

const startupFailure = (reason: string): StartupStatus => ({
  ok: false,
  reason,
});

export default Plugin.define({
  id: "command-gate",
  effect: (ctx) =>
    Effect.gen(function* () {
      const config = resolveConfig(ctx.options);
      const state = new GateState();
      const log = (kind: string, detail: Record<string, unknown>) =>
        console.log(`[command-gate] ${kind} ${JSON.stringify(detail)}`);

      const startup: StartupStatus = yield* Effect.gen(function* () {
        if (config.configError) {
          return startupFailure(
            `invalid gate configuration (${config.configError})`,
          );
        }
        const report = yield* attemptPromise((signal) =>
          callDoctor(
            config.binaryPath,
            ctx.location.directory,
            ctx.location.directory,
            config.timeoutMs,
            signal,
          ),
        );
        if (!report.ok)
          return startupFailure(`aar doctor failed (${report.reason})`);
        return normalizeDoctorResult(report.value, config.timeoutMs);
      });
      if (startup.ok)
        log("doctor-ok", { reviewerTimeoutMs: startup.reviewerTimeoutMs });
      else
        console.error(
          `[command-gate] startup-unavailable ${JSON.stringify({ reason: startup.reason, message: startupDiagnostic(startup.reason) })}`,
        );

      let changed = false;
      const approvals = new ApprovalQueue(() => {
        changed = true;
      });
      const locks = new Map<string, Semaphore.Semaphore>();
      const contexts = new Map<string, string>();
      const deniedResponses = new Map<
        string,
        { generation: string; fingerprints: Set<string> }
      >();
      const contextFor = (sessionID: string) =>
        Effect.gen(function* () {
          const info = yield* ctx.session.get({ sessionID } as Parameters<
            typeof ctx.session.get
          >[0]);
          if (info.location.directory !== ctx.location.directory)
            throw new Error("owning session belongs to a different location");
          const intent = state.intentFor(sessionID, info.parentID);
          const goal = goalFromMetadata(info.metadata);
          const generation = createHash("sha256")
            .update(
              JSON.stringify({
                intent: intent ?? null,
                goal: info.metadata?.goal ?? null,
                parentID: info.parentID ?? null,
              }),
            )
            .digest("hex");
          return { intent, goal, generation };
        });
      const registration = yield* ctx.rpc
        .register(Approvals, {
          connect: (input) =>
            Effect.sync(() => {
              const clientID = (input as { clientID: string }).clientID;
              if (approvals.connect(clientID))
                log("approval-client", { clientID });
              return { connected: true };
            }),
          disconnect: (input) =>
            Effect.sync(() => {
              approvals.disconnect((input as { clientID: string }).clientID);
              return { disconnected: true };
            }),
          list: (input) =>
            Effect.sync(() => {
              const { clientID, sessionID } = input as {
                clientID: string;
                sessionID?: string;
              };
              return approvals.list(clientID, sessionID);
            }),
          get: (input) =>
            Effect.sync(() => {
              const { clientID, pendingID } = input as {
                clientID: string;
                pendingID: string;
              };
              return approvals.get(clientID, pendingID);
            }),
          reply: (input) =>
            Effect.gen(function* () {
              const reply = input as ApprovalReply;
              const pending = approvals.get(reply.clientID, reply.pendingID);
              if (!pending) return { accepted: false };
              const current = yield* attempt(contextFor(pending.sessionID));
              if (
                !current.ok ||
                current.value.generation !== pending.intentGeneration
              ) {
                approvals.cancel(pending.pendingID);
                return { accepted: false };
              }
              const accepted = approvals.reply(reply);
              if (accepted && reply.decision === "deny") {
                const previous = deniedResponses.get(pending.sessionID);
                const denial =
                  previous?.generation === pending.intentGeneration
                    ? previous
                    : {
                        generation: pending.intentGeneration,
                        fingerprints: new Set<string>(),
                      };
                denial.fingerprints.add(pending.fingerprint);
                deniedResponses.set(pending.sessionID, denial);
              }
              if (accepted)
                log("human-response", {
                  session: pending.sessionID,
                  call: pending.callID,
                  decision: reply.decision,
                  pendingID: pending.pendingID,
                  clientID: reply.clientID,
                });
              return { accepted };
            }),
        })
        .pipe(Effect.orDie);
      yield* Effect.forkScoped(
        Effect.gen(function* () {
          while (true) {
            if (changed) {
              changed = false;
              yield* registration.events
                .emit("changed", {})
                .pipe(Effect.ignore);
            }
            yield* Effect.sleep("1 second");
          }
        }),
      );
      yield* Effect.addFinalizer(() => Effect.sync(() => approvals.close()));

      const reviewInvocation = (
        invocation: ShellCreateBefore,
        call: CallIdentity,
      ) =>
        Effect.gen(function* () {
          if (
            typeof invocation.command !== "string" ||
            invocation.command === ""
          ) {
            return deny(
              "the shell invocation did not provide a command string",
            );
          }
          if (path.basename(invocation.shell).toLowerCase() !== "bash") {
            return deny(
              `unsupported shell ${invocation.shell}; Command Gate reviews Bash only`,
            );
          }
          const prior: AuthorizingRecord | null = state.claim({
            ...call,
            command: invocation.command,
            cwd: invocation.cwd,
            shell: invocation.shell,
            intentId: null,
          });
          if (prior) {
            return deny(
              "this tool call already started a reviewed shell command; only one invocation per call is allowed",
            );
          }
          const release = () => state.release(call);
          const session = yield* attempt(
            ctx.session.get({ sessionID: call.sessionID } as Parameters<
              typeof ctx.session.get
            >[0]),
          );
          if (!session.ok) {
            release();
            return deny("the owning session could not be resolved");
          }
          const info = session.value;
          if (info.location.directory !== call.location) {
            release();
            return deny(
              "the owning session belongs to a different location; this Gate refuses the invocation",
            );
          }
          const intent = state.intentFor(call.sessionID, info.parentID);
          const goal = goalFromMetadata(info.metadata);
          let request: Request;
          try {
            request = buildRequest(
              {
                command: invocation.command,
                cwd: invocation.cwd,
                env: invocation.env,
              },
              {
                sessionID: call.sessionID,
                intentId: intent?.id ?? null,
                goal,
                latestUserRequest: intent?.text ?? null,
              },
              ctx.location.directory,
            );
          } catch (error) {
            release();
            return deny(
              `the actual working directory could not be resolved (${errorMessage(error)})`,
            );
          }
          let grantMayExist = false;
          yield* Effect.addFinalizer(() =>
            Effect.gen(function* () {
              if (!grantMayExist) return;
              contexts.delete(call.sessionID);
              yield* attemptPromise((signal) =>
                callAction(
                  config.binaryPath,
                  request,
                  "session-event",
                  ["--event", "clear"],
                  config.timeoutMs,
                  signal,
                ),
              );
            }),
          );
          const evidence = {
            session: call.sessionID,
            call: call.callID,
            command: request.command,
            cwd: request.cwd,
            env: request.env,
            intentId: request.session.intentId,
            goal: request.intent.goal,
          };
          if (!startup.ok) {
            release();
            log("review-deny", { ...evidence, reason: startup.reason });
            return deny(unavailableReason(startup.reason));
          }
          const currentContext = yield* attempt(contextFor(call.sessionID));
          if (!currentContext.ok)
            return deny("approval context could not be reconciled");
          const generation = currentContext.value.generation;
          if (
            (currentContext.value.intent?.id ?? "") !==
              request.session.intentId ||
            currentContext.value.goal !== request.intent.goal
          )
            return deny("intent changed before review");
          if (deniedResponses.get(call.sessionID)?.generation !== generation)
            deniedResponses.delete(call.sessionID);
          if (contexts.get(call.sessionID) !== generation) {
            const reset = yield* attemptPromise((signal) =>
              callAction(
                config.binaryPath,
                request,
                "session-event",
                ["--event", "new-intent"],
                config.timeoutMs,
                signal,
              ),
            );
            if (!reset.ok)
              return deny(`approval context reset failed (${reset.reason})`);
            contexts.set(call.sessionID, generation);
          }
          const checked = yield* attemptPromise((signal) =>
            callCheck(config.binaryPath, request, config.timeoutMs, signal),
          );
          if (!checked.ok) {
            release();
            log("review-deny", { ...evidence, reason: checked.reason });
            return deny(
              `the Command Reviewer was unavailable (${checked.reason})`,
            );
          }
          let decision: Decision;
          try {
            decision = validateDecision(checked.value, request);
          } catch (error) {
            release();
            const reason = errorMessage(error);
            log("review-deny", { ...evidence, reason });
            return deny(
              `the Command Reviewer returned an invalid decision (${reason})`,
            );
          }
          const fingerprint = fingerprintFor(request);
          if (
            deniedResponses
              .get(call.sessionID)
              ?.fingerprints.has(decision.requestFingerprint)
          ) {
            const reason =
              "human approval was denied for this exact command; a new intent is required";
            log("review-deny", {
              ...evidence,
              source: decision.source,
              reason,
              fingerprint,
            });
            return deny(reason);
          }
          if (decision.decision === "allow") {
            log("review-allow", {
              ...evidence,
              source: decision.source,
              auditId: decision.auditId,
              fingerprint,
            });
            return allow(request, decision);
          }
          if (decision.decision === "ask") {
            log("approval-ask", {
              ...evidence,
              source: decision.source,
              reason: decision.reason,
              fingerprint: decision.requestFingerprint,
            });
            const response = yield* attemptPromise((signal) =>
              approvals.wait(
                call,
                request,
                decision,
                generation,
                config.approvalTimeoutMs,
                signal,
              ),
            );
            if (!response.ok || response.value !== "once") {
              if (response.ok && response.value === "deny") {
                const noted = yield* attemptPromise((signal) =>
                  callAction(
                    config.binaryPath,
                    request,
                    "deny-note",
                    ["--fingerprint", decision.requestFingerprint],
                    config.timeoutMs,
                    signal,
                  ),
                );
                if (!noted.ok)
                  log("approval-deny-note-failed", {
                    session: call.sessionID,
                    reason: noted.reason,
                  });
              }
              return deny(
                `this command requires human approval; approval ${response.ok ? response.value : "failed"}`,
              );
            }
            const reconcile = () =>
              Effect.gen(function* () {
                const current = yield* contextFor(call.sessionID);
                const fresh = buildRequest(
                  invocation,
                  {
                    sessionID: call.sessionID,
                    intentId: current.intent?.id ?? null,
                    goal: current.goal,
                    latestUserRequest: current.intent?.text ?? null,
                  },
                  ctx.location.directory,
                );
                if (
                  current.generation !== generation ||
                  JSON.stringify(fresh) !== JSON.stringify(request) ||
                  path.basename(invocation.shell).toLowerCase() !== "bash"
                )
                  throw new Error(
                    "invocation or intent changed during approval",
                  );
                return fresh;
              });
            const live = yield* attempt(reconcile());
            if (!live.ok) return deny(live.reason);
            grantMayExist = true;
            const granted = yield* attemptPromise((signal) =>
              callAction(
                config.binaryPath,
                live.value,
                "grant",
                [
                  "--fingerprint",
                  decision.requestFingerprint,
                  "--scope",
                  "once",
                ],
                config.timeoutMs,
                signal,
              ),
            );
            if (!granted.ok)
              return deny(
                `Allow once could not be recorded (${granted.reason})`,
              );
            const fresh = yield* attemptPromise((signal) =>
              callCheck(
                config.binaryPath,
                live.value,
                config.timeoutMs,
                signal,
              ),
            );
            const reconciled = yield* attempt(reconcile());
            let reviewed: Decision | null = null;
            if (fresh.ok) {
              try {
                reviewed = validateDecision(fresh.value, live.value);
              } catch {}
            }
            if (reviewed)
              log("approval-fresh", {
                ...evidence,
                source: reviewed.source,
                decision: reviewed.decision,
                fingerprint: reviewed.requestFingerprint,
              });
            if (
              !reconciled.ok ||
              !reviewed ||
              reviewed.decision !== "allow" ||
              reviewed.source !== "grant" ||
              reviewed.grantScope !== "once" ||
              reviewed.requestFingerprint !== decision.requestFingerprint
            ) {
              return deny(
                !reconciled.ok
                  ? reconciled.reason
                  : (reviewed?.reason ??
                      "fresh review did not consume the matching once grant"),
              );
            }
            grantMayExist = false;
            return allow(live.value, reviewed);
          }
          release();
          log("review-deny", {
            ...evidence,
            source: decision.source,
            auditId: decision.auditId,
            fingerprint,
            reason: decision.reason,
          });
          return deny(decision.reason || "the command was not proven safe");
        }).pipe(
          Effect.scoped,
          Effect.catchDefect((defect) =>
            Effect.succeed(deny(unavailableReason(errorMessage(defect)))),
          ),
        );

      yield* ctx.tool.transform((editor) => {
        for (const item of editor.list()) {
          if (!config.tools.includes(item.name.toLowerCase())) continue;
          editor.update(item.id, (tool) => {
            const execute = tool.execute;
            tool.execute = (input, call) =>
              execute(input, call).pipe(
                Effect.provideService(BoundCallRef, {
                  location: ctx.location.directory,
                  sessionID: call.sessionID,
                  messageID: call.messageID,
                  callID: call.id,
                }),
                Effect.catchCause((cause) => {
                  const denial = cause.reasons.find(
                    (reason) =>
                      reason._tag === "Die" &&
                      reason.defect instanceof ToolError,
                  );
                  return denial && denial._tag === "Die"
                    ? Effect.fail(denial.defect as ToolError)
                    : Effect.failCause(cause);
                }),
                Effect.onExit(() =>
                  Effect.sync(() =>
                    state.release({
                      location: ctx.location.directory,
                      sessionID: call.sessionID,
                      messageID: call.messageID,
                      callID: call.id,
                    }),
                  ),
                ),
              );
          });
        }
      });

      yield* ctx.tool.hook("execute.before", (event) =>
        Effect.gen(function* () {
          if (!config.tools.includes(event.tool.toLowerCase())) return;
          const input = event.input as { background?: unknown };
          if (input?.background === true) {
            return yield* Effect.fail(
              new ToolError({
                message: blockedMessage(
                  "background execution is outside Command Gate coverage in this release",
                ),
              }),
            );
          }
        }),
      );

      yield* ctx.shell.hook("create.before", (invocation) =>
        Effect.gen(function* () {
          const call = yield* BoundCallRef;
          if (!call) return;
          let lock = locks.get(call.sessionID);
          if (!lock) {
            lock = Semaphore.makeUnsafe(1);
            locks.set(call.sessionID, lock);
          }
          const outcome = yield* lock.withPermit(
            reviewInvocation(invocation, call),
          );
          if (outcome.kind === "deny")
            return yield* Effect.die(
              new ToolError({ message: outcome.message }),
            );
        }),
      );

      yield* ctx.tool.hook("execute.after", (event) =>
        Effect.sync(() => {
          if (!config.tools.includes(event.tool.toLowerCase())) return;
          state.release({
            location: ctx.location.directory,
            sessionID: event.sessionID,
            messageID: event.messageID,
            callID: event.id,
          });
        }),
      );

      yield* ctx.session.hook("prompt", (event) =>
        Effect.sync(() => {
          state.admit(event.sessionID, event.messageID, event.prompt.text);
        }),
      );

      yield* Effect.addFinalizer(() =>
        Effect.sync(() => log("unload", { location: ctx.location.directory })),
      );
    }),
});
