import path from "node:path";
import { createHash } from "node:crypto";
import { Context, Deferred, Effect, Semaphore, Stream } from "effect";
import { Plugin } from "@opencode/plugin/effect";
import { Error as ToolError } from "@opencode/plugin/promise/tool";
import type { ShellCreateBefore } from "@opencode/plugin/effect/shell";
import { resolveConfig } from "./config.ts";
import {
  blockedMessage,
  errorMessage,
  neverAskDenialMessage,
  reviewerDenialMessage,
  startupDiagnostic,
  unavailableReason,
} from "./messages.ts";
import {
  assistantRationaleFor,
  buildRequest,
  type Request,
} from "./request.ts";
import {
  callAction,
  callCheck,
  callDoctor,
  callRewrite,
  fingerprintFor,
  normalizeDoctorResult,
  validateDecision,
  type Decision,
  type StartupStatus,
} from "./reviewer.ts";
import {
  GateState,
  authorizingKey,
  goalFromMetadata,
  type AuthorizingRecord,
  type CallIdentity,
} from "./state.ts";
import type { Intent } from "./state.ts";
import { ApprovalQueue, type ApprovalReply } from "./approval.ts";
import {
  UnavailableAlerts,
  safeOperationalReason,
  unavailableDecisionAlert,
} from "./unavailable.ts";
import { Approvals } from "./rpc.ts";

const BoundCallRef = Context.Reference<CallIdentity | null>(
  "command-gate/call",
  { defaultValue: () => null },
);

type ReviewOutcome =
  | { kind: "allow"; request: Request; decision: Decision }
  | { kind: "unreviewed"; request: Request }
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
function sealInvocation(invocation: ShellCreateBefore, request: Request): void {
  const refuse = (field: string): never => {
    throw new ToolError({
      message: blockedMessage(
        `late mutation changed reviewed invocation ${field}; disable the conflicting shell mutator`,
      ),
    });
  };
  const nativeMetadata: Record<string, string> = {
    AGENT: "1",
    OPENCODE: "1",
    AI_AGENT: "opencode",
    OPENCODE_SESSION_ID: request.session.id,
  };
  const env = new Proxy(
    { ...invocation.env },
    {
      set: (target, key, value) => {
        if (
          typeof key === "string" &&
          Object.hasOwn(nativeMetadata, key) &&
          value === nativeMetadata[key]
        )
          return Reflect.set(target, key, value);
        return refuse(`env.${String(key)}`);
      },
      deleteProperty: (_target, key) => refuse(`env.${String(key)}`),
      defineProperty: (_target, key) => refuse(`env.${String(key)}`),
      setPrototypeOf: () => refuse("env prototype"),
    },
  );
  for (const key of ["command", "cwd", "shell", "env"] as const) {
    let value = key === "env" ? env : invocation[key];
    Object.defineProperty(invocation, key, {
      enumerable: true,
      configurable: false,
      get: () => value,
      set: (next: unknown) => {
        if (next === value) return;
        if (key === "cwd" && next === request.cwd) {
          value = request.cwd;
          return;
        }
        refuse(key);
      },
    });
  }
}

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
    Effect.acquireUseRelease(
      Effect.sync(() => {
        const controller = new AbortController();
        const promise = Promise.resolve(try_(controller.signal));
        return { controller, promise };
      }),
      ({ promise }) =>
        Effect.tryPromise({
          try: () => promise,
          catch: (error): string => errorMessage(error),
        }),
      ({ controller, promise }) =>
        Effect.promise(async () => {
          controller.abort();
          await promise.catch(() => {});
        }),
    ),
  );

const startupFailure = (reason: string): StartupStatus => ({
  ok: false,
  reason,
});

export default Plugin.define({
  id: "command-gate",
  effect: (ctx) =>
    Effect.gen(function* () {
      if (process.env.OPENCODE_SANDBOX_MODE === "sandboxed") return;
      if (ctx.options.enabled === false) return;
      const config = resolveConfig(ctx.options);
      const state = new GateState();
      let active = true;
      const shutdown = yield* Deferred.make<void>();
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
          `[command-gate] startup-unavailable ${JSON.stringify({ reason: startup.reason, message: !config.configError && config.onReviewerFailure === "passthrough" ? `UNREVIEWED execution: explicit passthrough; ${startup.reason}. Fix aar doctor and reload.` : startupDiagnostic(startup.reason) })}`,
        );
      if (!config.configError && config.onReviewerFailure === "passthrough")
        console.error(
          '[command-gate] startup-unreviewed {"message":"UNREVIEWED mode: explicit passthrough permits Reviewer operational failures to execute without review"}',
        );

      let changed = false;
      const unavailableAlerts = new UnavailableAlerts();
      const reportUnavailable = (
        sessionID: string,
        component: "reviewer" | "assessor",
        reason: string,
      ) => {
        const alert = unavailableAlerts.fail(sessionID, component, reason);
        if (alert) {
          changed = true;
          log("unavailable-alert", { session: sessionID, ...alert });
        }
      };
      const approvals = new ApprovalQueue(() => {
        changed = true;
      });
      const locks = new Map<string, Semaphore.Semaphore>();
      const contexts = new Map<string, string>();
      const epochs = new Map<string, number>();
      const parents = new Map<string, string>();
      const requests = new Map<string, Request>();
      const backgroundCalls = new Set<string>();
      const goals = new Map<string, string>();
      const admissions = new Map<string, Set<string>>();
      const invalidate = (sessionID: string, event: string) =>
        Effect.gen(function* () {
          const family = new Set([sessionID]);
          for (const parent of family)
            for (const [child, owner] of parents)
              if (owner === parent) family.add(child);
          for (const id of family) {
            epochs.set(id, (epochs.get(id) ?? 0) + 1);
            contexts.delete(id);
            deniedResponses.delete(id);
            approvals.invalidate(id);
            if (event === "clear" || event === "end") {
              state.forgetIntent(id);
            }
          }
          let invalidated = true;
          for (const id of family) {
            const request =
              requests.get(id) ??
              buildRequest(
                { command: "true", cwd: ctx.location.directory, env: {} },
                {
                  sessionID: id,
                  intentId: null,
                  goal: null,
                  latestUserRequest: null,
                },
                ctx.location.directory,
              );
            const reset = yield* attemptPromise((signal) =>
              callAction(
                config.binaryPath,
                request,
                "session-event",
                ["--event", event],
                config.timeoutMs,
                signal,
              ),
            );
            if (!reset.ok) invalidated = false;
            log("invalidation", { session: id, event, ok: reset.ok });
          }
          return invalidated;
        });
      let clientGeneration = 0;
      let connectedBefore = false;
      const deniedResponses = new Map<
        string,
        { generation: string; fingerprints: Set<string> }
      >();
      const admit = (sessionID: string, messageID: string, text: string) =>
        Effect.gen(function* () {
          const seen = admissions.get(sessionID) ?? new Set<string>();
          admissions.set(sessionID, seen);
          const previous = state.intentFor(sessionID, undefined);
          if (
            seen.has(messageID) &&
            (previous?.id !== messageID || previous.text === text)
          )
            return;
          seen.add(messageID);
          yield* invalidate(sessionID, "new-intent");
          state.admit(sessionID, messageID, text);
        });
      const contextFor = (sessionID: string, call?: CallIdentity) =>
        Effect.gen(function* () {
          const clientEpoch = clientGeneration;
          const lineage: {
            id: string;
            epoch: number;
            goal: string;
            intent: Intent | null;
          }[] = [];
          let id: string | undefined = sessionID;
          let intent: Intent | undefined;
          let goal: string | null = null;
          let assistantRationale: string | null = null;
          while (id) {
            if (lineage.some((entry) => entry.id === id))
              throw new Error("cyclic session parent relationship");
            const epoch = epochs.get(id) ?? 0;
            const info: Effect.Success<ReturnType<typeof ctx.session.get>> =
              yield* ctx.session.get({ sessionID: id } as Parameters<
                typeof ctx.session.get
              >[0]);
            if (info.location.directory !== ctx.location.directory)
              throw new Error("owning session belongs to a different location");
            if (!epochs.has(id)) epochs.set(id, epoch);
            if (info.parentID) parents.set(id, info.parentID);
            else parents.delete(id);
            const messages = yield* ctx.session.context({
              sessionID: id,
            } as Parameters<typeof ctx.session.context>[0]);
            if (call && id === sessionID)
              assistantRationale = assistantRationaleFor(
                messages,
                call.messageID,
                call.callID,
              );
            if ((epochs.get(id) ?? 0) !== epoch)
              throw new Error("intent changed during reconciliation");
            const latest = messages.findLast(
              (message) => message.type === "user",
            );
            const seen = admissions.get(id) ?? new Set<string>();
            admissions.set(id, seen);
            for (const message of messages)
              if (message.type === "user" && message.id !== latest?.id)
                seen.add(message.id);
            if (latest?.type === "user")
              yield* admit(id, latest.id, latest.text);
            const goalSignature = JSON.stringify(info.metadata?.goal ?? null);
            if (goals.has(id) && goals.get(id) !== goalSignature)
              yield* invalidate(id, "goal-change");
            goals.set(id, goalSignature);
            const ownIntent = state.intentFor(id, undefined);
            intent ??= ownIntent;
            if (id === sessionID) goal = goalFromMetadata(info.metadata);
            lineage.push({
              id,
              epoch: epochs.get(id) ?? 0,
              goal: goalSignature,
              intent: ownIntent ?? null,
            });
            id = info.parentID;
          }
          if (
            clientEpoch !== clientGeneration ||
            lineage.some((entry) => entry.epoch !== (epochs.get(entry.id) ?? 0))
          )
            throw new Error("intent changed during reconciliation");
          const generation = createHash("sha256")
            .update(JSON.stringify({ lineage, clientEpoch }))
            .digest("hex");
          return { intent, goal, generation, assistantRationale };
        });
      const registration = yield* ctx.rpc
        .register(Approvals, {
          alerts: (input) =>
            Effect.succeed(
              unavailableAlerts.list(
                (input as { sessionID: string }).sessionID,
              ),
            ),
          status: () =>
            Effect.succeed({
              healthy: startup.ok,
              reason: startup.ok ? null : startup.reason,
              failureMode: config.configError
                ? "deny"
                : config.onReviewerFailure,
              approvalAvailable: approvals.available(),
              settings: {
                binaryPath: config.binaryPath,
                tools: config.tools,
                timeoutMs: config.timeoutMs,
                approvalTimeoutMs: config.approvalTimeoutMs,
                approvalMode: config.approvalMode,
                commandRewriter: config.commandRewriter,
                rewriterPath: config.rewriterPath,
              },
            }),
          connect: (input) =>
            Effect.gen(function* () {
              const clientID = (input as { clientID: string }).clientID;
              if (approvals.connect(clientID)) {
                if (connectedBefore) {
                  clientGeneration++;
                  for (const sessionID of [...epochs.keys()])
                    yield* invalidate(sessionID, "new-intent");
                }
                connectedBefore = true;
                log("approval-client", { clientID });
              }
              return { connected: true };
            }),
          disconnect: (input) =>
            Effect.sync(() => {
              approvals.disconnect((input as { clientID: string }).clientID);
              return { disconnected: true };
            }),
          clear: (input) =>
            Effect.gen(function* () {
              const { clientID, sessionID } = input as {
                clientID: string;
                sessionID: string;
              };
              if (!approvals.connected(clientID)) return { invalidated: false };
              const current = yield* attempt(contextFor(sessionID));
              if (!current.ok) return { invalidated: false };
              return { invalidated: yield* invalidate(sessionID, "clear") };
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
        background: boolean,
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
          if (config.commandRewriter === "rtk" && !config.configError) {
            const rewritten = yield* attemptPromise((signal) =>
              callRewrite(
                config.rewriterPath,
                invocation.command,
                invocation.cwd,
                config.timeoutMs,
                signal,
              ),
            );
            if (rewritten.ok && rewritten.value !== "")
              invocation.command = rewritten.value;
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
          const initialContext = yield* attempt(
            contextFor(call.sessionID, call),
          );
          if (!initialContext.ok) {
            release();
            return deny(
              `the owning session could not be reconciled (${initialContext.reason})`,
            );
          }
          const { intent, goal, assistantRationale } = initialContext.value;
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
                assistantRationale,
                ...(background ? { background: true } : {}),
              },
              ctx.location.directory,
            );
          } catch (error) {
            release();
            return deny(
              `the actual working directory could not be resolved (${errorMessage(error)})`,
            );
          }
          requests.set(call.sessionID, request);
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
            shell: invocation.shell,
            intentId: request.session.intentId,
            goal: request.intent.goal,
            ...(background ? { background: true } : {}),
          };
          const operationalFailure = (
            reason: string,
            passthrough = true,
          ): ReviewOutcome => {
            if (
              active &&
              passthrough &&
              !config.configError &&
              config.onReviewerFailure === "passthrough"
            ) {
              console.error(
                `[command-gate] review-unreviewed ${JSON.stringify({ ...evidence, reason, message: "UNREVIEWED execution: explicit onReviewerFailure passthrough" })}`,
              );
              return { kind: "unreviewed", request };
            }
            if (reason !== "reviewer cancelled") {
              reportUnavailable(
                call.sessionID,
                "reviewer",
                safeOperationalReason(reason),
              );
            }
            const diagnostic = safeOperationalReason(reason);
            log("review-deny", { ...evidence, reason: diagnostic });
            return deny(unavailableReason(diagnostic));
          };
          if (!startup.ok) {
            return operationalFailure(startup.reason);
          }
          const currentContext = yield* attempt(
            contextFor(call.sessionID, call),
          );
          if (!currentContext.ok)
            return deny("approval context could not be reconciled");
          const generation = currentContext.value.generation;
          if (
            (currentContext.value.intent?.id ?? "") !==
              request.session.intentId ||
            currentContext.value.goal !== request.intent.goal ||
            (currentContext.value.assistantRationale ?? "") !==
              (request.intent.assistantRationale ?? "")
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
          const reconciledContext = yield* attempt(
            contextFor(call.sessionID, call),
          );
          if (
            !reconciledContext.ok ||
            reconciledContext.value.generation !== generation ||
            (reconciledContext.value.assistantRationale ?? "") !==
              (request.intent.assistantRationale ?? "")
          )
            return deny("intent changed during review");
          if (!checked.ok) return operationalFailure(checked.reason);
          let decision: Decision;
          try {
            decision = validateDecision(checked.value, request);
          } catch (error) {
            return operationalFailure(errorMessage(error));
          }
          unavailableAlerts.reviewed(call.sessionID, decision);
          if (
            decision.source === "unavailable" &&
            (decision.decision === "deny" ||
              config.approvalMode === "never-ask")
          ) {
            const diagnostic = unavailableDecisionAlert(decision.failureKind);
            reportUnavailable(
              call.sessionID,
              diagnostic.component,
              diagnostic.reason,
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
            if (config.approvalMode === "never-ask") {
              release();
              log("review-deny", {
                ...evidence,
                source: decision.source,
                reason: decision.reason,
                fingerprint,
                approvalMode: "never-ask",
                mappedFrom: "ask",
              });
              return {
                kind: "deny",
                message: neverAskDenialMessage(decision),
              } satisfies ReviewOutcome;
            }
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
            if (!response.ok || !["once", "session"].includes(response.value)) {
              if (
                decision.source === "unavailable" &&
                response.ok &&
                ["unavailable", "disconnected", "timeout"].includes(
                  response.value,
                )
              ) {
                const diagnostic = unavailableDecisionAlert(
                  decision.failureKind,
                );
                reportUnavailable(
                  call.sessionID,
                  diagnostic.component,
                  diagnostic.reason,
                );
              }
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
                const current = yield* contextFor(call.sessionID, call);
                const fresh = buildRequest(
                  invocation,
                  {
                    sessionID: call.sessionID,
                    intentId: current.intent?.id ?? null,
                    goal: current.goal,
                    latestUserRequest: current.intent?.text ?? null,
                    assistantRationale: current.assistantRationale,
                    ...(background ? { background: true } : {}),
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
                  response.value,
                ],
                config.timeoutMs,
                signal,
              ),
            );
            if (!granted.ok)
              return deny(
                `Approval Grant could not be recorded (${granted.reason})`,
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
            if (reconciled.ok && !fresh.ok)
              return operationalFailure(fresh.reason, false);
            if (reconciled.ok && fresh.ok && !reviewed)
              return operationalFailure(
                "reviewer emitted an invalid fresh decision",
                false,
              );
            if (reconciled.ok && reviewed) {
              unavailableAlerts.reviewed(call.sessionID, reviewed);
              if (reviewed.source === "unavailable") {
                const diagnostic = unavailableDecisionAlert(
                  reviewed.failureKind,
                );
                reportUnavailable(
                  call.sessionID,
                  diagnostic.component,
                  diagnostic.reason,
                );
                return {
                  kind: "deny",
                  message: reviewerDenialMessage(reviewed),
                } satisfies ReviewOutcome;
              }
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
              reviewed.grantScope !== response.value ||
              reviewed.requestFingerprint !== decision.requestFingerprint
            ) {
              if (reconciled.ok && reviewed?.decision === "deny")
                return {
                  kind: "deny",
                  message: reviewerDenialMessage(reviewed),
                } satisfies ReviewOutcome;
              return deny(
                !reconciled.ok
                  ? reconciled.reason
                  : (reviewed?.reason ??
                      "fresh review did not match the Approval Grant"),
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
          return {
            kind: "deny",
            message: reviewerDenialMessage(decision),
          } satisfies ReviewOutcome;
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
              Effect.suspend(() => {
                if (!active)
                  return Effect.fail(
                    new ToolError({
                      message: blockedMessage(
                        "Command Gate was unloaded; retry with a loaded Gate",
                      ),
                    }),
                  );
                if (
                  (input as { background?: unknown })?.background === true &&
                  !config.allowBackground
                )
                  return Effect.fail(
                    new ToolError({
                      message: blockedMessage(
                        "background execution is outside Command Gate coverage in this release",
                      ),
                    }),
                  );
                if (config.allowBackground) {
                  const reviewed = backgroundCalls.has(
                    authorizingKey({
                      location: ctx.location.directory,
                      sessionID: call.sessionID,
                      messageID: call.messageID,
                      callID: call.id,
                    }),
                  );
                  const actual =
                    (input as { background?: unknown })?.background === true;
                  if (reviewed !== actual)
                    return Effect.fail(
                      new ToolError({
                        message: blockedMessage(
                          "late mutation changed reviewed invocation background; disable the conflicting shell mutator",
                        ),
                      }),
                    );
                }
                return execute(input, call);
              }).pipe(
                Effect.raceFirst(
                  Deferred.await(shutdown).pipe(
                    Effect.flatMap(() =>
                      Effect.fail(
                        new ToolError({
                          message:
                            "Command Gate was unloaded during the native call. Execution was cancelled; earlier side effects may have occurred.",
                        }),
                      ),
                    ),
                  ),
                ),
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
            if (!config.allowBackground) {
              return yield* Effect.fail(
                new ToolError({
                  message: blockedMessage(
                    "background execution is outside Command Gate coverage in this release",
                  ),
                }),
              );
            }
            backgroundCalls.add(
              authorizingKey({
                location: ctx.location.directory,
                sessionID: event.sessionID,
                messageID: event.messageID,
                callID: event.id,
              }),
            );
          }
          if (
            config.allowBackground &&
            input !== null &&
            typeof input === "object" &&
            "background" in input
          ) {
            const fact = input.background === true;
            try {
              Object.defineProperty(input, "background", {
                enumerable: true,
                configurable: false,
                get: () => fact,
                set: (next: unknown) => {
                  if (next === fact) return;
                  throw new ToolError({
                    message: blockedMessage(
                      "late mutation changed reviewed invocation background; disable the conflicting shell mutator",
                    ),
                  });
                },
              });
            } catch {
              // a foreign seal may own the property; the execute wrapper still refuses mismatches
            }
          }
        }),
      );

      yield* ctx.shell.hook("create.before", (invocation) =>
        Effect.gen(function* () {
          const call = yield* BoundCallRef;
          if (!call) return;
          if (!active)
            return yield* Effect.die(
              new ToolError({
                message: blockedMessage(
                  "Command Gate was unloaded; retry with a loaded Gate",
                ),
              }),
            );
          let lock = locks.get(call.sessionID);
          if (!lock) {
            lock = Semaphore.makeUnsafe(1);
            locks.set(call.sessionID, lock);
          }
          const shell = invocation.shell;
          const background = backgroundCalls.has(authorizingKey(call));
          const outcome = yield* Effect.raceFirst(
            lock.withPermit(reviewInvocation(invocation, call, background)),
            Deferred.await(shutdown).pipe(
              Effect.as(deny("Command Gate was unloaded during review")),
            ),
          );
          if (outcome.kind === "deny")
            return yield* Effect.die(
              new ToolError({ message: outcome.message }),
            );
          const fresh = buildRequest(
            invocation,
            {
              sessionID: call.sessionID,
              intentId: outcome.request.session.intentId,
              goal: outcome.request.intent.goal,
              latestUserRequest: outcome.request.intent.latestUserRequest,
              assistantRationale: outcome.request.intent.assistantRationale,
              ...(background ? { background: true } : {}),
            },
            ctx.location.directory,
          );
          if (
            invocation.shell !== shell ||
            JSON.stringify(fresh) !== JSON.stringify(outcome.request)
          )
            return yield* Effect.die(
              new ToolError({
                message: blockedMessage("invocation changed during review"),
              }),
            );
          sealInvocation(invocation, outcome.request);
        }),
      );

      yield* ctx.tool.hook("execute.after", (event) =>
        Effect.sync(() => {
          if (!config.tools.includes(event.tool.toLowerCase())) return;
          const identity = {
            location: ctx.location.directory,
            sessionID: event.sessionID,
            messageID: event.messageID,
            callID: event.id,
          };
          backgroundCalls.delete(authorizingKey(identity));
          state.release(identity);
        }),
      );

      yield* ctx.session.hook("prompt", (event) =>
        Effect.gen(function* () {
          yield* invalidate(event.sessionID, "new-intent");
        }),
      );
      yield* ctx.event.subscribe().pipe(
        Stream.runForEach((event) =>
          Effect.gen(function* () {
            if (
              event.type === "session.deleted" &&
              epochs.has(event.data.sessionID)
            )
              yield* invalidate(event.data.sessionID, "end");
            if (
              event.type === "session.metadata.updated" &&
              goals.has(event.data.sessionID)
            )
              yield* attempt(contextFor(event.data.sessionID));
            if (
              event.type === "session.inbox.enqueued" &&
              event.data.item.type === "user" &&
              epochs.has(event.data.sessionID)
            )
              yield* admit(
                event.data.sessionID,
                event.data.inboxID,
                event.data.item.payload.text,
              );
          }),
        ),
        Effect.forkScoped,
      );

      yield* Effect.addFinalizer(() =>
        Effect.gen(function* () {
          active = false;
          approvals.close();
          yield* Deferred.succeed(shutdown, undefined);
          log("unload", { location: ctx.location.directory });
        }),
      );
    }),
});
