import path from "node:path";
import { Context, Effect } from "effect";
import { Plugin } from "@opencode/plugin/effect";
import { Error as ToolError } from "@opencode/plugin/promise/tool";
import type { ShellCreateBefore } from "@opencode/plugin/effect/shell";
import { resolveConfig } from "./config.ts";
import {
  approvalReason,
  blockedMessage,
  errorMessage,
  startupDiagnostic,
  unavailableReason,
} from "./messages.ts";
import { buildRequest, type Request } from "./request.ts";
import {
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
          if (decision.decision === "allow") {
            log("review-allow", {
              ...evidence,
              source: decision.source,
              auditId: decision.auditId,
              fingerprint,
            });
            return allow(request, decision);
          }
          release();
          log("review-deny", {
            ...evidence,
            source: decision.source,
            auditId: decision.auditId,
            fingerprint,
            reason: decision.reason,
          });
          if (decision.decision === "ask") return deny(approvalReason());
          return deny(decision.reason || "the command was not proven safe");
        }).pipe(
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
          const outcome = yield* reviewInvocation(invocation, call);
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
