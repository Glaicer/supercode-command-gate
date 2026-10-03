import { appendFileSync, realpathSync } from "node:fs";
import { spawn } from "node:child_process";
import { Plugin } from "@opencode/plugin/effect";
import { Error as ToolError } from "@opencode/plugin/promise/tool";
import { Context, Effect } from "effect";
import { randomUUID } from "node:crypto";
import { Proof } from "./rpc.mjs";
import { setupLifecycle } from "./lifecycle.js";

const BoundCall = Context.Reference<Record<string, unknown> | null>(
  "command-gate-proof/call",
  { defaultValue: () => null },
);

export default Plugin.define({
  id: "command-gate-contract-proof",
  effect: (ctx) =>
    Effect.gen(function* () {
      const root = String(ctx.options.root);
      const log = (kind: string, event: unknown) =>
        appendFileSync(
          `${root}/events.jsonl`,
          JSON.stringify({ kind, event }) + "\n",
        );
      const pending = new Map<
        string,
        { payload: object; reply: (decision: string) => void }
      >();
      const aar = (args: string[], request?: { cwd: string }) =>
        Effect.tryPromise({
          try: (signal) =>
            new Promise<{
              decision: string;
              source: string;
              reason: string;
              requestFingerprint: string;
              grantEligible: boolean;
            }>((resolve, reject) => {
              const child = spawn(`${root}/aar`, args, {
                cwd: request?.cwd ?? ctx.location.directory,
                env: process.env,
                signal,
                timeout: 10000,
                stdio: ["pipe", "pipe", "pipe"],
              });
              let stdout = "";
              let stderr = "";
              child.stdout.on("data", (data) => {
                stdout += data;
              });
              child.stderr.on("data", (data) => {
                stderr += data;
              });
              child.on("error", reject);
              child.on("close", (code) => {
                if (code !== 0) return reject(new Error(stderr));
                try {
                  resolve(JSON.parse(stdout));
                } catch (error) {
                  reject(error);
                }
              });
              child.stdin.end(request ? JSON.stringify(request) : undefined);
            }),
          catch: (error) =>
            new ToolError({
              message: `Reviewer failure: ${String(error)}; command was not executed.`,
            }),
        });
      const life = yield* setupLifecycle(ctx, aar, log);
      yield* ctx.rpc
        .register(Proof, {
          ...life.handlers,
          list: () =>
            Effect.sync(() =>
              [...pending.values()].map((item) => item.payload),
            ),
          reply: (input) =>
            Effect.sync(() => {
              const { pendingID, decision } = input as {
                pendingID: string;
                decision: string;
              };
              const item = pending.get(pendingID);
              if (!item) return { accepted: false };
              pending.delete(pendingID);
              log("human.reply", { pendingID, decision });
              item.reply(decision);
              return { accepted: true };
            }),
        })
        .pipe(Effect.orDie);
      log("setup", {
        version: ctx.app.version,
        location: ctx.location,
        domains: Object.keys(ctx),
        sessionMethods: Object.keys(ctx.session),
      });
      yield* ctx.tool.transform((editor) => {
        log("transform", { shellPresent: Boolean(editor.get("shell")) });
        editor.update("shell", (tool) => {
          const execute = tool.execute;
          tool.execute = (input, call) =>
            execute(input, call).pipe(
              Effect.provideService(BoundCall, {
                sessionID: call.sessionID,
                messageID: call.messageID,
                id: call.id,
              }),
              Effect.catchCause((cause) => {
                const denial = cause.reasons.find(
                  (reason) =>
                    reason._tag === "Die" && reason.defect instanceof ToolError,
                );
                return denial && denial._tag === "Die"
                  ? Effect.fail(denial.defect as ToolError)
                  : Effect.failCause(cause);
              }),
            );
        });
      });
      yield* ctx.tool.hook("execute.before", (event) =>
        Effect.gen(function* () {
          log("tool.before", event);
          if (event.tool !== "shell") return;
          const input = event.input as { command: string; workdir?: string };
          if (input.command.includes("scanner-empty-deny.marker")) {
            return yield* Effect.fail(
              new ToolError({
                message:
                  "Command Gate proof failure fixture: command was not executed.",
              }),
            );
          }
          if (
            /invocation\.marker|effective-facts\.marker|scanner-empty-observe\.marker|human-once\.marker|effective-deny\.marker|approval-cancel\.marker/.test(
              input.command,
            )
          )
            return;
          const initialRequest = {
            schemaVersion: "aar-request-v1",
            command: input.command,
            cwd: realpathSync(input.workdir ?? ctx.location.directory),
            workspaceRoot: ctx.location.directory,
            env: { HOME: `${root}/home`, PWD: ctx.location.directory },
            session: { id: event.sessionID, host: "opencode", intentId: "" },
            intent: { goal: null, latestUserRequest: null, purpose: null },
          };
          const { request, decision } = yield* life.review(initialRequest);
          log("review", {
            sessionID: event.sessionID,
            messageID: event.messageID,
            id: event.id,
            request,
            decision,
          });
          if (decision.decision !== "allow") {
            return yield* Effect.fail(
              new ToolError({
                message: `Command Gate proof blocked: ${decision.reason}. The command was not executed.`,
              }),
            );
          }
        }),
      );
      yield* ctx.tool.hook("execute.after", (event) =>
        Effect.sync(() => log("tool.after", event)),
      );
      yield* ctx.shell.hook("create.before", (event) =>
        Effect.gen(function* () {
          const call = yield* BoundCall;
          log("shell.before", {
            keys: Object.keys(event),
            call,
            command: event.command,
            cwd: event.cwd,
            shell: event.shell,
            env: Object.fromEntries(
              ["HOME", "PWD", "CDPATH", "SHELL", "PROOF_ENV"].map((key) => [
                key,
                event.env[key] ?? null,
              ]),
            ),
          });
          if (
            !call ||
            !/human-once\.marker|effective-deny\.marker|approval-cancel\.marker|effective-facts\.marker/.test(
              event.command,
            )
          )
            return;
          const initialRequest = {
            schemaVersion: "aar-request-v1",
            command: event.command,
            cwd: realpathSync(event.cwd),
            workspaceRoot: ctx.location.directory,
            env: Object.fromEntries(
              ["HOME", "PWD", "CDPATH"]
                .filter((key) => event.env[key] !== undefined)
                .map((key) => [key, event.env[key]]),
            ),
            session: {
              id: String(call.sessionID),
              host: "opencode",
              intentId: "",
            },
            intent: { goal: null, latestUserRequest: null, purpose: null },
          };
          const { request, decision } = yield* life
            .review(initialRequest)
            .pipe(Effect.orDie);
          log("effective.review", { call, request, decision });
          if (decision.decision === "deny")
            return yield* Effect.die(
              new ToolError({
                message: `Command Gate proof blocked: ${decision.reason}. The command was not executed.`,
              }),
            );
          if (decision.decision === "allow") return;
          if (decision.decision !== "ask")
            return yield* Effect.die(
              new ToolError({
                message:
                  "Proof expected Reviewer ask; command was not executed.",
              }),
            );
          const pendingID = randomUUID();
          const choice = yield* Effect.tryPromise({
            try: (signal) =>
              new Promise<string>((resolve) => {
                const finish = (value: string) => {
                  clearTimeout(timer);
                  pending.delete(pendingID);
                  signal.removeEventListener("abort", cancel);
                  resolve(value);
                };
                const cancel = () => {
                  log("wait.cancelled", { pendingID, call });
                  finish("deny");
                };
                const timer = setTimeout(cancel, 600000);
                signal.addEventListener("abort", cancel, { once: true });
                pending.set(pendingID, {
                  payload: { pendingID, call, request, decision },
                  reply: finish,
                });
                log("human.pending", { pendingID, call, request, decision });
              }),
            catch: (error) =>
              new ToolError({
                message: `${String(error)}; command was not executed.`,
              }),
          }).pipe(Effect.orDie);
          if (choice === "deny")
            return yield* Effect.die(
              new ToolError({
                message: "Human denied; command was not executed.",
              }),
            );
          const current = yield* life.reconcile(request).pipe(Effect.orDie);
          if (JSON.stringify(current) !== JSON.stringify(request))
            return yield* Effect.die(
              new ToolError({
                message: "Admission or Goal changed; command was not executed.",
              }),
            );
          yield* aar([
            "grant",
            "--session",
            request.session.id,
            "--fingerprint",
            decision.requestFingerprint,
            "--scope",
            choice,
          ]).pipe(Effect.orDie);
          const fresh = yield* aar(["check"], request).pipe(Effect.orDie);
          log("fresh.review", { call, request, decision: fresh });
          if (fresh.decision !== "allow" || fresh.source !== "grant")
            return yield* Effect.die(
              new ToolError({
                message: "Fresh review refused; command was not executed.",
              }),
            );
        }),
      );
      yield* ctx.shell.hook("create.before", (event) =>
        Effect.sync(() => {
          if (event.command === "touch late-shell-observe.marker")
            event.command = "touch late-shell-executed.marker";
        }),
      );
      yield* ctx.tool.hook("execute.before", (event) =>
        Effect.sync(() => {
          const input = event.input as { command?: string };
          if (
            event.tool === "shell" &&
            input.command === "touch late-tool-observe.marker"
          )
            event.input = {
              ...input,
              command: "touch late-tool-executed.marker",
            };
        }),
      );
      yield* ctx.permission.hook("evaluate", (event) =>
        Effect.sync(() => log("permission", event)),
      );
      yield* Effect.addFinalizer(() => Effect.sync(() => log("unload", {})));
    }),
});
