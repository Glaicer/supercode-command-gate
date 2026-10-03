import type { Plugin } from "@opencode/plugin/effect";
import { Error as ToolError } from "@opencode/plugin/promise/tool";
import { Effect, Stream } from "effect";

export type Request = {
  schemaVersion: string;
  command: string;
  cwd: string;
  workspaceRoot: string;
  env: Record<string, string | undefined>;
  session: { id: string; host: string; intentId: string };
  intent: {
    goal: string | null;
    latestUserRequest: string | null;
    purpose: null;
  };
};
export type Decision = {
  decision: string;
  source: string;
  reason: string;
  requestFingerprint: string;
  grantEligible: boolean;
};

export function setupLifecycle(
  ctx: Plugin.Context,
  aar: (
    args: string[],
    request?: Request,
  ) => Effect.Effect<Decision, ToolError>,
  log: (kind: string, event: unknown) => void,
) {
  return Effect.gen(function* () {
    const seen = new Set<string>();
    const parents = new Map<string, string>();
    const intents = new Map<string, { id: string; text: string }>();
    const goals = new Map<string, string | null>();
    let lastClientID: string | undefined;
    const invalidate = (sessionID: string, event: string) =>
      Effect.gen(function* () {
        const family = new Set([sessionID]);
        for (const parent of family)
          for (const [child, owner] of parents)
            if (owner === parent) family.add(child);
        for (const id of family) {
          yield* aar(["session-event", "--session", id, "--event", event]);
          log("invalidation", { sessionID: id, event });
          if (event === "clear" || event === "end") intents.delete(id);
        }
      });
    const reconcile = (request: Request) =>
      Effect.gen(function* () {
        const info = yield* ctx.session
          .get({ sessionID: request.session.id } as Parameters<
            typeof ctx.session.get
          >[0])
          .pipe(Effect.orDie);
        if (info.location.directory !== ctx.location.directory)
          return yield* Effect.fail(
            new ToolError({
              message: "Foreign location/session; command was not executed.",
            }),
          );
        if (!seen.has(info.id)) {
          const admission = intents.get(info.id);
          yield* invalidate(info.id, "clear");
          if (admission) intents.set(info.id, admission);
          seen.add(info.id);
        }
        if (info.parentID) parents.set(info.id, info.parentID);
        const raw = info.metadata?.goal;
        const goal =
          raw &&
          typeof raw === "object" &&
          "condition" in raw &&
          typeof raw.condition === "string" &&
          (!("status" in raw) || raw.status === "active")
            ? raw.condition
            : null;
        if (goals.has(info.id) && goals.get(info.id) !== goal)
          yield* invalidate(info.id, "goal-change");
        goals.set(info.id, goal);
        const intent =
          intents.get(info.id) ??
          (info.parentID ? intents.get(info.parentID) : undefined);
        return {
          ...request,
          session: { ...request.session, intentId: intent?.id ?? "" },
          intent: {
            ...request.intent,
            goal,
            latestUserRequest: intent?.text ?? null,
          },
        };
      });
    const review = (request: Request) =>
      Effect.gen(function* () {
        const current = yield* reconcile(request);
        const decision = yield* aar(["check"], current);
        log("lifecycle.review", { request: current, decision });
        return { request: current, decision };
      });
    yield* ctx.session.hook("prompt", (event) =>
      Effect.gen(function* () {
        log("prompt", event);
        yield* invalidate(event.sessionID, "new-intent").pipe(Effect.orDie);
        intents.set(event.sessionID, {
          id: event.messageID,
          text: event.prompt.text,
        });
      }),
    );
    yield* ctx.event.subscribe().pipe(
      Stream.runForEach((event) =>
        Effect.gen(function* () {
          if (
            event.type !== "session.deleted" ||
            !seen.has(event.data.sessionID)
          )
            return;
          log("event", event);
          yield* invalidate(event.data.sessionID, "end").pipe(Effect.orDie);
        }),
      ),
      Effect.forkScoped,
    );
    return {
      review,
      reconcile,
      invalidate,
      handlers: {
        clientReport: (input: unknown) =>
          Effect.sync(() => {
            log("client.report", input);
            return { recorded: true };
          }),
        connect: (input: unknown) =>
          Effect.gen(function* () {
            const { clientID } = input as { clientID: string };
            const reset =
              lastClientID !== undefined && lastClientID !== clientID;
            if (reset) for (const id of seen) yield* invalidate(id, "clear");
            lastClientID = clientID;
            log("client.connect", { clientID, reset });
            return { reset };
          }).pipe(Effect.orDie),
        check: (input: unknown) => review(input as Request).pipe(Effect.orDie),
        invalidate: (input: unknown) =>
          Effect.gen(function* () {
            const { sessionID, event } = input as {
              sessionID: string;
              event: string;
            };
            if (event === "reconnect") {
              for (const id of seen) yield* invalidate(id, "clear");
            } else yield* invalidate(sessionID, event);
            return { invalidated: true };
          }).pipe(Effect.orDie),
        admit: (input: unknown) =>
          ctx.session
            .prompt({
              ...(input as Parameters<typeof ctx.session.prompt>[0]),
              resume: false,
            })
            .pipe(
              Effect.map((result) => ({ id: result.id })),
              Effect.orDie,
            ),
      },
    };
  });
}
