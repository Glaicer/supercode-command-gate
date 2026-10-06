import { Plugin } from "@opencode/plugin/tui";
import { createSignal, untrack } from "solid-js";
import { Approvals } from "./rpc.ts";
import { CLIENT_HEARTBEAT_MS, type PendingApproval } from "./approval.ts";
import {
  approvalSummary,
  approvalDetails,
  approvalTechnicalDetails,
  approvalPages,
} from "./approval-text.ts";

export default Plugin.define({
  id: "command-gate-tui",
  setup(ctx) {
    if (ctx.options.enabled === false) return;
    const rpc = ctx.client.rpc(Approvals);
    const clientID = crypto.randomUUID();
    let disposed = false;
    let showing = false;
    let syncing = false;
    let active: string | null = null;
    let clearReady = false;
    let diagnostic: string | null = null;
    const seen = new Set<string>();
    const unavailable = (error: unknown) =>
      ctx.ui.toast.show({
        title: "Command Gate approval unavailable",
        message: String(error),
        variant: "error",
      });
    const readText = async (title: string, message: string) => {
      let cursor = 0;
      while (!disposed) {
        const width = Math.max(1, Math.min(116, ctx.renderer.width - 2) - 5);
        const pageHeight = Math.max(1, ctx.renderer.height - 10);
        const pages = approvalPages(message, width, pageHeight);
        let end = 0;
        const ends = pages.map((text) => {
          for (const row of text.split("\n")) {
            end += row.length;
            if (message[end] === "\n") end++;
          }
          return end;
        });
        const first = Math.max(
          0,
          ends.findIndex((end) => end > cursor),
        );
        for (let page = first; page < pages.length;) {
          if (disposed) return false;
          let resized = false;
          const resize = () => {
            resized = true;
            ctx.ui.dialog.clear();
          };
          const shown = ctx.ui.dialog.confirm({
            title: `${title} (${page + 1}/${pages.length})`,
            message: pages[page],
            label: {
              confirm: page + 1 < pages.length ? "Next" : "Actions",
              cancel: page > 0 ? "Previous" : "Dismiss",
            },
          });
          ctx.ui.dialog.set({ size: "xlarge", centered: true });
          ctx.renderer.on("resize", resize);
          let acknowledged;
          try {
            acknowledged = await shown;
          } finally {
            ctx.renderer.off("resize", resize);
          }
          if (resized) break;
          if (acknowledged === false && page > 0) {
            page--;
            cursor = page === 0 ? 0 : ends[page - 1];
            continue;
          }
          if (acknowledged !== true) return false;
          cursor = ends[page];
          page++;
          if (page === pages.length) return true;
        }
      }
      return false;
    };
    const show = async (item: PendingApproval) => {
      showing = true;
      active = item.pendingID;
      seen.add(item.pendingID);
      try {
        const read = await readText(
          "Command Gate — command needs approval",
          approvalSummary(item),
        );
        let choice: string | undefined;
        while (read && !disposed) {
          const selected = ctx.ui.dialog.select({
            title: "Command Gate — human approval",
            current: "deny",
            options: [
              { title: "Deny", value: "deny" },
              { title: "Allow once", value: "once" },
              ...(item.grantEligible
                ? [{ title: "Trust exact for session", value: "session" }]
                : []),
              { title: "Details", value: "details" },
              { title: "Full command", value: "command" },
              { title: "Diagnostics", value: "technical" },
            ],
          });
          ctx.ui.dialog.set({ size: "xlarge", centered: true });
          choice = await selected;
          if (
            !["details", "command", "technical"].includes(choice ?? "") ||
            disposed
          )
            break;
          if (
            !(await readText(
              choice === "command"
                ? "Full command — may contain secrets"
                : choice === "technical"
                  ? "Diagnostics — may contain secrets"
                  : "Details — may contain secrets",
              choice === "command"
                ? item.command
                : choice === "technical"
                  ? approvalTechnicalDetails(item)
                  : approvalDetails(item),
            ))
          ) {
            choice = undefined;
            break;
          }
        }
        if (disposed) return;
        const response = (await rpc.reply({
          clientID,
          pendingID: item.pendingID,
          sessionID: item.sessionID,
          messageID: item.messageID,
          callID: item.callID,
          intentGeneration: item.intentGeneration,
          fingerprint: item.fingerprint,
          decision: choice ?? "dismiss",
        })) as { accepted: boolean };
        ctx.ui.toast.show({
          message: response.accepted
            ? "Human response recorded; server performs fresh review"
            : "Approval expired or context changed; command remains blocked",
          variant: response.accepted ? "info" : "warning",
        });
      } catch (error) {
        unavailable(error);
        await rpc.disconnect({ clientID }).catch(() => {});
      } finally {
        active = null;
        showing = false;
      }
    };
    const sync = async () => {
      if (disposed || syncing || !clearReady) return;
      syncing = true;
      try {
        await rpc.connect({ clientID });
        const status = (await rpc.status({})) as {
          healthy: boolean;
          reason: string | null;
          failureMode: string;
        };
        const message =
          status.failureMode === "passthrough"
            ? "UNREVIEWED mode: Reviewer operational failures execute without review. Explicit passthrough is enabled."
            : !status.healthy
              ? `Command Gate unavailable: ${status.reason}. Commands remain denied; fix aar doctor and reload.`
              : null;
        if (message && message !== diagnostic)
          ctx.ui.toast.show({
            title: "Command Gate",
            message,
            variant: "warning",
          });
        diagnostic = message;
        const pending = (await rpc.list({ clientID })) as PendingApproval[];
        if (active && !pending.some((item) => item.pendingID === active))
          ctx.ui.dialog.clear();
        if (!showing) {
          const item = pending.find((request) => !seen.has(request.pendingID));
          if (item) void show(item);
        }
      } catch (error) {
        if (!disposed) unavailable(error);
        if (active) ctx.ui.dialog.clear();
      } finally {
        syncing = false;
      }
    };
    const stop = rpc.events.on("changed", (event) => {
      const location = ctx.location ?? ctx.data.location.default();
      if (event.location.directory === location.directory) void sync();
    });
    const heartbeat = setInterval(() => void sync(), CLIENT_HEARTBEAT_MS);
    const stopSlot = ctx.ui.slot({
      append: "app",
      render: () =>
        untrack(() => {
          ctx.keymap.layer(() => ({
            mode: "global",
            commands: [
              {
                id: "command-gate.health",
                title: "Command Gate: health",
                group: "Command Gate",
                palette: true,
                slash: { name: "gate-health" },
                run: async () => {
                  try {
                    const status = await rpc.status({});
                    await readText(
                      "Command Gate — health",
                      JSON.stringify(status, null, 2),
                    );
                  } catch (error) {
                    unavailable(error);
                  }
                },
              },
            ],
          }));
          const nativeClear = ctx.keymap
            .commands()
            .find((command) => command.slash?.name === "clear");
          if (!nativeClear?.id) {
            unavailable(
              "Native /clear bridge is unavailable; approval adapter is disabled",
            );
            return null;
          }
          const [clearing, setClearing] = createSignal(false);
          ctx.keymap.layer(() => ({
            mode: "global",
            priority: 10,
            commands: clearing()
              ? []
              : [
                  {
                    ...nativeClear,
                    run: async (input, event) => {
                      const route = { ...ctx.ui.router.current() };
                      try {
                        if (route.type === "session") {
                          const result = (await rpc.clear({
                            clientID,
                            sessionID: route.sessionID,
                          })) as { invalidated: boolean };
                          if (!result.invalidated)
                            throw new Error(
                              "Reviewer clear failed; native /clear was not dispatched",
                            );
                          const current = ctx.ui.router.current();
                          if (
                            current.type !== "session" ||
                            current.sessionID !== route.sessionID
                          )
                            throw new Error(
                              "Session changed during clear; native /clear was not dispatched",
                            );
                        }
                        setClearing(true);
                        try {
                          await nativeClear.run(input, event);
                        } finally {
                          setClearing(false);
                        }
                      } catch (error) {
                        unavailable(error);
                      }
                    },
                  },
                ],
          }));
          clearReady = true;
          void sync();
          return null;
        }),
    });
    return () => {
      disposed = true;
      clearInterval(heartbeat);
      stopSlot();
      stop();
      if (active) ctx.ui.dialog.clear();
      void rpc.disconnect({ clientID }).catch(() => {});
    };
  },
});
