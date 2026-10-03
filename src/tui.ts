import { Plugin } from "@opencode/plugin/tui";
import { Approvals } from "./rpc.ts";
import { CLIENT_HEARTBEAT_MS, type PendingApproval } from "./approval.ts";

export default Plugin.define({
  id: "command-gate-tui",
  setup(ctx) {
    const rpc = ctx.client.rpc(Approvals);
    const clientID = crypto.randomUUID();
    let disposed = false;
    let showing = false;
    let syncing = false;
    let active: string | null = null;
    const seen = new Set<string>();
    const unavailable = (error: unknown) =>
      ctx.ui.toast.show({
        title: "Command Gate approval unavailable",
        message: String(error),
        variant: "error",
      });
    const readText = async (title: string, message: string) => {
      const width = Math.max(1, Math.min(116, ctx.renderer.width - 2) - 5);
      const pageHeight = Math.max(1, ctx.renderer.height - 10);
      const lines = message.split("\n").flatMap((line) => {
        const characters = Array.from(line);
        if (!characters.length) return [""];
        const wrapped: string[] = [];
        while (characters.length > width) {
          let end = width;
          for (let index = width; index > 0; index--) {
            if (/\s/u.test(characters[index])) {
              end = index;
              break;
            }
          }
          wrapped.push(characters.splice(0, end).join(""));
          while (characters[0] === " ") characters.shift();
        }
        wrapped.push(characters.join(""));
        return wrapped;
      });
      const pages = Math.ceil(lines.length / pageHeight);
      for (let page = 0; page < pages; page++) {
        if (disposed) return false;
        const shown = ctx.ui.dialog.confirm({
          title: `${title} (${page + 1}/${pages})`,
          message: lines
            .slice(page * pageHeight, (page + 1) * pageHeight)
            .join("\n"),
          label: {
            confirm: page + 1 < pages ? "Next" : "Actions",
            cancel: "Dismiss",
          },
        });
        ctx.ui.dialog.set({ size: "xlarge", centered: true });
        if ((await shown) !== true) return false;
      }
      return true;
    };
    const show = async (item: PendingApproval) => {
      showing = true;
      active = item.pendingID;
      seen.add(item.pendingID);
      try {
        const summary = `Effect: ${item.effectSummary}\ncwd: ${item.cwd}\nPreview: ${item.preview}\nSession: ${item.sessionID}\nCall: ${item.callID}`;
        const read = await readText("Command Gate — summary", summary);
        let choice: string | undefined;
        while (read && !disposed) {
          const selected = ctx.ui.dialog.select({
            title: "Command Gate — human approval",
            current: "deny",
            options: [
              { title: "Deny", value: "deny" },
              { title: "Allow once", value: "once" },
              { title: "Full details", value: "details" },
            ],
          });
          ctx.ui.dialog.set({ size: "xlarge", centered: true });
          choice = await selected;
          if (choice !== "details" || disposed) break;
          if (
            !(await readText(
              "Full details — may contain secrets",
              `Command:\n${item.command}\n\nRiskAssessment:\n${JSON.stringify(item.assessment, null, 2)}\n\nFingerprint: ${item.fingerprint}\nPurpose: not supplied`,
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
      if (disposed || syncing) return;
      syncing = true;
      try {
        await rpc.connect({ clientID });
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
    void sync();
    return () => {
      disposed = true;
      clearInterval(heartbeat);
      stop();
      if (active) ctx.ui.dialog.clear();
      void rpc.disconnect({ clientID }).catch(() => {});
    };
  },
});
