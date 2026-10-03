import { Plugin } from "@opencode/plugin/tui";
import { createSignal, untrack } from "solid-js";
import { Proof } from "./rpc.mjs";

export default Plugin.define({
  id: "command-gate-proof-tui",
  setup(ctx) {
    const rpc = ctx.client.rpc(Proof);
    const connected = ctx.options.smokeClear
      ? Promise.resolve()
      : rpc.connect({ clientID: crypto.randomUUID() });
    ctx.ui.toast.show({
      message: "Command Gate proof: /proof-approve",
      variant: "info",
      duration: 12000,
    });
    return ctx.ui.slot({
      append: "app",
      render: () =>
        untrack(() => {
          const clear = ctx.keymap
            .commands()
            .find((command) => command.slash?.name === "clear");
          const [clearing, setClearing] = createSignal(false);
          const runClear = async (input, event) => {
            const route = ctx.ui.router.current();
            if (route.type !== "session" || !clear)
              throw Error("Native clear/session is unavailable");
            await rpc.invalidate({
              sessionID: route.sessionID,
              event: "clear",
            });
            setClearing(true);
            try {
              await clear.run(input, event);
            } finally {
              setClearing(false);
            }
            await rpc.clientReport({
              event: "native-clear",
              commandID: clear.id,
              route: ctx.ui.router.current(),
            });
          };
          if (ctx.options.smokeClear)
            connected.then(() =>
              clear?.id
                ? ctx.keymap.dispatch(clear.id)
                : rpc.clientReport({ event: "native-clear-unavailable" }),
            );
          connected.catch((error) =>
            ctx.ui.toast.show({
              message: `Proof connection failed: ${String(error)}`,
              variant: "error",
            }),
          );
          ctx.keymap.layer(() => ({
            mode: "global",
            priority: 10,
            commands: [
              {
                id: "command-gate-proof.approve",
                title: "Command Gate proof approval",
                palette: true,
                slash: { name: "proof-approve" },
                run: async () => {
                  const pending = await rpc.list({});
                  if (!pending.length)
                    return ctx.ui.dialog.alert({
                      title: "Proof",
                      message: "No pending requests",
                    });
                  const item = pending[0];
                  await ctx.ui.dialog.alert({
                    title: "Effect: create one harmless marker",
                    message: `cwd: ${item.request.cwd}\nSession: ${item.call.sessionID}\nCall: ${item.call.id}\nCommand: ${item.request.command}\nFingerprint: ${item.decision.requestFingerprint}`,
                  });
                  const options = [
                    { title: "Deny", value: "deny" },
                    { title: "Allow once", value: "once" },
                    ...(item.decision.grantEligible
                      ? [{ title: "Trust exact for session", value: "session" }]
                      : []),
                  ];
                  const decision = await ctx.ui.dialog.select({
                    title: "Command Gate proof — human decision",
                    current: "deny",
                    options,
                  });
                  await rpc.reply({
                    pendingID: item.pendingID,
                    decision: decision ?? "deny",
                  });
                  ctx.ui.toast.show({
                    message: "Proof reply recorded",
                    variant: "info",
                  });
                },
              },
              ...(clear && !clearing() ? [{ ...clear, run: runClear }] : []),
            ],
          }));
          return null;
        }),
    });
  },
});
