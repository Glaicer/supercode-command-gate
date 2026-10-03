import { Plugin } from "@opencode/plugin/tui";
import { untrack } from "solid-js";
import { existsSync, writeFileSync } from "node:fs";

export default Plugin.define({
  id: "command-gate-clear-fixture",
  setup(ctx) {
    const root = process.env.CLEAR_SMOKE_ROOT;
    let timer;
    const stop = ctx.ui.slot({
      append: "app",
      render: () =>
        untrack(() => {
          const initial = { ...ctx.ui.router.current() };
          const clear = ctx.keymap
            .commands()
            .find((command) => command.slash?.name === "clear");
          let closedAt = 0;
          let reopened = false;
          let dispatched = false;
          let ready = false;
          timer = setInterval(() => {
            try {
              if (!ready) {
                ready = true;
                writeFileSync(
                  `${root}/tui-ready.json`,
                  JSON.stringify({ route: initial, clearID: clear?.id }),
                );
              }
              if (!closedAt && existsSync(`${root}/tab.trigger`)) {
                closedAt = Date.now();
                ctx.ui.tabs.close(initial.sessionID);
              }
              if (closedAt && !reopened && Date.now() - closedAt > 500) {
                reopened = true;
                const enabled = ctx.ui.tabs.enabled();
                const tabs = ctx.ui.tabs.list();
                ctx.ui.router.navigate(initial);
                writeFileSync(`${root}/tab-closed.json`, JSON.stringify({ enabled, tabs }));
              }
              if (!dispatched && existsSync(`${root}/clear.trigger`)) {
                dispatched = true;
                writeFileSync(`${root}/clear-command.json`, JSON.stringify(ctx.keymap.commands().filter((command) => command.slash?.name === "clear" || command.id?.startsWith("command-gate."))));
                ctx.keymap.dispatch(clear.id);
              }
              if (dispatched && ctx.ui.router.current().type === "home")
                writeFileSync(
                  `${root}/clear-done.json`,
                  JSON.stringify({ route: ctx.ui.router.current() }),
                );
            } catch (error) {
              writeFileSync(
                `${root}/tui-error.json`,
                JSON.stringify({ error: String(error) }),
              );
            }
          }, 100);
          return null;
        }),
    });
    return () => {
      clearInterval(timer);
      stop();
    };
  },
});
