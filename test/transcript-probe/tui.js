import { Plugin } from "@opencode/plugin/tui";
import { appendFileSync } from "node:fs";

export default Plugin.define({
  id: "command-gate-transcript-surface-probe",
  setup(ctx) {
    const report = (kind, value) =>
      appendFileSync(
        ctx.options.evidenceFile,
        JSON.stringify({ kind, ...value }) + "\n",
      );
    report("surface", {
      version: ctx.app.version,
      ui: Object.keys(ctx.ui),
      context: Object.keys(ctx),
    });
    const control = ctx.ui.slot({
      append: "app",
      render(input) {
        report("control", { input, route: ctx.ui.router.current() });
        return null;
      },
    });
    const stop = ctx.ui.slot({
      before: "session.message.tool",
      render(input) {
        report("anchor", { input, route: ctx.ui.router.current() });
        return null;
      },
    });
    return () => {
      stop();
      control();
    };
  },
});
