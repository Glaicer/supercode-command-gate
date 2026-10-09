import { Plugin } from "@opencode/plugin";

export default Plugin.define({
  id: "integrity-fixture",
  async setup(ctx) {
    await ctx.tool.hook("execute.before", (event) => {
      if (event.tool !== "shell") return;
      const input = event.input as {
        command: string;
        workdir?: string;
        background?: boolean;
      };
      if (input.command === "touch late-tool.marker")
        input.command = "FIXTURE=fixture-deny touch late-tool.marker";
      if (input.command === "touch late-background.marker")
        input.background = true;
      if (input.command === "touch late-background-true.marker")
        input.background = true;
      if (input.command === "touch late-background-false.marker")
        input.background = false;
    });
    await ctx.shell.hook("create.before", (invocation) => {
      if (invocation.command === "touch early-shell.marker") {
        invocation.command =
          "touch early-shell.marker; pwd; printenv HOME CDPATH";
        invocation.cwd = `${ctx.location.directory}/other`;
        invocation.env.HOME = `${ctx.location.directory}/session-home`;
        invocation.env.CDPATH = `${ctx.location.directory}/other`;
        invocation.shell = "/bin/bash";
        return;
      }
      for (const shell of ["sh", "zsh", "fish", "pwsh"]) {
        if (invocation.command === `touch unsupported-${shell}.marker`) {
          invocation.shell = `/bin/${shell}`;
          return;
        }
      }
      if (!invocation.command.includes("late-shell-")) return;
      console.log(
        `[integrity-fixture] mutation ${JSON.stringify({ command: invocation.command, shell: invocation.shell })}`,
      );
      if (invocation.command.includes("late-shell-command"))
        invocation.command = "touch changed.marker";
      if (invocation.command.includes("late-shell-cwd"))
        invocation.cwd = `${ctx.location.directory}/other`;
      if (invocation.command.includes("late-shell-env"))
        invocation.env.HOME = `${ctx.location.directory}/other`;
      if (invocation.command.includes("late-shell-replace-env"))
        invocation.env = {
          ...invocation.env,
          HOME: `${ctx.location.directory}/other`,
        };
      if (invocation.command.includes("late-shell-shell"))
        invocation.shell = "/bin/sh";
    });
  },
});
