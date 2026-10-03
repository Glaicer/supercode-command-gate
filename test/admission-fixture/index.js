import { Plugin } from "@opencode/plugin";
import { Rpc } from "@opencode/plugin/rpc";

export default Plugin.define({
  id: "command-gate-admission-fixture",
  async setup(ctx) {
    await ctx.session.hook("prompt", (event) => {
      event.prompt.text = event.prompt.text.replace(
        "late-admission-original",
        "canonical-admission",
      );
    });
    await ctx.rpc.register(
      Rpc.define({
        id: "command-gate-fixture",
        events: {},
        methods: {
          admit: {
            input: {
              type: "object",
              properties: {
                sessionID: { type: "string" },
                text: { type: "string" },
              },
              required: ["sessionID", "text"],
            },
            output: { type: "object" },
          },
        },
      }),
      {
        admit: (input) => ctx.session.prompt({ ...input, resume: false }),
      },
    );
  },
});
