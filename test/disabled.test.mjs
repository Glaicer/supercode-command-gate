import assert from "node:assert/strict";
import { test } from "node:test";
import { Effect } from "effect";
import server from "../src/plugin.ts";
import tui from "../src/tui.ts";

function disabledContext() {
  return new Proxy(
    { options: { enabled: false, binaryPath: "", timeoutMs: -1 } },
    {
      get(target, key) {
        assert.equal(key, "options", `disabled plugin accessed ${String(key)}`);
        return target.options;
      },
    },
  );
}

test("disabled server registers nothing and never calls Reviewer", async () => {
  await Effect.runPromise(server.effect(disabledContext()));
});

test("disabled TUI registers nothing and never connects to RPC", () => {
  tui.setup(disabledContext());
});
