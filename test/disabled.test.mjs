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

function sandboxMode(t, mode) {
  const previous = process.env.OPENCODE_SANDBOX_MODE;
  t.after(() => {
    if (previous === undefined) delete process.env.OPENCODE_SANDBOX_MODE;
    else process.env.OPENCODE_SANDBOX_MODE = previous;
  });
  if (mode === undefined) delete process.env.OPENCODE_SANDBOX_MODE;
  else process.env.OPENCODE_SANDBOX_MODE = mode;
}

test("sandboxed server and TUI register nothing without reading options", async (t) => {
  sandboxMode(t, "sandboxed");
  const context = new Proxy(
    {},
    {
      get(_target, key) {
        assert.fail(`sandboxed plugin accessed ${String(key)}`);
      },
    },
  );
  await Effect.runPromise(server.effect(context));
  tui.setup(context);
});

for (const mode of [undefined, "unsandboxed", "unknown", "SANDBOXED", ""]) {
  test(`sandbox marker ${JSON.stringify(mode)} preserves normal initialization`, async (t) => {
    sandboxMode(t, mode);
    await assert.rejects(Effect.runPromise(server.effect({})), /enabled/);
    assert.throws(() => tui.setup({}), /enabled/);
  });
}
