import assert from "node:assert/strict";
import { test } from "node:test";
import { runSeam } from "./seam-driver.mjs";

test("deadline and session interruption terminate a SIGTERM-resistant Reviewer and prevent late continuation", async () => {
  const evidence = await runSeam({ cancellation: true });
  assert.equal(evidence.cancellation.inventoryOK, true);
  for (const result of evidence.cancellation.cases) {
    assert.equal(result.marker, false, result.name);
    assert.equal(result.ownedRunning, false, result.name);
    assert.equal(result.lateEffect, false, result.name);
    const tools = result.context.data
      .filter((message) => message.type === "assistant")
      .flatMap((message) => message.content)
      .filter((part) => part.type === "tool");
    assert.equal(tools.length, 1, result.name);
    assert.equal(tools[0].state.status, "error", result.name);
    assert.match(
      tools[0].state.error.message,
      /command was not executed|interrupted|cancelled/i,
      result.name,
    );
    if (result.name === "fixture-timeout") {
      assert.equal(result.finished, true);
      assert.match(result.toolResult, /timeout.*command was not executed/i);
    }
  }
});

test("unload after Reviewer allow cannot resume an old native permission wait", async () => {
  const evidence = await runSeam({ nativeUnload: true });
  const result = evidence.nativeUnload.cases[0];
  assert.ok(result.events.some((event) => event.kind === "review-allow"));
  assert.equal(result.marker, false);
  assert.equal(result.finished, true);
  assert.match(
    result.toolResult,
    /command was not executed|cancelled|interrupted|denied/i,
  );
  const running = evidence.nativeUnload.cases[1];
  assert.equal(running.marker, true);
  assert.equal(running.sideEffect, "started");
  assert.equal(running.finished, true);
  assert.doesNotMatch(running.toolResult, /command was not executed/i);
});
