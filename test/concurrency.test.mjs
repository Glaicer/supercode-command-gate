import assert from "node:assert/strict";
import { test } from "node:test";
import { runSeam } from "./seam-driver.mjs";

test("concurrent identical calls consume once at most once; child sessions and locations keep replies isolated", async () => {
  const evidence = await runSeam({ concurrency: true });
  assert.equal(evidence.concurrency.inventoryOK, true);
  const result = evidence.concurrency.concurrency;
  assert.equal(result.identical.accepted.accepted, true);
  assert.equal(result.identical.duplicate.accepted, false);
  assert.equal(result.identical.mixedCall.accepted, false);
  assert.notEqual(
    result.identical.first.callID,
    result.identical.second.callID,
  );
  assert.equal(result.identical.marker, "run\n");
  assert.equal(result.wrongLocation.accepted, false);
  assert.equal(result.wrongSession.accepted, false);
  assert.equal(result.otherApproved.accepted, true);
  assert.equal(result.childApproved.accepted, true);
  for (const item of result.independent) {
    assert.equal(
      item.marker,
      item.name === "concurrent-main" ? "" : "run\n",
      item.name,
    );
    assert.deepEqual(item.pending, []);
    assert.match(JSON.stringify(item.context), /FINISHED/);
  }
});

test("invalidation before and after grant commit refuses the old call and a retry cannot inherit stale trust", async () => {
  const evidence = await runSeam({ grantRaces: true });
  assert.equal(evidence.grantRaces.inventoryOK, true);
  for (const result of evidence.grantRaces.grantRaces) {
    assert.equal(result.accepted.accepted, true, result.name);
    assert.equal(result.stale.accepted, false, result.name);
    assert.equal(result.marker, "", result.name);
    assert.equal(result.ownedRunning, false, result.name);
    assert.deepEqual(result.pending, [], result.name);
    const tools = result.context.data
      .filter((message) => message.type === "assistant")
      .flatMap((message) => message.content)
      .filter((part) => part.type === "tool");
    assert.equal(tools.length, 1, result.name);
    assert.notEqual(result.retry.callID, tools[0].id, result.name);
    assert.equal(tools[0].state.status, "error", result.name);
    assert.match(
      tools[0].state.error.message,
      /command was not executed|interrupted|cancelled/i,
      result.name,
    );
  }
});
