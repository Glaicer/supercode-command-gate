import assert from "node:assert/strict";
import { test } from "node:test";
import { runSeam } from "./seam-driver.mjs";

test("automated real TUI actions distinguish once from exact-session trust", async () => {
  const evidence = await runSeam({
    approval: true,
    human: true,
    tuiActions: true,
  });
  assert.equal(evidence.approval.inventoryOK, true);
  const once = evidence.approval.cases.find(
    (item) => item.name === "human-once",
  );
  const trusted = evidence.approval.cases.find(
    (item) => item.name === "human-session",
  );
  const denied = evidence.approval.cases.find(
    (item) => item.name === "human-deny",
  );
  for (const result of [once, trusted]) {
    assert.equal(result.sideEffect, "once\nonce\n");
    assert.equal(result.modelCalls, 2);
  }
  assert.equal(denied.marker, false);
  for (const [result, decision, count] of [
    [once, "once", 2],
    [trusted, "session", 1],
    [denied, "deny", 1],
  ]) {
    const replies = result.events.filter(
      (event) => event.kind === "human-response",
    );
    assert.equal(replies.length, count);
    for (const reply of replies) {
      assert.equal(reply.decision, decision);
      assert.notEqual(reply.clientID, "integration-adapter");
    }
  }
  assert.ok(
    trusted.events.some(
      (event) => event.kind === "review-allow" && event.source === "grant",
    ),
  );
});
