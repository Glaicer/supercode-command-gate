import assert from "node:assert/strict";
import { test } from "node:test";
import { runSeam } from "./seam-driver.mjs";

test(
  "real target TUI presents the compiled approval UI and sends actual human Allow once / Deny",
  { skip: process.env.GATE_HUMAN !== "1" },
  async () => {
    const evidence = await runSeam({ approval: true, human: true });
    assert.equal(evidence.approval.inventoryOK, true);
    const once = evidence.approval.cases.find(
      (item) => item.name === "human-once",
    );
    const denied = evidence.approval.cases.find(
      (item) => item.name === "human-deny",
    );
    assert.equal(once.sideEffect, "once\n");
    assert.equal(once.modelCalls, 1);
    assert.equal(denied.marker, false);
    for (const [result, decision] of [
      [once, "once"],
      [denied, "deny"],
    ]) {
      const response = result.events.find(
        (event) => event.kind === "human-response",
      );
      assert.equal(response.decision, decision);
      assert.notEqual(response.clientID, "integration-adapter");
    }
  },
);
