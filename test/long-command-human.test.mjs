import assert from "node:assert/strict";
import { test } from "node:test";
import { runSeam, versionAtLeast } from "./seam-driver.mjs";

test(
  "human inspects every long-command page then explicitly approves or denies native execution",
  { skip: process.env.GATE_LONG_HUMAN !== "1" },
  async () => {
    assert.equal(
      process.env.GATE_PACKED,
      "1",
      "human acceptance uses a packed installation",
    );
    const evidence = await runSeam({
      approval: true,
      human: true,
      longHuman: true,
    });
    assert.ok(
      versionAtLeast(evidence.version, "2.0.22"),
      `expected OpenCode 2.0.22 or newer, got ${evidence.version}`,
    );
    assert.equal(evidence.approval.inventoryOK, true);
    assert.equal(evidence.approval.status.settings.approvalMode, "interactive");
    assert.ok(evidence.approval.installation);
    const [once, denied] = evidence.approval.cases;
    assert.equal(once.sideEffect, "once\n");
    assert.equal(once.modelCalls, 1);
    assert.ok(once.toolResult.includes("FINAL_COMMAND_LINE"));
    assert.equal(denied.marker, false);
    assert.equal(denied.modelCalls, 1);
    for (const [result, decision] of [
      [once, "once"],
      [denied, "deny"],
    ]) {
      const replies = result.events.filter(
        (event) => event.kind === "human-response",
      );
      assert.equal(replies.length, 1);
      assert.equal(replies[0].decision, decision);
      assert.notEqual(replies[0].clientID, "integration-adapter");
      const checked = result.events.find(
        (event) => event.kind === "approval-ask",
      );
      assert.ok(checked);
    }
  },
);
