import assert from "node:assert/strict";
import { test } from "node:test";
import { runSeam } from "./seam-driver.mjs";

test(
  "real target TUI sends actual human once / exact-session trust / Deny",
  { skip: process.env.GATE_HUMAN !== "1" },
  async () => {
    const evidence = await runSeam({
      approval: true,
      human: true,
      humanTrust: true,
    });
    assert.equal(evidence.approval.inventoryOK, true);
    const once = evidence.approval.cases.find(
      (item) => item.name === "human-once",
    );
    const denied = evidence.approval.cases.find(
      (item) => item.name === "human-deny",
    );
    const trusted = evidence.approval.cases.find(
      (item) => item.name === "human-session",
    );
    assert.equal(once.sideEffect, "once\nonce\n");
    assert.equal(once.modelCalls, 2);
    assert.equal(
      once.events.filter((event) => event.kind === "human-response").length,
      2,
    );
    assert.equal(trusted.sideEffect, "once\nonce\n");
    assert.equal(trusted.modelCalls, 2);
    assert.equal(
      trusted.events.filter((event) => event.kind === "human-response").length,
      1,
    );
    assert.equal(denied.marker, false);
    for (const [result, decision] of [
      [once, "once"],
      [trusted, "session"],
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
