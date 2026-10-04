import assert from "node:assert/strict";
import { before, test } from "node:test";
import { runSeam } from "./seam-driver.mjs";

let evidence;
before(async () => {
  evidence = await runSeam({ neverAsk: true });
});

test("default never-ask maps every Reviewer ask to an immediate policy denial, even with a connected adapter and explicit passthrough", () => {
  const boot = evidence.neverAsk;
  assert.equal(boot.inventoryOK, true);
  assert.equal(boot.status.healthy, true);
  assert.equal(boot.status.settings.approvalMode, "never-ask");
  assert.equal(boot.status.failureMode, "passthrough");
  assert.ok(
    boot.gateEvents.some((event) => event.kind === "approval-client"),
    "one case really ran with a connected approval adapter",
  );
  for (const name of ["never-ask-adapter", "never-ask-no-adapter"]) {
    const result = boot.cases.find((item) => item.name === name);
    assert.equal(result.marker, false, name);
    assert.equal(result.modelCalls, 2, name);
    assert.equal(result.finished, true, name);
    assert.equal(result.maxPending, 0, name);
    assert.equal(result.pending, null, name);
    assert.equal(result.remaining.length, 0, name);
    const messages = result.toolResult
      .split("\n")
      .map((line) => JSON.parse(line).error.message);
    assert.ok(messages.length >= 2, name);
    for (const message of messages) {
      assert.match(message, /command was not executed/i, name);
      assert.match(
        message,
        /Human approval is required by Reviewer policy, but prompts are disabled\./,
        name,
      );
      assert.match(message, /Risk 1 of 2\nRisk: Critical data loss/, name);
      assert.match(message, /Risk 2 of 2\nRisk: Network access/, name);
      assert.match(
        message,
        /Evidence:\nDeterministic fake assessment for the Command Gate seam/,
        name,
      );
      assert.match(message, /• Backup availability is unknown/, name);
    }
    assert.equal(
      new Set(messages).size,
      1,
      `${name}: every identical retry is denied identically`,
    );
    assert.equal(
      result.events.filter((event) => event.kind === "approval-ask").length,
      0,
      name,
    );
    assert.equal(
      result.events.filter((event) => event.kind === "human-response").length,
      0,
      name,
    );
    assert.equal(
      result.events.filter(
        (event) => event.kind === "review-deny" && event.mappedFrom === "ask",
      ).length,
      2,
      name,
    );
    assert.equal(
      result.events.filter((event) => event.kind === "review-unreviewed")
        .length,
      0,
      `${name}: Ask-to-Deny is a policy refusal, never passthrough`,
    );
  }
});
