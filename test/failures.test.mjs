import assert from "node:assert/strict";
import { test } from "node:test";
import { runSeam } from "./seam-driver.mjs";

test("explicit passthrough labels operational failures as unreviewed; defaults and invalid options deny", async () => {
  const evidence = await runSeam({ failures: true });
  for (const name of ["default", "invalid", "passthrough"]) {
    const boot = evidence[name];
    assert.equal(boot.inventoryOK, true, name);
    for (const result of boot.cases) {
      assert.equal(result.finished, true, `${name}/${result.name}`);
      assert.equal(
        result.marker,
        name === "passthrough",
        `${name}/${result.name}`,
      );
      if (name === "passthrough")
        assert.ok(
          result.events.some((event) => event.kind === "review-unreviewed"),
        );
      else assert.match(result.toolResult, /command was not executed/i);
    }
  }
  const invalidBackground = evidence.backgroundInvalid.cases[0];
  assert.equal(invalidBackground.marker, false);
  assert.match(
    invalidBackground.toolResult,
    /background execution is outside/i,
    "an invalid allowBackground value fails closed for background calls",
  );
  assert.equal(invalidBackground.finished, true);
  assert.ok(
    evidence.backgroundInvalid.gateEvents.some(
      (event) => event.kind === "startup-unavailable",
    ),
    "the invalid option is a configuration error",
  );
  for (const boot of evidence.startupFailures) {
    const result = boot.cases[0];
    const unreviewed =
      boot.name.startsWith("passthrough-") && !boot.name.endsWith("-config");
    assert.equal(boot.inventoryOK, true, boot.name);
    assert.equal(result.finished, true, boot.name);
    assert.equal(result.marker, unreviewed, boot.name);
    assert.ok(
      boot.gateEvents.some((event) => event.kind === "startup-unavailable"),
      boot.name,
    );
    if (!unreviewed)
      assert.match(result.toolResult, /command was not executed/i);
  }
});

test("passthrough never bypasses an ask, failed approval or native deny", async () => {
  const evidence = await runSeam({ approval: true, passthrough: true });
  for (const name of [
    "ask-deny",
    "ask-dismiss",
    "ask-timeout",
    "ask-no-client",
    "ask-disconnected",
    "ask-cancel",
    "ask-invalid",
    "ask-stale-intent",
    "ask-stale-goal",
    "ask-reservation",
    "ask-script",
    "ask-script-deny",
    "ask-native-deny",
  ]) {
    const result = evidence.approval.cases.find((item) => item.name === name);
    assert.ok(result, name);
    assert.equal(result.marker, false, name);
    assert.deepEqual(result.remaining, [], name);
    assert.ok(
      !result.events.some((event) => event.kind === "review-unreviewed"),
      name,
    );
  }
  assert.equal(
    evidence.approval.cases.find((item) => item.name === "ask-once").sideEffect,
    "once\n",
  );
});
