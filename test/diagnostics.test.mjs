import assert from "node:assert/strict";
import { test } from "node:test";
import { runSeam } from "./seam-driver.mjs";

test("target TUI exposes doctor health, missing Reviewer and explicit unreviewed mode without duplicated options", async () => {
  const evidence = await runSeam({ diagnostics: true });
  for (const boot of evidence.diagnostics) {
    assert.equal(boot.inventoryOK, true, boot.name);
    assert.match(boot.diagnostics, /CommandGate—health/, boot.name);
    assert.match(boot.diagnostics, /binaryPath/, boot.name);
    assert.match(boot.diagnostics, /approvalAvailable/, boot.name);
    assert.equal(boot.status.settings.tools.length, 2);
    assert.equal(
      boot.inventory.filter((plugin) => plugin.id === "command-gate").length,
      1,
    );
  }
  const [healthy, missing, passthrough, healthyPassthrough] =
    evidence.diagnostics;
  assert.equal(healthy.status.healthy, true);
  assert.equal(missing.status.healthy, false);
  assert.match(missing.diagnostics, /Commands.*remaindenied/);
  assert.equal(passthrough.status.failureMode, "passthrough");
  assert.match(passthrough.diagnostics, /UNREVIEWED/);
  assert.equal(healthyPassthrough.status.healthy, true);
  assert.match(healthyPassthrough.diagnostics, /UNREVIEWED/);
  assert.ok(
    healthyPassthrough.gateEvents.some(
      (event) => event.kind === "startup-unreviewed",
    ),
  );
});
