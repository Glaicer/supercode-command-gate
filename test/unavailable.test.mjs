import assert from "node:assert/strict";
import { test } from "node:test";
import { runSeam } from "./seam-driver.mjs";

test("blocked operational outcomes create scoped episodes with component recovery", async () => {
  const evidence = await runSeam({
    unavailableAlerts: true,
    minimumVersion: process.env.GATE_PROBE_VERSION ?? "2.0.22",
  });
  const results = evidence.unavailable.cases;
  const assessor = results.find((item) => item.name === "assessor-outages");
  const transport = results.find((item) => item.name === "transport-outages");
  const policy = results.find((item) => item.name === "policy-refusal");
  for (const result of results) {
    assert.equal(result.marker, false);
    assert.equal(result.finished, true);
  }
  for (const [result, component] of [
    [assessor, "assessor"],
    [transport, "reviewer"],
  ]) {
    const episodes = result.events.filter(
      (item) => item.kind === "unavailable-alert",
    );
    assert.equal(episodes.length, 2, result.name);
    assert.notEqual(episodes[0].id, episodes[1].id);
    assert.ok(
      episodes.every(
        (item) =>
          item.component === component && item.sessionID === result.sessionID,
      ),
    );
    assert.equal(result.alerts.length, 1);
    assert.equal(result.alerts[0].id, episodes[1].id);
    assert.doesNotMatch(
      JSON.stringify(result.alerts),
      /fixture-private-secret|provider body/,
    );
  }
  const unavailableAsk = results.find(
    (item) => item.name === "unavailable-ask",
  );
  assert.equal(unavailableAsk.alerts[0].component, "assessor");
  const fresh = evidence.freshUnavailable.cases[0];
  assert.equal(fresh.marker, false);
  assert.equal(fresh.alerts[0].component, "assessor");
  assert.match(fresh.toolResult, /Command Gate is unavailable/);
  assert.deepEqual(policy.alerts, []);
  assert.ok(!policy.events.some((item) => item.kind === "unavailable-alert"));
});

test("real TUI displays operational alert and dismisses without native execution", async () => {
  const evidence = await runSeam({
    unavailableAlerts: true,
    tuiUnavailable: true,
    minimumVersion: process.env.GATE_PROBE_VERSION ?? "2.0.22",
  });
  const result = evidence.unavailable.cases[0];
  assert.equal(result.marker, false);
  assert.equal(result.finished, true);
  assert.equal(evidence.unavailable.unavailableUI.visible, true);
  assert.equal(evidence.unavailable.unavailableUI.dismissed, true);
  assert.ok(!result.events.some((item) => item.kind === "human-response"));
});
