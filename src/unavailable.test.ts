import assert from "node:assert/strict";
import { test } from "node:test";
import { unavailableDecisionAlert, UnavailableAlerts } from "./unavailable.ts";

test("only structured Assessor failures create Assessor unavailable episodes", () => {
  for (const kind of [undefined, "unknown-kind"]) {
    const alerts = new UnavailableAlerts();
    const diagnostic = unavailableDecisionAlert(kind);
    alerts.fail("session", diagnostic.component, diagnostic.reason);
    assert.equal(alerts.list("session")[0].component, "reviewer");
    assert.doesNotMatch(alerts.list("session")[0].reason, /Assessor/);
  }
  for (const kind of [
    "provider-outage",
    "invalid-json",
    "schema-invalid",
    "context-evidence",
  ]) {
    const diagnostic = unavailableDecisionAlert(kind);
    assert.equal(diagnostic.component, "assessor");
    assert.match(diagnostic.reason, /Command Risk Assessor unavailable/);
  }
});

test("repeated generic review failures remain one episode until a healthy review", () => {
  const alerts = new UnavailableAlerts();
  const generic = unavailableDecisionAlert();
  alerts.reviewed("session", { source: "unavailable" });
  const first = alerts.fail("session", generic.component, generic.reason);
  assert.ok(first);
  alerts.reviewed("session", { source: "unavailable", failureKind: "unknown" });
  assert.equal(alerts.fail("session", generic.component, generic.reason), null);
  assert.equal(alerts.list("session")[0].id, first.id);
  alerts.reviewed("session", { source: "assessor" });
  assert.deepEqual(alerts.list("session"), []);
  const next = alerts.fail("session", generic.component, generic.reason);
  assert.notEqual(next?.id, first.id);
});
