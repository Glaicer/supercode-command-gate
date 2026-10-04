import assert from "node:assert/strict";
import { before, test } from "node:test";
import { runSeam } from "./seam-driver.mjs";

let evidence;
before(async () => {
  evidence = await runSeam({ approval: true });
});

test("Allow once resumes the same native call after a real reserved grant and fresh review", () => {
  const result = evidence.approval.cases[0];
  assert.equal(evidence.approval.inventoryOK, true);
  assert.equal(result.reply.accepted, true);
  assert.equal(result.modelCalls, 1);
  assert.equal(result.sideEffect, "once\n");
  assert.equal(result.finished, true);
  assert.ok(result.pending.fingerprint);
  const reviews = evidence.approval.auditRecords
    .filter(
      (record) => record.requestFingerprint === result.pending.fingerprint,
    )
    .sort((a, b) => a.recordedAt.localeCompare(b.recordedAt));
  assert.deepEqual(
    reviews.map((record) => record.decision),
    ["ask", "allow"],
  );
  assert.equal(
    result.events.find((event) => event.kind === "approval-fresh").source,
    "grant",
  );
});

test("Deny records a real deny-note and suppresses an identical model retry", () => {
  const result = evidence.approval.cases.find(
    (item) => item.name === "ask-deny",
  );
  assert.equal(result.reply.accepted, true);
  assert.equal(result.marker, false);
  assert.equal(result.modelCalls, 2);
  assert.equal(result.finished, true);
  assert.equal(
    result.events.filter((event) => event.kind === "approval-ask").length,
    1,
  );
  assert.ok(
    result.events.some(
      (event) => event.kind === "review-deny" && event.source === "deny-note",
    ),
  );
});

test("dismissal, bounded timeout, unavailable/disconnected clients and cancellation never execute", () => {
  for (const name of [
    "ask-dismiss",
    "ask-timeout",
    "ask-no-client",
    "ask-disconnected",
    "ask-cancel",
    "ask-invalid",
  ]) {
    const result = evidence.approval.cases.find((item) => item.name === name);
    assert.equal(result.marker, false, name);
    assert.equal(result.remaining.length, 0, name);
    assert.equal(
      result.events.some((event) => event.kind === "approval-fresh"),
      false,
      name,
    );
  }
  const invalid = evidence.approval.cases.find(
    (item) => item.name === "ask-invalid",
  );
  for (const reply of Object.values(invalid.reply))
    assert.equal(reply.accepted, false);
});

test("Allow once cannot authorize the next identical call or a duplicate reply", () => {
  const result = evidence.approval.cases.find(
    (item) => item.name === "ask-consumed",
  );
  assert.equal(result.modelCalls, 2);
  assert.equal(result.sideEffect, "once\n");
  assert.equal(result.reply.duplicate.accepted, false);
  assert.equal(
    result.events.filter(
      (event) => event.kind === "approval-fresh" && event.source === "grant",
    ).length,
    1,
  );
  assert.equal(
    result.events.filter((event) => event.kind === "approval-ask").length,
    2,
  );
});

test("changed scripts, intent and Goal cannot execute using the old human response", () => {
  for (const name of [
    "ask-script",
    "ask-script-deny",
    "ask-stale-intent",
    "ask-stale-goal",
    "ask-reservation",
  ]) {
    const result = evidence.approval.cases.find((item) => item.name === name);
    assert.equal(result.marker, false, name);
    assert.equal(result.remaining.length, 0, name);
  }
  for (const name of ["ask-stale-intent", "ask-stale-goal"]) {
    assert.equal(
      evidence.approval.cases.find((item) => item.name === name).reply.accepted,
      false,
    );
  }
  const scriptDenied = evidence.approval.cases.find(
    (item) => item.name === "ask-script-deny",
  );
  const denied = scriptDenied.events.find(
    (event) => event.kind === "approval-fresh",
  );
  assert.equal(denied.source, "assessor");
  assert.equal(denied.decision, "deny");
  const message = JSON.parse(scriptDenied.toolResult).error.message;
  assert.match(message, /Risk: Critical data loss/);
  assert.match(
    message,
    /Evidence:\nDeterministic fake assessment for the Command Gate seam/,
  );
  assert.match(message, /The command was not executed\.$/);
  assert.equal(scriptDenied.finished, true);
  const script = evidence.approval.cases.find(
    (item) => item.name === "ask-script",
  );
  const fresh = script.events.find((event) => event.kind === "approval-fresh");
  assert.notEqual(fresh.fingerprint, script.pending.fingerprint);
  assert.notEqual(fresh.source, "grant");
});

test("a human approval still cannot override configured native deny", () => {
  const result = evidence.approval.cases.find(
    (item) => item.name === "ask-native-deny",
  );
  assert.equal(result.reply.accepted, true);
  assert.equal(result.marker, false);
  assert.match(result.toolResult, /denied|permission|not allowed/i);
});

test("a failed deny-note still suppresses a retry rather than prompting again", () => {
  const result = evidence.denialFailure.cases[0];
  assert.equal(result.marker, false);
  assert.equal(result.modelCalls, 2);
  assert.equal(result.finished, true);
  assert.equal(
    result.events.filter((event) => event.kind === "approval-ask").length,
    1,
  );
  assert.ok(
    result.events.some((event) => event.kind === "approval-deny-note-failed"),
  );
});

test("retained human Deny overrides a later assessor allow even if deny-note failed", () => {
  const result = evidence.denialFailure.cases.find(
    (item) => item.name === "denial-allow",
  );
  assert.equal(result.modelCalls, 2);
  assert.equal(result.marker, false);
  assert.equal(result.finished, true);
});

test("recovering a failed approval of B cannot erase the human Deny for A", () => {
  const result = evidence.denialFailure.cases.find(
    (item) => item.name === "denial-recovery",
  );
  assert.equal(result.modelCalls, 3);
  assert.equal(result.reply.recovery.accepted, true);
  assert.equal(result.marker, false);
  assert.equal(result.finished, true);
});
