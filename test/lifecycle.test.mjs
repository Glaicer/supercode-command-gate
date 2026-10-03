import assert from "node:assert/strict";
import { test } from "node:test";
import { runSeam } from "./seam-driver.mjs";

test("eligible exact-session trust reviews and executes two calls using one approval", async () => {
  const evidence = await runSeam({ approval: true, trust: true });
  const result = evidence.approval.cases[0];
  assert.equal(evidence.approval.inventoryOK, true);
  assert.equal(result.pending.grantEligible, true);
  assert.equal(result.reply.accepted, true);
  assert.equal(result.modelCalls, 2);
  assert.equal(result.sideEffect, "once\nonce\n");
  assert.equal(
    result.events.filter((event) => event.kind === "approval-ask").length,
    1,
  );
  assert.ok(
    result.events.some(
      (event) => event.kind === "review-allow" && event.source === "grant",
    ),
  );
  assert.equal(
    evidence.assessorRequests.filter(
      (request) =>
        JSON.parse(
          request.messages.find((message) => message.role === "user").content,
        ).command === "bash trusted.sh",
    ).length,
    1,
  );
  const reconnect = evidence.approval.cases.find(
    (item) => item.name === "ask-reconnect",
  );
  assert.equal(reconnect.reply.accepted, false);
  assert.equal(reconnect.marker, false);
});

test("synthetic continuation preserves admitted intent but clear invalidates exact-session trust", async () => {
  const evidence = await runSeam({ lifecycle: true });
  const { calls, clear, foreignClear } = evidence.lifecycle.lifecycle;
  assert.equal(evidence.lifecycle.inventoryOK, true);
  const initialEvidence = JSON.parse(
    evidence.assessorRequests[0].messages.find(
      (message) => message.role === "user",
    ).content,
  );
  assert.equal(
    initialEvidence.contextCapsule.latestUserRequest,
    "CASE lifecycle-native — canonical-admission",
  );
  assert.equal(calls[0].reply.accepted, true);
  assert.equal(calls[1].pending, undefined);
  assert.equal(clear.invalidated, true);
  assert.ok(calls.find((item) => item.name === "after-clear").pending);
  const admission = calls.find((item) => item.name === "pending-admission");
  assert.deepEqual(admission.staleRemaining, []);
  assert.equal(admission.reply.accepted, false);
  assert.equal(admission.sideEffect, admission.sideEffectBefore);
  const goal = calls.find((item) => item.name === "pending-goal");
  assert.deepEqual(goal.staleRemaining, []);
  assert.equal(goal.reply.accepted, false);
  assert.equal(
    calls.find((item) => item.name === "custom-id-admission").assessments[0]
      .contextCapsule.latestUserRequest,
    "CASE lifecycle-native — custom-ID admission",
  );
  assert.equal(
    calls.find((item) => item.name === "goal-seed").assessments[0]
      .contextCapsule.latestUserRequest,
    "CASE lifecycle-native — replacement admitted intent",
  );
  for (const name of [
    "goal-replaced",
    "goal-cleared",
    "same-text-new-admission",
    "plugin-admission",
    "changed-script",
    "changed-dependency",
    "changed-bytes",
    "changed-cwd",
    "changed-symlink",
    "changed-policy",
    "restart",
    "reload",
    "reconnect",
    "child-inherits",
    "parent-new-intent",
    "parent-isolation",
    "child-own-admission",
    "sibling-isolation",
    "location-isolation",
    "denial-cleared",
  ])
    assert.ok(calls.find((item) => item.name === name)?.pending, name);
  for (const name of [
    "synthetic-reuse",
    "compaction-reuse",
    "restart-reuse",
    "child-reuse",
    "child-after-parent-call-reuse",
    "child-own-reuse",
    "foreign-clear-refused-reuse",
    "tab-close-reuse",
  ]) {
    const result = calls.find((item) => item.name === name);
    assert.equal(result.pending, undefined, name);
    assert.equal(result.assessments.length, 0, name);
    assert.equal(result.sideEffect, `${result.sideEffectBefore}run\n`, name);
  }
  assert.equal(foreignClear.invalidated, false);
  assert.deepEqual(calls.find((item) => item.name === "symlink-seed").targets, [
    "onefixture-ask\n",
    "two",
  ]);
  assert.deepEqual(
    calls.find((item) => item.name === "symlink-reuse").targets,
    ["onefixture-ask\nfixture-ask\n", "two"],
  );
  assert.equal(
    calls.find((item) => item.name === "symlink-reuse").assessments.length,
    0,
  );
  assert.deepEqual(
    calls.find((item) => item.name === "changed-symlink").targets,
    ["onefixture-ask\nfixture-ask\n", "two"],
  );
  const hardDeny = calls.find((item) => item.name === "fresh-hard-deny");
  assert.equal(hardDeny.pending, undefined);
  assert.equal(hardDeny.assessments.length, 0);
  assert.ok(
    evidence.lifecycle.gateEvents.some(
      (event) =>
        event.kind === "review-deny" &&
        event.source === "hard-deny" &&
        event.command.includes("fixture-ask-target"),
    ),
  );
  for (const name of ["dynamic-ineligible", "missing-script-ineligible"]) {
    const result = calls.find((item) => item.name === name);
    assert.equal(result.pending.grantEligible, false, name);
    assert.equal(result.sessionAttempt.accepted, false, name);
    assert.equal(result.sideEffect, result.sideEffectBefore, name);
  }
  assert.equal(
    calls.find((item) => item.name === "dynamic-ineligible").dynamicMarker,
    null,
  );
  assert.equal(
    calls.find((item) => item.name === "configuration-ineligible").pending
      .grantEligible,
    false,
  );
  for (const [name, text] of [
    ["after-clear", null],
    [
      "plugin-admission",
      "CASE lifecycle-native — programmatic public admission",
    ],
    ["child-inherits", "CASE lifecycle-native — programmatic public admission"],
    ["parent-new-intent", "CASE lifecycle-native — new parent intent"],
    [
      "child-own-admission",
      "CASE lifecycle-native — child own public admission",
    ],
    ["native-clear", null],
  ]) {
    const result = calls.find((item) => item.name === name);
    assert.equal(
      result.assessments[0].contextCapsule.latestUserRequest,
      text,
      name,
    );
  }
  assert.equal(
    calls.find((item) => item.name === "goal-seed").assessments[0]
      .contextCapsule.goal,
    "Inspect disposable project",
  );
  assert.equal(
    calls.find((item) => item.name === "goal-cleared").assessments[0]
      .contextCapsule.goal,
    null,
  );
  for (const name of [
    "after-clear",
    "pending-admission",
    "pending-goal",
    "changed-script",
    "changed-dependency",
    "changed-bytes",
    "changed-cwd",
    "sibling-isolation",
    "parent-isolation",
    "pending-clear",
    "after-child-clear",
    "denial-suppressed",
    "denial-cleared",
    "pending-deletion",
    "native-clear",
  ]) {
    const result = calls.find((item) => item.name === name);
    assert.equal(result.sideEffect, result.sideEffectBefore, name);
  }
  for (const name of ["pending-clear", "pending-deletion"]) {
    const result = calls.find((item) => item.name === name);
    assert.ok(result.pending, name);
    assert.equal(result.reply.accepted, false, name);
    assert.deepEqual(result.staleRemaining, [], name);
  }
  assert.equal(evidence.lifecycle.lifecycle.tabClosed.enabled, true);
  assert.ok(
    !evidence.lifecycle.lifecycle.tabClosed.tabs.some(
      (tab) => tab.sessionID === evidence.lifecycle.lifecycle.tuiSessionID,
    ),
  );
  assert.equal(
    calls.find((item) => item.name === "tab-close-reuse").pending,
    undefined,
  );
  assert.equal(evidence.lifecycle.lifecycle.nativeClear.route.type, "home");
  assert.ok(calls.find((item) => item.name === "native-clear").pending);
  const clears = evidence.lifecycle.gateEvents.filter(
    (event) =>
      event.kind === "invalidation" &&
      event.event === "clear" &&
      event.session === evidence.lifecycle.lifecycle.tuiSessionID,
  );
  assert.equal(clears.length, 1);
});
