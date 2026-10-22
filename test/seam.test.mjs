import assert from "node:assert/strict";
import { before, test } from "node:test";
import path from "node:path";
import {
  COMPOUND_ALLOW_COMMAND,
  COMPOUND_COMMAND,
  INVOCATION_COMMAND,
  runSeam,
} from "./seam-driver.mjs";

let evidence;
before(async () => {
  evidence = await runSeam({
    minimumVersion: process.env.GATE_PROBE_VERSION ?? "2.0.22",
  });
});

const find = (boot, name) => {
  const result = boot.cases.find((item) => item.name === name);
  assert.ok(result, `missing seam case ${name}`);
  return result;
};
const reviewOf = (result, kind) => {
  const event = result.events.find((item) => item.kind === kind);
  assert.ok(event, `missing ${kind} event for ${result.name}`);
  return event;
};

test("every boot activates the Gate and startup validates the Reviewer contract", () => {
  for (const boot of [
    evidence.main,
    evidence.checkFailures,
    evidence.doctorFail,
    evidence.missingBinary,
    evidence.nonBash,
  ]) {
    assert.equal(boot.inventoryOK, true, boot.name);
  }
  const doctor = evidence.main.gateEvents.find(
    (item) => item.kind === "doctor-ok",
  );
  assert.ok(doctor, "the healthy boot must report a passing doctor");
  assert.equal(doctor.reviewerTimeoutMs, 5000);
});

test("public health distinguishes Reviewer failure and absent approval adapter and delivers server settings", () => {
  assert.equal(evidence.main.status.healthy, true);
  assert.equal(evidence.main.status.approvalAvailable, false);
  assert.equal(evidence.main.status.failureMode, "deny");
  assert.deepEqual(evidence.main.status.settings, {
    binaryPath: `${evidence.root}/aar`,
    tools: ["bash", "shell"],
    timeoutMs: 5500,
    approvalTimeoutMs: 600000,
    approvalMode: "never-ask",
    commandRewriter: "none",
    rewriterPath: "rtk",
  });
  for (const boot of [evidence.doctorFail, evidence.missingBinary]) {
    assert.equal(boot.status.healthy, false);
    assert.ok(boot.status.reason.length > 0);
    assert.equal(boot.status.failureMode, "deny");
  }
});

test("real auto-allow and assessor allow run exactly one native invocation", () => {
  assert.equal(evidence.main.status.settings.approvalMode, "never-ask");
  const autoAllow = find(evidence.main, "auto-allow");
  assert.equal(autoAllow.modelCalls, 1);
  assert.equal(autoAllow.toolResult.trim(), evidence.main.project);
  assert.equal(autoAllow.finished, true);
  const autoReview = reviewOf(autoAllow, "review-allow");
  assert.equal(autoReview.source, "auto-allow");
  assert.equal(
    evidence.main.auditRecords.filter(
      (record) => record.command === "pwd" && record.decision === "allow",
    ).length,
    1,
    "the reviewed command runs exactly once",
  );

  const safe = find(evidence.main, "assessor-allow");
  assert.equal(safe.marker, true, "the safe marker appears exactly once");
  assert.equal(safe.modelCalls, 1);
  assert.equal(safe.finished, true);
  assert.equal(reviewOf(safe, "review-allow").source, "assessor");
  assert.equal(
    evidence.main.auditRecords.filter(
      (record) => record.command === "touch safe.marker",
    ).length,
    1,
    "exactly one reviewed invocation for the safe marker",
  );
});

test("assessor deny and hard deny stop before process start and the session continues", () => {
  assert.equal(evidence.main.status.settings.approvalMode, "never-ask");
  const denied = find(evidence.main, "assessor-deny");
  assert.equal(denied.marker, false, "the denied marker must stay absent");
  assert.match(denied.toolResult, /command was not executed/i);
  assert.equal(denied.finished, true);
  const review = reviewOf(denied, "review-deny");
  assert.equal(review.source, "assessor");
  const message = JSON.parse(denied.toolResult).error.message;
  assert.ok(message.includes(review.reason));
  assert.match(message, /Risk 1 of 2\nRisk: Critical data loss/);
  assert.match(message, /Severity: Critical · Likelihood: Certain/);
  assert.match(message, /Reversible: No · Protected paths affected: Yes/);
  assert.match(
    message,
    /Evidence:\nDeterministic fake assessment for the Command Gate seam/,
  );
  assert.match(message, /Risk 2 of 2\nRisk: Network access/);
  assert.match(message, /The command may contact a remote service/);
  assert.match(
    message,
    /• Backup availability is unknown\n• Remote behavior is unknown/,
  );
  assert.doesNotMatch(message, /"risks"|"env"/);
  assert.equal(
    review.command,
    "export PROOF_SUB=$(printf side-effect > denied.marker); printf '%s' fixture-deny",
    "substitutions stay inside the reviewed bytes",
  );

  const hard = find(evidence.main, "hard-deny");
  assert.match(hard.toolResult, /command was not executed/i);
  assert.equal(hard.finished, true);
  assert.equal(reviewOf(hard, "review-deny").source, "hard-deny");
  const hardAudit = evidence.main.auditRecords.find(
    (record) =>
      record.command === "printf x > /etc" && record.decision === "deny",
  );
  assert.ok(hardAudit?.rule);
  const hardMessage = JSON.parse(hard.toolResult).error.message;
  assert.ok(hardMessage.includes(`Rule: ${hardAudit.rule}`));
  assert.ok(hardMessage.includes(reviewOf(hard, "review-deny").reason));
  assert.doesNotMatch(hardMessage, /Risk:|Uncertainties:|Reversible:/);
  assert.equal(
    evidence.assessorRequests.filter((text) => text.includes("printf x > /etc"))
      .length,
    0,
    "hard deny stops before any assessor call",
  );
});

test("compound programs and scanner-empty commands are reviewed verbatim", () => {
  const compound = find(evidence.main, "compound");
  assert.equal(compound.marker, false);
  assert.equal(compound.finished, true);
  assert.match(
    compound.toolResult,
    /Human approval is required by Reviewer policy, but prompts are disabled\./,
  );
  const compoundReview = reviewOf(compound, "review-deny");
  assert.equal(compoundReview.mappedFrom, "ask");
  assert.equal(compoundReview.command, COMPOUND_COMMAND);
  assert.match(compoundReview.reason, /uncertainty/i);

  assert.ok(
    evidence.main.auditRecords.some(
      (record) =>
        record.command === COMPOUND_COMMAND &&
        record.cwd === evidence.main.project,
    ),
    "the audit keeps the exact reviewed bytes and cwd",
  );

  const compoundAllow = find(evidence.main, "compound-allow");
  assert.equal(compoundAllow.marker, true);
  assert.equal(compoundAllow.finished, true);
  assert.equal(
    reviewOf(compoundAllow, "review-allow").command,
    COMPOUND_ALLOW_COMMAND,
  );
  assert.equal(
    evidence.main.auditRecords.filter(
      (record) => record.command === COMPOUND_ALLOW_COMMAND,
    ).length,
    1,
  );

  const scannerEmpty = find(evidence.main, "scanner-empty");
  assert.match(scannerEmpty.toolResult, /command was not executed/i);
  assert.equal(scannerEmpty.finished, true);
  assert.equal(reviewOf(scannerEmpty, "review-deny").source, "assessor");
});

test("reviewed cwd and env facts match the actual invocation without forwarding secrets", () => {
  const invocation = find(evidence.main, "invocation");
  assert.equal(invocation.marker, true);
  const review = reviewOf(invocation, "review-allow");
  assert.equal(review.cwd, evidence.main.canonicalWorkdir);
  assert.equal(review.command, INVOCATION_COMMAND);
  assert.equal(
    review.env.HOME,
    path.resolve(evidence.main.project, "../home/session-home"),
  );
  assert.equal(review.env.CDPATH, `${evidence.main.project}/other`);
  assert.deepEqual(Object.keys(review.env).sort(), ["CDPATH", "HOME", "PATH"]);
  assert.ok(review.env.PATH.length > 0);
  assert.equal("PROOF_ENV" in review.env, false, "session secrets stay out");
  assert.equal("OPENCODE_SERVER_PASSWORD" in review.env, false);
  const audit = evidence.main.auditRecords.find(
    (record) => record.command === INVOCATION_COMMAND,
  );
  assert.ok(audit, "the audit records the reviewed invocation bytes");
  assert.equal(audit.cwd, evidence.main.canonicalWorkdir);

  const goal = find(evidence.main, "goal-intent");
  assert.equal(goal.marker, true);
  const goalReview = reviewOf(goal, "review-allow");
  assert.equal(goalReview.goal, "Inspect only this disposable project");
  assert.ok(goalReview.intentId.length > 0);
});

test("default never-ask maps Reviewer ask to an immediate policy denial without approval state", () => {
  const ask = find(evidence.main, "ask-refusal");
  assert.equal(ask.marker, false);
  const message = JSON.parse(ask.toolResult).error.message;
  assert.match(message, /command was not executed/i);
  assert.match(
    message,
    /Human approval is required by Reviewer policy, but prompts are disabled\./,
  );
  assert.match(message, /Risk: Critical data loss/);
  assert.match(
    message,
    /Evidence:\nDeterministic fake assessment for the Command Gate seam/,
  );
  assert.equal(ask.finished, true);
  assert.equal(ask.maxPending ?? 0, 0);
  assert.equal(ask.remaining.length, 0);
  assert.equal(
    ask.events.filter((event) => event.kind === "approval-ask").length,
    0,
  );
  const denial = ask.events.find(
    (event) => event.kind === "review-deny" && event.mappedFrom === "ask",
  );
  assert.ok(denial, "the ask is logged as a mapped policy denial");
  assert.equal(denial.source, "assessor");
});

test("background invocations are reviewed by default and run in the host background", () => {
  const background = find(evidence.main, "background-default");
  assert.equal(
    background.marker,
    true,
    "the reviewed background command really executes",
  );
  assert.equal(background.finished, true);
  assert.match(background.toolResult, /Command moved to the background/);
  assert.equal(
    reviewOf(background, "review-allow").background,
    true,
    "the review-allow event logs the background fact",
  );
});

test("allowBackground: false refuses background invocations before any review", () => {
  const background = find(evidence.backgroundDisabled, "background-refuse");
  assert.equal(background.marker, false);
  assert.match(background.toolResult, /background execution is outside/i);
  assert.match(background.toolResult, /command was not executed/i);
  assert.equal(
    background.events.filter((item) => item.kind.startsWith("review")).length,
    0,
    "background refuses before any review",
  );
  assert.equal(background.finished, true);
});

test("non-Bash invocations refuse explicitly", () => {
  const sh = find(evidence.nonBash, "shcase");
  assert.equal(sh.marker, false);
  assert.match(sh.toolResult, /unsupported shell/i);
  assert.match(sh.toolResult, /command was not executed/i);
});

test("allowBackground reviews background invocations and runs them in the host background", () => {
  const boot = evidence.background;
  assert.equal(
    boot.inventoryOK,
    true,
    "the allowBackground boot activates the Gate",
  );

  const allow = find(boot, "background-allow");
  assert.equal(
    allow.marker,
    true,
    "the reviewed background command really executes",
  );
  assert.equal(allow.finished, true);
  assert.match(allow.toolResult, /Command moved to the background/);
  const allowReview = reviewOf(allow, "review-allow");
  assert.equal(
    allowReview.background,
    true,
    "the review-allow event logs the background fact",
  );
  const allowAudit = boot.auditRecords.find(
    (record) => record.command === "touch background-allow.marker",
  );
  assert.ok(allowAudit, "the background request reached the reviewer");
  assert.equal(
    allowAudit.background,
    true,
    "the review request to aar carries background: true",
  );

  const deny = find(boot, "background-deny");
  assert.equal(deny.marker, false);
  assert.match(deny.toolResult, /command was not executed/i);
  assert.equal(deny.finished, true);
  const denyReview = reviewOf(deny, "review-deny");
  assert.equal(denyReview.background, true);
  assert.equal(denyReview.source, "assessor");

  const foreground = find(boot, "foreground-unchanged");
  assert.equal(foreground.marker, true);
  assert.equal(foreground.finished, true);
  const foregroundReview = reviewOf(foreground, "review-allow");
  assert.equal(
    "background" in foregroundReview,
    false,
    "foreground events stay unchanged",
  );
  const foregroundAudit = boot.auditRecords.find(
    (record) => record.command === "touch foreground-unchanged.marker",
  );
  assert.ok(foregroundAudit);
  assert.equal(
    "background" in foregroundAudit,
    false,
    "foreground requests omit the background field entirely",
  );
});

test("child sessions pass the same Gate while non-shell tools and human shell stay untouched", () => {
  const child = find(evidence.main, "child-allow");
  assert.equal(child.marker, true);
  assert.equal(reviewOf(child, "review-allow").session, child.sessionID);

  const read = find(evidence.main, "read-tool");
  assert.equal(
    read.events.filter((item) => item.kind.startsWith("review")).length,
    0,
    "non-shell tools are not intercepted",
  );
  assert.ok(read.toolResult.length > 0, "the read tool still works");

  assert.equal(evidence.main.bypass.marker, true);
  assert.equal(
    evidence.main.bypass.events.length,
    0,
    "human shell bypasses the review",
  );
});

test("native permissions stay authoritative and the shell Decision authorizes nothing else", () => {
  const native = find(evidence.main, "native-deny");
  assert.equal(native.marker, false);
  assert.ok(native.events.some((item) => item.kind === "review-allow"));
  assert.doesNotMatch(native.toolResult, /Command Gate blocked this command/i);
  assert.match(native.toolResult, /denied|permission|not allowed/i);

  const external = find(evidence.main, "external-dir");
  assert.equal(external.marker, false);
  assert.ok(external.events.some((item) => item.kind === "review-allow"));
  assert.doesNotMatch(
    external.toolResult,
    /Command Gate blocked this command/i,
  );
  assert.match(external.toolResult, /denied|permission|not allowed/i);

  const other = find(evidence.main, "other-location");
  assert.equal(other.marker, true);
  assert.equal(reviewOf(other, "review-allow").session, other.sessionID);
});

test("operational Reviewer failures deny by default without dropping the interception", () => {
  const expectations = {
    "fixture-nonzero": /exited unsuccessfully/,
    "fixture-malformed": /unavailable/,
    "fixture-multi": /invalid stdout/,
    "fixture-invalid": /invalid decision/,
    "fixture-timeout": /timeout|timed out/,
  };
  for (const [name, pattern] of Object.entries(expectations)) {
    const result = find(evidence.checkFailures, name);
    assert.equal(result.marker, false, name);
    assert.match(result.toolResult, /command was not executed/i, name);
    assert.match(result.toolResult, pattern, name);
    assert.match(result.toolResult, /Command Gate is unavailable/i, name);
    assert.doesNotMatch(
      result.toolResult,
      /Risk:|Uncertainties:|Reversible:/,
      name,
    );
    assert.equal(result.finished, true, name);
    assert.ok(
      result.events.some((item) => item.kind === "review-deny"),
      `denial must come from the interception (${name})`,
    );
  }
  for (const [label, boot] of [
    ["unhealthy doctor", evidence.doctorFail],
    ["missing binary", evidence.missingBinary],
  ]) {
    const result = boot.cases[0];
    assert.equal(result.marker, false, label);
    assert.match(result.toolResult, /Command Gate is unavailable/i, label);
    assert.match(result.toolResult, /command was not executed/i, label);
    assert.equal(result.finished, true, label);
    const diagnostic = boot.gateEvents.find(
      (item) => item.kind === "startup-unavailable",
    );
    assert.ok(diagnostic, `startup diagnostic missing for ${label}`);
    assert.ok(diagnostic.reason.length > 0);
  }
});
