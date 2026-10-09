import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { before, test } from "node:test";
import path from "node:path";
import { runSeam } from "./seam-driver.mjs";

let evidence;
before(async () => {
  evidence = await runSeam({
    backgroundGrants: true,
    expectedVersion: process.env.GATE_PROBE_VERSION ?? "2.0.22",
  });
});

const find = (boot, name) => {
  const result = boot.cases.find((item) => item.name === name);
  assert.ok(result, `missing background grants case ${name}`);
  return result;
};

const waitForMarkerContent = async (boot, result, expected) => {
  const file = path.join(boot.project, `${result.name}.marker`);
  const deadline = Date.now() + 5000;
  let content = null;
  for (;;) {
    content = await readFile(file, "utf8").catch(() => null);
    if (content === expected) return;
    if (Date.now() >= deadline) break;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.equal(content, expected, `${result.name} marker content`);
};

test("interactive: a background ask opens the ordinary dialog and Allow once runs it via a real reserved grant", async () => {
  const boot = evidence.backgroundInteractive;
  assert.equal(boot.inventoryOK, true);
  assert.equal(boot.status.settings.approvalMode, "interactive");
  const result = find(boot, "bg-ask-once");
  assert.equal(result.reply.accepted, true);
  assert.equal(result.modelCalls, 1);
  assert.equal(result.finished, true);
  assert.equal(result.pending.grantEligible, true);
  const ask = result.events.find((event) => event.kind === "approval-ask");
  assert.ok(ask, "the background ask reaches the approval queue");
  assert.equal(ask.background, true);
  const reviews = boot.auditRecords
    .filter(
      (record) => record.requestFingerprint === result.pending.fingerprint,
    )
    .sort((a, b) => a.recordedAt.localeCompare(b.recordedAt));
  assert.deepEqual(
    reviews.map((record) => record.decision),
    ["ask", "allow"],
  );
  assert.equal(
    reviews.every((record) => record.background === true),
    true,
    "the reviewer audit carries the background fact",
  );
  assert.equal(
    result.events.find((event) => event.kind === "approval-fresh").source,
    "grant",
  );
  await waitForMarkerContent(boot, result, "once\n");
});

test("interactive: Trust for this session covers repeated background invocations of the same command", async () => {
  const boot = evidence.backgroundInteractive;
  const result = find(boot, "bg-trust-bg");
  assert.equal(result.reply.accepted, true);
  assert.equal(result.modelCalls, 2);
  assert.equal(result.finished, true);
  assert.equal(
    result.events.filter((event) => event.kind === "approval-ask").length,
    1,
    "the trusted background retry does not ask again",
  );
  assert.ok(
    result.events.some(
      (event) =>
        event.kind === "review-allow" &&
        event.source === "grant" &&
        event.background === true,
    ),
  );
  assert.equal(
    evidence.assessorRequests.filter((text) =>
      text.includes("bg-trust-bg.marker"),
    ).length,
    1,
    "the trusted background retry is not re-assessed",
  );
  await waitForMarkerContent(boot, result, "once\nonce\n");
});

test("interactive: Trust on a background ask never authorizes the same foreground command", async () => {
  const boot = evidence.backgroundInteractive;
  const result = find(boot, "bg-trust-fg-asks");
  assert.deepEqual(
    result.reply.map((item) => item.accepted),
    [true, true],
  );
  assert.equal(result.modelCalls, 2);
  assert.equal(result.finished, true);
  assert.equal(result.pendings.length, 2);
  assert.notEqual(
    result.pendings[0].fingerprint,
    result.pendings[1].fingerprint,
    "the background grant fingerprint never matches the foreground command",
  );
  const asks = result.events.filter((event) => event.kind === "approval-ask");
  assert.equal(asks.length, 2);
  assert.equal(asks[0].background, true);
  assert.equal("background" in asks[1], false);
  assert.equal(
    evidence.assessorRequests.filter((text) =>
      text.includes("bg-trust-fg-asks.marker"),
    ).length,
    2,
    "the foreground re-invocation gets a fresh assessment",
  );
  await waitForMarkerContent(boot, result, "once\n");
});

test("interactive: Trust on a foreground ask never authorizes a background invocation of the same command", async () => {
  const boot = evidence.backgroundInteractive;
  const result = find(boot, "fg-trust-bg-asks");
  assert.deepEqual(
    result.reply.map((item) => item.accepted),
    [true, true],
  );
  assert.equal(result.modelCalls, 2);
  assert.equal(result.finished, true);
  assert.equal(result.pendings.length, 2);
  assert.notEqual(
    result.pendings[0].fingerprint,
    result.pendings[1].fingerprint,
    "the foreground grant fingerprint never matches the background command",
  );
  const asks = result.events.filter((event) => event.kind === "approval-ask");
  assert.equal(asks.length, 2);
  assert.equal("background" in asks[0], false);
  assert.equal(asks[1].background, true);
  assert.equal(
    evidence.assessorRequests.filter((text) =>
      text.includes("fg-trust-bg-asks.marker"),
    ).length,
    2,
    "the background re-invocation gets a fresh assessment",
  );
  await waitForMarkerContent(boot, result, "once\n");
});

test("never-ask: a background ask becomes the ordinary policy refusal with the Reviewer reason and the fixed phrase", () => {
  const boot = evidence.backgroundNeverAsk;
  assert.equal(boot.inventoryOK, true);
  assert.equal(boot.status.settings.approvalMode, "never-ask");
  const result = find(boot, "bg-never-ask");
  assert.equal(result.marker, false);
  assert.equal(result.modelCalls, 2);
  assert.equal(result.finished, true);
  assert.equal(result.maxPending, 0);
  assert.equal(result.pending, null);
  assert.equal(result.remaining.length, 0);
  assert.equal(
    result.events.filter((event) => event.kind === "approval-ask").length,
    0,
  );
  const denial = result.events.find(
    (event) => event.kind === "review-deny" && event.mappedFrom === "ask",
  );
  assert.ok(denial, "the background ask is logged as a mapped policy denial");
  assert.equal(denial.background, true);
  assert.equal(
    result.events.filter((event) => event.kind === "review-unreviewed").length,
    0,
  );
  const messages = result.toolResult
    .split("\n")
    .map((line) => JSON.parse(line).error.message);
  assert.ok(messages.length >= 2);
  assert.equal(
    new Set(messages).size,
    1,
    "every identical retry is denied identically",
  );
  for (const message of messages) {
    assert.match(message, /command was not executed/i);
    assert.match(
      message,
      /Human approval is required by Reviewer policy, but prompts are disabled\./,
    );
    assert.ok(
      message.includes(denial.reason),
      "the refusal keeps the original Reviewer reason",
    );
    assert.match(message, /Risk 1 of 1\nRisk: Critical data loss/);
    assert.match(
      message,
      /Evidence:\nDeterministic fake assessment for the Command Gate seam/,
    );
  }
});

test("passthrough: a Reviewer failure on a background invocation executes unreviewed with a visible event", () => {
  const boot = evidence.backgroundPassthrough;
  assert.equal(boot.inventoryOK, true);
  assert.equal(boot.status.failureMode, "passthrough");
  const result = find(boot, "bg-passthrough");
  assert.equal(result.finished, true);
  assert.equal(result.marker, true);
  const unreviewed = result.events.find(
    (event) => event.kind === "review-unreviewed",
  );
  assert.ok(unreviewed, "the unreviewed background execution is visible");
  assert.equal(unreviewed.background, true);
  assert.match(
    unreviewed.message,
    /UNREVIEWED execution: explicit onReviewerFailure passthrough/,
  );
});

test("default: background stays an explicit coverage refusal before any review", () => {
  const boot = evidence.backgroundDefault;
  assert.equal(boot.inventoryOK, true);
  const result = find(boot, "bg-default-reject");
  assert.equal(result.marker, false);
  assert.equal(result.finished, true);
  assert.match(result.toolResult, /background execution is outside/i);
  assert.match(result.toolResult, /command was not executed/i);
  assert.equal(
    result.events.filter((item) => item.kind.startsWith("review")).length,
    0,
    "the refusal happens before any review",
  );
});
