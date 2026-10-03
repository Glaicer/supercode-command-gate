import assert from "node:assert/strict";
import { before, test } from "node:test";
import { runProbe } from "./run.mjs";

let evidence;
before(async () => {
  evidence = await runProbe();
});

test("real Reviewer denial reaches the model before substitutions, and the session continues", () => {
  assert.equal(evidence.version, "2.0.22");
  assert.equal(evidence.inventoryOK, true);
  const review = evidence.cases
    .find((item) => item.name === "assessor-deny")
    .events.find((item) => item.kind === "review").event;
  assert.equal(review.decision.source, "assessor");
  assert.equal(review.decision.decision, "deny");
  assert.equal(
    review.request.command,
    "export PROOF_SUB=$(printf side-effect > assessor-deny.marker); printf '%s' harmless",
  );
  for (const name of ["assessor-deny", "scanner-empty-deny"]) {
    const result = evidence.cases.find((item) => item.name === name);
    assert.equal(result.marker, false, name);
    assert.equal(result.modelCalls, 1, name);
    assert.match(result.toolResult, /command was not executed/i, name);
    assert.equal(result.finished, true, name);
    assert.equal(result.shellEvents.length, 0, name);
  }
  const effective = evidence.cases.find(
    (item) => item.name === "effective-deny",
  );
  assert.equal(effective.marker, false);
  assert.equal(effective.finished, true);
  assert.match(effective.toolResult, /command was not executed/i);
  assert.equal(
    effective.events.find((item) => item.kind === "effective.review").event
      .decision.source,
    "assessor",
  );
  assert.equal(
    effective.shellEvents.length,
    1,
    "This is the before hook, not process start",
  );
});

test("normal auto-allow and assessor allow retain one native execution", () => {
  for (const [name, source] of [
    ["auto-allow", "auto-allow"],
    ["assessor-allow", "assessor"],
  ]) {
    const result = evidence.cases.find((item) => item.name === name);
    const review = result.events.find((item) => item.kind === "review").event;
    assert.equal(review.decision.source, source);
    assert.equal(review.decision.decision, "allow");
    assert.equal(result.modelCalls, 1);
    assert.equal(result.shellEvents.length, 1);
    assert.equal(result.finished, true);
    if (name === "assessor-allow") assert.equal(result.marker, true);
    else assert.equal(result.toolResult.trim(), `${evidence.root}/project`);
  }
});

test("scanner-empty observation really executes without a shell permission evaluation", () => {
  const result = evidence.cases.find(
    (item) => item.name === "scanner-empty-observe",
  );
  assert.equal(result.shellEvents.length, 1);
  assert.equal(result.finished, true);
  assert.equal(
    result.events.filter(
      (item) => item.kind === "permission" && item.event.action === "shell",
    ).length,
    0,
  );
});

test("effective invocation has public call-bound identity, not a guessed location or environment", () => {
  const result = evidence.cases.find((item) => item.name === "invocation");
  const tool = result.events.find((item) => item.kind === "tool.before").event;
  const shell = result.shellEvents[0].event;
  assert.equal(shell.cwd, evidence.canonicalWorkdir);
  assert.equal(shell.env.PROOF_ENV, "session-only");
  assert.equal(shell.env.HOME, `${evidence.root}/home/session-home`);
  assert.equal(shell.shell, "/bin/bash");
  assert.match(result.markerContent, /session-only\n5\./);
  const facts = evidence.cases.find(
    (item) => item.name === "invocation-review",
  );
  const reviewed = facts.events.find(
    (item) => item.kind === "effective.review",
  ).event;
  assert.equal(facts.marker, true);
  assert.equal(reviewed.request.cwd, evidence.canonicalWorkdir);
  assert.equal(reviewed.request.env.HOME, shell.env.HOME);
  assert.equal(reviewed.request.env.CDPATH, shell.env.CDPATH);
  assert.equal(reviewed.request.command, facts.shellEvents[0].event.command);
  assert.equal(reviewed.decision.decision, "allow");
  assert.equal(
    shell.call?.sessionID,
    tool.sessionID,
    "BLOCKER: effective shell event is not bound to its owning session",
  );
  assert.equal(
    shell.call?.id,
    tool.id,
    "BLOCKER: effective shell event is not bound to its native tool call",
  );
});

test("human TUI approval produces a fresh real Reviewer check before one native continuation", () => {
  const result = evidence.cases.find((item) => item.name === "human-once");
  assert.ok(
    result,
    "BLOCKER: run PROOF_HUMAN=1 and answer in the real TUI; HTTP reply is not UI evidence",
  );
  const kinds = result.events.map((item) => item.kind);
  const pending = result.events.find(
    (item) => item.kind === "human.pending",
  ).event;
  const replied = result.events.find((item) => item.kind === "human.reply");
  assert.ok(
    replied,
    "BLOCKER: no real human reply was observed; timeout/dismissal is denial",
  );
  const reply = replied.event;
  const reviewed = result.events.find((item) => item.kind === "fresh.review");
  assert.ok(reviewed, "BLOCKER: approval did not reach a fresh Reviewer check");
  const fresh = reviewed.event;
  assert.equal(pending.decision.decision, "ask");
  assert.equal(reply.pendingID, pending.pendingID);
  assert.equal(reply.decision, "once");
  assert.equal(fresh.decision.decision, "allow");
  assert.equal(fresh.decision.source, "grant");
  assert.ok(kinds.indexOf("human.reply") < kinds.indexOf("fresh.review"));
  assert.ok(kinds.indexOf("fresh.review") < kinds.indexOf("tool.after"));
  assert.equal(result.marker, true);
  assert.equal(result.modelCalls, 1);
  assert.equal(result.shellEvents.length, 1);
  assert.equal(result.finished, true);
});

test("user admissions, Goal and lifecycle boundaries invalidate real session grants without treating idle as end", () => {
  assert.ok(evidence.lifecycle, "Lifecycle proof is missing");
  for (const name of [
    "new-intent",
    "plugin-admission",
    "goal-change",
    "clear",
    "reconnect",
    "reload",
    "restart",
    "end",
  ]) {
    const item = evidence.lifecycle.find((item) => item.name === name);
    assert.equal(item.before.decision.source, "grant", name);
    assert.equal(item.after.decision.decision, "ask", name);
    assert.notEqual(item.after.decision.source, "grant", name);
  }
  assert.equal(
    evidence.lifecycle.find((item) => item.name === "idle").after.decision
      .source,
    "grant",
  );
  assert.equal(
    evidence.lifecycle.find((item) => item.name === "plugin-admission").after
      .request.intent.latestUserRequest,
    "Programmatic admission is user intent",
  );
  assert.equal(
    evidence.lifecycle.find((item) => item.name === "synthetic").after.decision
      .source,
    "grant",
  );
  for (const name of ["idle", "synthetic", "compaction"]) {
    const item = evidence.lifecycle.find((item) => item.name === name);
    assert.equal(item.after.decision.source, "grant", name);
    assert.equal(
      item.after.request.intent.latestUserRequest,
      `Lifecycle intent baseline ${name}`,
    );
  }
  const clears = evidence.lifecycleEvents.filter(
    (item) =>
      item.kind === "client.report" && item.event.event === "native-clear",
  );
  assert.equal(
    clears.length,
    1,
    "Native clear must not recursively dispatch its bridge",
  );
  assert.equal(clears[0].event.route.type, "home");
  assert.equal(clears[0].event.commandID, "session.clear");
  assert.ok(
    evidence.lifecycleEvents.some(
      (item) => item.kind === "event" && item.event.type === "session.deleted",
    ),
  );
  assert.equal(
    evidence.lifecycle.find((item) => item.name === "goal-change").after.request
      .intent.goal,
    "Inspect only this disposable project",
  );
  for (const name of ["clear", "reload", "restart"])
    assert.equal(
      evidence.lifecycle.find((item) => item.name === name).after.request.intent
        .latestUserRequest,
      null,
      name,
    );
});

test("late mutators are reproducible unsupported compositions, while human shell is an explicit bypass", () => {
  for (const name of ["late-tool", "late-shell"]) {
    const result = evidence.cases.find((item) => item.name === name);
    assert.equal(result.unsupportedComposition, true);
    assert.equal(result.marker, true);
    assert.equal(
      result.events.find((item) => item.kind === "review").event.request
        .command,
      `touch ${name}-observe.marker`,
    );
    assert.equal(result.shellEvents.length, 1);
    assert.equal(
      result.shellEvents[0].event.command,
      `touch ${name === "late-tool" ? "late-tool-executed" : "late-shell-observe"}.marker`,
    );
  }
  assert.equal(evidence.bypass.marker, true);
  assert.equal(
    evidence.bypass.events.some((item) => /review|tool.before/.test(item.kind)),
    false,
  );
  assert.equal(
    evidence.bypass.events.find((item) => item.kind === "shell.before").event
      .call,
    null,
  );
});

test("child and location ownership cannot reuse parent authorization", () => {
  const {
    parent,
    parentBefore,
    child,
    childInitial,
    childBefore,
    childAfter,
    other,
    otherAfter,
    foreignError,
  } = evidence.ownership;
  assert.equal(child.parentID, parent.id);
  assert.equal(parentBefore.decision.source, "grant");
  assert.equal(childInitial.decision.decision, "ask");
  assert.equal(
    childInitial.request.intent.latestUserRequest,
    "Parent admitted intent",
  );
  assert.equal(childBefore.decision.source, "grant");
  assert.equal(childAfter.decision.decision, "ask");
  assert.equal(
    childAfter.request.intent.latestUserRequest,
    "Replacement parent intent",
  );
  assert.notEqual(other.location.directory, parent.location.directory);
  assert.equal(
    otherAfter.request.intent.latestUserRequest,
    "Other location intent",
  );
  assert.equal(otherAfter.decision.decision, "ask");
  assert.match(foreignError, /RpcInternalError/);
  for (const name of ["child-allow", "other-location-allow"]) {
    const result = evidence.cases.find((item) => item.name === name);
    assert.equal(result.marker, true, name);
    assert.equal(
      result.events.find((item) => item.kind === "review").event.sessionID,
      result.sessionID,
    );
    assert.equal(result.shellEvents[0].event.call.sessionID, result.sessionID);
  }
});

test("native interruption cancels the approval wait without execution or a grant", () => {
  const result = evidence.cases.find((item) => item.name === "approval-cancel");
  assert.equal(result.marker, false);
  assert.ok(result.events.some((item) => item.kind === "human.pending"));
  assert.ok(result.events.some((item) => item.kind === "wait.cancelled"));
  assert.equal(
    result.events.some(
      (item) => item.kind === "fresh.review" || item.kind === "human.reply",
    ),
    false,
  );
});
