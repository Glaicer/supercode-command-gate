import assert from "node:assert/strict";
import { access } from "node:fs/promises";
import { before, test } from "node:test";
import { runSeam } from "./seam-driver.mjs";
import { REWRITTEN_COMMAND } from "./rtk-driver.mjs";

let evidence;
before(async () => {
  evidence = await runSeam({ rtk: true });
});

test("RTK completes before real review and native execution uses the same bytes, cwd and session env", () => {
  const boot = evidence.rtk;
  assert.equal(boot.inventoryOK, true);
  const result = boot.cases[0];
  assert.equal(result.marker, true);
  assert.equal(result.modelCalls, 1);
  assert.equal(result.finished, true);
  const review = result.events.find((event) => event.kind === "review-allow");
  assert.ok(review);
  assert.equal(review.command, REWRITTEN_COMMAND);
  assert.equal(review.cwd, boot.canonicalWorkdir);
  const output = result.toolResult.trim().split("\n");
  assert.equal(output[0], review.cwd);
  assert.equal(output[1], review.env.HOME);
  assert.equal(output[2], review.env.CDPATH);
  assert.ok(
    boot.auditRecords.some(
      (record) =>
        record.command === REWRITTEN_COMMAND && record.cwd === review.cwd,
    ),
  );
  const rewrites = boot.rewrites.filter(
    (entry) => entry.args[1] === "touch original.marker",
  );
  assert.equal(rewrites.length, 1);
  assert.deepEqual(rewrites[0].args, ["rewrite", "touch original.marker"]);
  assert.equal(rewrites[0].cwd, review.cwd);
  assert.equal("SECRET" in boot.rewrites[0].env, false);
});

test("empty, failed, timed-out and absent RTK preserve the original reviewed native command", () => {
  for (const name of ["rtk-empty", "rtk-failure", "rtk-timeout"]) {
    const result = evidence.rtk.cases.find((item) => item.name === name);
    assert.equal(result.marker, true, name);
    assert.equal(
      result.events.find((event) => event.kind === "review-allow").command,
      `touch ${name}.marker`,
    );
    assert.equal(result.modelCalls, 1);
    assert.equal(result.finished, true);
  }
  const timeout = evidence.rtk.cases.find(
    (item) => item.name === "rtk-timeout",
  );
  assert.equal(timeout.ownedRunning, false);
  assert.equal(timeout.lateEffect, false);
  for (const boot of evidence.rtk.fallbackBoots) {
    assert.equal(boot.inventoryOK, true);
    const result = boot.cases[0];
    assert.equal(result.marker, true);
    assert.equal(
      result.events.find((event) => event.kind === "review-allow").command,
      `touch ${result.name}.marker`,
    );
  }
});

test("rewritten denials, redirections and heredocs never run during rewrite or after denial", () => {
  for (const name of ["rtk-deny", "rtk-redirection", "rtk-heredoc"]) {
    const result = evidence.rtk.cases.find((item) => item.name === name);
    assert.equal(result.marker, false, name);
    assert.equal(result.finished, true);
    assert.match(result.toolResult, /command was not executed/i);
    const review = result.events.find(
      (event) => event.kind === "review-deny" || event.kind === "approval-ask",
    );
    assert.ok(review);
    assert.ok(
      evidence.rtk.auditRecords.some(
        (record) => record.command === review.command,
      ),
    );
    if (name === "rtk-heredoc")
      assert.equal(
        review.command,
        "cat <<'EOF' > rtk-heredoc.marker\nfixture-deny\nEOF",
      );
    if (name === "rtk-redirection")
      assert.equal(
        review.command,
        "printf fixture-deny > rtk-redirection.marker",
      );
    if (name === "rtk-deny")
      assert.equal(
        review.command,
        "FIXTURE=fixture-deny touch rewritten-denied.marker",
      );
  }
});

test("human shell and non-shell tools are neither reviewed nor rewritten", () => {
  assert.equal(evidence.rtk.bypass.marker, true);
  assert.equal(evidence.rtk.bypass.events.length, 0);
  assert.ok(
    !evidence.rtk.rewrites.some((entry) =>
      entry.args[1].includes("human-bypass"),
    ),
  );
  const read = evidence.rtk.cases.find((item) => item.name === "rtk-read");
  assert.equal(
    read.events.some((event) => event.kind.startsWith("review")),
    false,
  );
  assert.ok(read.toolResult.length > 0);
});

test("rewrite failures do not turn a real Reviewer deny into allow", () => {
  const results = evidence.rtk.cases.filter((item) =>
    ["rtk-empty-deny", "rtk-failure-deny"].includes(item.name),
  );
  results.push(...evidence.rtk.fallbackBoots.map((boot) => boot.cases[1]));
  assert.equal(results.length, 4);
  for (const result of results) {
    assert.equal(result.marker, false);
    assert.match(result.toolResult, /command was not executed/i);
    assert.equal(
      result.events.find((event) => event.kind === "review-deny").command,
      `FIXTURE=fixture-deny touch ${result.name}.marker`,
    );
  }
});

test("interrupt and location reload stop owned RTK descendants without native execution", () => {
  for (const name of ["fixture-cancel", "fixture-unload"]) {
    const result = evidence.rtk.cases.find((item) => item.name === name);
    assert.equal(result.marker, false);
    assert.equal(result.ownedRunning, false);
    assert.equal(result.lateEffect, false);
    const tools = result.context.data
      .flatMap((message) => message.content ?? [])
      .filter((part) => part.type === "tool");
    assert.equal(tools.length, 1);
    assert.equal(tools[0].executed, false);
    assert.equal(tools[0].state.error.type, "aborted");
    if (name === "fixture-cancel")
      assert.equal(
        result.events.some((event) => event.kind === "review-allow"),
        false,
      );
  }
});

test("only the rewritten native command produces effects, never the original or failed rewrite output", async () => {
  for (const marker of ["other/original.marker", "must-not-run.marker"]) {
    assert.equal(
      await access(`${evidence.rtk.project}/${marker}`)
        .then(() => true)
        .catch(() => false),
      false,
    );
  }
});
