import assert from "node:assert/strict";
import { access } from "node:fs/promises";
import { before, test } from "node:test";
import { runSeam } from "./seam-driver.mjs";

let evidence;
before(async () => {
  evidence = await runSeam({ integrity: true });
});

test("late tool input edits are reviewed at actual shell creation, not authorized by an earlier command", () => {
  const result = evidence.integrity.cases.find(
    (item) => item.name === "late-tool",
  );
  assert.equal(evidence.integrity.inventoryOK, true);
  assert.equal(result.marker, false);
  assert.equal(result.finished, true);
  assert.equal(
    result.events.find((event) => event.kind === "review-deny").command,
    "FIXTURE=fixture-deny touch late-tool.marker",
  );
});

test("native background edited after tool-before refusal still cannot start", () => {
  const result = evidence.integrity.cases.find(
    (item) => item.name === "late-background",
  );
  assert.equal(result.marker, false);
  assert.match(result.toolResult, /background execution is outside/i);
  assert.equal(
    result.events.some((event) => event.kind === "review-allow"),
    false,
  );
});

test("late background flag mutations under allowBackground refuse before native start", () => {
  const boot = evidence.integrityBackground;
  assert.equal(boot.inventoryOK, true);
  for (const name of ["late-background-true", "late-background-false"]) {
    const result = boot.cases.find((item) => item.name === name);
    assert.equal(result.marker, false, name);
    assert.equal(result.finished, true, name);
    assert.match(
      result.toolResult,
      /late mutation changed reviewed invocation background/i,
      name,
    );
    assert.match(result.toolResult, /command was not executed/i, name);
  }
});

test("controlled late shell command, cwd, env and shell mutations refuse before native start", async () => {
  for (const name of ["command", "cwd", "env", "replace-env", "shell"]) {
    const result = evidence.integrity.cases.find(
      (item) => item.name === `late-shell-${name}`,
    );
    assert.equal(result.marker, false, name);
    assert.equal(result.finished, true, name);
    assert.ok(
      result.events.some((event) => event.kind === "review-allow"),
      name,
    );
    assert.match(result.toolResult, /invocation.*changed|late.*mutat/i, name);
    assert.match(result.toolResult, /command was not executed/i, name);
    assert.equal(
      await access(
        `${evidence.integrity.project}/other/late-shell-${name}.marker`,
      )
        .then(() => true)
        .catch(() => false),
      false,
      name,
    );
  }
  assert.equal(
    await access(`${evidence.integrity.project}/changed.marker`)
      .then(() => true)
      .catch(() => false),
    false,
  );
});

test("a traced pre-review shell composition uses final command, cwd, env and Bash", () => {
  const boot = evidence.early;
  assert.equal(boot.inventoryOK, true);
  const result = boot.cases.find((item) => item.name === "early-shell");
  assert.equal(result.marker, true);
  assert.equal(result.finished, true);
  const review = result.events.find((event) => event.kind === "review-allow");
  assert.equal(
    review.command,
    "touch early-shell.marker; pwd; printenv HOME CDPATH",
  );
  assert.equal(review.cwd, boot.canonicalWorkdir);
  assert.equal(review.shell, "/bin/bash");
  assert.deepEqual(result.toolResult.trim().split("\n"), [
    review.cwd,
    review.env.HOME,
    review.env.CDPATH,
  ]);
});

test("sh, zsh, fish and PowerShell are not reviewed or started as Bash", () => {
  for (const shell of ["sh", "zsh", "fish", "pwsh"]) {
    const result = evidence.early.cases.find(
      (item) => item.name === `unsupported-${shell}`,
    );
    assert.equal(result.marker, false);
    assert.equal(result.finished, true);
    assert.match(result.toolResult, /unsupported shell/);
    assert.equal(
      result.events.some((event) => event.kind === "review-allow"),
      false,
    );
  }
});
