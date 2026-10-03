import { test } from "node:test";
import assert from "node:assert/strict";
import {
  approvalReason,
  blockedMessage,
  compactReason,
  errorMessage,
  startupDiagnostic,
  unavailableReason,
} from "./messages.ts";

test("denial messages state the reason and the non-execution explicitly", () => {
  const message = blockedMessage("the command was not proven safe");
  assert.match(message, /blocked this command/);
  assert.match(message, /Reason: the command was not proven safe/);
  assert.match(message, /The command was not executed\.$/);
  assert.doesNotMatch(message, /\n/);
});

test("reasons are compacted to one line", () => {
  assert.equal(compactReason("  a \n b\t c  "), "a b c");
  assert.equal(errorMessage(new Error("x\ny")), "x y");
  assert.equal(errorMessage("plain"), "plain");
});

test("every model-facing denial keeps the same envelope", () => {
  for (const reason of [
    unavailableReason("aar doctor failed"),
    approvalReason(),
    "the command was not proven safe",
  ]) {
    assert.match(
      blockedMessage(reason),
      /^Auto Approve Permissions blocked this command\. Reason: .+\. The command was not executed\.$/,
    );
  }
});

test("startup diagnostic is loud and actionable", () => {
  const message = startupDiagnostic("missing binary");
  assert.match(message, /Command Gate is unavailable: missing binary/);
  assert.match(message, /aar doctor/);
  assert.match(message, /Bash commands remain denied/);
});
