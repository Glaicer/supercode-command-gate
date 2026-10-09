import { test } from "node:test";
import assert from "node:assert/strict";
import {
  approvalReason,
  blockedMessage,
  compactReason,
  errorMessage,
  NEVER_ASK_EXPLANATION,
  neverAskDenialMessage,
  startupDiagnostic,
  unavailableReason,
  reviewerDenialMessage,
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
      /^Command Gate blocked this command\. Reason: .+\. The command was not executed\.$/,
    );
  }
});

test("startup diagnostic is loud and actionable", () => {
  const message = startupDiagnostic("missing binary");
  assert.match(message, /Command Gate is unavailable: missing binary/);
  assert.match(message, /aar doctor/);
  assert.match(message, /Bash commands remain denied/);
});

test("Reviewer denial includes every risk and uncertainty without request data", () => {
  const message = reviewerDenialMessage({
    reason: "Protected data could be lost",
    source: "assessor",
    rule: null,
    assessment: {
      risks: [
        {
          category: "critical_data_loss",
          severity: "critical",
          likelihood: "possible",
          reversible: false,
          affectsProtectedPaths: true,
          evidence:
            "The target may contain the only copy; recovery is not established",
        },
        {
          category: "network",
          severity: "low",
          likelihood: "unlikely",
          reversible: true,
          affectsProtectedPaths: false,
          evidence:
            "A request could send token=demo-secret to https://user:demo-password@example.test",
        },
      ],
      uncertainties: [
        "The backup has not been verified",
        "Remote behavior is unknown",
      ],
    },
  });
  assert.match(message, /Reason: Protected data could be lost/);
  assert.match(message, /Risk 1 of 2\nRisk: Critical data loss/);
  assert.match(message, /Severity: Critical · Likelihood: Possible/);
  assert.match(message, /Reversible: No · Protected paths affected: Yes/);
  assert.match(
    message,
    /The target may contain the only copy; recovery is not established/,
  );
  assert.match(message, /Risk 2 of 2\nRisk: Network access/);
  assert.match(message, /Severity: Low · Likelihood: Unlikely/);
  assert.match(message, /Reversible: Yes · Protected paths affected: No/);
  assert.match(message, /A request could send token=\[REDACTED\]/);
  assert.match(
    message,
    /• The backup has not been verified\n• Remote behavior is unknown/,
  );
  assert.match(message, /The command was not executed\.$/);
  assert.doesNotMatch(
    message,
    /demo-secret|demo-password|"risks"|Command:|Working directory:/,
  );
});

test("missing assessment and fields never imply safety", () => {
  for (const assessment of [null, undefined, {}, { risks: [] }]) {
    const message = reviewerDenialMessage({
      reason: "Insufficient evidence",
      source: "assessor",
      rule: null,
      assessment,
    });
    assert.match(message, /Reason: Insufficient evidence/);
    assert.match(message, /The command was not executed\.$/);
    assert.doesNotMatch(message, /Risk:|None reported|safe|Reversible: Yes/);
  }
  const message = reviewerDenialMessage({
    reason: "Evidence incomplete",
    source: "assessor",
    rule: null,
    assessment: {
      risks: [{ category: "network" }],
      uncertainties: ["Destination unknown"],
    },
  });
  assert.match(message, /Severity: Unknown · Likelihood: Unknown/);
  assert.match(
    message,
    /Reversible: Unknown · Protected paths affected: Unknown/,
  );
  assert.match(message, /Evidence:\nNot supplied/);
  assert.match(message, /• Destination unknown/);
});

test("Hard Deny includes the rule and reason without inventing assessment", () => {
  const message = reviewerDenialMessage({
    reason: "Protected path write",
    source: "hard-deny",
    rule: "protected-write",
    assessment: null,
  });
  assert.match(message, /Reason: Protected path write/);
  assert.match(message, /Rule: protected-write/);
  assert.match(message, /The command was not executed\.$/);
  assert.doesNotMatch(message, /Risk:|Uncertainties:|Reversible:/);
});

test("Reviewer unavailable remains an operational diagnostic without assessed risks", () => {
  const message = reviewerDenialMessage({
    reason: "Assessor unavailable: token=demo-secret",
    source: "unavailable",
    rule: null,
    assessment: null,
  });
  assert.match(message, /Command Gate is unavailable/);
  assert.match(message, /Assessor unavailable: token=\[REDACTED\]/);
  assert.match(message, /The command was not executed\.$/);
  assert.doesNotMatch(message, /demo-secret|Risk:|Uncertainties:/);
});

test("never-ask denial keeps the Reviewer evidence and explains disabled prompts", () => {
  const message = neverAskDenialMessage({
    reason: "The command may destroy data token=demo-secret",
    rule: null,
    assessment: {
      risks: [
        {
          category: "critical_data_loss",
          severity: "high",
          likelihood: "possible",
          reversible: false,
          affectsProtectedPaths: true,
          evidence: "The target may contain the only copy",
        },
      ],
      uncertainties: ["Backup availability is unknown"],
    },
  });
  assert.match(
    message,
    /Reason: The command may destroy data token=\[REDACTED\]/,
  );
  assert.match(message, /Risk 1 of 1\nRisk: Critical data loss/);
  assert.match(message, /The target may contain the only copy/);
  assert.match(message, /• Backup availability is unknown/);
  assert.ok(message.endsWith(NEVER_ASK_EXPLANATION));
  assert.doesNotMatch(message, /demo-secret|request_command_approval/);
});

test("never-ask denial without assessment still states the policy refusal", () => {
  const message = neverAskDenialMessage({
    reason: "Insufficient evidence",
    rule: "protected-write",
    assessment: null,
  });
  assert.match(message, /Reason: Insufficient evidence/);
  assert.match(message, /Rule: protected-write/);
  assert.ok(message.endsWith(NEVER_ASK_EXPLANATION));
  assert.doesNotMatch(message, /Risk:|None reported|safe/);
});
