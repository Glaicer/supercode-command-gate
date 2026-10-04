import assert from "node:assert/strict";
import { test } from "node:test";
import type { PendingApproval } from "./approval.ts";
import {
  approvalSummary,
  approvalDetails,
  approvalTechnicalDetails,
  redactText,
  approvalPages,
} from "./approval-text.ts";

const risk = {
  category: "critical_data_loss",
  likelihood: "possible",
  severity: "critical",
  reversible: true,
  affectsProtectedPaths: true,
  evidence: "The script can overwrite protected files",
};
const item: PendingApproval = {
  location: "/project",
  sessionID: "session-id",
  messageID: "message-id",
  callID: "call-id",
  pendingID: "pending-id",
  clientID: "client-id",
  intentGeneration: "generation",
  fingerprint: "fingerprint-id",
  command: "API_TOKEN=demo-secret bash mutable.sh",
  preview: "API_TOKEN=[REDACTED] bash mutable.sh",
  cwd: "/project",
  effectSummary: "Approval is required",
  assessment: { risks: [risk], uncertainties: [] },
  grantEligible: true,
  purpose: null,
  expiresAt: 0,
};

test("summary puts the highest-severity risk and evidence before the working directory", () => {
  const low = { ...risk, severity: "low", evidence: "Low risk evidence" };
  const other = { ...risk, severity: "high", evidence: "Other evidence" };
  const summary = approvalSummary({
    ...item,
    assessment: { risks: [low, risk, other], uncertainties: [] },
  });
  assert.match(summary, /Risk: Critical data loss/);
  assert.match(summary, /Severity: Critical · Likelihood: Possible/);
  assert.match(summary, /Reversible: Yes · Protected paths affected: Yes/);
  assert.match(summary, /Evidence:\nThe script can overwrite protected files/);
  assert.match(summary, /2 more risks — see Details/);
  assert.ok(
    summary.indexOf("Evidence:") < summary.indexOf("Working directory:"),
  );
  for (const hidden of [
    "Low risk evidence",
    "Other evidence",
    "session-id",
    "call-id",
    "fingerprint-id",
    "demo-secret",
  ])
    assert.ok(!summary.includes(hidden));
});

test("summary keeps the first risk on severity ties and uses singular counts", () => {
  const summary = approvalSummary({
    ...item,
    assessment: {
      risks: [risk, { ...risk, evidence: "Second critical risk" }],
      uncertainties: ["Script contents are incomplete"],
    },
  });
  assert.match(summary, /1 more risk — see Details/);
  assert.match(summary, /1 uncertainty — see Details/);
  assert.ok(!summary.includes("Second critical risk"));
  assert.ok(!approvalSummary(item).includes("more risk"));
});

test("summary masks credentials in risk evidence and fallback reasons", () => {
  assert.ok(
    !approvalSummary({
      ...item,
      assessment: { risks: [{ ...risk, evidence: "API_TOKEN=demo-secret" }] },
    }).includes("demo-secret"),
  );
  assert.ok(
    !approvalSummary({
      ...item,
      assessment: null,
      effectSummary: "API_TOKEN=demo-secret",
    }).includes("demo-secret"),
  );
  assert.equal(
    redactText("Bearer abc https://user:password@example.org sk-abcdef"),
    "Bearer [REDACTED] https://user:[REDACTED]@example.org sk-[REDACTED]",
  );
});

test("details show every risk and uncertainty without JSON or technical identifiers", () => {
  const details = approvalDetails({
    ...item,
    assessment: {
      risks: [
        risk,
        {
          ...risk,
          category: "network",
          reversible: false,
          affectsProtectedPaths: false,
          evidence: "Contacts a remote host",
        },
      ],
      uncertainties: ["Destination is unknown", "Script may change"],
    },
  });
  for (const shown of [
    item.preview,
    "Risk 1 of 2",
    "Risk 2 of 2",
    "Risk: Network access",
    "Reversible: No · Protected paths affected: No",
    "Contacts a remote host",
    "• Destination is unknown",
    "• Script may change",
  ])
    assert.ok(details.includes(shown));
  for (const hidden of [
    "session-id",
    "call-id",
    "fingerprint-id",
    "Purpose:",
    '"risks"',
  ])
    assert.ok(!details.includes(hidden));
  assert.ok(!details.includes(item.command));
  assert.ok(
    details.indexOf("Risk 1 of 2") < details.indexOf("Command preview"),
  );
  assert.match(approvalDetails(item), /Uncertainties:\nNone reported/);
});

test("absent assessments fall back to the reviewer reason without claiming safety", () => {
  for (const assessment of [null, {}, { risks: [], uncertainties: [] }]) {
    assert.match(
      approvalSummary({ ...item, assessment }),
      /Why approval is needed:\nApproval is required/,
    );
    assert.match(
      approvalDetails({ ...item, assessment }),
      /Why approval is needed:\nApproval is required/,
    );
  }
});

test("technical details retain identifiers and the complete raw assessment", () => {
  const details = approvalTechnicalDetails(item);
  for (const value of [
    item.sessionID,
    item.callID,
    item.fingerprint,
    JSON.stringify(item.assessment, null, 2),
  ])
    assert.ok(details.includes(value));
});

test("long masked previews are explicitly shortened and follow the risk information", () => {
  const command = `API_TOKEN=demo-secret printf '${"x".repeat(500)}'`;
  const preview = `${redactText(command).slice(0, 237)}...`;
  const pending = { ...item, command, preview };
  const summary = approvalSummary(pending);
  assert.match(summary, /Command preview \(shortened\):/);
  assert.ok(summary.indexOf("Evidence:") < summary.indexOf("Command preview"));
  assert.ok(!summary.includes("demo-secret"));
  assert.ok(!approvalSummary(item).includes("shortened"));
  assert.ok(!approvalDetails(pending).includes(command));
  assert.match(approvalDetails(pending), /Command preview \(shortened\):/);
});

test("command pages preserve every character, including spaces at presentation breaks", () => {
  assert.deepEqual(approvalPages("1234567890  abcdef", 8, 2), [
    "12345678\n90  abcd",
    "ef",
  ]);
  const command = `printf '${"x".repeat(4000)}'; printf FINAL_COMMAND_LINE`;
  const pages = approvalPages(command, 57, 14);
  assert.ok(pages.length > 1);
  assert.equal(pages.join("").replaceAll("\n", ""), command);
  assert.ok(pages.at(-1)?.includes("FINAL_COMMAND_LINE"));
});

test("pages keep Unicode graphemes intact within a conservative cell budget", () => {
  assert.deepEqual(approvalPages("A界B🙂e\u0301👩‍💻Z", 4, 2), [
    "A界B\n🙂e\u0301",
    "👩‍💻Z",
  ]);
});

test("multiline scripts, heredocs and quoted shell punctuation are not rewritten", () => {
  const command =
    "node <<'SCRIPT' | cat\n  console.log('quoted ; | 界');\n\nSCRIPT\nprintf 'outside'; echo end\n";
  assert.deepEqual(approvalPages(command, 120, 3), [
    "node <<'SCRIPT' | cat\n  console.log('quoted ; | 界');\n",
    "SCRIPT\nprintf 'outside'; echo end\n",
  ]);
  const crlf = "node -e 'console.log(1); console.log(2)'\r\n";
  assert.deepEqual(approvalPages(crlf, 120, 3), [crlf]);
});
