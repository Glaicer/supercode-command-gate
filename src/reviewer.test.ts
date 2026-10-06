import { test } from "node:test";
import assert from "node:assert/strict";
import {
  fingerprintFor,
  normalizeDoctorResult,
  validateDecision,
} from "./reviewer.ts";
import type { Request } from "./request.ts";

const request: Request = {
  schemaVersion: "aar-request-v1",
  command: "printf ok",
  cwd: "/workspace/project",
  workspaceRoot: "/workspace",
  env: { HOME: "/home/user" },
  session: { id: "ses_1", host: "opencode", intentId: "msg_1" },
  intent: { goal: null, latestUserRequest: null, purpose: null },
};

function decision(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: "aar-decision-v1",
    decision: "allow",
    reason: "the command matches a known-safe inspection rule",
    source: "auto-allow",
    rule: "AA001",
    assessment: null,
    requestFingerprint: fingerprintFor(request),
    grantEligible: false,
    auditId: "aud_1",
    ...overrides,
  };
}

test("fingerprints are deterministic and sensitive to every reviewed fact", () => {
  const base = fingerprintFor(request);
  assert.equal(base, fingerprintFor({ ...request }));
  assert.match(base, /^[0-9a-f]{64}$/);
  for (const change of [
    { command: "printf other" },
    { cwd: "/workspace/other" },
    { workspaceRoot: "/other" },
    { session: { ...request.session, id: "ses_2" } },
    { session: { ...request.session, intentId: "msg_2" } },
  ]) {
    assert.notEqual(fingerprintFor({ ...request, ...change }), base);
  }
});

test("valid decisions pass with their fingerprint verified against the request", () => {
  for (const value of [
    decision(),
    decision({ decision: "deny", source: "hard-deny", rule: "HD001" }),
    decision({ decision: "ask", source: "assessor", rule: null }),
    decision({
      requestFingerprint: "other",
      requestFingerprintBase: fingerprintFor(request),
    }),
  ]) {
    assert.equal(
      validateDecision(value, request).schemaVersion,
      "aar-decision-v1",
    );
  }
});

test("invalid decisions are rejected, so a malformed reply can never authorize", () => {
  const failures: Array<[string, Record<string, unknown>]> = [
    ["reviewer schemaVersion mismatch", { schemaVersion: "aar-decision-v2" }],
    ["reviewer omitted assessment", { assessment: undefined }],
    ["reviewer emitted invalid grantEligible", { grantEligible: "yes" }],
    ["reviewer emitted invalid rule", { rule: 7 }],
    ["reviewer emitted invalid decision", { decision: "maybe" }],
    ["reviewer emitted no reason", { reason: " " }],
    ["reviewer emitted invalid source", { source: "vibes" }],
    [
      "allow decisions must come from auto-allow, grant, assessor, or reviewed-trust",
      { source: "unavailable" },
    ],
    [
      "grant source requires an allow decision",
      { decision: "deny", source: "grant" },
    ],
    [
      "deny-note source requires a deny decision",
      { decision: "ask", source: "deny-note", rule: null },
    ],
    [
      "auto-allow source requires an allow decision",
      { decision: "ask", source: "auto-allow" },
    ],
    ["auto-allow decisions require a rule", { rule: "" }],
    ["reviewer emitted no request fingerprint", { requestFingerprint: "" }],
    [
      "reviewer request fingerprint mismatch",
      { requestFingerprint: "deadbeef", requestFingerprintBase: undefined },
    ],
    [
      "reviewer request base fingerprint mismatch",
      { requestFingerprintBase: "deadbeef" },
    ],
    ["reviewer emitted no audit id", { auditId: "" }],
  ];
  for (const [message, overrides] of failures) {
    const value = Object.fromEntries(
      Object.entries({ ...decision(), ...overrides }).filter(
        ([, entry]) => entry !== undefined,
      ),
    );
    assert.throws(
      () => validateDecision(value, request),
      new RegExp(message.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    );
  }
  assert.throws(
    () => validateDecision(null, request),
    /reviewer emitted no decision/,
  );
});

test("doctor reports are validated against the preserved contract versions", () => {
  const report = {
    schemaVersion: "aar-doctor-v1",
    contractVersion: "aar-contract-v1",
    status: "ok",
    requestSchemaVersion: "aar-request-v1",
    decisionSchemaVersion: "aar-decision-v1",
    reviewerTimeoutMs: 5000,
  };
  assert.deepEqual(normalizeDoctorResult(report, 5500), {
    ok: true,
    reviewerTimeoutMs: 5000,
  });
  assert.equal(
    normalizeDoctorResult({ ...report, schemaVersion: "other" }, 5500).ok,
    false,
  );
  for (const change of [
    { schemaVersion: "other" },
    { contractVersion: "other" },
    { requestSchemaVersion: "other" },
    { decisionSchemaVersion: "other" },
    { status: "error" },
    { reviewerTimeoutMs: 0 },
    { reviewerTimeoutMs: "soon" },
  ]) {
    const result = normalizeDoctorResult({ ...report, ...change }, 5500);
    assert.equal(result.ok, false, JSON.stringify(change));
    if (!result.ok) assert.ok(result.reason.length > 0);
  }
  const tooFast = normalizeDoctorResult(report, 5000);
  assert.equal(tooFast.ok, false);
  if (!tooFast.ok)
    assert.match(tooFast.reason, /greater than the reviewer deadline/);
  assert.equal(normalizeDoctorResult([], 5500).ok, false);
  assert.equal(normalizeDoctorResult(null, 5500).ok, false);
});

test("reviewed trust authorizes only an allow linked to its original audit", () => {
  assert.equal(
    validateDecision(
      decision({
        source: "reviewed-trust",
        rule: null,
        originAuditId: "a".repeat(32),
      }),
      request,
    ).source,
    "reviewed-trust",
  );
  for (const overrides of [
    { originAuditId: undefined },
    { originAuditId: "invalid" },
    { decision: "ask" },
  ]) {
    assert.throws(
      () =>
        validateDecision(
          decision({
            source: "reviewed-trust",
            rule: null,
            originAuditId: "a".repeat(32),
            ...overrides,
          }),
          request,
        ),
      /reviewed-trust requires allow/,
    );
  }
});
