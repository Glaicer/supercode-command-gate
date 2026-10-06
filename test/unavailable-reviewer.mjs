#!/usr/bin/env node
import { existsSync, writeFileSync, unlinkSync } from "node:fs";
import path from "node:path";
import { fingerprintFor } from "../src/reviewer.ts";

const grant = path.join(process.env.AAR_STATE_DIR, "fixture-granted");
if (process.argv[2] === "doctor") {
  console.log(
    JSON.stringify({
      schemaVersion: "aar-doctor-v1",
      contractVersion: "aar-contract-v1",
      status: "ok",
      requestSchemaVersion: "aar-request-v1",
      decisionSchemaVersion: "aar-decision-v1",
      reviewerTimeoutMs: 500,
    }),
  );
} else if (process.argv[2] === "session-event") {
  if (existsSync(grant)) unlinkSync(grant);
  console.log('{"status":"invalidated"}');
} else if (process.argv[2] === "grant") {
  writeFileSync(grant, "granted");
  console.log('{"status":"granted"}');
} else {
  let text = "";
  for await (const chunk of process.stdin) text += chunk;
  const request = JSON.parse(text);
  if (request.command.includes("transport-fail")) {
    console.error("provider body token=fixture-private-secret");
    process.exit(3);
  }
  const fresh = request.command.includes("fresh-fail");
  const failedAsk = request.command.includes("assessor-ask");
  const failed =
    request.command.includes("assessor-fail") ||
    failedAsk ||
    (fresh && existsSync(grant));
  const policy = request.command.includes("policy-deny");
  const ask =
    request.command.includes("policy-ask") || failedAsk || (fresh && !failed);
  const auto = request.command === "pwd";
  console.log(
    JSON.stringify({
      schemaVersion: "aar-decision-v1",
      decision: ask ? "ask" : failed || policy ? "deny" : "allow",
      reason: failed
        ? "fixture token=fixture-private-secret"
        : "fixture policy",
      source: failed
        ? "unavailable"
        : policy
          ? "hard-deny"
          : auto
            ? "auto-allow"
            : "assessor",
      failureKind: failed ? "provider-outage" : undefined,
      rule: auto ? "static-read-only" : null,
      assessment: null,
      requestFingerprint: fingerprintFor(request),
      grantEligible: false,
      auditId: "fixture",
    }),
  );
}
