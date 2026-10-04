#!/usr/bin/env node

const crypto = require("node:crypto")
const fs = require("node:fs")

const mode = process.env.FAKE_AAR_MODE ?? process.env.AAR_CONFIG?.match(/-([a-z-]+)\.toml$/)?.[1] ?? "allow"
const logPath = process.env.FAKE_AAR_LOG ?? process.env.AAR_CONFIG?.replace(/\.toml$/, ".log")
const grantPath = process.env.AAR_STATE_DIR ? `${process.env.AAR_STATE_DIR}/fake-grants.json` : null

function canonicalJSON(value) {
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029")
}

function fingerprintFor(request) {
  return crypto.createHash("sha256").update(canonicalJSON({
    command: request.command,
    cwd: request.cwd,
    workspaceRoot: request.workspaceRoot,
    sessionId: request.session.id,
    intentId: request.session.intentId ?? "",
    policyVersion: "deterministic-v1",
    shellIR: "shellir-v1",
  })).digest("hex")
}

function write(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`)
}

function readGrants() {
  if (!grantPath) return {}
  try {
    return JSON.parse(fs.readFileSync(grantPath, "utf8"))
  } catch {
    return {}
  }
}

function writeGrants(grants) {
  if (!grantPath) return
  fs.mkdirSync(require("node:path").dirname(grantPath), { recursive: true })
  fs.writeFileSync(grantPath, JSON.stringify(grants), { mode: 0o600 })
}

if (process.argv[2] === "doctor") {
  if (mode === "invalid-doctor") {
    write({ schemaVersion: "aar-doctor-v0", status: "ok" })
  } else {
    write({
      schemaVersion: "aar-doctor-v1",
      contractVersion: "aar-contract-v1",
      status: "ok",
      requestSchemaVersion: "aar-request-v1",
      decisionSchemaVersion: "aar-decision-v1",
      reviewerTimeoutMs: mode === "timeout" ? 1 : 5000,
    })
  }
  process.exit(0)
}

if (["grant", "deny-note", "session-event"].includes(process.argv[2])) {
  const args = process.argv.slice(3)
  const value = (name) => args[args.indexOf(name) + 1]
  const grants = readGrants()
  if (process.argv[2] === "grant") {
    grants[`${value("--session")}\u0000${value("--fingerprint")}`] = value("--scope")
    writeGrants(grants)
  } else if (process.argv[2] === "session-event") {
    writeGrants({})
  }
  write({ status: "ok" })
  process.exit(0)
}

if (process.argv[2] !== "check") process.exit(2)

let input = ""
process.stdin.setEncoding("utf8")
process.stdin.on("data", (chunk) => { input += chunk })
process.stdin.on("end", () => {
  const request = JSON.parse(input)
  if (mode === "nonzero") {
    process.stderr.write("simulated reviewer failure\n")
    process.exit(7)
  }
  if (mode === "malformed") {
    process.stdout.write("not-json\n")
    return
  }
  if (mode === "schema") {
    write({ schemaVersion: "aar-decision-v0" })
    return
  }
  if (mode === "timeout") {
    setTimeout(() => {}, 2000)
    return
  }

  if (logPath) fs.appendFileSync(logPath, `${JSON.stringify({ command: request.command })}\n`)
  const fingerprint = fingerprintFor(request)
  const grant = readGrants()[`${request.session.id}\u0000${fingerprint}`]
  if (grant) {
    write({
      schemaVersion: "aar-decision-v1",
      decision: "allow",
      reason: `a human approved this exact command for the current session (${grant})`,
      source: "grant",
      rule: null,
      assessment: null,
      requestFingerprint: fingerprint,
      grantEligible: false,
      grantScope: grant,
      auditId: "fixture-audit",
    })
    return
  }
  if (mode === "hard-deny") {
    write({
      schemaVersion: "aar-decision-v1",
      decision: "deny",
      reason: "the command targets a protected platform root",
      source: "hard-deny",
      rule: "HD001",
      assessment: null,
      requestFingerprint: fingerprint,
      grantEligible: false,
      auditId: "fixture-audit",
    })
    return
  }
  if (mode === "model-deny") {
    write({
      schemaVersion: "aar-decision-v1",
      decision: "deny",
      reason: "the assessor found an irreversible local effect",
      source: "assessor",
      rule: null,
      assessment: { risks: [{ category: "critical_data_loss" }], uncertainties: [] },
      requestFingerprint: fingerprint,
      grantEligible: false,
      auditId: "fixture-audit",
    })
    return
  }
  if (mode === "ask-once" || mode === "ask-session") {
    write({
      schemaVersion: "aar-decision-v1",
      decision: "ask",
      reason: "the assessor found an effect that needs human approval",
      source: "assessor",
      rule: null,
      assessment: { risks: [{ category: "external_side_effect" }], uncertainties: [] },
      requestFingerprint: fingerprint,
      grantEligible: mode === "ask-session",
      auditId: "fixture-audit",
    })
    return
  }
  write({
    schemaVersion: "aar-decision-v1",
    decision: "allow",
    reason: "the integration fixture permits this exact command",
    source: "assessor",
    rule: null,
    assessment: null,
    requestFingerprint: fingerprint,
    grantEligible: false,
    auditId: "fixture-audit",
  })
})
