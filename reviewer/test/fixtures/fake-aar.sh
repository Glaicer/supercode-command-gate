#!/bin/sh

IFS= read -r request
fingerprint=$(printf '%s' "$request" | node -e '
const crypto = require("node:crypto")
const request = JSON.parse(require("node:fs").readFileSync(0, "utf8"))
const input = {
  command: request.command,
  cwd: request.cwd,
  workspaceRoot: request.workspaceRoot,
  sessionId: request.session.id,
  intentId: request.session.intentId ?? "",
  policyVersion: "deterministic-v1",
  shellIR: "shellir-v1",
}
const canonical = JSON.stringify(input)
  .replaceAll("<", "\\u003c")
  .replaceAll(">", "\\u003e")
  .replaceAll("&", "\\u0026")
  .replaceAll("\u2028", "\\u2028")
  .replaceAll("\u2029", "\\u2029")
process.stdout.write(crypto.createHash("sha256").update(canonical).digest("hex"))
')
case "$request" in
  *'"command":"pwd"'*)
    printf '%s\n' "{\"schemaVersion\":\"aar-decision-v1\",\"decision\":\"allow\",\"reason\":\"pwd is safe\",\"source\":\"auto-allow\",\"rule\":\"AA001\",\"assessment\":null,\"requestFingerprint\":\"$fingerprint\",\"grantEligible\":false,\"auditId\":\"fixture-audit\"}"
    ;;
  *)
    printf '%s\n' "{\"schemaVersion\":\"aar-decision-v1\",\"decision\":\"deny\",\"reason\":\"command is not proven safe\",\"source\":\"unavailable\",\"rule\":null,\"assessment\":null,\"requestFingerprint\":\"$fingerprint\",\"grantEligible\":false,\"auditId\":\"fixture-audit\"}"
    ;;
esac
