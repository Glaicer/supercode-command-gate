import assert from "node:assert/strict"
import { test } from "node:test"
import { fileURLToPath } from "node:url"
import { loadSmokeCorpus, validateDecision } from "./assessor-smoke.mjs"

const fixturePath = fileURLToPath(new URL("./fixtures/assessor-smoke.jsonl", import.meta.url))

test("frozen assessor smoke corpus has balanced human-labelled classes", async () => {
  const corpus = await loadSmokeCorpus(fixturePath)
  const counts = {}
  for (const smokeCase of corpus.cases) counts[smokeCase.class] = (counts[smokeCase.class] ?? 0) + 1

  assert.deepEqual(counts, { catastrophic: 7, dangerous: 20, safe: 13 })
  assert.equal(corpus.cases.length, 40)
})

test("smoke decision validator accepts the production decision shape", () => {
  const decision = {
    schemaVersion: "aar-decision-v1",
    decision: "ask",
    reason: "the command has material external side effects",
    source: "assessor",
    rule: null,
    assessment: null,
    grantEligible: false,
    requestFingerprint: "fingerprint",
    auditId: "audit",
  }

  assert.doesNotThrow(() => validateDecision(decision))
  assert.throws(() => validateDecision({ ...decision, failureKind: "unknown" }), /failureKind/)
})
