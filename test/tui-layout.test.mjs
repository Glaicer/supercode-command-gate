import assert from "node:assert/strict";
import { test } from "node:test";
import { runSeam } from "./seam-driver.mjs";

test("a real 64x24 TUI displays complete action labels and readable paginated evidence", async () => {
  const evidence = await runSeam({ approval: true, human: true, layout: true });
  for (const [field, visible] of Object.entries(evidence.approval.layout))
    assert.equal(visible, true, `${field} was clipped or absent`);
  assert.equal(
    evidence.approval.cases[0].marker,
    false,
    "the automated UI fixture never approves execution",
  );
});
