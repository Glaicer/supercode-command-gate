import assert from "node:assert/strict";
import { test } from "node:test";
import { runSeam, versionAtLeast } from "./seam-driver.mjs";

const summaryFields = [
  "immediate_risk",
  "cwd",
  "shortened_preview",
  "masked",
  "deny",
  "once",
  "details",
  "command",
  "technical",
  "readable_assessment",
  "uncertainty",
  "details_without_command",
  "returned_actions",
  "no_execution_while_reading",
];

const commandFields = [
  "previous_label",
  "previous_returns_prior_page",
  "secret_warning",
  "unmasked_command",
  "unicode",
  "last_command_line",
  "all_command_pages",
  "resize_repagination",
  "resize_preserves_position",
];

test("a real 64x24 TUI displays complete action labels and readable paginated evidence", async () => {
  const evidence = await runSeam({ approval: true, human: true, layout: true });
  const modern = versionAtLeast(evidence.version, "2.1.0");
  const fields = modern ? summaryFields : [...summaryFields, ...commandFields];
  for (const field of fields)
    assert.equal(
      evidence.approval.layout[field],
      true,
      `${field} was clipped or absent`,
    );
  assert.equal(
    evidence.approval.cases[0].marker,
    false,
    "the automated UI fixture never approves execution",
  );
  const replies = evidence.approval.cases[0].events.filter(
    (event) => event.kind === "human-response",
  );
  assert.equal(replies.length, 1);
  assert.equal(replies[0].decision, modern ? "dismiss" : "deny");
});

test("Escape on a page with Previous still dismisses approval without execution", async () => {
  const evidence = await runSeam({
    approval: true,
    human: true,
    layout: true,
    layoutDismiss: true,
  });
  assert.equal(evidence.approval.layout.escape_on_later_page, true);
  const result = evidence.approval.cases[0];
  assert.equal(result.marker, false);
  const replies = result.events.filter(
    (event) => event.kind === "human-response",
  );
  assert.equal(replies.length, 1);
  assert.equal(replies[0].decision, "dismiss");
});
