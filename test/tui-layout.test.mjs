import assert from "node:assert/strict";
import { test } from "node:test";
import { runSeam } from "./seam-driver.mjs";

test("a real 64x24 TUI displays complete action labels and readable paginated evidence", async () => {
  const evidence = await runSeam({ approval: true, human: true, layout: true });
  for (const field of [
    "previous_label",
    "previous_returns_prior_page",
    "deny",
    "once",
    "details",
    "command",
    "technical",
    "immediate_risk",
    "cwd",
    "shortened_preview",
    "masked",
    "readable_assessment",
    "uncertainty",
    "details_without_command",
    "secret_warning",
    "unmasked_command",
    "unicode",
    "last_command_line",
    "all_command_pages",
    "resize_repagination",
    "resize_preserves_position",
    "returned_actions",
    "no_execution_while_reading",
  ])
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
  assert.equal(replies[0].decision, "deny");
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
