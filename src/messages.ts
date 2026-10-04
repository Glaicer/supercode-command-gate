import { redactText, riskAssessmentText } from "./approval-text.ts";
import type { Decision } from "./reviewer.ts";

export function compactReason(reason: unknown): string {
  return String(reason).replace(/\s+/g, " ").trim();
}

export function errorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return compactReason(message || "unknown operational failure");
}

export function blockedMessage(reason: string): string {
  return `Auto Approve Permissions blocked this command. Reason: ${compactReason(reason)}. The command was not executed.`;
}

export function reviewerDenialMessage(
  decision: Pick<Decision, "reason" | "source" | "rule" | "assessment">,
): string {
  if (decision.source === "unavailable")
    return redactText(blockedMessage(unavailableReason(decision.reason)));
  return redactText(
    [
      `Auto Approve Permissions blocked this command. Reason: ${compactReason(decision.reason)}.`,
      ...(decision.rule ? [`Rule: ${decision.rule}`] : []),
      riskAssessmentText(decision.assessment),
      "The command was not executed.",
    ]
      .filter(Boolean)
      .join("\n\n"),
  );
}

export const NEVER_ASK_EXPLANATION =
  "Human approval is required by Reviewer policy, but prompts are disabled. The command was not executed.";

export function neverAskDenialMessage(
  decision: Pick<Decision, "reason" | "rule" | "assessment">,
): string {
  return redactText(
    [
      `Auto Approve Permissions blocked this command. Reason: ${compactReason(decision.reason)}.`,
      ...(decision.rule ? [`Rule: ${decision.rule}`] : []),
      riskAssessmentText(decision.assessment),
      NEVER_ASK_EXPLANATION,
    ]
      .filter(Boolean)
      .join("\n\n"),
  );
}

export function unavailableReason(detail: string): string {
  return `the Command Gate is unavailable (${compactReason(detail)})`;
}

export function approvalReason(): string {
  return "this command requires human approval; no working approval client is available";
}

export function startupDiagnostic(reason: string): string {
  return `Command Gate is unavailable: ${compactReason(reason)}. Fix the installation or configuration, then restart OpenCode after \`aar doctor\` passes. Bash commands remain denied.`;
}
