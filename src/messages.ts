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

export function unavailableReason(detail: string): string {
  return `the Command Gate is unavailable (${compactReason(detail)})`;
}

export function approvalReason(): string {
  return "this command requires human approval; no working approval client is available";
}

export function startupDiagnostic(reason: string): string {
  return `Command Gate is unavailable: ${compactReason(reason)}. Fix the installation or configuration, then restart OpenCode after \`aar doctor\` passes. Bash commands remain denied.`;
}
