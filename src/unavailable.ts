import { randomUUID } from "node:crypto";
import { redactText } from "./approval-text.ts";

export type UnavailableAlert = {
  id: string;
  sessionID: string;
  component: "reviewer" | "assessor";
  reason: string;
};

export function safeOperationalReason(reason: string): string {
  const safe = redactText(reason).replace(/\s+/g, " ").trim();
  if (safe.includes("ENOENT")) return "Reviewer executable is unavailable";
  if (safe.includes("reviewer timeout")) return "Reviewer timed out";
  if (safe.includes("reviewer exited unsuccessfully"))
    return "Reviewer exited unsuccessfully; detailed subprocess output is omitted";
  if (/^reviewer (emitted|schemaVersion|omitted|request |stdout )/.test(safe))
    return safe.split(":")[0].slice(0, 160);
  return "Reviewer unavailable; a safe diagnostic reason is not available";
}

export function assessorUnavailableReason(failureKind?: string): string {
  const reasons: Record<string, string> = {
    "provider-outage": "provider request failed",
    "invalid-json": "response was not valid JSON",
    "schema-invalid": "response did not match the assessment schema",
    "context-evidence": "required evidence could not fit the context window",
  };
  return `Command Risk Assessor unavailable: ${reasons[failureKind ?? ""] ?? "diagnostic reason is not available"}`;
}

export class UnavailableAlerts {
  #episodes = new Map<string, UnavailableAlert>();
  fail(
    sessionID: string,
    component: UnavailableAlert["component"],
    reason: string,
  ): UnavailableAlert | null {
    const key = `${sessionID}:${component}`;
    if (this.#episodes.has(key)) return null;
    const alert = {
      id: randomUUID(),
      sessionID,
      component,
      reason: redactText(reason),
    };
    this.#episodes.set(key, alert);
    return alert;
  }
  recover(sessionID: string, component: UnavailableAlert["component"]): void {
    this.#episodes.delete(`${sessionID}:${component}`);
  }
  list(sessionID: string): UnavailableAlert[] {
    return [...this.#episodes.values()].filter(
      (item) => item.sessionID === sessionID,
    );
  }
}
