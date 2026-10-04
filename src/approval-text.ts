import type { PendingApproval } from "./approval.ts";

const categories: Record<string, string> = {
  critical_data_loss: "Critical data loss",
  credential_access: "Credential access",
  external_side_effect: "Changes outside this machine",
  network: "Network access",
  privilege: "Elevated privileges",
  persistence: "Persistent changes",
  process_control: "Process control",
  resource_exhaustion: "Resource exhaustion",
  opaque_execution: "Execution the reviewer cannot fully inspect",
  goal_mismatch: "Command may not match your intent",
};
const severities: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

type Risk = {
  category?: unknown;
  likelihood?: unknown;
  severity?: unknown;
  reversible?: unknown;
  affectsProtectedPaths?: unknown;
  evidence?: unknown;
};

export function redactText(text: string): string {
  return text
    .replace(/(Bearer\s+)[^\s'"`]+/gi, "$1[REDACTED]")
    .replace(
      /((?:token|password|secret|api[_-]?key)[^=\s]*\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s]+)/gi,
      "$1[REDACTED]",
    )
    .replace(/(https?:\/\/[^/\s:@]+:)[^@\s]+(@)/gi, "$1[REDACTED]$2")
    .replace(/\bsk-[A-Za-z0-9_-]+/g, "sk-[REDACTED]");
}

function label(value: unknown): string {
  if (typeof value !== "string" || !value) return "Unknown";
  return value.charAt(0).toUpperCase() + value.slice(1).replaceAll("_", " ");
}

function yesNo(value: unknown): string {
  return value === true ? "Yes" : value === false ? "No" : "Unknown";
}

function assessment(item: PendingApproval): {
  risks: Risk[];
  uncertainties: string[];
} {
  const data = item.assessment as {
    risks?: unknown;
    uncertainties?: unknown;
  } | null;
  return {
    risks: Array.isArray(data?.risks)
      ? data.risks.filter(
          (risk): risk is Risk => risk !== null && typeof risk === "object",
        )
      : [],
    uncertainties: Array.isArray(data?.uncertainties)
      ? data.uncertainties.filter(
          (value): value is string => typeof value === "string",
        )
      : [],
  };
}

function riskText(risk: Risk): string {
  const category =
    typeof risk.category === "string" ? categories[risk.category] : undefined;
  return [
    `Risk: ${category ?? label(risk.category)}`,
    `Severity: ${label(risk.severity)} · Likelihood: ${label(risk.likelihood)}`,
    `Reversible: ${yesNo(risk.reversible)} · Protected paths affected: ${yesNo(risk.affectsProtectedPaths)}`,
    `Evidence:\n${typeof risk.evidence === "string" && risk.evidence ? risk.evidence : "Not supplied"}`,
  ].join("\n");
}

export function approvalSummary(item: PendingApproval): string {
  const { risks, uncertainties } = assessment(item);
  const highest = risks.reduce<Risk | undefined>((prior, risk) => {
    const score = (value: unknown) =>
      typeof value === "string" ? (severities[value] ?? 0) : 0;
    return !prior || score(risk.severity) > score(prior.severity)
      ? risk
      : prior;
  }, undefined);
  return redactText(
    [
      `Command:\n${item.preview}`,
      highest
        ? riskText(highest)
        : `Why approval is needed:\n${item.effectSummary}`,
      ...(risks.length > 1
        ? [
            `${risks.length - 1} more ${risks.length === 2 ? "risk" : "risks"} — see Full details`,
          ]
        : []),
      ...(uncertainties.length
        ? [
            `${uncertainties.length} ${uncertainties.length === 1 ? "uncertainty" : "uncertainties"} — see Full details`,
          ]
        : []),
      `Working directory:\n${item.cwd}`,
    ].join("\n\n"),
  );
}

export function approvalDetails(item: PendingApproval): string {
  const { risks, uncertainties } = assessment(item);
  return [
    `Command:\n${item.command}`,
    `Working directory:\n${item.cwd}`,
    ...(risks.length
      ? risks.map(
          (risk, index) =>
            `Risk ${index + 1} of ${risks.length}\n${riskText(risk)}`,
        )
      : [`Why approval is needed:\n${item.effectSummary}`]),
    `Uncertainties:\n${uncertainties.length ? uncertainties.map((value) => `• ${value}`).join("\n") : "None reported"}`,
  ].join("\n\n");
}

export function approvalTechnicalDetails(item: PendingApproval): string {
  return `Session: ${item.sessionID}\nCall: ${item.callID}\nFingerprint: ${item.fingerprint}\n\nRiskAssessment:\n${JSON.stringify(item.assessment, null, 2)}`;
}
