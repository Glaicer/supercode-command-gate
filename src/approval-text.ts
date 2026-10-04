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

function assessment(item: Pick<PendingApproval, "assessment">): {
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

export function riskAssessmentText(value: unknown): string {
  const { risks, uncertainties } = assessment({ assessment: value });
  return [
    ...risks.map(
      (risk, index) =>
        `Risk ${index + 1} of ${risks.length}\n${riskText(risk)}`,
    ),
    ...(uncertainties.length
      ? [
          `Uncertainties:\n${uncertainties.map((value) => `• ${value}`).join("\n")}`,
        ]
      : []),
  ].join("\n\n");
}

function commandPreview(item: PendingApproval): string {
  const shortened = item.preview !== redactText(item.command);
  return `Command preview${shortened ? " (shortened)" : ""}:\n${item.preview}`;
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
      highest
        ? riskText(highest)
        : `Why approval is needed:\n${item.effectSummary}`,
      ...(risks.length > 1
        ? [
            `${risks.length - 1} more ${risks.length === 2 ? "risk" : "risks"} — see Details`,
          ]
        : []),
      ...(uncertainties.length
        ? [
            `${uncertainties.length} ${uncertainties.length === 1 ? "uncertainty" : "uncertainties"} — see Details`,
          ]
        : []),
      `Working directory:\n${item.cwd}`,
      commandPreview(item),
    ].join("\n\n"),
  );
}

export function approvalDetails(item: PendingApproval): string {
  const { risks, uncertainties } = assessment(item);
  return [
    ...(risks.length
      ? risks.map(
          (risk, index) =>
            `Risk ${index + 1} of ${risks.length}\n${riskText(risk)}`,
        )
      : [`Why approval is needed:\n${item.effectSummary}`]),
    `Uncertainties:\n${uncertainties.length ? uncertainties.map((value) => `• ${value}`).join("\n") : "None reported"}`,
    `Working directory:\n${item.cwd}`,
    commandPreview(item),
  ].join("\n\n");
}

export function approvalTechnicalDetails(item: PendingApproval): string {
  return `Session: ${item.sessionID}\nCall: ${item.callID}\nFingerprint: ${item.fingerprint}\n\nRiskAssessment:\n${JSON.stringify(item.assessment, null, 2)}`;
}

export function approvalPages(
  message: string,
  width: number,
  height: number,
): string[] {
  const graphemes = new Intl.Segmenter(undefined, { granularity: "grapheme" });
  const lines = message.split("\n").flatMap((line) => {
    const wrapped: string[] = [];
    let row = "";
    let cells = 0;
    for (const { segment } of graphemes.segment(line)) {
      // shortcut: reserve two cells for non-ASCII graphemes until the host exposes a public width helper.
      const size = segment === "\t" ? 8 : /^[\x20-\x7e]$/.test(segment) ? 1 : 2;
      if (row && cells + size > width) {
        wrapped.push(row);
        row = "";
        cells = 0;
      }
      row += segment;
      cells += size;
    }
    wrapped.push(row);
    return wrapped;
  });
  const pages: string[] = [];
  for (let start = 0; start < lines.length; start += height)
    pages.push(lines.slice(start, start + height).join("\n"));
  return pages;
}
