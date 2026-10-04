import { DEFAULT_APPROVAL_TIMEOUT_MS } from "./approval.ts";

export const DEFAULT_TOOLS = ["bash", "shell"];
export const DEFAULT_TIMEOUT_MS = 5500;

export type GateConfig = {
  binaryPath: string;
  tools: string[];
  timeoutMs: number;
  approvalTimeoutMs: number;
  approvalMode: "never-ask" | "interactive";
  onReviewerFailure: "deny" | "passthrough";
  commandRewriter: "none" | "rtk";
  rewriterPath: string;
  configError: string | null;
};

type Env = Record<string, string | undefined>;

function normalizeTools(value: unknown): string[] {
  if (Array.isArray(value))
    return value.map((tool) => String(tool).toLowerCase()).filter(Boolean);
  if (typeof value === "string" && value.trim() !== "") {
    return value
      .split(",")
      .map((tool) => tool.trim().toLowerCase())
      .filter(Boolean);
  }
  return DEFAULT_TOOLS;
}

function normalizeText(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

export function resolveConfig(
  options: Readonly<Record<string, unknown>>,
  env: Env = process.env,
): GateConfig {
  const rawBinaryPath = options.binaryPath ?? env.AAR_BINARY_PATH ?? "aar";
  const binaryPath =
    typeof rawBinaryPath === "string" && rawBinaryPath.trim() !== ""
      ? rawBinaryPath.trim()
      : "";
  const tools = normalizeTools(options.tools ?? env.AAR_GATE_TOOLS);
  const rawTimeout = options.timeoutMs ?? env.AAR_GATE_TIMEOUT_MS;
  const timeoutValue =
    rawTimeout === undefined ? DEFAULT_TIMEOUT_MS : Number(rawTimeout);
  const errors: string[] = [];
  if (binaryPath === "") errors.push("binaryPath must be a non-empty string");
  if (!Number.isFinite(timeoutValue) || timeoutValue <= 0)
    errors.push("timeoutMs must be a positive number");
  const timeoutMs =
    Number.isFinite(timeoutValue) && timeoutValue > 0
      ? timeoutValue
      : DEFAULT_TIMEOUT_MS;
  const approvalTimeoutMs = Number(
    options.approvalTimeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS,
  );
  if (!Number.isFinite(approvalTimeoutMs) || approvalTimeoutMs <= 0)
    errors.push("approvalTimeoutMs must be a positive number");

  const approvalMode = normalizeText(options.approvalMode ?? "never-ask");
  if (!["never-ask", "interactive"].includes(approvalMode))
    errors.push("approvalMode must be never-ask or interactive");

  const onReviewerFailure = normalizeText(
    options.onReviewerFailure ?? env.AAR_GATE_ON_REVIEWER_FAILURE ?? "deny",
  );
  if (!["deny", "passthrough"].includes(onReviewerFailure))
    errors.push("onReviewerFailure must be deny or passthrough");

  const commandRewriter = normalizeText(
    options.commandRewriter ?? env.AAR_GATE_COMMAND_REWRITER ?? "none",
  );
  if (!["none", "rtk"].includes(commandRewriter))
    errors.push("commandRewriter must be none or rtk");
  const rawRewriterPath =
    options.rewriterPath ?? env.AAR_GATE_REWRITER_PATH ?? "rtk";
  const rewriterPath =
    typeof rawRewriterPath === "string" ? rawRewriterPath.trim() : "";
  if (!rewriterPath) errors.push("rewriterPath must be a non-empty string");

  return {
    binaryPath: binaryPath === "" ? "aar" : binaryPath,
    tools,
    timeoutMs,
    approvalTimeoutMs,
    approvalMode: approvalMode === "interactive" ? "interactive" : "never-ask",
    commandRewriter: commandRewriter === "rtk" ? "rtk" : "none",
    rewriterPath: rewriterPath || "rtk",
    onReviewerFailure:
      onReviewerFailure === "passthrough" ? "passthrough" : "deny",
    configError: errors.length === 0 ? null : errors.join("; "),
  };
}
