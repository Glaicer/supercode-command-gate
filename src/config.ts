export const DEFAULT_TOOLS = ["bash", "shell"];
export const DEFAULT_TIMEOUT_MS = 5500;

export type GateConfig = {
  binaryPath: string;
  tools: string[];
  timeoutMs: number;
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

  const onReviewerFailure = normalizeText(
    options.onReviewerFailure ?? env.AAR_GATE_ON_REVIEWER_FAILURE ?? "deny",
  );
  if (onReviewerFailure !== "deny") {
    errors.push(
      onReviewerFailure === "passthrough"
        ? "onReviewerFailure passthrough is not available in this build yet; reviewer failures deny"
        : "onReviewerFailure must be deny",
    );
  }

  const commandRewriter = normalizeText(
    options.commandRewriter ?? env.AAR_GATE_COMMAND_REWRITER ?? "none",
  );
  if (commandRewriter !== "none") {
    errors.push(
      commandRewriter === "rtk"
        ? "commandRewriter rtk is not available in this build yet; rewrites stay disabled"
        : "commandRewriter must be none",
    );
  }

  return {
    binaryPath: binaryPath === "" ? "aar" : binaryPath,
    tools,
    timeoutMs,
    configError: errors.length === 0 ? null : errors.join("; "),
  };
}
