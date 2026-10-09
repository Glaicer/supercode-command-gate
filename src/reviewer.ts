import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import type { Request } from "./request.ts";

export const DECISION_SCHEMA_VERSION = "aar-decision-v1";
export const DOCTOR_SCHEMA_VERSION = "aar-doctor-v1";
export const CONTRACT_VERSION = "aar-contract-v1";

const MAX_REVIEWER_STDOUT_BYTES = 1024 * 1024;
const SOURCES = new Set([
  "hard-deny",
  "auto-allow",
  "grant",
  "assessor",
  "reviewed-trust",
  "unavailable",
  "deny-note",
]);
const ALLOW_SOURCES = new Set([
  "auto-allow",
  "grant",
  "assessor",
  "reviewed-trust",
]);

export type Decision = {
  schemaVersion: string;
  decision: string;
  reason: string;
  source: string;
  failureKind?: string;
  rule: string | null;
  assessment: unknown;
  requestFingerprint: string;
  requestFingerprintBase?: string;
  grantEligible: boolean;
  grantScope?: string;
  auditId: string;
  originAuditId?: string;
  reviewedCoverage?: Array<{
    commandIndex: number;
    source: "auto-allow" | "reviewed-trust";
    rule?: string;
    originAuditId?: string;
  }>;
};

export type DoctorReport = {
  schemaVersion: string;
  contractVersion: string;
  status: string;
  requestSchemaVersion: string;
  decisionSchemaVersion: string;
  reviewerTimeoutMs: number;
};

export type StartupStatus =
  { ok: true; reviewerTimeoutMs: number } | { ok: false; reason: string };

export function reviewerEnvironment(request: {
  cwd: string;
  workspaceRoot: string | null;
}): Record<string, string> {
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: process.env.HOME ?? "",
    PWD: request.cwd,
  };
  if (
    typeof request.workspaceRoot === "string" &&
    request.workspaceRoot !== ""
  ) {
    env.AAR_WORKSPACE_ROOT = request.workspaceRoot;
  }
  for (const key of [
    "AAR_STATE_DIR",
    "XDG_STATE_HOME",
    "AAR_CONFIG",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "OPENCODE_CONFIG_DIR",
    "OPENCODE_BIN",
  ]) {
    const value = process.env[key];
    if (typeof value === "string") env[key] = value;
  }
  for (const apiKeyEnv of reviewerApiKeyEnvs(request)) {
    if (typeof process.env[apiKeyEnv] === "string")
      env[apiKeyEnv] = process.env[apiKeyEnv];
  }
  return env;
}

function reviewerApiKeyEnvs(request: {
  cwd: string;
  workspaceRoot: string | null;
}): string[] {
  const baseCandidates: string[] = [];
  if (process.env.AAR_CONFIG) baseCandidates.push(process.env.AAR_CONFIG);
  if (process.env.XDG_CONFIG_HOME)
    baseCandidates.push(
      path.join(process.env.XDG_CONFIG_HOME, "aar", "config.toml"),
    );
  const home = homedir();
  if (process.platform === "darwin")
    baseCandidates.push(
      path.join(home, "Library", "Application Support", "aar", "config.toml"),
    );
  else if (process.platform === "win32")
    baseCandidates.push(
      path.join(
        process.env.AppData ?? path.join(home, "AppData", "Roaming"),
        "aar",
        "config.toml",
      ),
    );
  else baseCandidates.push(path.join(home, ".config", "aar", "config.toml"));
  const names = new Set<string>();
  const basePath = baseCandidates.find((candidate) => existsSync(candidate));
  const projectRoot = request.workspaceRoot || request.cwd;
  for (const configPath of [
    basePath,
    projectRoot ? path.join(projectRoot, ".aar.toml") : undefined,
  ]) {
    if (configPath)
      for (const name of readApiKeyEnvs(configPath)) names.add(name);
  }
  return [...names];
}

function readApiKeyEnvs(configPath: string): string[] {
  let source: string;
  try {
    source = readFileSync(configPath, "utf8");
  } catch {
    return [];
  }
  const declarations = source
    .split(/\r?\n/)
    .map((line) => line.replace(/#.*$/, ""))
    .join("\n");
  return [
    ...declarations.matchAll(
      /(?:^|[\n,{])\s*apiKeyEnv\s*=\s*["']([A-Za-z_][A-Za-z0-9_]*)["']/g,
    ),
  ].map((match) => match[1]);
}

function parseSingleDecisionLine(stdout: string): unknown {
  const lines = stdout.trim().split(/\r?\n/);
  if (lines.length !== 1 || lines[0] === "")
    throw new Error("reviewer emitted invalid stdout");
  return JSON.parse(lines[0]);
}

type SpawnRunner = typeof spawn;

function runReviewer(
  binaryPath: string,
  args: string[],
  options: {
    cwd: string;
    env: Record<string, string>;
    timeoutMs: number;
    stdin?: string;
    signal?: AbortSignal;
  },
  decode: (stdout: string) => unknown = parseSingleDecisionLine,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    if (options.signal?.aborted) {
      reject(new Error("reviewer cancelled"));
      return;
    }
    const child = spawn(binaryPath, args, {
      cwd: options.cwd,
      env: options.env,
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    let stdout = "";
    let stderr = "";
    let stdoutBytes = 0;
    let settled = false;
    let failure: Error | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (error: Error | null, value?: unknown) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
      if (error) reject(error);
      else resolve(value);
    };
    const stop = (error: Error) => {
      failure ??= error;
      if (child.pid && process.platform !== "win32") {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ESRCH")
            child.kill("SIGKILL");
        }
      } else child.kill("SIGKILL");
    };
    const abort = () => stop(new Error("reviewer cancelled"));
    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.signal?.aborted) abort();
    child.once("error", (error) => {
      failure ??= error;
    });
    child.stdin.on("error", (error) => stop(error));
    child.stdout.on("data", (chunk) => {
      if (settled) return;
      const text = String(chunk);
      stdoutBytes += Buffer.byteLength(text);
      if (stdoutBytes > MAX_REVIEWER_STDOUT_BYTES) {
        stop(new Error("reviewer stdout exceeded the safety limit"));
        return;
      }
      stdout += text;
    });
    child.stderr.on("data", (chunk) => {
      if (Buffer.byteLength(stderr) < 4096) stderr += String(chunk);
    });
    child.once("close", (code, signal) => {
      if (failure) {
        finish(failure);
        return;
      }
      if (code !== 0) {
        const detail = stderr.trim().split(/\r?\n/)[0] ?? "";
        finish(
          new Error(
            `reviewer exited unsuccessfully (${code ?? signal ?? "unknown"})${detail ? `: ${detail}` : ""}`,
          ),
        );
        return;
      }
      try {
        finish(null, decode(stdout));
      } catch (error) {
        finish(error instanceof Error ? error : new Error(String(error)));
      }
    });
    timer = setTimeout(() => {
      stop(new Error("reviewer timeout"));
    }, options.timeoutMs);
    child.stdin.end(options.stdin);
  });
}

export async function callRewrite(
  binaryPath: string,
  command: string,
  cwd: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<string> {
  return (await runReviewer(
    binaryPath,
    ["rewrite", command],
    {
      cwd,
      env: {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        HOME: process.env.HOME ?? "",
        PWD: cwd,
      },
      timeoutMs,
      signal,
    },
    (stdout) => stdout.trim(),
  )) as string;
}

export function callCheck(
  binaryPath: string,
  request: Request,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<Decision> {
  return runReviewer(binaryPath, ["check"], {
    cwd: request.cwd,
    env: reviewerEnvironment(request),
    timeoutMs,
    stdin: `${JSON.stringify(request)}\n`,
    signal,
  }) as Promise<Decision>;
}

export function callDoctor(
  binaryPath: string,
  cwd: string,
  workspaceRoot: string | null,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<DoctorReport> {
  return runReviewer(binaryPath, ["doctor"], {
    cwd,
    env: reviewerEnvironment({ cwd, workspaceRoot }),
    timeoutMs,
    signal,
  }) as Promise<DoctorReport>;
}

export async function callAction(
  binaryPath: string,
  request: Pick<Request, "cwd" | "workspaceRoot" | "session">,
  action: "grant" | "deny-note" | "session-event",
  args: string[],
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<void> {
  const result = await runReviewer(
    binaryPath,
    [action, "--session", request.session.id, ...args],
    {
      cwd: request.cwd,
      env: reviewerEnvironment(request),
      timeoutMs,
      signal,
    },
  );
  const status =
    action === "grant"
      ? "granted"
      : action === "deny-note"
        ? "denied"
        : "invalidated";
  if (
    !result ||
    typeof result !== "object" ||
    (result as { status?: unknown }).status !== status
  )
    throw new Error(`${action} returned an invalid status`);
}

export function normalizeDoctorResult(
  report: unknown,
  gateTimeoutMs: number,
): StartupStatus {
  if (report === false || report === null)
    return {
      ok: false,
      reason: "aar doctor reported an unhealthy installation",
    };
  if (typeof report !== "object" || Array.isArray(report))
    return { ok: false, reason: "aar doctor returned an invalid report" };
  const result = report as Record<string, unknown>;
  if (result.schemaVersion !== DOCTOR_SCHEMA_VERSION) {
    return {
      ok: false,
      reason: `unsupported aar doctor schemaVersion ${JSON.stringify(result.schemaVersion)}`,
    };
  }
  if (result.contractVersion !== CONTRACT_VERSION) {
    return {
      ok: false,
      reason: `unsupported reviewer contract ${JSON.stringify(result.contractVersion)}`,
    };
  }
  if (result.requestSchemaVersion !== "aar-request-v1") {
    return {
      ok: false,
      reason: `unsupported reviewer request contract ${JSON.stringify(result.requestSchemaVersion)}`,
    };
  }
  if (result.decisionSchemaVersion !== DECISION_SCHEMA_VERSION) {
    return {
      ok: false,
      reason: `unsupported reviewer decision contract ${JSON.stringify(result.decisionSchemaVersion)}`,
    };
  }
  if (result.status !== "ok")
    return { ok: false, reason: "aar doctor did not report status ok" };
  const reviewerTimeoutMs = Number(result.reviewerTimeoutMs);
  if (!Number.isFinite(reviewerTimeoutMs) || reviewerTimeoutMs <= 0) {
    return {
      ok: false,
      reason: "aar doctor returned an invalid reviewer timeout",
    };
  }
  if (gateTimeoutMs <= reviewerTimeoutMs) {
    return {
      ok: false,
      reason: `gate timeoutMs (${gateTimeoutMs}) must be greater than the reviewer deadline (${reviewerTimeoutMs})`,
    };
  }
  return { ok: true, reviewerTimeoutMs };
}

export function fingerprintFor(request: Request): string {
  const input = {
    command: request.command,
    cwd: request.cwd,
    workspaceRoot: request.workspaceRoot,
    ...(request.background ? { background: true } : {}),
    sessionId: request.session.id,
    intentId: request.session.intentId ?? "",
    policyVersion: "deterministic-v2",
    shellIR: "shellir-v1",
  };
  return createHash("sha256").update(canonicalJSON(input)).digest("hex");
}

function canonicalJSON(value: unknown): string {
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
}

export function validateDecision(
  decision: unknown,
  request: Request,
): Decision {
  if (!decision || typeof decision !== "object")
    throw new Error("reviewer emitted no decision");
  const value = decision as Record<string, unknown>;
  if (value.schemaVersion !== DECISION_SCHEMA_VERSION)
    throw new Error("reviewer schemaVersion mismatch");
  if (!Object.hasOwn(value, "assessment"))
    throw new Error("reviewer omitted assessment");
  if (
    !Object.hasOwn(value, "grantEligible") ||
    typeof value.grantEligible !== "boolean"
  ) {
    throw new Error("reviewer emitted invalid grantEligible");
  }
  if (
    !Object.hasOwn(value, "rule") ||
    (value.rule !== null && typeof value.rule !== "string")
  ) {
    throw new Error("reviewer emitted invalid rule");
  }
  if (!["allow", "deny", "ask"].includes(String(value.decision)))
    throw new Error("reviewer emitted invalid decision");
  if (typeof value.reason !== "string" || value.reason.trim() === "")
    throw new Error("reviewer emitted no reason");
  if (!SOURCES.has(String(value.source)))
    throw new Error("reviewer emitted invalid source");
  if (value.decision === "allow" && !ALLOW_SOURCES.has(String(value.source))) {
    throw new Error(
      "allow decisions must come from auto-allow, grant, assessor, or reviewed-trust",
    );
  }
  if (
    value.source === "reviewed-trust" &&
    (value.decision !== "allow" ||
      typeof value.originAuditId !== "string" ||
      !/^[a-f0-9]{32}$/.test(value.originAuditId))
  )
    throw new Error("reviewed-trust requires allow and an origin audit id");
  if (value.reviewedCoverage !== undefined) {
    const coverage = value.reviewedCoverage;
    const indexes = new Set<number>();
    if (
      value.source !== "reviewed-trust" ||
      !Array.isArray(coverage) ||
      coverage.length === 0
    )
      throw new Error("invalid reviewed composition provenance");
    let hasOrigin = false;
    for (const node of coverage) {
      if (
        !node ||
        typeof node !== "object" ||
        !Number.isInteger(node.commandIndex) ||
        node.commandIndex < 0 ||
        indexes.has(node.commandIndex)
      )
        throw new Error("invalid reviewed composition provenance");
      indexes.add(node.commandIndex);
      if (node.source === "reviewed-trust") {
        if (
          typeof node.originAuditId !== "string" ||
          !/^[a-f0-9]{32}$/.test(node.originAuditId)
        )
          throw new Error("invalid reviewed composition provenance");
        hasOrigin ||= node.originAuditId === value.originAuditId;
      } else if (
        node.source !== "auto-allow" ||
        typeof node.rule !== "string" ||
        node.rule.trim() === ""
      )
        throw new Error("invalid reviewed composition provenance");
    }
    if (!hasOrigin) throw new Error("invalid reviewed composition provenance");
  }
  if (value.source === "grant" && value.decision !== "allow")
    throw new Error("grant source requires an allow decision");
  if (value.source === "deny-note" && value.decision !== "deny")
    throw new Error("deny-note source requires a deny decision");
  if (value.decision !== "allow" && value.source === "auto-allow")
    throw new Error("auto-allow source requires an allow decision");
  if (
    value.decision === "allow" &&
    value.source === "auto-allow" &&
    (typeof value.rule !== "string" || value.rule.trim() === "")
  ) {
    throw new Error("auto-allow decisions require a rule");
  }
  if (
    typeof value.requestFingerprint !== "string" ||
    value.requestFingerprint === ""
  ) {
    throw new Error("reviewer emitted no request fingerprint");
  }
  const baseFingerprint = fingerprintFor(request);
  if (
    value.requestFingerprintBase !== undefined &&
    (typeof value.requestFingerprintBase !== "string" ||
      value.requestFingerprintBase !== baseFingerprint)
  ) {
    throw new Error("reviewer request base fingerprint mismatch");
  }
  if (
    value.requestFingerprint !== baseFingerprint &&
    value.requestFingerprintBase !== baseFingerprint
  ) {
    throw new Error("reviewer request fingerprint mismatch");
  }
  if (typeof value.auditId !== "string" || value.auditId === "")
    throw new Error("reviewer emitted no audit id");
  return value as unknown as Decision;
}
