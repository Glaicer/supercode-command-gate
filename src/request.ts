import { realpathSync } from "node:fs";

export type Request = {
  schemaVersion: string;
  command: string;
  cwd: string;
  workspaceRoot: string | null;
  env: Record<string, string>;
  session: { id: string; host: string; intentId: string };
  intent: {
    goal: string | null;
    latestUserRequest: string | null;
    purpose: null;
  };
};

export type Invocation = {
  command: string;
  cwd: string;
  env: Record<string, string | undefined>;
};

export type SessionFacts = {
  sessionID: string;
  intentId: string | null;
  goal: string | null;
  latestUserRequest: string | null;
};

export const MATERIAL_ENV_KEYS = ["CDPATH", "HOME", "PWD"];
export const REQUEST_SCHEMA_VERSION = "aar-request-v1";

export function canonicalDirectory(value: string): string {
  return realpathSync(value);
}

export function materialEnvSubset(
  env: Record<string, string | undefined>,
): Record<string, string> {
  const subset: Record<string, string> = {};
  for (const key of MATERIAL_ENV_KEYS) {
    const value = env[key];
    if (typeof value === "string") subset[key] = value;
  }
  return subset;
}

export function buildRequest(
  invocation: Invocation,
  facts: SessionFacts,
  workspaceRoot: string | null,
): Request {
  return {
    schemaVersion: REQUEST_SCHEMA_VERSION,
    command: invocation.command,
    cwd: canonicalDirectory(invocation.cwd),
    workspaceRoot:
      workspaceRoot === null ? null : canonicalDirectory(workspaceRoot),
    env: materialEnvSubset(invocation.env),
    session: {
      id: facts.sessionID,
      host: "opencode",
      intentId: facts.intentId ?? "",
    },
    intent: {
      goal: facts.goal,
      latestUserRequest: facts.latestUserRequest,
      purpose: null,
    },
  };
}
