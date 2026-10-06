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
    assistantRationale?: string;
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
  assistantRationale?: string | null;
};

export function assistantRationaleFor(
  messages: readonly {
    id: string;
    type: string;
    content?: readonly { type: string; text?: string; id?: string }[];
  }[],
  messageID: string,
  callID: string,
): string | null {
  const message = messages.find(
    (item) => item.type === "assistant" && item.id === messageID,
  );
  const content = message?.content;
  if (!content) return null;
  const callIndex = content.findIndex(
    (part) => part.type === "tool" && part.id === callID,
  );
  if (callIndex < 0) return null;
  const rationale = content
    .slice(0, callIndex)
    .filter((part) => part.type === "reasoning" || part.type === "text")
    .map((part) => part.text ?? "")
    .join("\n")
    .slice(-8192);
  return rationale || null;
}

export const MATERIAL_ENV_KEYS = [
  "CDPATH",
  "HOME",
  "PWD",
  "BASHOPTS",
  "SHELLOPTS",
  "GLOBIGNORE",
  "BASH_ENV",
  "ENV",
];
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
      ...(facts.assistantRationale
        ? { assistantRationale: facts.assistantRationale.slice(-8192) }
        : {}),
    },
  };
}
