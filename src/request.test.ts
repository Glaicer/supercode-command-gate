import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  MATERIAL_ENV_KEYS,
  assistantRationaleFor,
  buildRequest,
  canonicalDirectory,
  materialEnvSubset,
} from "./request.ts";

test("the material env subset keeps only the carried keys and never the full environment", () => {
  const subset = materialEnvSubset({
    HOME: "/home/user",
    PWD: "/work",
    CDPATH: "/cd",
    BASHOPTS: "dotglob",
    SHELLOPTS: "noglob",
    GLOBIGNORE: "ignored",
    BASH_ENV: "/startup.sh",
    ENV: "/sh-startup.sh",
    SECRET_TOKEN: "do-not-forward",
    PATH: "/usr/bin",
  });
  assert.deepEqual(subset, {
    PATH: "/usr/bin",
    CDPATH: "/cd",
    HOME: "/home/user",
    PWD: "/work",
    BASHOPTS: "dotglob",
    SHELLOPTS: "noglob",
    GLOBIGNORE: "ignored",
    BASH_ENV: "/startup.sh",
    ENV: "/sh-startup.sh",
  });
  assert.ok(
    Object.keys(subset).every((key) => MATERIAL_ENV_KEYS.includes(key)),
  );
  assert.equal("SECRET_TOKEN" in subset, false);
});

test("assistant rationale comes only from content before the owning tool call", () => {
  const messages = [
    {
      id: "other",
      type: "assistant",
      content: [{ type: "reasoning", text: "unrelated reasoning" }],
    },
    {
      id: "owning",
      type: "assistant",
      content: [
        { type: "reasoning", text: "This is a disposable clone I created." },
        { type: "text", text: "Removing the temporary clone." },
        { type: "tool", id: "call_1", text: "tool output must not cross" },
        { type: "reasoning", text: "later reasoning must not cross" },
      ],
    },
  ];
  const rationale = assistantRationaleFor(messages, "owning", "call_1");
  assert.equal(
    rationale,
    "This is a disposable clone I created.\nRemoving the temporary clone.",
  );
  assert.equal(assistantRationaleFor(messages, "other", "call_1"), null);
  assert.equal(assistantRationaleFor(messages, "owning", "missing"), null);
  const request = buildRequest(
    { command: "rm ./clone", cwd: process.cwd(), env: {} },
    {
      sessionID: "ses_1",
      intentId: "msg_1",
      goal: null,
      latestUserRequest: null,
      assistantRationale: rationale,
    },
    null,
  );
  assert.equal(request.intent.assistantRationale, rationale);
});

test("assistant rationale retains a bounded suffix nearest the call", () => {
  const rationale = assistantRationaleFor(
    [
      {
        id: "owning",
        type: "assistant",
        content: [
          { type: "reasoning", text: "x".repeat(9000) + "immediate reason" },
          { type: "tool", id: "call_1" },
        ],
      },
    ],
    "owning",
    "call_1",
  );
  assert.equal(rationale?.length, 8192);
  assert.ok(rationale?.endsWith("immediate reason"));
});

test("undefined values are dropped instead of sent as empty strings", () => {
  assert.deepEqual(materialEnvSubset({ HOME: "/home/user", PWD: undefined }), {
    HOME: "/home/user",
  });
});

test("buildRequest carries verbatim command bytes, canonical cwd and owning identity", () => {
  const root = mkdtempSync(path.join(tmpdir(), "command-gate-request-"));
  try {
    const request = buildRequest(
      {
        command:
          "export X=$(printf a); printf '%s' \"$X\" | cat > f <<'EOF'\nEOF\n",
        cwd: root,
        env: { HOME: "/home/user", SECRET_TOKEN: "do-not-forward" },
      },
      {
        sessionID: "ses_1",
        intentId: "msg_1",
        goal: "Inspect only",
        latestUserRequest: "look around",
      },
      root,
    );
    assert.equal(request.schemaVersion, "aar-request-v1");
    assert.equal(
      request.command,
      "export X=$(printf a); printf '%s' \"$X\" | cat > f <<'EOF'\nEOF\n",
    );
    assert.equal(request.cwd, canonicalDirectory(root));
    assert.equal(request.workspaceRoot, canonicalDirectory(root));
    assert.deepEqual(request.env, { HOME: "/home/user" });
    assert.deepEqual(request.session, {
      id: "ses_1",
      host: "opencode",
      intentId: "msg_1",
    });
    assert.deepEqual(request.intent, {
      goal: "Inspect only",
      latestUserRequest: "look around",
      purpose: null,
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("canonicalDirectory resolves symlinks to the actual directory", () => {
  const root = mkdtempSync(path.join(tmpdir(), "command-gate-cwd-"));
  try {
    const real = path.join(root, "real");
    const link = path.join(root, "link");
    mkdirSync(real);
    symlinkSync(real, link);
    assert.equal(canonicalDirectory(link), canonicalDirectory(real));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("missing intent facts degrade to explicit nulls without fabrication", () => {
  const request = buildRequest(
    { command: "pwd", cwd: process.cwd(), env: {} },
    { sessionID: "ses_2", intentId: null, goal: null, latestUserRequest: null },
    null,
  );
  assert.equal(request.workspaceRoot, null);
  assert.deepEqual(request.env, {});
  assert.equal(request.session.intentId, "");
  assert.deepEqual(request.intent, {
    goal: null,
    latestUserRequest: null,
    purpose: null,
  });
});

test("launch environment changes invalidate trust without disclosing secret values", () => {
  const make = (env: Record<string, string>) =>
    buildRequest(
      { command: "pnpm typecheck", cwd: process.cwd(), env },
      { sessionID: "s", intentId: "i", goal: null, latestUserRequest: null },
      null,
    );
  const first = make({ PATH: "/usr/bin", SECRET_TOKEN: "first" });
  const reordered = make({ SECRET_TOKEN: "first", PATH: "/usr/bin" });
  const changed = make({ PATH: "/usr/bin", SECRET_TOKEN: "second" });
  assert.match(first.executionEnvDigest!, /^[a-f0-9]{64}$/);
  assert.equal(first.executionEnvDigest, reordered.executionEnvDigest);
  assert.notEqual(first.executionEnvDigest, changed.executionEnvDigest);
  assert.equal(JSON.stringify(first).includes("SECRET_TOKEN"), false);
});

test("the background fact is carried only when the invocation requested background", () => {
  const facts = {
    sessionID: "ses_1",
    intentId: "msg_1",
    goal: null,
    latestUserRequest: null,
  };
  const invocation = { command: "pwd", cwd: process.cwd(), env: {} };
  const foreground = buildRequest(invocation, facts, null);
  const background = buildRequest(
    invocation,
    { ...facts, background: true },
    null,
  );
  assert.equal(background.background, true);
  assert.equal("background" in foreground, false);
  assert.equal(JSON.stringify(foreground).includes("background"), false);
  assert.notEqual(JSON.stringify(foreground), JSON.stringify(background));
});
