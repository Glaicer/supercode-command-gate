import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  MATERIAL_ENV_KEYS,
  buildRequest,
  canonicalDirectory,
  materialEnvSubset,
} from "./request.ts";

test("the material env subset keeps only the carried keys and never the full environment", () => {
  const subset = materialEnvSubset({
    HOME: "/home/user",
    PWD: "/work",
    CDPATH: "/cd",
    SECRET_TOKEN: "do-not-forward",
    PATH: "/usr/bin",
  });
  assert.deepEqual(subset, { CDPATH: "/cd", HOME: "/home/user", PWD: "/work" });
  assert.deepEqual(Object.keys(subset).sort(), [...MATERIAL_ENV_KEYS].sort());
  assert.equal("SECRET_TOKEN" in subset, false);
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
