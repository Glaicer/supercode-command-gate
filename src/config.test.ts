import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_TIMEOUT_MS, DEFAULT_TOOLS, resolveConfig } from "./config.ts";

test("defaults follow the carried V1 contract", () => {
  const config = resolveConfig({}, {});
  assert.equal(config.binaryPath, "aar");
  assert.deepEqual(config.tools, DEFAULT_TOOLS);
  assert.equal(config.timeoutMs, DEFAULT_TIMEOUT_MS);
  assert.equal(config.configError, null);
});

test("options take precedence over environment overrides", () => {
  const config = resolveConfig(
    { binaryPath: "/opt/aar", tools: ["SHELL"], timeoutMs: 9000 },
    {
      AAR_BINARY_PATH: "ignored",
      AAR_GATE_TOOLS: "bash",
      AAR_GATE_TIMEOUT_MS: "1111",
    },
  );
  assert.equal(config.binaryPath, "/opt/aar");
  assert.deepEqual(config.tools, ["shell"]);
  assert.equal(config.timeoutMs, 9000);
  assert.equal(config.configError, null);
});

test("environment overrides apply without options", () => {
  const config = resolveConfig(
    {},
    {
      AAR_BINARY_PATH: "/env/aar",
      AAR_GATE_TOOLS: "bash,shell",
      AAR_GATE_TIMEOUT_MS: "7000",
    },
  );
  assert.equal(config.binaryPath, "/env/aar");
  assert.deepEqual(config.tools, ["bash", "shell"]);
  assert.equal(config.timeoutMs, 7000);
});

test("invalid timeout is a configuration error, never an implicit allow", () => {
  const config = resolveConfig({ timeoutMs: -1 }, {});
  assert.match(
    String(config.configError),
    /timeoutMs must be a positive number/,
  );
});

test("empty binaryPath is a configuration error", () => {
  assert.match(
    String(resolveConfig({ binaryPath: "  " }, {}).configError),
    /binaryPath must be a non-empty string/,
  );
});

test("explicit failure modes are accepted; unknown modes and unimplemented rewrites refuse", () => {
  assert.equal(resolveConfig({}, {}).onReviewerFailure, "deny");
  const passthrough = resolveConfig({ onReviewerFailure: "passthrough" }, {});
  assert.equal(passthrough.configError, null);
  assert.equal(passthrough.onReviewerFailure, "passthrough");
  assert.match(
    String(resolveConfig({ onReviewerFailure: "yes" }, {}).configError),
    /must be deny/,
  );
  assert.match(
    String(resolveConfig({ commandRewriter: "rtk" }, {}).configError),
    /not available in this build/,
  );
  assert.equal(
    resolveConfig({ onReviewerFailure: "deny", commandRewriter: "none" }, {})
      .configError,
    null,
  );
});
