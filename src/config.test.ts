import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_TIMEOUT_MS, DEFAULT_TOOLS, resolveConfig } from "./config.ts";

test("defaults follow the carried V1 contract", () => {
  const config = resolveConfig({}, {});
  assert.equal(config.binaryPath, "aar");
  assert.deepEqual(config.tools, DEFAULT_TOOLS);
  assert.equal(config.timeoutMs, DEFAULT_TIMEOUT_MS);
  assert.equal(config.approvalMode, "never-ask");
  assert.equal(config.configError, null);
});

test("approvalMode defaults to never-ask and accepts only its two explicit values", () => {
  assert.equal(resolveConfig({}, {}).approvalMode, "never-ask");
  for (const approvalMode of ["never-ask", "interactive", "Interactive"]) {
    const config = resolveConfig({ approvalMode }, {});
    assert.equal(config.configError, null, approvalMode);
  }
  assert.equal(
    resolveConfig({ approvalMode: "never-ask" }, {}).approvalMode,
    "never-ask",
  );
  assert.equal(
    resolveConfig({ approvalMode: "interactive" }, {}).approvalMode,
    "interactive",
  );
  for (const approvalMode of ["always", "", "never_ask"]) {
    const config = resolveConfig({ approvalMode }, {});
    assert.match(
      String(config.configError),
      /approvalMode must be never-ask or interactive/,
      JSON.stringify(approvalMode),
    );
    assert.equal(
      config.approvalMode,
      "never-ask",
      "invalid values fail closed to never-ask",
    );
  }
  const withPassthrough = resolveConfig(
    { approvalMode: "auto", onReviewerFailure: "passthrough" },
    {},
  );
  assert.match(
    String(withPassthrough.configError),
    /approvalMode must be never-ask or interactive/,
  );
  assert.equal(withPassthrough.onReviewerFailure, "passthrough");
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

test("explicit failure modes and RTK are accepted; unknown modes refuse", () => {
  assert.equal(resolveConfig({}, {}).onReviewerFailure, "deny");
  const passthrough = resolveConfig({ onReviewerFailure: "passthrough" }, {});
  assert.equal(passthrough.configError, null);
  assert.equal(passthrough.onReviewerFailure, "passthrough");
  assert.match(
    String(resolveConfig({ onReviewerFailure: "yes" }, {}).configError),
    /must be deny/,
  );
  const rtk = resolveConfig(
    { commandRewriter: "rtk", rewriterPath: "/opt/rtk" },
    {},
  );
  assert.equal(rtk.configError, null);
  assert.equal(rtk.commandRewriter, "rtk");
  assert.equal(rtk.rewriterPath, "/opt/rtk");
  assert.match(
    String(resolveConfig({ commandRewriter: "unknown" }, {}).configError),
    /must be none or rtk/,
  );
  assert.match(
    String(resolveConfig({ rewriterPath: "" }, {}).configError),
    /non-empty string/,
  );
  const fromEnv = resolveConfig(
    {},
    { AAR_GATE_COMMAND_REWRITER: "rtk", AAR_GATE_REWRITER_PATH: "/env/rtk" },
  );
  assert.equal(fromEnv.commandRewriter, "rtk");
  assert.equal(fromEnv.rewriterPath, "/env/rtk");
  assert.equal(
    resolveConfig({ onReviewerFailure: "deny", commandRewriter: "none" }, {})
      .configError,
    null,
  );
});

test("enabled defaults to true and only boolean false disables the gate", () => {
  assert.equal(resolveConfig({}, {}).enabled, true);
  assert.equal(resolveConfig({ enabled: true }, {}).enabled, true);
  assert.equal(resolveConfig({ enabled: false }, {}).enabled, false);
  for (const enabled of ["false", 0, null]) {
    const config = resolveConfig({ enabled }, {});
    assert.equal(config.enabled, true);
    assert.match(String(config.configError), /enabled must be a boolean/);
  }
});

test("allowBackground defaults to false and only an explicit boolean opts in", () => {
  assert.equal(resolveConfig({}, {}).allowBackground, false);
  assert.equal(
    resolveConfig({ allowBackground: false }, {}).allowBackground,
    false,
  );
  assert.equal(
    resolveConfig({ allowBackground: true }, {}).allowBackground,
    true,
  );
  assert.equal(resolveConfig({ allowBackground: true }, {}).configError, null);
  for (const allowBackground of ["true", 1, null, {}]) {
    const config = resolveConfig({ allowBackground }, {});
    assert.equal(
      config.allowBackground,
      false,
      JSON.stringify(allowBackground),
    );
    assert.match(
      String(config.configError),
      /allowBackground must be a boolean/,
      JSON.stringify(allowBackground),
    );
  }
});
