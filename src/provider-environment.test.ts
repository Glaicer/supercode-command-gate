import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { reviewerEnvironment } from "./reviewer.ts";

test("reviewer receives explicitly configured primary and fallback credentials", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "aar-provider-env-"));
  const config = path.join(cwd, "config.toml");
  writeFileSync(
    config,
    `[assessor]\napiKeyEnv = "SYNTHETIC_PRIMARY"\n[[assessor.fallbacks]]\napiKeyEnv = "SYNTHETIC_TABLE"\n`,
  );
  writeFileSync(
    path.join(cwd, ".aar.toml"),
    `[assessor]\nfallbacks = [\n { model = "m", apiKeyEnv = 'SYNTHETIC_INLINE' }\n]\n`,
  );
  const original = { ...process.env };
  try {
    process.env.AAR_CONFIG = config;
    process.env.SYNTHETIC_PRIMARY = "primary";
    process.env.SYNTHETIC_TABLE = "table";
    process.env.SYNTHETIC_INLINE = "inline";
    process.env.SYNTHETIC_UNRELATED = "do not forward";
    const env = reviewerEnvironment({ cwd, workspaceRoot: cwd });
    assert.equal(env.SYNTHETIC_PRIMARY, "primary");
    assert.equal(env.SYNTHETIC_TABLE, "table");
    assert.equal(env.SYNTHETIC_INLINE, "inline");
    assert.equal(env.SYNTHETIC_UNRELATED, undefined);
  } finally {
    process.env = original;
  }
});
