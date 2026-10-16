import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

test("packed release exposes compiled server, TUI and RPC without source or a second renderer", () => {
  const manifest = JSON.parse(readFileSync("package.json", "utf8"));
  assert.equal(manifest.name, "@glaicer/supercode-command-gate");
  assert.equal(manifest.private, false);
  assert.equal(manifest.license, "MIT");
  assert.equal(manifest.publishConfig.access, "public");
  assert.equal(manifest.publishConfig.registry, "https://registry.npmjs.org/");
  const packed = JSON.parse(
    execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
      encoding: "utf8",
    }),
  );
  const pack = Array.isArray(packed) ? packed[0] : packed[manifest.name];
  const files = pack.files.map((file) => file.path);
  for (const [entry, target] of Object.entries(manifest.exports)) {
    assert.equal(typeof target, "string", `${entry} export exists`);
    assert.ok(target.endsWith(".js"), `${entry} is compiled JavaScript`);
    assert.ok(files.includes(target.slice(2)), `${entry} is shipped`);
  }
  for (const entry of ["index.js", "tui.js", "rpc.js"])
    assert.ok(files.includes(entry), `${entry} directory entry exists`);
  for (const entry of ["README.md", "LICENSE"])
    assert.ok(files.includes(entry), `${entry} is shipped`);
  for (const file of files)
    assert.ok(
      [
        "package.json",
        "README.md",
        "LICENSE",
        "index.js",
        "tui.js",
        "rpc.js",
      ].includes(file) || /^dist\/.+\.js$/.test(file),
      `${file} belongs in the published package`,
    );
  assert.ok(
    !files.some(
      (file) =>
        /\.(?:tsx?|map)$/.test(file) ||
        file.startsWith("src/") ||
        file.includes("node_modules/"),
    ),
  );
  assert.ok(!manifest.dependencies["solid-js"]);
  assert.ok(
    !Object.keys(manifest.dependencies).some((name) =>
      name.startsWith("@opentui/"),
    ),
  );
  for (const file of files.filter((file) => file.endsWith(".js"))) {
    const source = readFileSync(file, "utf8");
    assert.doesNotMatch(source, /from ["'][^"']+\.tsx?["']/);
    assert.doesNotMatch(
      source,
      /@opencode-ai\/sdk|1\.18\.21|createCommandGate|readGateConfig/,
    );
  }
});
