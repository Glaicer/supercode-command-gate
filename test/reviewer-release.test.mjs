import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("reviewer release builds all six targets with Windows extensions and checksums", async (t) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "aar-release-"));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const bin = path.join(temporary, "bin");
  await mkdir(bin);
  const buildLog = path.join(temporary, "build.log");
  await writeFile(
    path.join(bin, "go"),
    `#!/bin/sh
set -eu
printf '%s\\t%s\\t%s\\t%s\\n' "$GOOS" "$GOARCH" "$CGO_ENABLED" "$*" >> "$AAR_BUILD_LOG"
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then
    printf '%s-%s' "$GOOS" "$GOARCH" > "$2"
    exit 0
  fi
  shift
done
exit 1
`,
    { mode: 0o755 },
  );
  const output = path.join(temporary, "release artifacts");
  const options = {
    cwd: path.join(root, "reviewer"),
    env: {
      ...process.env,
      PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      AAR_RELEASE_VERSION: "v0.1.0",
      AAR_RELEASE_DIR: output,
      AAR_BUILD_LOG: buildLog,
    },
  };
  await exec("sh", ["scripts/release.sh"], options);

  const targets = [
    "linux-amd64",
    "linux-arm64",
    "darwin-amd64",
    "darwin-arm64",
    "windows-amd64",
    "windows-arm64",
  ];
  const names = targets.map(
    (target) =>
      `aar-v0.1.0-${target}${target.startsWith("windows-") ? ".exe" : ""}`,
  );
  assert.deepEqual(
    (await readdir(output)).sort(),
    [...names, "SHA256SUMS"].sort(),
  );
  const builds = (await readFile(buildLog, "utf8")).trim().split("\n");
  assert.equal(builds.length, targets.length);
  for (const [index, target] of targets.entries()) {
    const [goos, goarch, cgo, args] = builds[index].split("\t");
    assert.equal(`${goos}-${goarch}`, target);
    assert.equal(cgo, "0");
    assert.ok(args.includes("-trimpath"));
    assert.ok(args.includes("-s -w -X main.version=v0.1.0"));
    assert.ok(args.includes(`-o ${path.join(output, names[index])} ./cmd/aar`));
  }

  const checksums = (await readFile(path.join(output, "SHA256SUMS"), "utf8"))
    .trim()
    .split("\n");
  assert.equal(checksums.length, names.length);
  for (const line of checksums) {
    const [, digest, name] = /^([a-f0-9]{64})  (.+)$/.exec(line) ?? [];
    assert.ok(names.includes(name), `unexpected checksum entry: ${line}`);
    const payload = await readFile(path.join(output, name));
    assert.equal(digest, createHash("sha256").update(payload).digest("hex"));
  }

  await assert.rejects(exec("sh", ["scripts/release.sh"], options), {
    stderr: /refusing to overwrite existing release artifact/,
  });
  assert.equal((await readFile(buildLog, "utf8")).trim().split("\n").length, 6);
});
