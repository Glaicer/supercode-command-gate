import assert from "node:assert/strict";
import { execFile, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const shellSource = (
  await readFile(path.join(root, "install.sh"), "utf8")
).replace(/\nrun_wizard "\$@"; exit\n$/, "");
const powershell =
  process.env.AAR_TEST_PWSH ??
  ["pwsh", "powershell"].find(
    (binary) =>
      spawnSync(binary, ["-NoLogo", "-NoProfile", "-Command", "exit 0"])
        .status === 0,
  );

async function run(kind, body, env = {}, input = "") {
  const command = kind === "bash" ? "bash" : powershell;
  const code =
    kind === "bash"
      ? `${shellSource}\n${body}`
      : `$ErrorActionPreference = 'Stop'; . $env:AAR_TEST_SCRIPT\n${body}`;
  const args =
    kind === "bash"
      ? ["-c", code]
      : ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", code];
  const result = exec(command, args, {
    cwd: root,
    env: {
      ...process.env,
      AAR_TEST_SCRIPT: path.join(root, "install.ps1"),
      ...env,
    },
  });
  result.child.stdin.end(input);
  return await result;
}

async function temporary(t) {
  const directory = await mkdtemp(
    path.join(os.tmpdir(), "aar-installer-test-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test("Bash prompts validate choices, handle EOF, and resolve OS-specific config defaults", async () => {
  await run(
    "bash",
    `
ENV_FILE=/dev/null
choice answer "Mode" 1 "1 2 3"
[[ "$answer" = 2 ]]
absolute_path destination "Directory" ""
[[ "$destination" = "$HOME/example" ]]
unset AAR_CONFIG XDG_CONFIG_HOME
os=linux
[[ "$(default_config_path)" = "$HOME/.config/aar/config.toml" ]]
os=darwin
[[ "$(default_config_path)" = "$HOME/Library/Application Support/aar/config.toml" ]]
XDG_CONFIG_HOME="$HOME/custom-config"
[[ "$(default_config_path)" = "$HOME/custom-config/aar/config.toml" ]]
AAR_CONFIG="$HOME/explicit.toml"
[[ "$(default_config_path)" = "$HOME/explicit.toml" ]]
`,
    {},
    "invalid\n2\n~/example\n",
  );
  await assert.rejects(
    run("bash", "ENV_FILE=/dev/null; prompt answer 'Required value'"),
    /Input ended/,
  );
});

for (const kind of ["bash", "powershell"]) {
  const options = { skip: kind === "powershell" && !powershell };

  test(
    `${kind} rejects unsafe API URLs without calling providers`,
    options,
    async () => {
      const urls = {
        "https://api.example.com/v1": true,
        "https://[::1]:8123/v1": true,
        "http://localhost:8123/v1": true,
        "http://127.0.0.1:8123/v1": true,
        "http://[::1]:8123/v1": true,
        "http://api.example.com/v1": false,
        "https://user:secret@api.example.com/v1": false,
        "https://api.example.com/v1?key=secret": false,
        "https://api.example.com/v1#fragment": false,
        "not a URL": false,
      };
      for (const [url, expected] of Object.entries(urls)) {
        const { stdout } = await run(
          kind,
          kind === "bash"
            ? 'if valid_api_url "$AAR_TEST_URL"; then printf true; else printf false; fi'
            : "(Test-AarApiUrl $env:AAR_TEST_URL).ToString().ToLowerInvariant()",
          { AAR_TEST_URL: url },
        );
        assert.equal(stdout.trim(), String(expected), url);
      }
    },
  );

  test(
    `${kind} verifies release checksums before any destination changes`,
    options,
    async (t) => {
      const directory = await temporary(t);
      const binary = "fake reviewer, never executed\n";
      await writeFile(path.join(directory, "payload"), binary);
      const digest = createHash("sha256").update(binary).digest("hex");
      const bashMock = `
curl() {
  local output="" url=""
  while (( $# )); do
    case "$1" in -o) output="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac
  done
  printf '%s\\n' "$url" >> "$AAR_TEST_ROOT/requests"
  case "$url" in
    */releases/latest) printf '{"tag_name":"%s"}\\n' "$AAR_TEST_TAG" ;;
    */SHA256SUMS) cp "$AAR_TEST_ROOT/checksums" "$output" ;;
    *) cp "$AAR_TEST_ROOT/payload" "$output" ;;
  esac
}
os=linux; arch=amd64; work_dir="$AAR_TEST_ROOT"
download_aar
`;
      const psMock = `
function Invoke-RestMethod { param($Uri, $Headers) return @{ tag_name = $env:AAR_TEST_TAG } }
function Invoke-WebRequest {
  param($Uri, [switch]$UseBasicParsing, $OutFile)
  [IO.File]::AppendAllText((Join-Path $env:AAR_TEST_ROOT 'requests'), "$Uri\n")
  $file = 'payload'; if ($Uri.EndsWith('/SHA256SUMS')) { $file = 'checksums' }
  [IO.File]::Copy((Join-Path $env:AAR_TEST_ROOT $file), $OutFile, $true)
}
Get-AarRelease $env:AAR_TEST_ROOT 'arm64'
`;
      const asset =
        kind === "bash"
          ? "aar-v0.1.0-linux-amd64"
          : "aar-v0.1.0-windows-arm64.exe";
      for (const tag of ["v0.1.0", "aar-v0.1.0"]) {
        await writeFile(
          path.join(directory, "checksums"),
          `${digest}  ${asset}\n`,
        );
        await run(kind, kind === "bash" ? bashMock : psMock, {
          AAR_TEST_ROOT: directory,
          AAR_TEST_TAG: tag,
        });
        const requests = await readFile(
          path.join(directory, "requests"),
          "utf8",
        );
        assert.ok(requests.includes(`/download/${tag}/${asset}`));
      }
      for (const checksums of [
        `${"0".repeat(64)}  ${asset}\n`,
        `${digest}  other-binary\n`,
        `${digest}  ${asset}\n${digest}  ${asset}\n`,
      ]) {
        await writeFile(path.join(directory, "checksums"), checksums);
        await assert.rejects(
          run(kind, kind === "bash" ? bashMock : psMock, {
            AAR_TEST_ROOT: directory,
            AAR_TEST_TAG: "v0.1.0",
          }),
        );
      }
    },
  );

  for (const scenario of ["fresh", "replace", "keep", "changed"]) {
    test(
      `${kind} ${scenario} config preserves user data`,
      options,
      async (t) => {
        const directory = await temporary(t);
        const work = path.join(directory, "work");
        const bin = path.join(directory, "bin with spaces");
        const config = path.join(directory, "config [test].toml");
        await mkdir(work);
        const binaryName = kind === "bash" ? "aar" : "aar.exe";
        await writeFile(path.join(work, binaryName), "new binary");
        await writeFile(path.join(work, "config.toml"), "new config\n");
        if (scenario !== "fresh") {
          await mkdir(bin);
          await writeFile(path.join(bin, binaryName), "old binary");
          await writeFile(config, "old config\n");
        }
        const before =
          scenario === "fresh"
            ? ""
            : createHash("sha256")
                .update(
                  scenario === "changed"
                    ? "different config\n"
                    : "old config\n",
                )
                .digest("hex");
        const env = {
          AAR_TEST_ROOT: directory,
          AAR_TEST_CONFIG: config,
          AAR_TEST_BEFORE: before,
          AAR_TEST_KEEP: scenario === "keep" ? "true" : "false",
        };
        const body =
          kind === "bash"
            ? `
work_dir="$AAR_TEST_ROOT/work"; bin_dir="$AAR_TEST_ROOT/bin with spaces"
config_path="$AAR_TEST_CONFIG"; config_before="$AAR_TEST_BEFORE"; keep_config="$AAR_TEST_KEEP"
install_files
`
            : `Save-AarFiles (Join-Path $env:AAR_TEST_ROOT 'work') (Join-Path $env:AAR_TEST_ROOT 'bin with spaces') $env:AAR_TEST_CONFIG ($env:AAR_TEST_KEEP -eq 'true') $env:AAR_TEST_BEFORE`;
        if (scenario === "changed")
          await assert.rejects(run(kind, body, env), /Config changed/);
        else await run(kind, body, env);
        assert.equal(
          await readFile(config, "utf8"),
          ["fresh", "replace"].includes(scenario)
            ? "new config\n"
            : "old config\n",
        );
        assert.equal(
          await readFile(path.join(bin, binaryName), "utf8"),
          scenario === "changed" ? "old binary" : "new binary",
        );
        const backups = (await readdir(directory)).filter((name) =>
          name.startsWith("config [test].toml.bak."),
        );
        assert.equal(backups.length, scenario === "replace" ? 1 : 0);
        if (backups.length)
          assert.equal(
            await readFile(path.join(directory, backups[0]), "utf8"),
            "old config\n",
          );
        if (kind === "bash" && ["fresh", "replace"].includes(scenario)) {
          assert.equal((await stat(config)).mode & 0o777, 0o600);
          assert.equal(
            (await stat(path.join(bin, binaryName))).mode & 0o777,
            0o755,
          );
        }
      },
    );
  }
}
