import assert from "node:assert/strict"
import { readFile, readdir } from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { test } from "node:test"

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

async function read(relativePath) {
  return await readFile(path.join(root, relativePath), "utf8")
}

test("published Gate metadata pins the supported OpenCode runtime and ships TypeScript", async () => {
  const packageJSON = JSON.parse(await read("package.json"))

  assert.notEqual(packageJSON.private, true)
  assert.equal(packageJSON.main, "./plugin/command-gate.ts")
  assert.equal(packageJSON.exports["."], "./plugin/command-gate.ts")
  assert.equal(packageJSON.engines.opencode, "1.18.21")
  assert.equal(packageJSON.dependencies["@opencode-ai/plugin"], "1.18.21")
  assert.equal(packageJSON.dependencies["@opencode-ai/sdk"], "1.18.21")
  assert.equal(packageJSON.files.includes("plugin/command-gate.ts"), true)
  assert.equal(packageJSON.files.includes("plugin/command-gate.js"), false)

  const pluginSource = await read("plugin/command-gate.ts")
  assert.match(pluginSource, /gate\.binaryPath|AAR_BINARY_PATH/)
  assert.doesNotMatch(pluginSource, /npm\s+(install|pack)|fetch\s*\(|https?:\/\//i)
})

test("release metadata builds static binaries for all supported targets with checksums", async () => {
  const workflow = await read(".github/workflows/release.yml")
  const releaseScript = await read("scripts/release.sh")

  for (const target of ["linux", "darwin", "amd64", "arm64"]) assert.match(releaseScript, new RegExp(target))
  assert.match(releaseScript, /CGO_ENABLED=0/)
  assert.match(releaseScript, /sha256|shasum/)
  assert.match(workflow, /linux|darwin/)
  assert.match(workflow, /amd64|arm64/)
  assert.match(workflow, /CGO_ENABLED\s*:\s*["']?0/)
  assert.match(workflow, /release_version="\$\{GITHUB_REF_NAME#aar-v\}"/)
  assert.match(workflow, /artifact="dist\/aar-v\$\{release_version\}-\$\{GOOS\}-\$\{GOARCH\}"/)
  assert.match(workflow, /-X main\.version=v\$\{release_version\}/)
  assert.match(workflow, /SHA256SUMS|sha256/)
  assert.match(workflow, /npm version --no-git-tag-version "\$\{GITHUB_REF_NAME#aar-v\}"/)
  assert.match(workflow, /id-token:\s*write/)
  assert.match(workflow, /npm publish/)
})

test("reviewer packaging has no WASM parser, provider SDK, runtime download, or command execution", async () => {
  const goMod = await read("go.mod")
  assert.match(goMod, /mvdan\.cc\/sh\/v3\s+v3\.13\.1/)
  assert.doesNotMatch(goMod, /wasm|provider|openai|anthropic/i)

  const productionFiles = await collectProductionFiles(path.join(root, "cmd"), path.join(root, "internal"))
  const production = (await Promise.all(productionFiles.map(async (file) => await read(path.relative(root, file))))).join("\n")
  assert.doesNotMatch(production, /\.wasm|WebAssembly|go:embed/i)
  assert.doesNotMatch(production, /os\/exec|exec\.Command|syscall\.Exec/)

  const pluginSource = await read("plugin/command-gate.ts")
  assert.doesNotMatch(pluginSource, /postDecision|afterDecision|rewrite.*decision/i)
  assert.match(pluginSource, /rewriteCommand\(command, config, options\)/)
})

test("npm package allowlist contains the Gate source and no reviewer implementation", async () => {
  const packageJSON = JSON.parse(await read("package.json"))
  const names = [...packageJSON.files, "package.json"].sort()

  assert.equal(names.includes("plugin/command-gate.ts"), true)
  assert.equal(names.includes("plugin/command-gate.js"), false)
  assert.equal(names.some((name) => name.startsWith("cmd/") || name.startsWith("internal/") || name.startsWith("test/")), false)
  assert.equal(names.some((name) => /\.wasm$|node_modules|provider-sdk/i.test(name)), false)
})

async function collectProductionFiles(...directories) {
  const files = []
  for (const directory of directories) await visit(directory, files)
  return files.filter((file) => !file.endsWith("_test.go"))
}

async function visit(directory, files) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name)
    if (entry.isDirectory()) await visit(fullPath, files)
    else if (entry.name.endsWith(".go")) files.push(fullPath)
  }
}
