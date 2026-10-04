import { access, chmod, copyFile, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises"
import { constants } from "node:fs"
import { execFile, spawn } from "node:child_process"
import { promisify } from "node:util"
import net from "node:net"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { test } from "node:test"
import assert from "node:assert/strict"

const execFileAsync = promisify(execFile)
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const openaiCompatibleVersion = process.env.AAR_OPENAI_COMPATIBLE_VERSION ?? "3.0.35"

test("real OpenCode runs pwd and does not run a denied command", async () => {
  const opencode = await findExecutable(process.env.OPENCODE_BIN ?? "opencode")
  if (!opencode) throw new Error("opencode is required for the integration test")

  const go = process.env.GO ?? "/home/glaicer/.local/go/bin/go"
  const runRoot = await makeTempDirectory("aar-opencode-")
  const binary = path.join(runRoot, "aar")
  const goCache = path.join(runRoot, "go-cache")
  await execFileAsync(go, ["build", "-o", binary, "./cmd/aar"], {
    cwd: root,
    env: { ...process.env, GOCACHE: goCache, GOMODCACHE: process.env.GOMODCACHE ?? "/tmp/aar-go-modcache" },
  })

  await mkdir(path.join(runRoot, ".opencode", "plugins"), { recursive: true })
  await copyFile(path.join(root, "plugin", "command-gate.ts"), path.join(runRoot, ".opencode", "plugins", "command-gate.ts"))
  await installProviderAdapter(runRoot)

  await runProbe({
    opencode,
    runRoot,
    binary,
    command: "pwd",
    assertResult({ modelCalls }) {
      const toolResults = modelCalls.flatMap((call) => call.toolResults ?? []).map(String)
      assert.equal(toolResults.some((result) => result.trim() === runRoot), true, "fake model did not receive pwd output")
    },
  })

  const sideEffect = path.join(runRoot, "blocked-side-effect")
  await runProbe({
    opencode,
    runRoot,
    binary,
    command: `touch ${sideEffect}`,
    assertResult({ combined, modelCalls }) {
      assert.equal(combined.includes("Auto Approve Permissions blocked this command"), true)
      assert.equal(combined.includes("not executed"), true)
      const toolResults = modelCalls.flatMap((call) => call.toolResults ?? []).map(String)
      assert.equal(toolResults.some((result) => result.includes("not executed")), true)
    },
  })
  await assert.rejects(access(sideEffect, constants.F_OK), "denied command created a side effect")

  const approvedSideEffect = path.join(runRoot, "approved-side-effect")
  await runProbe({
    opencode,
    runRoot,
    binary,
    command: `touch ${approvedSideEffect}`,
    flow: "approval-roundtrip",
    autoApprove: true,
    reviewerConfig: "[assessor]\nonUnavailable = \"ask\"\n",
    assertResult({ combined, modelCalls }) {
      assert.equal(combined.includes("request_command_approval"), true)
      assert.equal(combined.includes("Command approval recorded"), true)
      assert.equal(modelCalls.some((call) => call.tool === "request_command_approval"), true)
    },
  })
  await access(approvedSideEffect, constants.F_OK)

  const modelAllowedSideEffect = path.join(runRoot, "model-allow-side-effect")
  await runProbe({
    opencode,
    runRoot,
    binary,
    command: `touch ${modelAllowedSideEffect}`,
    reviewerMode: "model-allow",
    assertResult({ combined }) {
      assert.doesNotMatch(combined, /not executed/i)
    },
  })
  await access(modelAllowedSideEffect, constants.F_OK)

  for (const mode of ["hard-deny", "model-deny"]) {
    const deniedSideEffect = path.join(runRoot, `${mode}-side-effect`)
    await runProbe({
      opencode,
      runRoot,
      binary,
      command: `touch ${deniedSideEffect}`,
      reviewerMode: mode,
      assertResult({ combined }) {
        assert.match(combined, /not executed/i)
      },
    })
    await assert.rejects(access(deniedSideEffect, constants.F_OK), `${mode} command unexpectedly ran`)
  }

  for (const mode of ["ask-once", "ask-session"]) {
    const grantedSideEffect = path.join(runRoot, `${mode}-side-effect`)
    await runProbe({
      opencode,
      runRoot,
      binary,
      command: `touch ${grantedSideEffect}`,
      flow: "approval-roundtrip",
      autoApprove: true,
      reviewerMode: mode,
      assertResult({ combined }) {
        assert.match(combined, /Command approval recorded/i)
        if (mode === "ask-session") assert.match(combined, /session/i)
        else assert.match(combined, /once/i)
      },
    })
    await access(grantedSideEffect, constants.F_OK)
  }
})

test("real OpenCode keeps reviewer failures fail-closed and preserves reviewed bytes", async () => {
  const opencode = await findExecutable(process.env.OPENCODE_BIN ?? "opencode")
  if (!opencode) throw new Error("opencode is required for the integration test")

  const go = process.env.GO ?? "/home/glaicer/.local/go/bin/go"
  const runRoot = await makeTempDirectory("aar-opencode-hardening-")
  const binary = path.join(runRoot, "aar")
  const goCache = path.join(runRoot, "go-cache")
  await execFileAsync(go, ["build", "-o", binary, "./cmd/aar"], {
    cwd: root,
    env: { ...process.env, GOCACHE: goCache, GOMODCACHE: process.env.GOMODCACHE ?? "/tmp/aar-go-modcache" },
  })
  await mkdir(path.join(runRoot, ".opencode", "plugins"), { recursive: true })
  await copyFile(path.join(root, "plugin", "command-gate.ts"), path.join(runRoot, ".opencode", "plugins", "command-gate.ts"))
  await installProviderAdapter(runRoot)

  for (const mode of ["nonzero", "malformed", "schema", "timeout"]) {
    for (const failureMode of ["deny", "passthrough"]) {
      const sideEffect = path.join(runRoot, `${mode}-${failureMode}-side-effect`)
      await runProbe({
        opencode,
        runRoot,
        binary,
        command: `touch ${sideEffect}`,
        reviewerMode: mode,
        gateConfig: { onReviewerFailure: failureMode, ...(mode === "timeout" ? { timeoutMs: 100 } : {}) },
        assertResult({ combined }) {
          if (failureMode === "deny") assert.match(combined, /not executed/i)
        },
      })
      if (failureMode === "deny") {
        await assert.rejects(access(sideEffect, constants.F_OK), `${mode} failure unexpectedly executed a denied command`)
      } else {
        await access(sideEffect, constants.F_OK)
      }
    }
  }

  for (const failureMode of ["deny", "passthrough"]) {
    const sideEffect = path.join(runRoot, `missing-${failureMode}-side-effect`)
    await runProbe({
      opencode,
      runRoot,
      binary,
      command: `touch ${sideEffect}`,
      reviewerMode: "missing",
      gateConfig: { onReviewerFailure: failureMode },
      assertResult({ combined }) {
        assert.match(combined, /Command Gate is unavailable|not executed/i)
      },
    })
    await assert.rejects(access(sideEffect, constants.F_OK), "missing aar binary unexpectedly executed a command")
  }

  const filteredSideEffect = path.join(runRoot, "filtered-side-effect")
  await runProbe({
    opencode,
    runRoot,
    binary,
    command: `touch ${filteredSideEffect}`,
    reviewerMode: "nonzero",
    gateConfig: { tools: ["shell"] },
    assertResult({ combined, reviewerCalls }) {
      assert.equal(reviewerCalls.length, 0)
      assert.doesNotMatch(combined, /Auto Approve Permissions blocked this command/i)
    },
  })
  await access(filteredSideEffect, constants.F_OK)

  const originalOutput = path.join(runRoot, "original-output")
  const originalCommand = `printf 'original' > ${originalOutput}`
  const originalRun = await runProbe({
    opencode,
    runRoot,
    binary,
    command: originalCommand,
    reviewerMode: "allow",
    assertResult({ reviewerCalls }) {
      assert.equal(reviewerCalls[0].command, originalCommand)
    },
  })
  assert.equal(originalRun.reviewerCalls[0].command, originalCommand)
  assert.equal(await readFile(originalOutput, "utf8"), "original")

  const rewrittenOutput = path.join(runRoot, "rewritten-output")
  const rewrittenCommand = `printf 'rewritten' > ${rewrittenOutput}`
  const rtkRun = await runProbe({
    opencode,
    runRoot,
    binary,
    command: originalCommand,
    reviewerMode: "allow",
    gateConfig: { commandRewriter: "rtk" },
    rtkOutput: rewrittenCommand,
    assertResult({ reviewerCalls }) {
      assert.equal(reviewerCalls[0].command, rewrittenCommand)
    },
  })
  assert.equal(rtkRun.reviewerCalls[0].command, rewrittenCommand)
  assert.equal(await readFile(rewrittenOutput, "utf8"), "rewritten")

  const absentOutput = path.join(runRoot, "rtk-absent-output")
  const absentCommand = `printf 'absent' > ${absentOutput}`
  const absentRtkRun = await runProbe({
    opencode,
    runRoot,
    binary,
    command: absentCommand,
    reviewerMode: "allow",
    gateConfig: {
      commandRewriter: "rtk",
      rewriterPath: path.join(runRoot, "missing-rtk-rewriter"),
    },
    assertResult({ reviewerCalls }) {
      assert.equal(reviewerCalls[0].command, absentCommand)
    },
  })
  assert.equal(absentRtkRun.reviewerCalls[0].command, absentCommand)
  assert.equal(await readFile(absentOutput, "utf8"), "absent")
})

async function runProbe({
  opencode,
  runRoot,
  binary,
  command,
  flow,
  autoApprove,
  reviewerConfig,
  reviewerMode,
  gateConfig,
  extraEnv = {},
  rtkOutput,
  assertResult,
}) {
  const port = await freePort()
  const logPath = path.join(runRoot, `llm-${Date.now()}-${Math.random()}.log`)
  let reviewerBinary = binary
  let reviewerConfigPath
  let reviewerLogPath
  if (reviewerMode !== undefined) {
    if (reviewerMode === "missing") {
      reviewerBinary = path.join(runRoot, `missing-aar-${Date.now()}-${Math.random()}`)
    } else {
      reviewerBinary = path.join(runRoot, `fake-aar-${Date.now()}-${Math.random()}.cjs`)
      await copyFile(path.join(root, "test", "fixtures", "fake-aar-reviewer.cjs"), reviewerBinary)
      await chmod(reviewerBinary, 0o755)
      reviewerConfigPath = path.join(runRoot, `aar-fixture-${Date.now()}-${Math.random()}-${reviewerMode}.toml`)
      reviewerLogPath = reviewerConfigPath.replace(/\.toml$/, ".log")
    }
  }
  let pathPrefix = ""
  if (rtkOutput !== undefined) {
    const rtkDirectory = path.join(runRoot, `rtk-${Date.now()}-${Math.random()}`)
    await mkdir(rtkDirectory, { recursive: true })
    const rtkBinary = path.join(rtkDirectory, "rtk")
    await writeFile(rtkBinary, `#!/usr/bin/env node\nprocess.stdout.write(${JSON.stringify(rtkOutput)})\n`)
    await chmod(rtkBinary, 0o755)
    pathPrefix = `${rtkDirectory}:`
  }
  const server = spawn(process.execPath, [path.join(root, "harness", "fakellm.cjs")], {
    cwd: runRoot,
    env: {
      ...process.env,
      FAKE_LLM_PORT: String(port),
      FAKE_LLM_COMMAND: command,
      FAKE_LLM_FLOW: flow ?? "default",
      FAKE_LLM_LOG: logPath,
    },
    stdio: ["ignore", "ignore", "pipe"],
  })
  let serverError = ""
  server.stderr.on("data", (chunk) => { serverError += String(chunk) })
  try {
    await waitForPort(port)
    if (reviewerConfig !== undefined) {
      const projectConfigPath = path.join(runRoot, ".aar.toml")
      await writeFile(projectConfigPath, reviewerConfig)
      if (reviewerConfigPath === undefined) reviewerConfigPath = projectConfigPath
    }
    const xdgConfig = path.join(runRoot, `xdg-${Date.now()}-${Math.random()}`)
    await mkdir(xdgConfig, { recursive: true })
    const config = JSON.parse((await readFile(path.join(root, "harness", "opencode.jsonc"), "utf8")).replaceAll("FAKE_PORT", String(port)))
    config.gate = { ...config.gate, ...gateConfig }
    await writeFile(path.join(runRoot, "opencode.jsonc"), JSON.stringify(config))
    const runArgs = ["run", "--print-logs", "--log-level", "DEBUG"]
    if (autoApprove) runArgs.push("--auto")
    runArgs.push("-m", "fake/probe-model", "go")
    const result = await runProcess(opencode, runArgs, {
      cwd: runRoot,
      env: {
        ...process.env,
        ...extraEnv,
        PATH: `${pathPrefix}${extraEnv.PATH ?? process.env.PATH ?? ""}`,
        AAR_BINARY_PATH: reviewerBinary,
        AAR_STATE_DIR: path.join(runRoot, `aar-state-${Date.now()}-${Math.random()}`),
        FAKE_LLM_FLOW: flow ?? "default",
        ...(reviewerConfigPath === undefined ? {} : { AAR_CONFIG: reviewerConfigPath }),
        ...(reviewerMode === undefined ? {} : { FAKE_AAR_MODE: reviewerMode, FAKE_AAR_LOG: reviewerLogPath }),
        HOME: path.join(runRoot, "home"),
        PWD: runRoot,
        XDG_DATA_HOME: path.join(runRoot, "data"),
        XDG_CONFIG_HOME: xdgConfig,
        OPENCODE_CONFIG_DIR: xdgConfig,
      },
      timeout: 60000,
      maxBuffer: 4 * 1024 * 1024,
    })
    const log = await readFile(logPath, "utf8")
    const modelCalls = log.trim().split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line))
    let reviewerCalls = []
    if (reviewerLogPath !== undefined) {
      try {
        const reviewerLog = await readFile(reviewerLogPath, "utf8")
        reviewerCalls = reviewerLog.trim().split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line))
      } catch {
        reviewerCalls = []
      }
    }
    assertResult({ combined: `${result.stdout}\n${result.stderr}\n${log}`, modelCalls, reviewerCalls })
    return { result, modelCalls, reviewerCalls }
  } finally {
    server.kill("SIGTERM")
    await new Promise((resolve) => server.once("close", resolve))
    if (serverError !== "") throw new Error(`fake LLM failed: ${serverError}`)
  }
}

async function installProviderAdapter(runRoot) {
  await execFileAsync(process.env.NPM ?? "npm", [
    "install",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--prefix",
    path.join(runRoot, ".opencode"),
    "@opencode-ai/plugin@1.18.21",
    "@opencode-ai/sdk@1.18.21",
    `@ai-sdk/openai-compatible@${openaiCompatibleVersion}`,
  ], {
    cwd: runRoot,
    env: process.env,
    timeout: 60000,
    maxBuffer: 2 * 1024 * 1024,
  })
}

async function runProcess(command, args, options) {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...options, stdio: ["pipe", "pipe", "pipe"] })
    let stdout = ""
    let stderr = ""
    let settled = false
    const timer = options.timeout ? setTimeout(() => child.kill("SIGTERM"), options.timeout) : null
    const finish = (error, result) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      if (error) reject(error)
      else resolve(result)
    }
    child.stdout.on("data", (chunk) => { stdout += String(chunk) })
    child.stderr.on("data", (chunk) => { stderr += String(chunk) })
    child.once("error", (error) => finish(error))
    child.once("close", (code, signal) => {
      if (code !== 0) {
        const error = new Error(`Command failed: ${command} ${args.join(" ")}`)
        error.code = code
        error.signal = signal
        error.stdout = stdout
        error.stderr = stderr
        finish(error)
        return
      }
      finish(null, { stdout, stderr })
    })
    child.stdin.end()
  })
}

async function findExecutable(command) {
  try {
    await execFileAsync(command, ["--version"], { timeout: 5000 })
    return command
  } catch {
    return null
  }
}

async function makeTempDirectory(prefix) {
  return await mkdtemp(path.join(os.tmpdir(), prefix))
}

async function freePort() {
  return await new Promise((resolve, reject) => {
    const server = net.createServer()
    server.once("error", reject)
    server.listen(0, "127.0.0.1", () => {
      const address = server.address()
      server.close(() => resolve(address.port))
    })
  })
}

async function waitForPort(port) {
  const deadline = Date.now() + 5000
  while (Date.now() < deadline) {
    try {
      await new Promise((resolve, reject) => {
        const socket = net.createConnection({ port, host: "127.0.0.1" })
        socket.once("connect", () => { socket.destroy(); resolve() })
        socket.once("error", reject)
      })
      return
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 50))
    }
  }
  throw new Error(`fake LLM did not listen on ${port}`)
}
