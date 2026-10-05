import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises"
import { createHash } from "node:crypto"
import { EventEmitter } from "node:events"
import os from "node:os"
import { PassThrough } from "node:stream"
import path from "node:path"
import { test } from "node:test"
import assert from "node:assert/strict"
import { CommandGatePlugin } from "../plugin/command-gate.ts"

const { callReviewer, createCommandGate, buildRequest } = CommandGatePlugin

const allowDecision = {
  schemaVersion: "aar-decision-v1",
  decision: "allow",
  reason: "pwd only reads the current working directory",
  source: "auto-allow",
  rule: "AA001",
  assessment: null,
  requestFingerprint: "fingerprint-1",
  grantEligible: false,
  auditId: "audit-1",
}

function context() {
  return { directory: process.cwd(), worktree: process.cwd() }
}

function fingerprintFor(request) {
  return createHash("sha256").update(canonicalJSON({
    command: request.command,
    cwd: request.cwd,
    workspaceRoot: request.workspaceRoot,
    sessionId: request.session.id,
    intentId: request.session.intentId ?? "",
    policyVersion: "deterministic-v2",
    shellIR: "shellir-v1",
  })).digest("hex")
}

function canonicalJSON(value) {
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029")
}

test("allow returns without changing native bash arguments", async () => {
  const requests = []
  const plugin = createCommandGate({
    review: async (request) => {
      requests.push(request)
      return { ...allowDecision, requestFingerprint: fingerprintFor(request) }
    },
  })
  const hooks = await plugin(context())
  const args = { command: "pwd", timeout: 4000 }

  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args })

  assert.deepEqual(args, { command: "pwd", timeout: 4000 })
  assert.equal(requests.length, 1)
  assert.equal(requests[0].command, "pwd")
  assert.equal(requests[0].schemaVersion, "aar-request-v1")
  assert.equal(requests[0].session.id, "session-1")
})

test("shell is covered by default and a denied decision throws before execution", async () => {
  const plugin = createCommandGate({
    review: async (request) => ({ ...allowDecision, decision: "deny", source: "unavailable", reason: "writes outside the workspace", requestFingerprint: fingerprintFor(request) }),
  })
  const hooks = await plugin(context())
  const args = { command: "touch should-not-exist" }

  await assert.rejects(
    hooks["tool.execute.before"]({ tool: "shell", sessionID: "session-1" }, { args }),
    /writes outside the workspace.*not executed/,
  )
  assert.deepEqual(args, { command: "touch should-not-exist" })
})

test("tools outside gate.tools are ignored", async () => {
  let called = false
  const plugin = createCommandGate({
    tools: ["bash"],
    review: async () => {
      called = true
      return allowDecision
    },
  })
  const hooks = await plugin(context())

  await hooks["tool.execute.before"]({ tool: "read", sessionID: "session-1" }, { args: { command: "pwd" } })
  assert.equal(called, false)
})

test("context gate.tools selects the production tool boundary", async () => {
  let called = false
  const plugin = createCommandGate({
    review: async (request) => {
      called = request.command
      return { ...allowDecision, requestFingerprint: fingerprintFor(request) }
    },
  })
  const hooks = await plugin({ ...context(), config: { gate: { tools: ["shell"] } } })

  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args: { command: "pwd" } })
  assert.equal(called, false)
  await hooks["tool.execute.before"]({ tool: "shell", sessionID: "session-1" }, { args: { command: "pwd" } })
  assert.equal(called, "pwd")
})

test("production initializer denies when the OpenCode runtime contract is unavailable", async () => {
  const plugin = await CommandGatePlugin(context(), {
    runtimeCheck: async () => ({ ok: false, reason: "@opencode-ai/plugin 1.18.21 is required" }),
    doctor: async () => ({
      schemaVersion: "aar-doctor-v1",
      contractVersion: "aar-contract-v1",
      status: "ok",
      requestSchemaVersion: "aar-request-v1",
      decisionSchemaVersion: "aar-decision-v1",
      reviewerTimeoutMs: 5000,
    }),
  })
  const args = { command: "pwd" }

  await assert.rejects(
    plugin["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args }),
    /OpenCode runtime contract is unavailable|1\.18\.21.*required.*not executed/i,
  )
})

test("Windows is reported as unsupported before the Gate can authorize execution", async () => {
  const result = await CommandGatePlugin.checkRuntimeCompatibility({ platform: "win32" })
  assert.equal(result.ok, false)
  assert.match(result.reason, /Windows execution is unsupported/i)
})

test("project Gate configuration overlays the global Gate configuration", async () => {
  const globalRoot = await mkdtemp(path.join(os.tmpdir(), "aar-global-config-"))
  const projectRoot = await mkdtemp(path.join(os.tmpdir(), "aar-project-config-"))
  const previousConfigDir = process.env.OPENCODE_CONFIG_DIR
  try {
    await writeFile(path.join(globalRoot, "opencode.jsonc"), JSON.stringify({
      gate: { binaryPath: "global-aar", timeoutMs: 6000, commandRewriter: "none" },
    }))
    await writeFile(path.join(projectRoot, "opencode.jsonc"), JSON.stringify({
      gate: { binaryPath: "project-aar", commandRewriter: "rtk" },
    }))
    process.env.OPENCODE_CONFIG_DIR = globalRoot
    const gate = CommandGatePlugin.readGateConfig({ directory: projectRoot })

    assert.equal(gate.binaryPath, "project-aar")
    assert.equal(gate.timeoutMs, 6000)
    assert.equal(gate.commandRewriter, "rtk")
  } finally {
    if (previousConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR
    else process.env.OPENCODE_CONFIG_DIR = previousConfigDir
    await rm(globalRoot, { recursive: true, force: true })
    await rm(projectRoot, { recursive: true, force: true })
  }
})

test("Gate-owned RTK rewriting preserves reviewed bytes for either hook order and both modes", async () => {
  for (const commandRewriter of ["none", "rtk"]) {
    for (const order of ["gate-before-rtk", "rtk-before-gate"]) {
      let rewriteCalls = 0
      let reviewedCommand
      const plugin = createCommandGate({
        commandRewriter,
        rewrite: async () => {
          rewriteCalls += 1
          return "printf 'rewritten'"
        },
        review: async (request) => {
          reviewedCommand = request.command
          return { ...allowDecision, requestFingerprint: fingerprintFor(request) }
        },
      })
      const hooks = await plugin(context())
      const args = { command: "printf 'original'" }
      const externalRtkHook = async (_input, _output) => {
        // When the Gate owns rewriting, the separately installed RTK hook is
        // configured as a no-op. This keeps both plugin orders equivalent.
      }
      if (order === "rtk-before-gate") await externalRtkHook({ tool: "bash" }, { args })
      await hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args })
      if (order === "gate-before-rtk") await externalRtkHook({ tool: "bash" }, { args })

      const expected = commandRewriter === "rtk" ? "printf 'rewritten'" : "printf 'original'"
      assert.equal(rewriteCalls, commandRewriter === "rtk" ? 1 : 0)
      assert.equal(reviewedCommand, expected)
      assert.equal(args.command, expected)
    }
  }
})

test("reviewer failures are deny-by-default", async () => {
  const plugin = createCommandGate({ review: async () => { throw new Error("malformed stdout") } })
  const hooks = await plugin(context())

  await assert.rejects(
    hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args: { command: "pwd" } }),
    /Command Reviewer was unavailable.*not executed/,
  )
})

test("an allow decision with invalid provenance is denied", async () => {
  const plugin = createCommandGate({
    review: async (request) => ({ ...allowDecision, source: "hard-deny", requestFingerprint: fingerprintFor(request) }),
  })
  const hooks = await plugin(context())

  await assert.rejects(
    hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args: { command: "pwd" } }),
    /invalid decision.*auto-allow.*not executed/,
  )
})

test("an assessor allow decision is accepted without an auto-allow rule", async () => {
  const plugin = createCommandGate({
    review: async (request) => ({
      ...allowDecision,
      source: "assessor",
      rule: null,
      requestFingerprint: fingerprintFor(request),
    }),
  })
  const hooks = await plugin(context())

  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args: { command: "touch ./output" } })
})

test("an allow decision for another request is denied", async () => {
  const plugin = createCommandGate({ review: async () => allowDecision })
  const hooks = await plugin(context())

  await assert.rejects(
    hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args: { command: "pwd" } }),
    /fingerprint mismatch.*not executed/,
  )
})

test("subprocess reviewer receives the command through stdin", async () => {
  const fixture = path.join(process.cwd(), "test", "fixtures", "fake-aar.sh")
  await chmod(fixture, 0o755)
  const plugin = createCommandGate({
    binaryPath: fixture,
    doctor: async () => ({
      schemaVersion: "aar-doctor-v1",
      contractVersion: "aar-contract-v1",
      status: "ok",
      requestSchemaVersion: "aar-request-v1",
      decisionSchemaVersion: "aar-decision-v1",
      reviewerTimeoutMs: 5000,
    }),
  })
  const hooks = await plugin(context())
  const args = { command: "pwd" }

  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args })
  assert.equal(args.command, "pwd")
})

test("reviewer subprocess does not receive unrelated parent environment", async () => {
  const secretName = "AAR_TEST_PARENT_SECRET"
  const previousSecret = process.env[secretName]
  process.env[secretName] = "should-not-cross-the-boundary"
  let spawnOptions
  const child = new EventEmitter()
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  child.stdin = { end() {
    setImmediate(() => {
      child.stdout.end(JSON.stringify({ ...allowDecision, requestFingerprint: fingerprintFor(buildRequest("pwd", { sessionID: "session-1" }, context())) }))
      child.emit("close", 0, null)
    })
  } }
  child.kill = () => child.emit("close", null, "SIGKILL")

  try {
    const decision = await callReviewer(
      buildRequest("pwd", { sessionID: "session-1" }, context()),
      { binaryPath: "aar", timeoutMs: 1000 },
      (_binary, _args, options) => {
        spawnOptions = options
        return child
      },
    )
    assert.equal(decision.decision, "allow")
    assert.equal(spawnOptions.env[secretName], undefined)
    assert.equal(spawnOptions.shell, false)
  } finally {
    if (previousSecret === undefined) delete process.env[secretName]
    else process.env[secretName] = previousSecret
  }
})

test("reviewer subprocess receives only the configured assessor key environment", async () => {
  const configDir = await mkdtemp(path.join(os.tmpdir(), "aar-gate-config-"))
  const configPath = path.join(configDir, "config.toml")
  await writeFile(configPath, '[assessor]\napiKeyEnv = "AAR_TEST_API_KEY"\n')
  const previousConfig = process.env.AAR_CONFIG
  const previousKey = process.env.AAR_TEST_API_KEY
  process.env.AAR_CONFIG = configPath
  process.env.AAR_TEST_API_KEY = "key-crosses-only-by-name"
  let spawnOptions
  const child = new EventEmitter()
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  child.stdin = { end() {
    setImmediate(() => {
      child.stdout.end(JSON.stringify({ ...allowDecision, requestFingerprint: fingerprintFor(buildRequest("pwd", { sessionID: "session-1" }, context())) }))
      child.emit("close", 0, null)
    })
  } }
  child.kill = () => child.emit("close", null, "SIGKILL")

  try {
    await callReviewer(
      buildRequest("pwd", { sessionID: "session-1" }, context()),
      { binaryPath: "aar", timeoutMs: 1000 },
      (_binary, _args, options) => {
        spawnOptions = options
        return child
      },
    )
    assert.equal(spawnOptions.env.AAR_TEST_API_KEY, "key-crosses-only-by-name")
    assert.equal(spawnOptions.env.AAR_TEST_PARENT_SECRET, undefined)
  } finally {
    if (previousConfig === undefined) delete process.env.AAR_CONFIG
    else process.env.AAR_CONFIG = previousConfig
    if (previousKey === undefined) delete process.env.AAR_TEST_API_KEY
    else process.env.AAR_TEST_API_KEY = previousKey
    await rm(configDir, { recursive: true, force: true })
  }
})

test("request contains only the safe environment subset", () => {
  const request = buildRequest("pwd", { sessionID: "session-1" }, context())
  assert.deepEqual(Object.keys(request.env).sort(), ["CDPATH", "HOME", "PWD"].filter((key) => process.env[key]).sort())
  assert.equal(request.intent.goal, null)
  assert.equal(request.workspaceRoot, process.cwd())
})

test("request carries available genuine intent without inventing purpose", () => {
  const request = buildRequest(
    "touch ./output",
    { sessionID: "session-1", latestUserRequest: "Inspect the repository" },
    { ...context(), goal: "Inspect the repository safely" },
  )
  assert.equal(request.intent.goal, "Inspect the repository safely")
  assert.equal(request.intent.latestUserRequest, "Inspect the repository")
  assert.equal(request.intent.purpose, null)
})

test("ask path uses the custom approval tool and records only the selected exact grant", async () => {
  const actions = []
  let approvalInput
  const plugin = createCommandGate({
    review: async (request) => ({
      ...allowDecision,
      decision: "ask",
      source: "assessor",
      rule: null,
      reason: "the command has an external side effect",
      grantEligible: true,
      requestFingerprint: fingerprintFor(request),
    }),
    runAction: async (subcommand, args) => actions.push({ subcommand, args }),
  })
  const hooks = await plugin(context())
  const args = { command: "touch ./output" }
  await assert.rejects(
    hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args }),
    /request_command_approval.*requestFingerprint.*touch \.\/output/,
  )

  const fingerprint = fingerprintFor(buildRequest(args.command, { sessionID: "session-1" }, context()))
  const result = await hooks.tool.request_command_approval.execute(
    { command: args.command, requestFingerprint: fingerprint, purpose: "Create the requested output" },
    {
      sessionID: "session-1",
      directory: process.cwd(),
      worktree: process.cwd(),
      abort: new AbortController().signal,
      ask: async (input) => {
        approvalInput = input
        return "always"
      },
    },
  )

  assert.equal(approvalInput.permission, "request_command_approval")
  assert.deepEqual(approvalInput.always, [`aar-exact:${fingerprint}`])
  assert.equal(approvalInput.metadata.effectSummary, "the command has an external side effect")
  assert.equal(approvalInput.metadata.canonicalWorkingDirectory, process.cwd())
  assert.equal(approvalInput.metadata.claimedPurpose, "Create the requested output")
  assert.equal(approvalInput.metadata.commandPreview, "touch ./output")
  assert.deepEqual(actions, [{ subcommand: "grant", args: ["--session", "session-1", "--fingerprint", fingerprint, "--scope", "session"] }])
  assert.match(result.output, /re-issue the original bash command verbatim/i)
  assert.equal(args.command, "touch ./output")
})

test("approval dismissal records a deny note and never creates a grant", async () => {
  const actions = []
  const plugin = createCommandGate({
    review: async (request) => ({
      ...allowDecision,
      decision: "ask",
      source: "assessor",
      rule: null,
      grantEligible: true,
      requestFingerprint: fingerprintFor(request),
    }),
    runAction: async (subcommand, args) => actions.push({ subcommand, args }),
  })
  const hooks = await plugin(context())
  const command = "touch ./output"
  await assert.rejects(hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args: { command } }))
  const fingerprint = fingerprintFor(buildRequest(command, { sessionID: "session-1" }, context()))
  const result = await hooks.tool.request_command_approval.execute(
    { command, requestFingerprint: fingerprint, purpose: "Create the requested output" },
    {
      sessionID: "session-1",
      directory: process.cwd(),
      worktree: process.cwd(),
      abort: new AbortController().signal,
      ask: async () => { throw new Error("dismissed") },
    },
  )
  assert.deepEqual(actions, [{ subcommand: "deny-note", args: ["--session", "session-1", "--fingerprint", fingerprint] }])
  assert.match(result.output, /not executed/i)
})

test("approval adapter timeouts and multiline purposes fail closed", async () => {
  const actions = []
  const plugin = createCommandGate({
    review: async (request) => ({
      ...allowDecision,
      decision: "ask",
      source: "assessor",
      rule: null,
      grantEligible: true,
      requestFingerprint: fingerprintFor(request),
    }),
    runAction: async (subcommand, args) => actions.push({ subcommand, args }),
  })
  const hooks = await plugin(context())
  const command = "touch ./output"
  await assert.rejects(hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args: { command } }))
  const fingerprint = fingerprintFor(buildRequest(command, { sessionID: "session-1" }, context()))

  const timeoutResult = await hooks.tool.request_command_approval.execute(
    { command, requestFingerprint: fingerprint, purpose: "Create the requested output" },
    { sessionID: "session-1", ask: async () => undefined },
  )
  assert.match(timeoutResult.output, /not executed/i)
  assert.deepEqual(actions, [{ subcommand: "deny-note", args: ["--session", "session-1", "--fingerprint", fingerprint] }])

  actions.length = 0
  await assert.rejects(hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args: { command } }))
  const multilineResult = await hooks.tool.request_command_approval.execute(
    { command, requestFingerprint: fingerprint, purpose: "first line\nsecond line" },
    { sessionID: "session-1", ask: async () => "always" },
  )
  assert.match(multilineResult.output, /not executed/i)
  assert.deepEqual(actions, [{ subcommand: "deny-note", args: ["--session", "session-1", "--fingerprint", fingerprint] }])
})

test("doctor failure is loud and keeps every configured command denied", async () => {
  const errors = []
  const toasts = []
  const previousError = console.error
  console.error = (message) => errors.push(String(message))
  try {
    const plugin = createCommandGate({
      doctor: async () => ({ ok: false, reason: "configuration is invalid" }),
      review: async () => ({ ...allowDecision, requestFingerprint: "never-used" }),
    })
    const hooks = await plugin({
      ...context(),
      client: { tui: { showToast: async (input) => toasts.push(input) } },
    })

    await assert.rejects(
      hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args: { command: "pwd" } }),
      /Command Gate is unavailable.*configuration is invalid.*not executed/i,
    )
    assert.match(errors.join("\n"), /Command Gate.*configuration is invalid/i)
    assert.equal(toasts.length, 1)
    assert.equal(toasts[0].body.variant, "error")
    assert.match(toasts[0].body.message, /configuration is invalid/i)
  } finally {
    console.error = previousError
  }
})

test("doctor rejects an unsupported contract before a reviewer can allow", async () => {
  let reviewed = false
  const plugin = createCommandGate({
    doctor: async () => ({
      schemaVersion: "aar-doctor-v1",
      contractVersion: "aar-contract-v0",
      status: "ok",
    }),
    review: async (request) => {
      reviewed = true
      return { ...allowDecision, requestFingerprint: fingerprintFor(request) }
    },
  })
  const hooks = await plugin(context())

  await assert.rejects(
    hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args: { command: "pwd" } }),
    /unsupported reviewer contract.*not executed/i,
  )
  assert.equal(reviewed, false)
})

test("doctor rejects an incomplete health report before a reviewer can allow", async () => {
  let reviewed = false
  const plugin = createCommandGate({
    doctor: async () => ({ status: "ok" }),
    review: async (request) => {
      reviewed = true
      return { ...allowDecision, requestFingerprint: fingerprintFor(request) }
    },
  })
  const hooks = await plugin(context())

  await assert.rejects(
    hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args: { command: "pwd" } }),
    /Command Gate is unavailable.*not executed/i,
  )
  assert.equal(reviewed, false)
})

test("reviewer failure passthrough is only enabled explicitly", async () => {
  const plugin = createCommandGate({
    onReviewerFailure: "passthrough",
    review: async () => { throw new Error("reviewer unavailable") },
  })
  const hooks = await plugin(context())
  const args = { command: "pwd" }

  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args })
  assert.deepEqual(args, { command: "pwd" })
})

test("rtk rewrites before review and leaves only the command argument changed", async () => {
  const reviewed = []
  let rewriteCalls = 0
  const plugin = createCommandGate({
    commandRewriter: "rtk",
    rewrite: async (command) => {
      rewriteCalls++
      return `rtk ${command}`
    },
    review: async (request) => {
      reviewed.push(request.command)
      return { ...allowDecision, requestFingerprint: fingerprintFor(request) }
    },
  })
  const hooks = await plugin(context())
  const args = { command: "git status", timeout: 4000, description: "keep this" }

  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args })

  assert.equal(rewriteCalls, 1)
  assert.deepEqual(reviewed, ["rtk git status"])
  assert.deepEqual(args, { command: "rtk git status", timeout: 4000, description: "keep this" })
})

test("failed and empty rewrites preserve the original command", async () => {
  for (const rewrite of [async () => "", async () => { throw new Error("rtk missing") }]) {
    const reviewed = []
    const plugin = createCommandGate({
      commandRewriter: "rtk",
      rewrite,
      review: async (request) => {
        reviewed.push(request.command)
        return { ...allowDecision, requestFingerprint: fingerprintFor(request) }
      },
    })
    const hooks = await plugin(context())
    const args = { command: "cat <<'EOF'\nbody\nEOF", timeout: 4000 }

    await hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args })

    assert.deepEqual(reviewed, [args.command])
    assert.equal(args.command, "cat <<'EOF'\nbody\nEOF")
    assert.equal(args.timeout, 4000)
  }
})

test("gate ignores its approval tool and never rewrites unrelated tools", async () => {
  let reviewed = 0
  let rewritten = 0
  const plugin = createCommandGate({
    commandRewriter: "rtk",
    rewrite: async (command) => {
      rewritten++
      return `rtk ${command}`
    },
    review: async () => {
      reviewed++
      return allowDecision
    },
  })
  const hooks = await plugin(context())

  await hooks["tool.execute.before"](
    { tool: "request_command_approval", sessionID: "session-1" },
    { args: { command: "touch approval-argument" } },
  )
  await hooks["tool.execute.before"](
    { tool: "read", sessionID: "session-1" },
    { args: { command: "touch unrelated-argument" } },
  )

  assert.equal(reviewed, 0)
  assert.equal(rewritten, 0)
})

test("subagent sessions use the same native bash hook", async () => {
  let reviewedSession
  const plugin = createCommandGate({
    review: async (request) => {
      reviewedSession = request.session.id
      return { ...allowDecision, requestFingerprint: fingerprintFor(request) }
    },
  })
  const hooks = await plugin(context())

  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "subagent-session-1" }, { args: { command: "pwd" } })

  assert.equal(reviewedSession, "subagent-session-1")
})

test("genuine user intent is cached by message id and goal lookup is best effort", async () => {
  const actions = []
  const goals = []
  let goalLookups = 0
  const plugin = createCommandGate({
    runAction: async (subcommand, args) => actions.push({ subcommand, args }),
    review: async (request) => {
      goals.push({ goal: request.intent.goal, latestUserRequest: request.intent.latestUserRequest })
      return { ...allowDecision, requestFingerprint: fingerprintFor(request) }
    },
  })
  const hooks = await plugin({
    ...context(),
    client: {
      session: {
        get: async () => {
          goalLookups++
          return { data: { goal: "Inspect the workspace" } }
        },
      },
    },
  })

  await hooks["chat.message"](
    { sessionID: "session-1", messageID: "message-1" },
    { message: { id: "message-1", role: "user" }, parts: [{ type: "text", text: "Inspect the workspace" }] },
  )
  await hooks["chat.message"](
    { sessionID: "session-1", messageID: "message-1" },
    { message: { id: "message-1", role: "user" }, parts: [{ type: "text", text: "duplicate" }] },
  )
  await hooks["chat.message"](
    { sessionID: "session-1", messageID: "synthetic", },
    { message: { id: "synthetic", role: "user" }, parts: [{ type: "text", text: "continue", synthetic: true }] },
  )
  await hooks["chat.message"](
    { sessionID: "session-1", messageID: "message-2" },
    { message: { id: "message-2", role: "user" }, parts: [{ type: "text", text: "Review the changes" }] },
  )

  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args: { command: "pwd" } })
  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args: { command: "pwd" } })

  assert.equal(goalLookups, 1)
  assert.deepEqual(goals, [
    { goal: "Inspect the workspace", latestUserRequest: "Review the changes" },
    { goal: "Inspect the workspace", latestUserRequest: "Review the changes" },
  ])
  assert.deepEqual(actions, [
    { subcommand: "session-event", args: ["--session", "session-1", "--event", "new-intent"] },
    { subcommand: "session-event", args: ["--session", "session-1", "--event", "new-intent"] },
  ])
})

test("goal lookup extracts the active canonical Goal from session metadata", async () => {
  const goals = []
  const plugin = createCommandGate({
    getSession: async () => ({ data: { metadata: { goal: { condition: "Keep the workspace safe", status: "active" } } } }),
    review: async (request) => {
      goals.push(request.intent.goal)
      return { ...allowDecision, requestFingerprint: fingerprintFor(request) }
    },
  })
  const hooks = await plugin(context())

  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args: { command: "pwd" } })

  assert.deepEqual(goals, ["Keep the workspace safe"])
})

test("clear and session deletion invalidate the reviewer session", async () => {
  const actions = []
  const plugin = createCommandGate({
    runAction: async (subcommand, args) => actions.push({ subcommand, args }),
    review: async (request) => ({ ...allowDecision, requestFingerprint: fingerprintFor(request) }),
  })
  const hooks = await plugin(context())

  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "session-1" }, { args: { command: "pwd" } })
  await hooks.event({ event: { type: "tui.command.execute", properties: { command: "prompt.clear" } } })
  await hooks.event({ event: { type: "session.deleted", properties: { info: { id: "session-1" } } } })

  assert.deepEqual(actions, [
    { subcommand: "session-event", args: ["--session", "session-1", "--event", "clear"] },
    { subcommand: "session-event", args: ["--session", "session-1", "--event", "end"] },
  ])
})

test("human !command remains outside the Gate hook boundary", async () => {
  const plugin = createCommandGate({
    review: async () => { throw new Error("must not be called") },
  })
  const hooks = await plugin(context())

  assert.equal(hooks["command.execute.before"], undefined)
  assert.equal(hooks["tool.execute.after"], undefined)
  assert.equal(hooks["permission.ask"], undefined)
})
