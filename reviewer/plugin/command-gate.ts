import { createHash } from "node:crypto"
import { spawn as nodeSpawn } from "node:child_process"
import { existsSync, readFileSync, realpathSync } from "node:fs"
import { fileURLToPath } from "node:url"
import os from "node:os"
import path from "node:path"

const REQUEST_SCHEMA_VERSION = "aar-request-v1"
const DECISION_SCHEMA_VERSION = "aar-decision-v1"
const DOCTOR_SCHEMA_VERSION = "aar-doctor-v1"
const CONTRACT_VERSION = "aar-contract-v1"
const DEFAULT_TOOLS = ["bash", "shell"]
const DEFAULT_TIMEOUT_MS = 5500
const MAX_REVIEWER_STDOUT_BYTES = 1024 * 1024
const SOURCES = new Set(["hard-deny", "auto-allow", "grant", "assessor", "unavailable", "deny-note"])
const ALLOW_SOURCES = new Set(["auto-allow", "grant", "assessor"])
const APPROVAL_TOOL = "request_command_approval"
const FAILURE_MODES = new Set(["deny", "passthrough"])
const REWRITERS = new Set(["none", "rtk"])
const SUPPORTED_OPENCODE_VERSION = "1.18.21"

function createCommandGate(options = {}) {
  return async function commandGate(context = {}) {
    const config = resolveConfig(options, context)
    const review = options.review ?? ((request) => callReviewer(request, config))
    const startup = await runStartupDoctor(config, context, options)
    if (!startup.ok) await announceStartupFailure(context, startup.reason)
    const pendingApprovals = new Map()
    const sessionIntentIDs = new Map()
    const latestUserRequests = new Map()
    const sessionGoals = new Map()
    const goalCache = new Map()
    const knownSessions = new Set()
    const emitSessionEvent = (sessionID, event) => emitReviewerAction("session-event", ["--session", sessionID, "--event", event], config, options)
    const permissionReplies = createPermissionReplyChannel(context.client)
    const approvalTool = await createApprovalTool({
      config,
      options,
      pendingApprovals,
      permissionReplies,
    })

    const hooks = {
      "tool.execute.before": async (input, output) => {
        const toolID = String(input?.tool ?? "").toLowerCase()
        if (toolID === APPROVAL_TOOL || !config.tools.includes(toolID)) return

        if (!startup.ok) {
          throw commandGateUnavailable(startup.reason)
        }

        const command = output?.args?.command
        if (typeof command !== "string") {
          if (config.onReviewerFailure === "passthrough") return
          throw reviewerFailure("the bash tool did not provide a string command")
        }

        const originalCommand = command
        const rewrittenCommand = await rewriteCommand(command, config, options)
        if (rewrittenCommand !== originalCommand) output.args.command = rewrittenCommand

        const sessionID = typeof input?.sessionID === "string" ? input.sessionID : ""
        if (sessionID) knownSessions.add(sessionID)
        const goal = await resolveActiveGoal(sessionID, input, context, options, goalCache)
        if (sessionGoals.has(sessionID) && sessionGoals.get(sessionID) !== goal) {
          await safelyEmitSessionEvent(emitSessionEvent, sessionID, "goal-change")
        }
        sessionGoals.set(sessionID, goal)
        const request = buildRequest(rewrittenCommand, {
          ...input,
          intentId: sessionIntentIDs.get(sessionID) ?? input.intentId,
          latestUserRequest: latestUserRequests.get(sessionID) ?? input.latestUserRequest,
          goal,
        }, context)
        let decision
        try {
          decision = await review(request)
        } catch (error) {
          if (config.onReviewerFailure === "passthrough") return
          throw reviewerFailure(`the Command Reviewer was unavailable (${errorMessage(error)})`)
        }
        try {
          validateDecision(decision, request)
        } catch (error) {
          if (config.onReviewerFailure === "passthrough") return
          throw reviewerFailure(`the Command Reviewer returned an invalid decision (${errorMessage(error)})`)
        }

        if (decision.decision === "allow") return

        if (decision.decision === "ask") {
          pendingApprovals.set(approvalKey(request.session.id, decision.requestFingerprint), {
            request,
            decision,
            createdAt: Date.now(),
          })
          throw approvalRequired(request, decision)
        }

        const reason = compactReason(decision.reason || "the command was not proven safe")
        throw new Error(
          `Auto Approve Permissions blocked this command. Reason: ${reason}. The command was not executed.`,
        )
      },
      event: async ({ event }) => {
        const type = event?.type
        if (type === "session.deleted") {
          const sessionID = event.properties?.info?.id
          if (typeof sessionID === "string" && sessionID !== "") {
            await safelyEmitSessionEvent(emitSessionEvent, sessionID, "end")
            deletePendingForSession(pendingApprovals, sessionID)
            knownSessions.delete(sessionID)
            sessionIntentIDs.delete(sessionID)
            latestUserRequests.delete(sessionID)
            sessionGoals.delete(sessionID)
            goalCache.delete(sessionID)
          }
          return
        }
        if (type === "tui.command.execute" && event.properties?.command === "prompt.clear") {
          const sessions = [...knownSessions]
          for (const sessionID of sessions) {
            await safelyEmitSessionEvent(emitSessionEvent, sessionID, "clear")
          }
          for (const sessionID of sessions) {
            sessionIntentIDs.delete(sessionID)
            latestUserRequests.delete(sessionID)
            sessionGoals.delete(sessionID)
            goalCache.delete(sessionID)
          }
        }
      },
      "chat.message": async (input, output) => {
        const sessionID = typeof input?.sessionID === "string" ? input.sessionID : ""
        const message = output?.message
        const messageID = typeof message?.id === "string" ? message.id : input?.messageID
        if (!sessionID || !messageID || message?.role !== "user" || message.synthetic || message.ignored) return
        const text = genuineMessageText(output?.parts)
        if (text === null) return
        if (sessionIntentIDs.get(sessionID) === messageID) return
        knownSessions.add(sessionID)
        if (sessionIntentIDs.get(sessionID) !== messageID) {
          await safelyEmitSessionEvent(emitSessionEvent, sessionID, "new-intent")
        }
        sessionIntentIDs.set(sessionID, messageID)
        latestUserRequests.set(sessionID, text)
        goalCache.delete(sessionID)
      },
    }
    return { ...hooks, tool: { [APPROVAL_TOOL]: approvalTool } }
  }
}

async function commandGatePlugin(context, pluginOptions = {}) {
  const fileConfig = readGateConfig(context)
  const configuredGate = {
    ...fileConfig,
    ...(context?.config?.gate ?? {}),
    ...(pluginOptions.gate ?? pluginOptions ?? {}),
  }
  const runtime = await checkRuntimeCompatibility(pluginOptions)
  return createCommandGate({
    ...configuredGate,
    runtimeFailure: runtime.ok ? null : runtime.reason,
  })(context)
}

function readGateConfig(context) {
  const candidates = [
    process.env.OPENCODE_CONFIG_DIR ? path.join(process.env.OPENCODE_CONFIG_DIR, "opencode.json") : null,
    process.env.OPENCODE_CONFIG_DIR ? path.join(process.env.OPENCODE_CONFIG_DIR, "opencode.jsonc") : null,
    context?.directory ? path.join(context.directory, "opencode.json") : null,
    context?.directory ? path.join(context.directory, "opencode.jsonc") : null,
    context?.directory ? path.join(context.directory, ".opencode", "opencode.json") : null,
    context?.directory ? path.join(context.directory, ".opencode", "opencode.jsonc") : null,
  ].filter(Boolean)
  let gate = {}
  let configError = null
  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(stripJsonComments(readFileSync(candidate, "utf8")))
      if (parsed?.gate && typeof parsed.gate === "object" && !Array.isArray(parsed.gate)) {
        gate = { ...gate, ...parsed.gate }
      }
    } catch {
      if (existsSync(candidate)) configError = `could not parse OpenCode config ${candidate}`
    }
  }
  return configError === null ? gate : { ...gate, configError }
}

function stripJsonComments(source) {
  let output = ""
  let quote = false
  let escaped = false
  let lineComment = false
  let blockComment = false
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index]
    const next = source[index + 1]
    if (lineComment) {
      if (character === "\n") {
        lineComment = false
        output += character
      }
      continue
    }
    if (blockComment) {
      if (character === "*" && next === "/") {
        blockComment = false
        index += 1
      } else if (character === "\n") {
        output += character
      }
      continue
    }
    if (quote) {
      output += character
      if (escaped) escaped = false
      else if (character === "\\") escaped = true
      else if (character === '"') quote = false
      continue
    }
    if (character === '"') {
      quote = true
      output += character
    } else if (character === "/" && next === "/") {
      lineComment = true
      index += 1
    } else if (character === "/" && next === "*") {
      blockComment = true
      index += 1
    } else {
      output += character
    }
  }
  return stripJsonTrailingCommas(output)
}

function stripJsonTrailingCommas(source) {
  let output = ""
  let quote = false
  let escaped = false
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index]
    if (quote) {
      output += character
      if (escaped) escaped = false
      else if (character === "\\") escaped = true
      else if (character === '"') quote = false
      continue
    }
    if (character === '"') {
      quote = true
      output += character
      continue
    }
    if (character === ",") {
      let lookahead = index + 1
      while (/\s/.test(source[lookahead] ?? "")) lookahead += 1
      if (source[lookahead] === "}" || source[lookahead] === "]") continue
    }
    output += character
  }
  return output
}

// OpenCode treats every exported function as a plugin initializer. Keep the
// module surface to one initializer; helpers remain reachable to unit tests as
// properties without becoming additional plugin exports.
export const CommandGatePlugin = Object.assign(commandGatePlugin, {
  createCommandGate,
  buildRequest,
  callReviewer,
  callDoctor,
  readGateConfig,
  checkRuntimeCompatibility,
})

async function checkRuntimeCompatibility(options = {}) {
  const platform = options.platform ?? process.platform
  if (platform === "win32") {
    return { ok: false, reason: "Windows execution is unsupported in Auto Approve Permissions v1" }
  }
  if (typeof options.runtimeCheck === "function") {
    try {
      return normalizeRuntimeCheck(await options.runtimeCheck(options))
    } catch (error) {
      return { ok: false, reason: `OpenCode runtime compatibility check failed (${errorMessage(error)})` }
    }
  }
  try {
    const [pluginModule, sdkModule] = await Promise.all([
      import("@opencode-ai/plugin"),
      import("@opencode-ai/sdk"),
    ])
    if (typeof pluginModule.tool !== "function") {
      return { ok: false, reason: `@opencode-ai/plugin ${SUPPORTED_OPENCODE_VERSION} is required` }
    }
    for (const packageName of ["@opencode-ai/plugin", "@opencode-ai/sdk"]) {
      const version = packageVersion(packageName)
      if (version !== SUPPORTED_OPENCODE_VERSION) {
        return {
          ok: false,
          reason: `${packageName} ${SUPPORTED_OPENCODE_VERSION} is required; found ${version ?? "an unknown runtime"}`,
        }
      }
    }
    // Touch the SDK module so a package that resolves only its type surface
    // cannot pass the runtime check.
    if (!sdkModule || typeof sdkModule !== "object") {
      return { ok: false, reason: `@opencode-ai/sdk ${SUPPORTED_OPENCODE_VERSION} is unavailable at runtime` }
    }
    return { ok: true, version: SUPPORTED_OPENCODE_VERSION }
  } catch (error) {
    return { ok: false, reason: `OpenCode runtime packages are unavailable (${errorMessage(error)})` }
  }
}

function normalizeRuntimeCheck(result) {
  if (result === true) return { ok: true }
  if (result === false || result === null || typeof result !== "object") {
    return { ok: false, reason: `OpenCode ${SUPPORTED_OPENCODE_VERSION} runtime compatibility is unavailable` }
  }
  if (result.ok !== true) {
    return { ok: false, reason: errorMessage(result.reason || result.error || `OpenCode ${SUPPORTED_OPENCODE_VERSION} runtime compatibility is unavailable`) }
  }
  return result
}

function packageVersion(packageName) {
  let resolved
  try {
    resolved = import.meta.resolve(packageName)
  } catch {
    return null
  }
  if (typeof resolved !== "string" || !resolved.startsWith("file:")) return null
  let current
  try {
    current = path.dirname(fileURLToPath(resolved))
  } catch {
    return null
  }
  for (let depth = 0; depth < 8; depth += 1) {
    const candidate = path.join(current, "package.json")
    try {
      const packageJSON = JSON.parse(readFileSync(candidate, "utf8"))
      if (packageJSON?.name === packageName) return packageJSON.version ?? null
    } catch {
      // Keep walking: a bundled runtime may resolve through a generated path.
    }
    const parent = path.dirname(current)
    if (parent === current) break
    current = parent
  }
  return null
}

async function runStartupDoctor(config, context, options) {
  if (config.configError) {
    return { ok: false, reason: `invalid gate configuration (${config.configError})` }
  }
  if (options.runtimeFailure) {
    return { ok: false, reason: options.runtimeFailure }
  }

  if (typeof options.doctor === "function") {
    try {
      return normalizeDoctorResult(await options.doctor(config, context), config)
    } catch (error) {
      return { ok: false, reason: `aar doctor failed (${errorMessage(error)})` }
    }
  }

  // A custom reviewer is the unit-test/embedding seam. Production plugin
  // initialization always uses the real aar doctor below.
  if (typeof options.review === "function") return { ok: true }

  try {
    return normalizeDoctorResult(await callDoctor(config, context), config)
  } catch (error) {
    return { ok: false, reason: `aar doctor failed (${errorMessage(error)})` }
  }
}

function normalizeDoctorResult(result, config) {
  if (result === false || result === null) return { ok: false, reason: "aar doctor reported an unhealthy installation" }
  if (typeof result !== "object" || Array.isArray(result)) return { ok: false, reason: "aar doctor returned an invalid report" }
  if (result.ok === false || result.status === "error") {
    return { ok: false, reason: errorMessage(result.reason || result.error || "aar doctor reported an unhealthy installation") }
  }
  if (result.schemaVersion !== DOCTOR_SCHEMA_VERSION) {
    return { ok: false, reason: `unsupported aar doctor schemaVersion ${JSON.stringify(result.schemaVersion)}` }
  }
  if (result.contractVersion !== CONTRACT_VERSION) {
    return { ok: false, reason: `unsupported reviewer contract ${JSON.stringify(result.contractVersion)}` }
  }
  if (result.requestSchemaVersion !== REQUEST_SCHEMA_VERSION) {
    return { ok: false, reason: `unsupported reviewer request contract ${JSON.stringify(result.requestSchemaVersion)}` }
  }
  if (result.decisionSchemaVersion !== DECISION_SCHEMA_VERSION) {
    return { ok: false, reason: `unsupported reviewer decision contract ${JSON.stringify(result.decisionSchemaVersion)}` }
  }
  if (result.status !== "ok") {
    return { ok: false, reason: "aar doctor did not report status ok" }
  }
  const reviewerTimeoutMs = Number(result.reviewerTimeoutMs)
  if (!Number.isFinite(reviewerTimeoutMs) || reviewerTimeoutMs <= 0) {
    return { ok: false, reason: "aar doctor returned an invalid reviewer timeout" }
  }
  if (config.timeoutMs <= reviewerTimeoutMs) {
    return {
      ok: false,
      reason: `gate.timeoutMs (${config.timeoutMs}) must be greater than the reviewer deadline (${reviewerTimeoutMs})`,
    }
  }
  return { ok: true, reviewerTimeoutMs }
}

async function announceStartupFailure(context, reason) {
  const message = `Command Gate is unavailable: ${reason}. Fix the installation or configuration, then restart OpenCode after \`aar doctor\` passes. Bash commands remain denied.`
  console.error(`[Auto Approve Permissions] ${message}`)
  const showToast = context?.client?.tui?.showToast
  if (typeof showToast !== "function") return
  try {
    await showToast({
      body: {
        title: "Command Gate unavailable",
        message,
        variant: "error",
        duration: 12000,
      },
      query: context.directory ? { directory: context.directory } : undefined,
    })
  } catch {
    // Console diagnostics remain authoritative when the TUI is unavailable.
  }
}

function commandGateUnavailable(reason) {
  return reviewerFailure(`Command Gate is unavailable (${compactReason(reason)}); fix the installation or configuration and make \`aar doctor\` pass`)
}

async function rewriteCommand(command, config, options) {
  if (config.commandRewriter === "none") return command
  try {
    const result = typeof options.rewrite === "function"
      ? await withTimeout(options.rewrite(command, config), config.timeoutMs)
      : await callRewriter(command, config)
    if (typeof result !== "string") return command
    const rewritten = result.trim()
    return rewritten === "" ? command : rewritten
  } catch {
    return command
  }
}

function callRewriter(command, config, spawn = nodeSpawn) {
  const cwd = config.cwd ?? process.cwd()
  const binaryPath = config.rewriterPath ?? "rtk"
  const child = spawn(binaryPath, ["rewrite", command], {
    cwd,
    env: rewriterEnvironment({ cwd }),
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  })
  let stdout = ""
  let settled = false
  let timer
  return new Promise((resolve, reject) => {
    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error) reject(error)
      else resolve(value)
    }
    child.once("error", (error) => finish(error))
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk)
      if (Buffer.byteLength(stdout) > MAX_REVIEWER_STDOUT_BYTES) {
        child.kill?.("SIGKILL")
        finish(new Error("rewriter output exceeded the safety limit"))
      }
    })
    child.stderr.on("data", () => {})
    child.once("close", (code, signal) => {
      if (code !== 0) {
        finish(new Error(`rtk rewrite exited unsuccessfully (${code ?? signal ?? "unknown"})`))
        return
      }
      finish(null, stdout)
    })
    timer = setTimeout(() => {
      child.kill?.("SIGKILL")
      finish(new Error("rtk rewrite timed out"))
    }, config.timeoutMs)
  })
}

async function withTimeout(value, timeoutMs) {
  let timer
  try {
    return await Promise.race([
      Promise.resolve(value),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("operation timed out")), timeoutMs)
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

async function resolveActiveGoal(sessionID, input, context, options, cache) {
  const direct = firstGoal(context.goal, context.intent?.goal, input?.goal, input?.intent?.goal)
  if (direct !== null) {
    if (sessionID) cache.set(sessionID, direct)
    return direct
  }
  if (!sessionID) return null
  if (cache.has(sessionID)) return cache.get(sessionID)

  let goal = null
  try {
    let result
    if (typeof options.getGoal === "function") {
      result = await options.getGoal({ sessionID, directory: context.directory, worktree: context.worktree, client: context.client })
    } else if (typeof context.getGoal === "function") {
      result = await context.getGoal({ sessionID, directory: context.directory, worktree: context.worktree, client: context.client })
    } else if (typeof options.getSession === "function") {
      result = await options.getSession({ sessionID, directory: context.directory, worktree: context.worktree, client: context.client })
    } else if (context?.serverUrl) {
      result = await getSessionFromServer(context, sessionID)
    } else if (typeof context.client?.session?.get === "function") {
      result = await context.client.session.get({
        path: { id: sessionID },
        query: context.directory ? { directory: context.directory } : undefined,
      })
    }
    goal = extractGoal(result)
  } catch {
    goal = null
  }
  cache.set(sessionID, goal)
  return goal
}

function extractGoal(result) {
  const candidates = [
    result?.goal,
    result?.data?.goal,
    result?.info?.goal,
    result?.data?.info?.goal,
    result?.metadata?.goal,
    result?.data?.metadata?.goal,
    result?.session?.metadata?.goal,
    result?.data?.session?.metadata?.goal,
    result?.session?.goal,
    result?.data?.session?.goal,
  ]
  return firstGoal(...candidates)
}

async function getSessionFromServer(context, sessionID) {
  const sdk = await import("@opencode-ai/sdk/v2")
  if (typeof sdk.createOpencodeClient !== "function") throw new Error("OpenCode v2 SDK client is unavailable")
  const baseUrl = typeof context.serverUrl?.toString === "function" ? context.serverUrl.toString() : String(context.serverUrl)
  const client = sdk.createOpencodeClient({ baseUrl, directory: context.directory })
  return await client.session.get({ sessionID })
}

function buildRequest(command, input = {}, context = {}) {
  const cwd = canonicalDirectory(typeof context.directory === "string" && context.directory !== "" ? context.directory : process.cwd())
  const rawWorkspaceRoot = typeof context.worktree === "string" && context.worktree !== "" ? context.worktree : null
  const workspaceRoot = rawWorkspaceRoot === null ? null : canonicalDirectory(rawWorkspaceRoot)
  const goal = firstGoal(context.goal, context.intent?.goal, input.goal, input.intent?.goal)
  const latestUserRequest = firstText(
    context.latestUserRequest,
    context.userRequest,
    context.intent?.latestUserRequest,
    input.latestUserRequest,
    input.userRequest,
    input.intent?.latestUserRequest,
  )
  const env = {}
  for (const key of ["CDPATH", "HOME", "PWD"]) {
    if (typeof process.env[key] === "string") env[key] = process.env[key]
  }
  return {
    schemaVersion: REQUEST_SCHEMA_VERSION,
    command,
    cwd,
    workspaceRoot,
    env,
    session: {
      id: typeof input.sessionID === "string" ? input.sessionID : "",
      host: "opencode",
      intentId: firstText(
        input.intentId,
        input.intent?.id,
        context.intentId,
        context.intent?.id,
        context.latestUserMessageId,
      ),
    },
    intent: {
      goal,
      latestUserRequest,
      purpose: null,
    },
  }
}

function canonicalDirectory(value) {
  try {
    return realpathSync(value)
  } catch {
    return path.resolve(value)
  }
}

function firstText(...values) {
  return values.find((value) => typeof value === "string" && value !== "") ?? null
}

function firstGoal(...values) {
  for (const value of values) {
    const goal = goalText(value)
    if (goal !== null) return goal
  }
  return null
}

function goalText(value) {
  if (typeof value === "string" && value !== "") return value
  if (!value || typeof value !== "object" || typeof value.condition !== "string" || value.condition === "") return null
  if (value.status !== undefined && value.status !== "active") return null
  return value.condition
}

function createPermissionReplyChannel(client) {
  const ids = new Map()
  const responses = new Map()
  const waiters = new Map()
  if (typeof client?.event?.subscribe !== "function") {
    return { available: false, take: async () => null }
  }
  void (async () => {
    const result = await client.event.subscribe()
    for await (const streamed of result.stream) {
      const event = streamed?.data?.type ? streamed.data : streamed
      if (event?.type === "permission.updated") {
        const fingerprint = event.properties?.metadata?.requestFingerprint
        const permissionID = event.properties?.id
        if (typeof fingerprint === "string" && typeof permissionID === "string") ids.set(permissionID, fingerprint)
        continue
      }
      if (event?.type !== "permission.replied") continue
      const permissionID = event.properties?.permissionID
      const fingerprint = ids.get(permissionID)
      if (!fingerprint) continue
      const response = event.properties?.response
      const pending = waiters.get(fingerprint)
      if (pending) {
        waiters.delete(fingerprint)
        pending(response)
      } else {
        responses.set(fingerprint, response)
      }
    }
  })().catch(() => {})
  return {
    available: true,
    take: async (fingerprint) => {
      if (responses.has(fingerprint)) {
        const response = responses.get(fingerprint)
        responses.delete(fingerprint)
        return response
      }
      return await new Promise((resolve) => {
        const timer = setTimeout(() => {
          waiters.delete(fingerprint)
          resolve(null)
        }, 100)
        waiters.set(fingerprint, (response) => {
          clearTimeout(timer)
          resolve(response)
        })
      })
    },
  }
}

async function createApprovalTool({ config, options, pendingApprovals, permissionReplies }) {
  let toolFactory
  try {
    const pluginModule = await import("@opencode-ai/plugin")
    toolFactory = pluginModule.tool
  } catch {
    toolFactory = null
  }

  const schema = toolFactory?.schema
  const args = schema
    ? {
        command: schema.string().describe("The exact command originally blocked by the Command Gate."),
        requestFingerprint: schema.string().describe("The opaque fingerprint from the blocked bash request."),
        purpose: schema.string().describe("One short line explaining why this exact command is needed."),
      }
    : {
        command: { type: "string", description: "The exact blocked command." },
        requestFingerprint: { type: "string", description: "The blocked request fingerprint." },
        purpose: { type: "string", description: "One-line claimed purpose." },
      }
  const definition = {
    description: "Ask a human to approve one exact blocked command. This tool never executes commands; re-issue the ordinary bash call after it returns.",
    args,
    execute: async (input, toolContext = {}) => executeApprovalRequest({
      input,
      toolContext,
      config,
      options,
      pendingApprovals,
      permissionReplies,
    }),
  }
  return typeof toolFactory === "function" ? toolFactory(definition) : definition
}

async function executeApprovalRequest({ input, toolContext, config, options, pendingApprovals, permissionReplies }) {
  const command = typeof input?.command === "string" ? input.command : ""
  const fingerprint = typeof input?.requestFingerprint === "string" ? input.requestFingerprint : ""
  const sessionID = typeof toolContext.sessionID === "string" ? toolContext.sessionID : ""
  const purpose = oneLinePurpose(input?.purpose)
  if (!command || !sessionID || !fingerprint || !purpose) {
    if (command && sessionID && fingerprint) await bestEffortDenyNote(sessionID, fingerprint, config, options)
    return { title: "Command approval denied", output: "Approval was denied because the command, fingerprint, session, or one-line purpose was missing. The command was not executed; re-issue nothing." }
  }

  const pending = pendingApprovals.get(approvalKey(sessionID, fingerprint))
  const request = pending?.request
  const decision = pending?.decision
  if (!request || !decision) {
    return { title: "Command approval denied", output: "The approval request did not match a pending exact blocked bash request. The command was not executed." }
  }
  if (request.command !== command || decision.requestFingerprint !== fingerprint || decision.decision !== "ask") {
    return { title: "Command approval denied", output: "The approval request did not match the exact blocked bash request. The command was not executed." }
  }

  const metadata = {
    aar: true,
    requestFingerprint: fingerprint,
    effectSummary: compactReason(decision.reason),
    canonicalWorkingDirectory: request.cwd,
    claimedPurpose: purpose,
    commandPreview: maskCommand(command),
    command,
    riskAssessment: decision.assessment ?? null,
    grantEligible: Boolean(decision.grantEligible),
    approvalOptions: decision.grantEligible ? ["Deny", "Allow once", "Trust exact for session"] : ["Deny", "Allow once"],
  }

  let response
  try {
    if (toolContext.abort?.aborted) throw new Error("approval request was cancelled")
    if (typeof toolContext.ask !== "function") throw new Error("ToolContext.ask is unavailable")
    response = await toolContext.ask({
      permission: APPROVAL_TOOL,
      patterns: [maskCommand(command)],
      always: decision.grantEligible ? [`aar-exact:${fingerprint}`] : [],
      metadata,
    })
    const observedResponse = await permissionReplies.take(fingerprint)
    if (observedResponse !== null) response = observedResponse
    // OpenCode 1.18.x resolves ToolContext.ask() with void after native
    // permission approval. The resolved promise is the confirmation; the
    // event stream is an optional response-detail channel, not the approval
    // authority.
    if ((response === undefined || response === null) && permissionReplies.available) response = "once"
  } catch (error) {
    await bestEffortDenyNote(sessionID, fingerprint, config, options)
    return { title: "Command approval denied", output: `Human approval was denied or unavailable (${errorMessage(error)}). The command was not executed.` }
  }

  if (toolContext.abort?.aborted) {
    await bestEffortDenyNote(sessionID, fingerprint, config, options)
    return { title: "Command approval denied", output: "Human approval was cancelled. The command was not executed." }
  }
  const scope = approvalScope(response, decision.grantEligible)
  if (scope === "deny") {
    await bestEffortDenyNote(sessionID, fingerprint, config, options)
    return { title: "Command approval denied", output: "Human approval was denied. The command was not executed; submit a new genuine user request before asking again." }
  }

  try {
    await emitReviewerAction("grant", ["--session", sessionID, "--fingerprint", fingerprint, "--scope", scope], config, options)
  } catch (error) {
    await bestEffortDenyNote(sessionID, fingerprint, config, options)
    return { title: "Command approval denied", output: `The approval record could not be written (${errorMessage(error)}). The command was not executed.` }
  }
  pendingApprovals.delete(approvalKey(sessionID, fingerprint))
  return {
    title: "Command approval recorded",
    output: `Approval recorded for this exact command (${scope}). Re-issue the original bash command verbatim; this tool executed nothing.`,
    metadata: { requestFingerprint: fingerprint, scope },
  }
}

function approvalScope(response, eligible) {
  const value = typeof response === "string" ? response : response?.response ?? response?.decision ?? response?.scope
  if (value === undefined || value === null || value === "") return "deny"
  const normalized = String(value ?? "once").toLowerCase().replaceAll("_", "-")
  if (normalized === "reject" || normalized === "deny" || normalized === "denied") return "deny"
  if ((normalized === "always" || normalized === "session" || normalized === "trust-session" || normalized === "trust-exact-for-session") && eligible) {
    return "session"
  }
  if (normalized === "once" || normalized === "allow-once" || normalized === "allow") return "once"
  return "deny"
}

async function bestEffortDenyNote(sessionID, fingerprint, config, options) {
  try {
    await emitReviewerAction("deny-note", ["--session", sessionID, "--fingerprint", fingerprint], config, options)
  } catch {
    // A failed denial record still fails closed because no grant was written.
  }
}

function approvalRequired(request, decision) {
  const reason = compactReason(decision.reason || "the command needs human approval")
  return new Error(
    `Auto Approve Permissions blocked this command. Reason: ${reason}. Human approval is required; call ${APPROVAL_TOOL} with requestFingerprint ${JSON.stringify(decision.requestFingerprint)}, command exactly ${JSON.stringify(request.command)}, and a one-line purpose. The command was not executed.`,
  )
}

function approvalKey(sessionID, fingerprint) {
  return `${sessionID}\u0000${fingerprint}`
}

function deletePendingForSession(pendingApprovals, sessionID) {
  const prefix = `${sessionID}\u0000`
  for (const key of pendingApprovals.keys()) {
    if (key.startsWith(prefix)) pendingApprovals.delete(key)
  }
}

function genuineMessageText(parts) {
  if (!Array.isArray(parts)) return null
  const values = parts
    .filter((part) => part?.type === "text" && !part.synthetic && !part.ignored)
    .map((part) => String(part.text ?? ""))
    .filter(Boolean)
  return values.length === 0 ? null : values.join("\n")
}

function oneLinePurpose(value) {
  const rawPurpose = String(value ?? "").trim()
  if (rawPurpose === "" || /[\r\n]/.test(rawPurpose)) return null
  return rawPurpose.replace(/\s+/g, " ").slice(0, 240)
}

function maskCommand(command) {
  let masked = String(command)
    .replace(/(Bearer\s+)[^\s'"`]+/gi, "$1[REDACTED]")
    .replace(/((?:token|password|secret|api[_-]?key)[^=\s]*\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s]+)/gi, "$1[REDACTED]")
    .replace(/(https?:\/\/[^/\s:@]+:)[^@\s]+(@)/gi, "$1[REDACTED]$2")
    .replace(/\bsk-[A-Za-z0-9_-]+/g, "sk-[REDACTED]")
  if (masked.length > 240) masked = `${masked.slice(0, 237)}...`
  return masked
}

async function safelyEmitSessionEvent(emitSessionEvent, sessionID, event) {
  if (!sessionID) return
  try {
    await emitSessionEvent(sessionID, event)
  } catch {
    // A missed event is safe: the Reviewer also compares stored intent IDs.
  }
}

async function emitReviewerAction(subcommand, args, config, options = {}) {
  if (typeof options.runAction === "function") return options.runAction(subcommand, args)
  return callReviewerAction(subcommand, args, config)
}

async function callReviewer(request, config, spawn = nodeSpawn) {
  const child = spawn(config.binaryPath, ["check"], {
    cwd: request.cwd,
    env: reviewerEnvironment(request),
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
  })

  let stdout = ""
  let stdoutBytes = 0
  let settled = false
  let timer
  const finish = (resolve, reject, error, value) => {
    if (settled) return
    settled = true
    clearTimeout(timer)
    if (error) reject(error)
    else resolve(value)
  }

  const result = new Promise((resolve, reject) => {
    child.once("error", (error) => finish(resolve, reject, error))
    child.stdout.on("data", (chunk) => {
      if (settled) return
      const text = String(chunk)
      stdoutBytes += Buffer.byteLength(text)
      if (stdoutBytes > MAX_REVIEWER_STDOUT_BYTES) {
        child.kill?.("SIGKILL")
        finish(resolve, reject, new Error("reviewer stdout exceeded the safety limit"))
        return
      }
      stdout += text
    })
    child.stderr.on("data", () => {})
    child.once("close", (code, signal) => {
      if (code !== 0) {
        finish(resolve, reject, new Error(`reviewer exited unsuccessfully (${code ?? signal ?? "unknown"})`))
        return
      }
      let decision
      try {
        decision = parseSingleDecisionLine(stdout)
      } catch (error) {
        finish(resolve, reject, error)
        return
      }
      finish(resolve, reject, null, decision)
    })

    timer = setTimeout(() => {
      child.kill?.("SIGKILL")
      finish(resolve, reject, new Error("reviewer timeout"))
    }, config.timeoutMs)

    child.stdin.end(`${JSON.stringify(request)}\n`)
  })

  return result
}

function callDoctor(config, context = {}, spawn = nodeSpawn) {
  const cwd = config.cwd ?? context.directory ?? process.cwd()
  const request = { cwd, workspaceRoot: context.worktree ?? null }
  const child = spawn(config.binaryPath, ["doctor"], {
    cwd,
    env: reviewerEnvironment(request),
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
  })

  let stdout = ""
  let stderr = ""
  let stdoutBytes = 0
  let settled = false
  let timer
  return new Promise((resolve, reject) => {
    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error) reject(error)
      else resolve(value)
    }
    child.once("error", (error) => finish(error))
    child.stdout.on("data", (chunk) => {
      if (settled) return
      const text = String(chunk)
      stdoutBytes += Buffer.byteLength(text)
      if (stdoutBytes > MAX_REVIEWER_STDOUT_BYTES) {
        child.kill?.("SIGKILL")
        finish(new Error("aar doctor stdout exceeded the safety limit"))
        return
      }
      stdout += text
    })
    child.stderr.on("data", (chunk) => {
      if (Buffer.byteLength(stderr) < 4096) stderr += String(chunk)
    })
    child.once("close", (code, signal) => {
      if (code !== 0) {
        const detail = compactReason(stderr)
        finish(new Error(`aar doctor exited unsuccessfully (${code ?? signal ?? "unknown"})${detail ? `: ${detail}` : ""}`))
        return
      }
      try {
        finish(null, parseSingleDecisionLine(stdout))
      } catch (error) {
        finish(error)
      }
    })
    timer = setTimeout(() => {
      child.kill?.("SIGKILL")
      finish(new Error("aar doctor timed out"))
    }, config.timeoutMs)
    child.stdin.end()
  })
}

async function callReviewerAction(subcommand, args, config, spawn = nodeSpawn) {
  const cwd = config.cwd ?? process.cwd()
  const request = { cwd, workspaceRoot: config.workspaceRoot }
  const child = spawn(config.binaryPath, [subcommand, ...args], {
    cwd,
    env: reviewerEnvironment(request),
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
  })

  let settled = false
  let timer
  return await new Promise((resolve, reject) => {
    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error) reject(error)
      else resolve(value)
    }
    child.once("error", (error) => finish(error))
    child.stdout.on("data", () => {})
    child.stderr.on("data", () => {})
    child.once("close", (code, signal) => {
      if (code !== 0) {
        finish(new Error(`${subcommand} exited unsuccessfully (${code ?? signal ?? "unknown"})`))
        return
      }
      finish(null, true)
    })
    timer = setTimeout(() => {
      child.kill("SIGKILL")
      finish(new Error(`${subcommand} timed out`))
    }, config.timeoutMs)
    child.stdin.end()
  })
}

function reviewerEnvironment(request) {
  const env = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: process.env.HOME ?? "",
    PWD: request.cwd,
  }
  if (typeof request.workspaceRoot === "string" && request.workspaceRoot !== "") {
    env.AAR_WORKSPACE_ROOT = request.workspaceRoot
  }
  for (const key of ["AAR_STATE_DIR", "XDG_STATE_HOME", "AAR_CONFIG", "XDG_CONFIG_HOME"]) {
    if (typeof process.env[key] === "string") env[key] = process.env[key]
  }
  const apiKeyEnv = reviewerApiKeyEnv(request)
  if (apiKeyEnv && typeof process.env[apiKeyEnv] === "string") env[apiKeyEnv] = process.env[apiKeyEnv]
  return env
}

function rewriterEnvironment(request) {
  const env = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: process.env.HOME ?? "",
    PWD: request.cwd,
  }
  for (const key of ["XDG_CONFIG_HOME", "XDG_STATE_HOME"]) {
    if (typeof process.env[key] === "string") env[key] = process.env[key]
  }
  return env
}

function reviewerApiKeyEnv(request) {
  const baseCandidates = []
  if (process.env.AAR_CONFIG) baseCandidates.push(process.env.AAR_CONFIG)
  if (process.env.XDG_CONFIG_HOME) baseCandidates.push(path.join(process.env.XDG_CONFIG_HOME, "aar", "config.toml"))
  const home = os.homedir()
  if (process.platform === "darwin") baseCandidates.push(path.join(home, "Library", "Application Support", "aar", "config.toml"))
  else if (process.platform === "win32") baseCandidates.push(path.join(process.env.AppData ?? path.join(home, "AppData", "Roaming"), "aar", "config.toml"))
  else baseCandidates.push(path.join(home, ".config", "aar", "config.toml"))

  let apiKeyEnv = null
  const basePath = baseCandidates.find((candidate) => existsSync(candidate))
  if (basePath) apiKeyEnv = readApiKeyEnv(basePath)
  const projectRoot = request.workspaceRoot || request.cwd
  if (projectRoot) {
    const projectValue = readApiKeyEnv(path.join(projectRoot, ".aar.toml"))
    if (projectValue !== null) apiKeyEnv = projectValue
  }
  return apiKeyEnv
}

function readApiKeyEnv(configPath) {
  if (!existsSync(configPath)) return null
  let source
  try {
    source = readFileSync(configPath, "utf8")
  } catch {
    return null
  }
  let section = ""
  let value = null
  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*/, "").trim()
    const table = line.match(/^\[([^\]]+)\]$/)
    if (table) {
      section = table[1].trim()
      continue
    }
    if (section !== "assessor") continue
    const assignment = line.match(/^apiKeyEnv\s*=\s*["']([^"']*)["']\s*$/)
    if (assignment) value = assignment[1]
  }
  return value
}

function parseSingleDecisionLine(stdout) {
  const lines = stdout.trim().split(/\r?\n/)
  if (lines.length !== 1 || lines[0] === "") throw new Error("reviewer emitted invalid stdout")
  return JSON.parse(lines[0])
}

function validateDecision(decision, request) {
  if (!decision || typeof decision !== "object") throw new Error("reviewer emitted no decision")
  if (decision.schemaVersion !== DECISION_SCHEMA_VERSION) throw new Error("reviewer schemaVersion mismatch")
  if (!Object.hasOwn(decision, "assessment")) throw new Error("reviewer omitted assessment")
  if (!Object.hasOwn(decision, "grantEligible") || typeof decision.grantEligible !== "boolean") {
    throw new Error("reviewer emitted invalid grantEligible")
  }
  if (!Object.hasOwn(decision, "rule") || (decision.rule !== null && typeof decision.rule !== "string")) {
    throw new Error("reviewer emitted invalid rule")
  }
  if (!["allow", "deny", "ask"].includes(decision.decision)) throw new Error("reviewer emitted invalid decision")
  if (typeof decision.reason !== "string" || decision.reason.trim() === "") throw new Error("reviewer emitted no reason")
  if (!SOURCES.has(decision.source)) throw new Error("reviewer emitted invalid source")
  if (decision.decision === "allow" && !ALLOW_SOURCES.has(decision.source)) {
    throw new Error("allow decisions must come from auto-allow, grant, or assessor")
  }
  if (decision.source === "grant" && decision.decision !== "allow") {
    throw new Error("grant source requires an allow decision")
  }
  if (decision.source === "deny-note" && decision.decision !== "deny") {
    throw new Error("deny-note source requires a deny decision")
  }
  if (decision.decision !== "allow" && decision.source === "auto-allow") {
    throw new Error("auto-allow source requires an allow decision")
  }
  if (decision.decision === "allow" && decision.source === "auto-allow" && (typeof decision.rule !== "string" || decision.rule.trim() === "")) {
    throw new Error("auto-allow decisions require a rule")
  }
  if (typeof decision.requestFingerprint !== "string" || decision.requestFingerprint === "") {
    throw new Error("reviewer emitted no request fingerprint")
  }
  const baseFingerprint = fingerprintFor(request)
  if (decision.requestFingerprintBase !== undefined && (typeof decision.requestFingerprintBase !== "string" || decision.requestFingerprintBase !== baseFingerprint)) {
    throw new Error("reviewer request base fingerprint mismatch")
  }
  if (decision.requestFingerprint !== baseFingerprint && decision.requestFingerprintBase !== baseFingerprint) {
    throw new Error("reviewer request fingerprint mismatch")
  }
  if (typeof decision.auditId !== "string" || decision.auditId === "") throw new Error("reviewer emitted no audit id")
}

function fingerprintFor(request) {
  const input = {
    command: request.command,
    cwd: request.cwd,
    workspaceRoot: request.workspaceRoot,
    sessionId: request.session.id,
    intentId: request.session.intentId ?? "",
    policyVersion: "deterministic-v2",
    shellIR: "shellir-v1",
  }
  return createHash("sha256").update(canonicalJSON(input)).digest("hex")
}

function canonicalJSON(value) {
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029")
}

function resolveConfig(options, context) {
  const configured = context?.config?.gate ?? {}
  const binaryPath = options.binaryPath ?? configured.binaryPath ?? process.env.AAR_BINARY_PATH ?? "aar"
  const configuredTools = options.tools ?? configured.tools ?? process.env.AAR_GATE_TOOLS
  const tools = normalizeTools(configuredTools)
  const rawTimeout = options.timeoutMs ?? configured.timeoutMs ?? process.env.AAR_GATE_TIMEOUT_MS
  const timeoutValue = rawTimeout === undefined ? DEFAULT_TIMEOUT_MS : Number(rawTimeout)
  const errors = []
  const configError = options.configError ?? configured.configError
  if (typeof configError === "string" && configError !== "") errors.push(configError)
  if (!Number.isFinite(timeoutValue) || timeoutValue <= 0) errors.push("gate.timeoutMs must be a positive number")
  const timeoutMs = Number.isFinite(timeoutValue) && timeoutValue > 0 ? timeoutValue : DEFAULT_TIMEOUT_MS

  const rawFailureMode = options.onReviewerFailure ?? configured.onReviewerFailure ?? process.env.AAR_GATE_ON_REVIEWER_FAILURE ?? "deny"
  const onReviewerFailure = typeof rawFailureMode === "string" ? rawFailureMode.toLowerCase() : ""
  if (!FAILURE_MODES.has(onReviewerFailure)) errors.push("gate.onReviewerFailure must be deny or passthrough")

  const rawRewriter = options.commandRewriter ?? configured.commandRewriter ?? process.env.AAR_GATE_COMMAND_REWRITER ?? "none"
  const commandRewriter = typeof rawRewriter === "string" ? rawRewriter.toLowerCase() : ""
  if (!REWRITERS.has(commandRewriter)) errors.push("gate.commandRewriter must be none or rtk")

  return {
    binaryPath,
    tools,
    timeoutMs,
    onReviewerFailure: FAILURE_MODES.has(onReviewerFailure) ? onReviewerFailure : "deny",
    commandRewriter: REWRITERS.has(commandRewriter) ? commandRewriter : "none",
    rewriterPath: options.rewriterPath ?? configured.rewriterPath,
    cwd: context?.directory,
    workspaceRoot: context?.worktree,
    configError: errors.length === 0 ? null : errors.join("; "),
  }
}

function normalizeTools(value) {
  if (Array.isArray(value)) return value.map((tool) => String(tool).toLowerCase()).filter(Boolean)
  if (typeof value === "string" && value.trim() !== "") {
    return value.split(",").map((tool) => tool.trim().toLowerCase()).filter(Boolean)
  }
  return DEFAULT_TOOLS
}

function compactReason(reason) {
  return String(reason).replace(/\s+/g, " ").trim()
}

function errorMessage(error) {
  const message = error instanceof Error ? error.message : String(error)
  return compactReason(message || "unknown operational failure")
}

function reviewerFailure(reason) {
  return new Error(`Auto Approve Permissions blocked this command. Reason: ${reason}. The command was not executed.`)
}
