const http = require("node:http")
const fs = require("node:fs")

const port = Number(process.env.FAKE_LLM_PORT)
const command = process.env.FAKE_LLM_COMMAND ?? "pwd"
const logPath = process.env.FAKE_LLM_LOG

function writeLog(value) {
  if (!logPath) return
  fs.appendFileSync(logPath, `${JSON.stringify(value)}\n`)
}

function completion(messages) {
  const plan = responsePlan(messages)
  if (plan.done) {
    return {
      role: "assistant",
      content: "FINISHED",
      finish_reason: "stop",
    }
  }
  return {
    role: "assistant",
    content: null,
    tool_calls: [toolCall(plan.tool, plan.fingerprint, plan.id)],
    finish_reason: "tool_calls",
  }
}

function toolCall(tool, fingerprint, id = "call_probe_bash_1") {
  const call = {
    id,
    type: "function",
    function: {
      name: tool,
      arguments: JSON.stringify(tool === "request_command_approval"
        ? { command, requestFingerprint: fingerprint, purpose: "Approve the requested integration command" }
        : { command, description: "integration probe" }),
    },
  }
  call.index = 0
  return call
}

function responsePlan(messages) {
  const results = messages.filter((message) => message.role === "tool").map((message) => String(message.content ?? ""))
  if (process.env.FAKE_LLM_FLOW !== "approval-roundtrip") {
    return results.length > 0 ? { done: true, tool: "bash" } : { done: false, tool: "bash", id: "call_probe_bash_1" }
  }
  if (results.length === 0) return { done: false, tool: "bash", id: "call_probe_bash_1" }
  const approvalRecorded = results.some((result) =>
    result.includes("Command approval recorded") || result.includes("Approval recorded for this exact command"))
  const blocked = results.find((result) => result.match(/requestFingerprint\s+"([^"]+)"/))
  if (blocked && !approvalRecorded) {
    const fingerprint = blocked.match(/requestFingerprint\s+"([^"]+)"/)?.[1]
    return { done: false, tool: "request_command_approval", fingerprint, id: "call_probe_approval" }
  }
  if (approvalRecorded) {
    const approvalIndex = results.findIndex((result) =>
      result.includes("Command approval recorded") || result.includes("Approval recorded for this exact command"))
    if (results.length === approvalIndex + 1) return { done: false, tool: "bash", id: "call_probe_bash_2" }
  }
  return { done: true, tool: "bash" }
}

function sendJSON(response, value) {
  const body = JSON.stringify(value)
  response.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) })
  response.end(body)
}

function sendStream(response, messages) {
  response.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" })
  const message = completion(messages)
  const plan = responsePlan(messages)
  const deltas = plan.done
    ? [{ role: "assistant" }, { content: message.content }, {}]
    : [
        { role: "assistant" },
        {
          tool_calls: [toolCall(plan.tool, plan.fingerprint, plan.id)],
        },
        {},
      ]
  for (const [index, delta] of deltas.entries()) {
    const chunk = {
      id: "chatcmpl-probe",
      object: "chat.completion.chunk",
      created: Math.floor(Date.now() / 1000),
      model: "probe-model",
      choices: [{ index: 0, delta, finish_reason: index === deltas.length - 1 ? message.finish_reason : null }],
    }
    response.write(`data: ${JSON.stringify(chunk)}\n\n`)
  }
  response.end("data: [DONE]\n\n")
}

const server = http.createServer((request, response) => {
  if (request.method === "GET" && request.url?.startsWith("/v1/models")) {
    sendJSON(response, { object: "list", data: [{ id: "probe-model", object: "model", created: 0, owned_by: "fake" }] })
    return
  }
  if (request.method !== "POST") {
    sendJSON(response, { ok: true })
    return
  }

  let body = ""
  request.setEncoding("utf8")
  request.on("data", (chunk) => { body += chunk })
  request.on("end", () => {
    const payload = JSON.parse(body || "{}")
    const messages = payload.messages ?? []
    const plan = responsePlan(messages)
    writeLog({ done: plan.done, tool: plan.tool, toolResults: messages.filter((message) => message.role === "tool").map((message) => message.content) })
    const responseBody = {
      id: "chatcmpl-probe",
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: "probe-model",
      choices: [{ index: 0, message: completion(messages), finish_reason: completion(messages).finish_reason }],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    }
    if (payload.stream) sendStream(response, messages)
    else sendJSON(response, responseBody)
  })
})

server.listen(port, "127.0.0.1")
