import { createReadStream } from "node:fs"
import { createInterface } from "node:readline"
import { spawn } from "node:child_process"
import path from "node:path"
import { fileURLToPath } from "node:url"

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const corpusPath = process.env.AAR_CORPUS_PATH ?? path.resolve(repositoryRoot, "../../.scratch/029-auto-approval-reviewer/cmds.txt")
const binaryPath = process.env.AAR_BINARY_PATH ?? "aar"
const sampleStride = Math.max(1, Number(process.env.AAR_CORPUS_STRIDE ?? 179))
const stateDirectory = process.env.AAR_STATE_DIR ?? path.join("/tmp", "aar-corpus-state")

const samples = []
let totalLines = 0
let validCommands = 0
let invalidLines = 0

const input = createInterface({
  input: createReadStream(corpusPath),
  crlfDelay: Infinity,
})

for await (const line of input) {
  totalLines++
  let command
  try {
    command = JSON.parse(line)
  } catch {
    invalidLines++
    continue
  }
  if (typeof command !== "string") {
    invalidLines++
    continue
  }
  validCommands++
  if (validCommands % sampleStride === 0) {
    samples.push({ lineNumber: totalLines, command })
  }
}

const decisions = await Promise.all(samples.map(({ lineNumber, command }) => review(lineNumber, command)))
const allowed = decisions.filter((decision) => decision.decision === "allow").length
const invalidDecisions = decisions.filter((decision) => decision.invalid).length

console.log(JSON.stringify({
  corpusPath,
  binaryPath,
  corpusLines: totalLines,
  validCommands,
  invalidLines,
  sampled: samples.length,
  allowed,
  invalidDecisions,
  autoAllowRate: samples.length === 0 ? 0 : allowed / samples.length,
}, null, 2))

async function review(lineNumber, command) {
  const cwd = repositoryRoot
  const request = {
    schemaVersion: "aar-request-v1",
    command,
    cwd,
    workspaceRoot: cwd,
    env: { PWD: cwd },
    session: { id: `corpus-${lineNumber}`, host: "corpus", intentId: null },
    intent: { goal: null, latestUserRequest: null, purpose: null },
  }

  return new Promise((resolve, reject) => {
    const child = spawn(binaryPath, ["check"], {
      cwd,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: process.env.HOME ?? "", AAR_STATE_DIR: stateDirectory },
      stdio: ["pipe", "pipe", "pipe"],
    })
    let stdout = ""
    let stderr = ""
    child.stdout.on("data", (chunk) => { stdout += String(chunk) })
    child.stderr.on("data", (chunk) => { stderr += String(chunk) })
    child.once("error", reject)
    child.once("close", (code) => {
      if (code !== 0) {
        reject(new Error(`aar exited with ${code} for corpus line ${lineNumber}: ${stderr.trim()}`))
        return
      }
      try {
        const lines = stdout.trim().split(/\r?\n/)
        if (lines.length !== 1 || lines[0] === "") throw new Error("invalid reviewer output")
        resolve(JSON.parse(lines[0]))
      } catch (error) {
        resolve({ invalid: true, error: String(error) })
      }
    })
    child.stdin.end(`${JSON.stringify(request)}\n`)
  })
}
