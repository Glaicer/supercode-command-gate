import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  mkdtemp,
  mkdir,
  writeFile,
  readFile,
  access,
  realpath,
} from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { runLifecycle } from "./lifecycle-run.mjs";

const exec = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const opencode =
  process.env.OPENCODE_BIN ?? "/home/glaicer/.opencode/bin/opencode";
const reviewer =
  process.env.AAR_SOURCE ??
  "/home/glaicer/Development/Personal/Supercode-dev/plugins/auto-approval-reviewer";
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function runProbe() {
  const version = (await exec(opencode, ["--version"])).stdout
    .trim()
    .replace(/^opencode v/, "");
  if (version !== "2.0.22")
    throw Error(`Expected OpenCode 2.0.22, got ${version}`);
  const human = process.env.PROOF_HUMAN === "1";
  const root =
    process.env.PROOF_ROOT ??
    (await mkdtemp("/tmp/opencode/command-gate-proof-"));
  if (process.env.PROOF_ROOT) await mkdir(root);
  for (const dir of [
    "home",
    "config/opencode",
    "data",
    "cache",
    "state",
    "project/other",
    "project-two",
    "reviewer-state",
  ]) {
    await mkdir(`${root}/${dir}`, { recursive: true });
  }
  const env = {
    PATH: process.env.PATH,
    LANG: "C.UTF-8",
    SHELL: "/bin/bash",
    HOME: `${root}/home`,
    XDG_CONFIG_HOME: `${root}/config`,
    XDG_DATA_HOME: `${root}/data`,
    XDG_CACHE_HOME: `${root}/cache`,
    XDG_STATE_HOME: `${root}/state`,
    OPENCODE_CONFIG_DIR: `${root}/config/opencode`,
    OPENCODE_SERVER_PASSWORD: "disposable-proof-only",
    PROOF_MODEL_KEY: "dummy-loopback-only",
    AAR_STATE_DIR: `${root}/reviewer-state`,
    AAR_CONFIG: `${root}/aar.toml`,
  };
  await exec("go", ["build", "-o", `${root}/aar`, "./cmd/aar"], {
    cwd: reviewer,
  });
  const reviewerCommit = (
    await exec("git", ["rev-parse", "HEAD"], { cwd: reviewer })
  ).stdout.trim();
  const modelRequests = [];
  const assessorRequests = [];
  const scenarios = [
    {
      name: "assessor-deny",
      command:
        "export PROOF_SUB=$(printf side-effect > assessor-deny.marker); printf '%s' harmless",
      marker: "assessor-deny.marker",
    },
    {
      name: "scanner-empty-deny",
      command: "export PROOF_ASSIGN=scanner-empty-deny.marker",
      marker: "scanner-empty-deny.marker",
      failureFixture: true,
    },
    {
      name: "effective-deny",
      command:
        "export PROOF_SUB=$(printf side-effect > effective-deny.marker); printf '%s' harmless",
      marker: "effective-deny.marker",
    },
    { name: "auto-allow", command: "pwd" },
    {
      name: "assessor-allow",
      command: "touch assessor-allow.marker",
      marker: "assessor-allow.marker",
    },
    {
      name: "scanner-empty-observe",
      command: "export PROOF_ASSIGN=scanner-empty-observe.marker",
      observationOnly: true,
    },
    {
      name: "invocation",
      command:
        'printf \'%s\\n\' "$PWD" "$HOME" "$PROOF_ENV" "$BASH_VERSION" > invocation.marker',
      marker: "other/invocation.marker",
      workdir: `${root}/project/other`,
      observationOnly: true,
    },
    {
      name: "invocation-review",
      command: "touch effective-facts.marker",
      marker: "other/effective-facts.marker",
      workdir: `${root}/project/other`,
    },
    {
      name: "late-shell",
      command: "touch late-shell-observe.marker",
      marker: "late-shell-executed.marker",
      unsupportedComposition: true,
    },
    {
      name: "late-tool",
      command: "touch late-tool-observe.marker",
      marker: "late-tool-executed.marker",
      unsupportedComposition: true,
    },
    {
      name: "child-allow",
      command: "touch child-allow.marker",
      marker: "child-allow.marker",
      child: true,
    },
    {
      name: "other-location-allow",
      command: "touch other-location-allow.marker",
      marker: "other-location-allow.marker",
      directory: `${root}/project-two`,
    },
    {
      name: "approval-cancel",
      command: "touch approval-cancel.marker",
      marker: "approval-cancel.marker",
    },
  ];
  if (human)
    scenarios.push({
      name: "human-once",
      command: "touch human-once.marker",
      marker: "human-once.marker",
    });
  const provider = http.createServer(async (request, response) => {
    try {
      let input = "";
      for await (const chunk of request) input += chunk;
      const body = JSON.parse(input);
      if (!body.stream) {
        assessorRequests.push(body);
        const denial = /assessor-deny\.marker|effective-deny\.marker/.test(
          JSON.stringify(body.messages),
        );
        const risk = {
          category: "critical_data_loss",
          severity: "critical",
          likelihood: "certain",
          reversible: false,
          affectsProtectedPaths: true,
          evidence: "Deterministic fake assessment for harmless denial proof",
        };
        response.writeHead(200, { "content-type": "application/json" });
        const approval =
          /human-once\.marker|approval-cancel\.marker|lifecycle\.marker/.test(
            JSON.stringify(body.messages),
          );
        response.end(
          JSON.stringify({
            choices: [
              {
                message: {
                  content: JSON.stringify({
                    risks: denial
                      ? [risk]
                      : approval
                        ? [
                            {
                              ...risk,
                              likelihood: "possible",
                              reversible: true,
                            },
                          ]
                        : [],
                    uncertainties: [],
                  }),
                },
              },
            ],
          }),
        );
        return;
      }
      const text = JSON.stringify(body.messages);
      const scenario = scenarios.find((item) =>
        new RegExp(`CASE ${item.name}(?![\\w-])`).test(text),
      );
      const toolResults = body.messages
        .filter((message) => message.role === "tool")
        .map((message) => message.content);
      const call = Boolean(scenario && toolResults.length === 0);
      modelRequests.push({ name: scenario?.name, call, toolResults });
      const delta = call
        ? {
            role: "assistant",
            tool_calls: [
              {
                index: 0,
                id: `call_${scenario.name.replaceAll("-", "_")}`,
                type: "function",
                function: {
                  name: "shell",
                  arguments: JSON.stringify({
                    command: scenario.command,
                    ...(scenario.workdir ? { workdir: scenario.workdir } : {}),
                  }),
                },
              },
            ],
          }
        : { role: "assistant", content: "FINISHED" };
      const chunk = (value) => ({
        id: "chatcmpl-proof",
        object: "chat.completion.chunk",
        created: 0,
        model: "probe",
        choices: [{ index: 0, delta: value, finish_reason: null }],
      });
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.end(
        [
          chunk(delta),
          {
            ...chunk({}),
            choices: [
              {
                index: 0,
                delta: {},
                finish_reason: call ? "tool_calls" : "stop",
              },
            ],
          },
        ]
          .map((value) => `data: ${JSON.stringify(value)}\n\n`)
          .join("") + "data: [DONE]\n\n",
      );
    } catch (error) {
      response.writeHead(500);
      response.end(String(error));
    }
  });
  let server;
  let logs = "";
  const stopServer = async () => {
    if (server && server.exitCode === null) {
      const exited = new Promise((resolve) => server.once("close", resolve));
      server.kill("SIGTERM");
      const kill = setTimeout(() => server.kill("SIGKILL"), 3000);
      await exited;
      clearTimeout(kill);
    }
  };
  try {
    await new Promise((resolve) => provider.listen(0, "127.0.0.1", resolve));
    const baseURL = `http://127.0.0.1:${provider.address().port}/v1`;
    await writeFile(
      `${root}/aar.toml`,
      `[assessor]\nmodel = "proof"\nbaseUrl = "${baseURL}"\nonUnavailable = "deny"\n`,
    );
    await writeFile(
      `${root}/config/opencode/cli.json`,
      JSON.stringify({ plugins: [here] }),
    );
    await writeFile(
      `${root}/config/opencode/opencode.json`,
      JSON.stringify({
        plugins: [{ package: here, options: { root } }],
        model: "proof-local/probe",
        providers: {
          "proof-local": {
            name: "Loopback proof",
            env: ["PROOF_MODEL_KEY"],
            package: "@opencode/ai/providers/openai-compatible",
            settings: { baseURL },
            models: {
              probe: {
                name: "Probe",
                limit: { context: 128000, output: 4096 },
              },
            },
          },
        },
        permissions: [{ action: "*", resource: "*", effect: "allow" }],
      }),
    );
    const port = await new Promise((resolve) => {
      const socket = net.createServer();
      socket.listen(0, "127.0.0.1", () => {
        const port = socket.address().port;
        socket.close(() => resolve(port));
      });
    });
    const startServer = () => {
      const child = spawn(
        opencode,
        [
          "serve",
          "--hostname",
          "127.0.0.1",
          "--port",
          String(port),
          "--log-level",
          "debug",
        ],
        { cwd: `${root}/project`, env, stdio: ["ignore", "pipe", "pipe"] },
      );
      child.stdout.on("data", (data) => {
        logs += data;
      });
      child.stderr.on("data", (data) => {
        logs += data;
      });
      child.on("error", (error) => {
        logs += String(error);
      });
      return child;
    };
    server = startServer();
    const api = async (method, route, body, timeout = 10000) => {
      const response = await fetch(`http://127.0.0.1:${port}${route}`, {
        method,
        headers: {
          authorization: `Basic ${Buffer.from("opencode:disposable-proof-only").toString("base64")}`,
          "content-type": "application/json",
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(timeout),
      });
      const text = await response.text();
      if (!response.ok)
        throw Error(`${method} ${route}: ${response.status} ${text}`);
      return text ? JSON.parse(text) : null;
    };
    let ready = false;
    for (let i = 0; i < 100; i++) {
      try {
        await api("GET", "/api/info");
        ready = true;
        break;
      } catch {}
      if (server.exitCode !== null) throw Error(`Server exited: ${logs}`);
      await delay(100);
    }
    if (!ready) throw Error("Isolated server did not start");
    const schema = await api("GET", "/openapi.json");
    await writeFile(`${root}/openapi.json`, JSON.stringify(schema, null, 2));
    const activation = await api("POST", "/api/session", {
      location: { directory: `${root}/project` },
      model: { providerID: "proof-local", id: "probe" },
      title: "Activate proof",
    });
    await api("POST", `/api/session/${activation.data.id}/prompt`, {
      text: "Activate proof",
      resume: false,
    });
    const inventory = await api(
      "GET",
      `/api/plugin?location[directory]=${encodeURIComponent(`${root}/project`)}`,
    );
    const plugins = inventory.data;
    const inventoryOK =
      Array.isArray(plugins) &&
      plugins.some(
        (item) =>
          item.id === "command-gate-contract-proof" &&
          item.state?.status === "active",
      ) &&
      plugins.every(
        (item) =>
          item.source?.type === "builtin" ||
          (item.source?.type === "local" &&
            item.source.path === `${here}/index.ts`),
      );
    if (!inventoryOK)
      throw Error(
        `Unexpected activated inventory: ${JSON.stringify(inventory)}`,
      );
    const initialPending = await api(
      "POST",
      `/api/rpc/command-gate-proof/list?location[directory]=${encodeURIComponent(`${root}/project`)}`,
      { input: {} },
    );
    if (
      !Array.isArray(initialPending.output) ||
      initialPending.output.length !== 0
    )
      throw Error(
        `Unexpected initial pending: ${JSON.stringify(initialPending)}`,
      );
    const launchTui = async (sessionID, basename = "launch-tui.sh") => {
      const quote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;
      const assignments = Object.entries(env)
        .map(([key, value]) => `${key}=${quote(value)}`)
        .join(" ");
      const script = `${root}/${basename}`;
      const manual = basename === "launch-tui.sh";
      const exitNotice = manual
        ? `trap ${quote(`touch ${quote(`${root}/human-tui.closed`)}`)} EXIT\n`
        : "";
      await writeFile(
        script,
        `#!/bin/sh\n${exitNotice}${manual ? "" : "exec "}env -i ${assignments} ${quote(opencode)} --server http://127.0.0.1:${port} --session ${quote(sessionID)} ${quote(`${root}/project`)}\n`,
      );
      return script;
    };
    const cases = [];
    for (const scenario of scenarios) {
      const directory = scenario.directory ?? `${root}/project`;
      const created = await api("POST", "/api/session", {
        location: { directory },
        ...(scenario.child ? { parentID: activation.data.id } : {}),
        model: { providerID: "proof-local", id: "probe" },
        title: `CASE ${scenario.name}`,
      });
      const sessionID = created.data.id;
      if (
        scenario.name === "invocation" ||
        scenario.name === "invocation-review"
      ) {
        await api("PUT", `/api/session/${sessionID}/environment`, {
          variables: {
            PATH: env.PATH,
            HOME: `${root}/home/session-home`,
            SHELL: "/bin/bash",
            PROOF_ENV: "session-only",
            CDPATH: `${root}/project/other`,
          },
        });
      }
      const prior = await readFile(`${root}/events.jsonl`, "utf8");
      if (scenario.name === "human-once") {
        await launchTui(sessionID);
        console.log(
          `Human TUI: sh ${root}/launch-tui.sh; run /proof-approve and choose Allow once, then exit the TUI.`,
        );
      }
      await api("POST", `/api/session/${sessionID}/prompt`, {
        text: `CASE ${scenario.name}`,
      });
      if (scenario.name === "approval-cancel") {
        let pending;
        for (let i = 0; i < 100; i++) {
          pending = (
            await api(
              "POST",
              `/api/rpc/command-gate-proof/list?location[directory]=${encodeURIComponent(directory)}`,
              { input: {} },
            )
          ).output.find((item) => item.call.sessionID === sessionID);
          if (pending) break;
          await delay(50);
        }
        if (!pending)
          throw Error(
            "Cancellation fixture never reached its real Reviewer ask",
          );
        await api("POST", `/api/session/${sessionID}/interrupt?resume=false`);
      }
      await api(
        "POST",
        `/api/experimental/session/${sessionID}/wait`,
        undefined,
        scenario.name === "human-once" ? 605000 : 20000,
      );
      if (scenario.name === "human-once") {
        console.log(
          "Human approval finished; close the test TUI before lifecycle smoke starts.",
        );
        let closed = false;
        for (let i = 0; i < 6000; i++) {
          closed = await access(`${root}/human-tui.closed`)
            .then(() => true)
            .catch(() => false);
          if (closed) break;
          await delay(100);
        }
        if (!closed)
          throw Error(
            "Human TUI did not close; lifecycle isolation cannot be proven",
          );
      }
      const context = await api("GET", `/api/session/${sessionID}/context`);
      const events = (await readFile(`${root}/events.jsonl`, "utf8"))
        .slice(prior.length)
        .trim()
        .split("\n")
        .filter(Boolean)
        .map(JSON.parse);
      const calls = modelRequests.filter((item) => item.name === scenario.name);
      const marker = scenario.marker
        ? await access(`${directory}/${scenario.marker}`)
            .then(() => true)
            .catch(() => false)
        : null;
      cases.push({
        ...scenario,
        sessionID,
        marker,
        markerContent: marker
          ? await readFile(`${directory}/${scenario.marker}`, "utf8")
          : null,
        modelCalls: calls.filter((item) => item.call).length,
        toolResult: calls.flatMap((item) => item.toolResults).join("\n"),
        finished: JSON.stringify(context).includes("FINISHED"),
        events,
        shellEvents: events.filter((item) => item.kind === "shell.before"),
        session: (await api("GET", `/api/session/${sessionID}`)).data,
      });
    }
    const bypassSession = (
      await api("POST", "/api/session", {
        location: { directory: `${root}/project` },
        title: "Human shell API bypass",
      })
    ).data.id;
    const beforeBypass = await readFile(`${root}/events.jsonl`, "utf8");
    await api("POST", `/api/session/${bypassSession}/shell`, {
      command: "touch human-bypass.marker",
    });
    const bypassEvents = (await readFile(`${root}/events.jsonl`, "utf8"))
      .slice(beforeBypass.length)
      .trim()
      .split("\n")
      .filter(Boolean)
      .map(JSON.parse);
    const bypass = {
      marker: await access(`${root}/project/human-bypass.marker`)
        .then(() => true)
        .catch(() => false),
      events: bypassEvents,
    };
    const anchor = cases.find((item) => item.name === "auto-allow").sessionID;
    const restart = async () => {
      await stopServer();
      server = startServer();
      let ready = false;
      for (let i = 0; i < 100; i++) {
        try {
          await api("GET", "/api/info");
          ready = true;
          break;
        } catch {}
        await delay(100);
      }
      if (!ready) throw Error("Own server did not restart");
    };
    const life = await runLifecycle({
      api,
      root,
      env,
      here,
      restart,
      launchTui,
      anchor,
    });
    const setup = (await readFile(`${root}/events.jsonl`, "utf8"))
      .trim()
      .split("\n")
      .map(JSON.parse)
      .find((item) => item.kind === "setup");
    const evidence = {
      root,
      version,
      reviewerCommit,
      inventoryOK,
      inventory,
      setup,
      environmentAPI: schema.paths["/api/session/{sessionID}/environment"],
      cases,
      bypass,
      ...life,
      assessorRequests,
      modelRequests,
      canonicalWorkdir: await realpath(`${root}/project/other`),
    };
    await writeFile(`${root}/results.json`, JSON.stringify(evidence, null, 2));
    console.log(`Proof evidence: ${root}/results.json`);
    return evidence;
  } finally {
    await stopServer();
    provider.closeAllConnections();
    await new Promise((resolve) => provider.close(resolve));
    await writeFile(`${root}/server.log`, logs);
    await writeFile(
      `${root}/provider-requests.json`,
      JSON.stringify({ modelRequests, assessorRequests }, null, 2),
    );
  }
}
