import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  writeFile,
} from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runLifecycleCases } from "./lifecycle-driver.mjs";

const exec = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const gateDir = path.dirname(here);
const opencode =
  process.env.OPENCODE_BIN ?? "/home/glaicer/.opencode/bin/opencode";
const reviewer =
  process.env.AAR_SOURCE ??
  "/home/glaicer/Development/Personal/Supercode-dev/plugins/auto-approval-reviewer";
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const COMPOUND_COMMAND = [
  "GATE_COMPOUND=$(printf '%s' \"compound\"); printf '%s\\n' \"$GATE_COMPOUND\" | tee compound-all.marker >/dev/null; cat <<'GATE_EOF' >> compound-all.marker",
  "heredoc body",
  "GATE_EOF",
].join("\n");

export const COMPOUND_ALLOW_COMMAND =
  "printf '%s\\n' 'compound' | tee compound.marker >/dev/null; pwd";

export const INVOCATION_COMMAND = "touch invocation.marker";

export async function runSeam(options = {}) {
  const version = (await exec(opencode, ["--version"])).stdout
    .trim()
    .replace(/^opencode v/, "");
  if (version !== "2.0.22")
    throw Error(`Expected OpenCode 2.0.22, got ${version}`);
  const root =
    process.env.SEAM_ROOT ??
    (await mkdtemp("/tmp/opencode/command-gate-seam-"));
  if (process.env.SEAM_ROOT) await mkdir(root, { recursive: true });
  const aar = `${root}/aar`;
  await exec("go", ["build", "-o", aar, "./cmd/aar"], { cwd: reviewer });
  const reviewerCommit = (
    await exec("git", ["rev-parse", "HEAD"], { cwd: reviewer })
  ).stdout.trim();

  const assessorRequests = [];
  const modelRequests = [];
  let cases = [];
  const provider = http.createServer(async (request, response) => {
    try {
      let input = "";
      for await (const chunk of request) input += chunk;
      const body = JSON.parse(input);
      if (!body.stream) {
        assessorRequests.push(body);
        const text = JSON.stringify(body.messages);
        const risk = {
          category: "critical_data_loss",
          severity: "critical",
          likelihood: "certain",
          reversible: false,
          affectsProtectedPaths: true,
          evidence: "Deterministic fake assessment for the Command Gate seam",
        };
        const varying = ["denial-allow.marker", "denial-recovery.marker"].find(
          (marker) => text.includes(marker),
        );
        const attempt = varying
          ? assessorRequests.filter((request) =>
              JSON.stringify(request.messages).includes(varying),
            ).length
          : 0;
        const risks = varying
          ? attempt === 1
            ? [{ ...risk, likelihood: "possible", reversible: true }]
            : []
          : text.includes("fixture-deny")
            ? [risk]
            : text.includes("fixture-ask")
              ? [{ ...risk, likelihood: "possible", reversible: true }]
              : [];
        response.writeHead(200, { "content-type": "application/json" });
        response.end(
          JSON.stringify({
            choices: [
              {
                message: {
                  content: JSON.stringify({ risks, uncertainties: [] }),
                },
              },
            ],
          }),
        );
        return;
      }
      const text = JSON.stringify(body.messages);
      const scenario = cases.find((item) =>
        new RegExp(`CASE ${item.name}(?![\\w-])`).test(text),
      );
      const toolResults = body.messages
        .filter((message) => message.role === "tool")
        .map((message) => message.content);
      const call = Boolean(
        scenario?.call &&
        (scenario.remaining !== undefined
          ? scenario.remaining > 0 && text.includes(scenario.token)
          : toolResults.length < (scenario.repeat ?? 1)),
      );
      if (call && scenario.remaining !== undefined) scenario.remaining--;
      modelRequests.push({ name: scenario?.name, call, toolResults });
      const delta = call
        ? {
            role: "assistant",
            tool_calls: [
              {
                index: 0,
                id: `call_${scenario.name.replaceAll("-", "_")}_${modelRequests.length}`,
                type: "function",
                function: {
                  name: scenario.call.tool,
                  arguments: JSON.stringify({
                    ...scenario.call.arguments,
                    ...(scenario.commands
                      ? { command: scenario.commands[toolResults.length] }
                      : {}),
                  }),
                },
              },
            ],
          }
        : { role: "assistant", content: "FINISHED" };
      const chunk = (value) => ({
        id: "chatcmpl-seam",
        object: "chat.completion.chunk",
        created: 0,
        model: "seam",
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
  await new Promise((resolve) => provider.listen(0, "127.0.0.1", resolve));
  const baseURL = `http://127.0.0.1:${provider.address().port}/v1`;

  const evidence = { version, root, reviewerCommit };
  try {
    if (options.lifecycle) {
      const scenario = {
        name: "lifecycle-native",
        remaining: 0,
        call: { tool: "shell", arguments: { command: "bash lifecycle.sh" } },
      };
      cases = [scenario];
      evidence.lifecycle = await boot({
        name: "lifecycle",
        root: `${root}/lifecycle`,
        baseURL,
        aar,
        modelRequests,
        assessorRequests,
        cases: [],
        lifecycle: scenario,
      });
      evidence.assessorRequests = assessorRequests;
      evidence.modelRequests = modelRequests;
      await writeFile(
        `${root}/results.json`,
        JSON.stringify(evidence, null, 2),
      );
      console.log(`Lifecycle evidence: ${root}/results.json`);
      return evidence;
    }
    if (options.approval) {
      const ask = (name, approval, extra = {}) => ({
        name,
        call: {
          tool: "shell",
          arguments: {
            command: `FIXTURE=fixture-ask sh -c 'echo once >> ${name}.marker'`,
          },
        },
        marker: `${name}.marker`,
        approval,
        ...extra,
      });
      cases = [
        ask("ask-once", "once"),
        ask("ask-deny", "deny", { repeat: 2 }),
        ask("ask-dismiss", "dismiss"),
        ask("ask-timeout", "timeout"),
        ask("ask-no-client", null),
        ask("ask-disconnected", "disconnect"),
        ask("ask-cancel", "cancel"),
        ask("ask-invalid", "invalid"),
        ask("ask-consumed", "once", { repeat: 2 }),
        ask("ask-stale-intent", "stale-intent"),
        ask("ask-stale-goal", "stale-goal"),
        ask("ask-reservation", "reservation"),
        {
          ...ask("ask-script", "script"),
          call: { tool: "shell", arguments: { command: "bash mutable.sh" } },
          script: "FIXTURE=fixture-ask touch ask-script.marker\n",
        },
        {
          ...ask("ask-script-deny", "script-deny"),
          call: {
            tool: "shell",
            arguments: { command: "bash denied-script.sh" },
          },
          script: "FIXTURE=fixture-ask touch ask-script-deny.marker\n",
        },
        ask("ask-native-deny", "once"),
      ];
      if (options.trust)
        cases = [
          ask("ask-session", "session", {
            repeat: 2,
            call: { tool: "shell", arguments: { command: "bash trusted.sh" } },
            script:
              "FIXTURE=fixture-ask printf 'once\\n' >> ask-session.marker\n",
          }),
          ask("ask-reconnect", "reconnect"),
        ];
      if (options.human)
        cases = ["human-once", "human-deny"].map((name) => ({
          ...ask(name, null),
          human: true,
          call: {
            tool: "shell",
            arguments: {
              command: `API_TOKEN=demo-secret FIXTURE=fixture-ask sh -c 'echo once >> ${name}.marker'`,
            },
          },
        }));
      if (options.tuiActions || options.humanTrust)
        cases = ["human-once", "human-session", "human-deny"].map((name) => ({
          ...ask(name, null),
          human: true,
          repeat: name === "human-deny" ? 1 : 2,
          call: { tool: "shell", arguments: { command: "bash mutable.sh" } },
          script: `FIXTURE=fixture-ask printf 'once\\n' >> ${name}.marker\n`,
        }));
      if (options.layout) cases = cases.slice(0, 1);
      evidence.approval = await boot({
        name: "approval",
        root: `${root}/approval`,
        baseURL,
        aar,
        modelRequests,
        cases,
        human: options.human,
        layout: options.layout,
        tuiActions: options.tuiActions,
        pluginOptions: { approvalTimeoutMs: options.human ? 600000 : 2000 },
        rules: () => [
          { action: "*", resource: "*", effect: "allow" },
          {
            action: "shell",
            resource: "*ask-native-deny.marker*",
            effect: "deny",
          },
        ],
      });
      if (!options.human && !options.trust) {
        cases = [
          ask("deny-note-failure", "deny", { repeat: 2 }),
          ask("denial-allow", "deny", {
            repeat: 2,
            call: {
              tool: "shell",
              arguments: { command: "touch denial-allow.marker" },
            },
          }),
          ask("denial-recovery", "denial-recovery", {
            repeat: 3,
            call: {
              tool: "shell",
              arguments: { command: "touch denial-recovery.marker" },
            },
            commands: [
              "touch denial-recovery.marker",
              "FIXTURE=fixture-ask touch recovery-b.marker",
              "touch denial-recovery.marker",
            ],
          }),
        ];
        evidence.denialFailure = await boot({
          name: "approval",
          root: `${root}/denial-failure`,
          baseURL,
          aar,
          binaryPath: await writeDenialFixture(`${root}/denial-failure`, aar),
          modelRequests,
          cases,
          pluginOptions: { approvalTimeoutMs: 2000 },
        });
      }
      evidence.assessorRequests = assessorRequests;
      await writeFile(
        `${root}/results.json`,
        JSON.stringify(evidence, null, 2),
      );
      console.log(`Approval evidence: ${root}/results.json`);
      return evidence;
    }
    cases = mainCases(`${root}/main`);
    evidence.main = await boot({
      name: "main",
      root: `${root}/main`,
      baseURL,
      aar,
      modelRequests,
      cases,
      rules: (bootRoot) => [
        { action: "*", resource: "*", effect: "allow" },
        {
          action: "shell",
          resource: "touch native-deny.marker",
          effect: "deny",
        },
        {
          action: "external_directory",
          resource: `${bootRoot}/project-two/*`,
          effect: "deny",
        },
      ],
      bypass: true,
    });
    cases = checkFailureCases();
    evidence.checkFailures = await boot({
      name: "check-failures",
      root: `${root}/check-failures`,
      baseURL,
      binaryPath: await writeCheckFixture(`${root}/check-failures`),
      modelRequests,
      cases,
      pluginOptions: { timeoutMs: 1500 },
    });
    cases = [single("doctorfail")];
    evidence.doctorFail = await boot({
      name: "doctor-fail",
      root: `${root}/doctor-fail`,
      baseURL,
      binaryPath: await writeDoctorFixture(`${root}/doctor-fail`),
      modelRequests,
      cases,
    });
    cases = [single("missing")];
    evidence.missingBinary = await boot({
      name: "missing-binary",
      root: `${root}/missing-binary`,
      baseURL,
      binaryPath: `${root}/missing-binary/definitely-missing-aar`,
      modelRequests,
      cases,
    });
    cases = [single("shcase")];
    evidence.nonBash = await boot({
      name: "non-bash",
      root: `${root}/non-bash`,
      baseURL,
      aar,
      modelRequests,
      cases,
      shell: "/bin/sh",
    });
    evidence.assessorRequests = assessorRequests.map((body) =>
      JSON.stringify(body.messages),
    );
    evidence.modelCalls = modelRequests;
    await writeFile(`${root}/results.json`, JSON.stringify(evidence, null, 2));
    console.log(`Seam evidence: ${root}/results.json`);
    return evidence;
  } finally {
    provider.closeAllConnections();
    await new Promise((resolve) => provider.close(resolve));
  }
}

function single(name) {
  return {
    name,
    call: { tool: "shell", arguments: { command: `touch ${name}.marker` } },
    marker: `${name}.marker`,
    expectMarker: false,
  };
}

function mainCases(root) {
  return [
    {
      name: "auto-allow",
      call: { tool: "shell", arguments: { command: "pwd" } },
      expectOutput: `${root}/project`,
    },
    {
      name: "assessor-allow",
      call: { tool: "shell", arguments: { command: "touch safe.marker" } },
      marker: "safe.marker",
      expectMarker: true,
    },
    {
      name: "assessor-deny",
      call: {
        tool: "shell",
        arguments: {
          command:
            "export PROOF_SUB=$(printf side-effect > denied.marker); printf '%s' fixture-deny",
        },
      },
      marker: "denied.marker",
      expectMarker: false,
    },
    {
      name: "hard-deny",
      call: { tool: "shell", arguments: { command: "printf x > /etc" } },
    },
    {
      name: "compound",
      call: { tool: "shell", arguments: { command: COMPOUND_COMMAND } },
      marker: "compound-all.marker",
      expectMarker: false,
    },
    {
      name: "compound-allow",
      call: { tool: "shell", arguments: { command: COMPOUND_ALLOW_COMMAND } },
      marker: "compound.marker",
      expectMarker: true,
    },
    {
      name: "scanner-empty",
      call: {
        tool: "shell",
        arguments: { command: "export PROOF_SUB=fixture-deny" },
      },
    },
    {
      name: "invocation",
      call: {
        tool: "shell",
        arguments: {
          command: INVOCATION_COMMAND,
          workdir: `${root}/project/other`,
        },
      },
      marker: "other/invocation.marker",
      expectMarker: true,
      environment: {
        PATH: process.env.PATH,
        HOME: `${root}/home/session-home`,
        SHELL: "/bin/bash",
        PROOF_ENV: "session-only-value",
        CDPATH: `${root}/project/other`,
      },
    },
    {
      name: "goal-intent",
      call: { tool: "shell", arguments: { command: "touch goal.marker" } },
      marker: "goal.marker",
      expectMarker: true,
      goal: {
        condition: "Inspect only this disposable project",
        status: "active",
        version: 1,
      },
    },
    {
      name: "ask-refusal",
      call: {
        tool: "shell",
        arguments: { command: "FIXTURE=fixture-ask touch ask.marker" },
      },
      marker: "ask.marker",
      expectMarker: false,
    },
    {
      name: "background-reject",
      call: {
        tool: "shell",
        arguments: { command: "touch background.marker", background: true },
      },
      marker: "background.marker",
      expectMarker: false,
    },
    {
      name: "child-allow",
      call: { tool: "shell", arguments: { command: "touch child.marker" } },
      marker: "child.marker",
      expectMarker: true,
      child: true,
    },
    {
      name: "read-tool",
      call: { tool: "read", arguments: { path: "/etc/hostname" } },
    },
    {
      name: "native-deny",
      call: {
        tool: "shell",
        arguments: { command: "touch native-deny.marker" },
      },
      marker: "native-deny.marker",
      expectMarker: false,
    },
    {
      name: "external-dir",
      call: {
        tool: "shell",
        arguments: {
          command: "touch external.marker",
          workdir: `${root}/project-two`,
        },
      },
      marker: "../project-two/external.marker",
      expectMarker: false,
    },
    {
      name: "other-location",
      call: {
        tool: "shell",
        arguments: { command: "touch other-location.marker" },
      },
      marker: "other-location.marker",
      expectMarker: true,
      directory: `${root}/project-two`,
    },
  ];
}

function checkFailureCases() {
  return [
    "fixture-nonzero",
    "fixture-malformed",
    "fixture-multi",
    "fixture-invalid",
    "fixture-timeout",
  ].map((token) => ({
    name: token,
    call: {
      tool: "shell",
      arguments: { command: `touch ${token}.marker ${token}` },
    },
    marker: `${token}.marker`,
    expectMarker: false,
  }));
}

async function writeCheckFixture(root) {
  await mkdir(root, { recursive: true });
  const file = path.join(root, "fixture-aar");
  const doctor =
    '{"schemaVersion":"aar-doctor-v1","contractVersion":"aar-contract-v1","status":"ok","requestSchemaVersion":"aar-request-v1","decisionSchemaVersion":"aar-decision-v1","reviewerTimeoutMs":500}';
  const invalid =
    '{"schemaVersion":"aar-decision-v1","decision":"maybe","reason":"fixture","source":"assessor","rule":null,"assessment":null,"requestFingerprint":"x","grantEligible":false,"auditId":"aud"}';
  await writeFile(
    file,
    `#!/bin/sh
if [ "$1" = "doctor" ]; then
  printf '%s\\n' '${doctor}'
  exit 0
fi
if [ "$1" = "session-event" ]; then
  printf '%s\\n' '{"status":"invalidated"}'
  exit 0
fi
input=$(cat)
case "$input" in
  *fixture-nonzero*) echo "fixture exploded" >&2; exit 3 ;;
  *fixture-malformed*) printf 'this is not json\\n' ;;
  *fixture-multi*) printf '{"decision":"deny"}\\n{"decision":"allow"}\\n' ;;
  *fixture-invalid*) printf '%s\\n' '${invalid}' ;;
  *fixture-timeout*) sleep 5 ;;
esac
exit 0
`,
  );
  await chmod(file, 0o755);
  return file;
}

async function writeDoctorFixture(root) {
  await mkdir(root, { recursive: true });
  const file = path.join(root, "fixture-aar");
  await writeFile(
    file,
    '#!/bin/sh\nif [ "$1" = "doctor" ]; then echo "fixture doctor failure" >&2; exit 1; fi\nexit 0\n',
  );
  await chmod(file, 0o755);
  return file;
}

async function writeDenialFixture(root, aar) {
  await mkdir(root, { recursive: true });
  const file = `${root}/fixture-aar`;
  await writeFile(
    file,
    `#!/bin/sh\nif [ "$1" = "deny-note" ]; then echo 'deny-note fixture failure' >&2; exit 3; fi\nexec '${aar.replaceAll("'", "'\\''")}' "$@"\n`,
  );
  await chmod(file, 0o755);
  return file;
}

async function boot(config) {
  const root = config.root;
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
    SHELL: config.shell ?? "/bin/bash",
    HOME: `${root}/home`,
    XDG_CONFIG_HOME: `${root}/config`,
    XDG_DATA_HOME: `${root}/data`,
    XDG_CACHE_HOME: `${root}/cache`,
    XDG_STATE_HOME: `${root}/state`,
    OPENCODE_CONFIG_DIR: `${root}/config/opencode`,
    OPENCODE_SERVER_PASSWORD: "disposable-seam-only",
    PROOF_MODEL_KEY: "dummy-loopback-only",
    AAR_STATE_DIR: `${root}/reviewer-state`,
    AAR_CONFIG: `${root}/aar.toml`,
  };
  const binaryPath = config.binaryPath ?? config.aar;
  await writeFile(
    `${root}/aar.toml`,
    `[assessor]\nmodel = "seam"\nbaseUrl = "${config.baseURL}"\nonUnavailable = "deny"\n`,
  );
  await writeFile(
    `${root}/config/opencode/cli.json`,
    JSON.stringify({ plugins: [gateDir] }),
  );
  await writeFile(
    `${root}/config/opencode/opencode.json`,
    JSON.stringify({
      plugins: [
        {
          package: gateDir,
          options: { binaryPath, ...(config.pluginOptions ?? {}) },
        },
        ...(config.lifecycle ? [`${here}/admission-fixture`] : []),
      ],
      model: "proof-local/probe",
      providers: {
        "proof-local": {
          name: "Loopback seam",
          env: ["PROOF_MODEL_KEY"],
          package: "@opencode/ai/providers/openai-compatible",
          settings: { baseURL: config.baseURL },
          models: {
            probe: { name: "Probe", limit: { context: 128000, output: 4096 } },
          },
        },
      },
      permissions: config.rules
        ? config.rules(root)
        : [{ action: "*", resource: "*", effect: "allow" }],
    }),
  );
  const port = await new Promise((resolve) => {
    const socket = net.createServer();
    socket.listen(0, "127.0.0.1", () => {
      const value = socket.address().port;
      socket.close(() => resolve(value));
    });
  });
  let logs = "";
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
    return child;
  };
  let server = startServer();
  const stopServer = async () => {
    if (server.exitCode === null) {
      const exited = new Promise((resolve) => server.once("close", resolve));
      server.kill("SIGTERM");
      const kill = setTimeout(() => server.kill("SIGKILL"), 3000);
      await exited;
      clearTimeout(kill);
    }
  };
  const api = async (method, route, body, timeout = 15000) => {
    const response = await fetch(`http://127.0.0.1:${port}${route}`, {
      method,
      headers: {
        authorization: `Basic ${Buffer.from("opencode:disposable-seam-only").toString("base64")}`,
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
  const waitReady = async () => {
    let ready = false;
    for (let index = 0; index < 100; index++) {
      try {
        await api("GET", "/api/info");
        ready = true;
        break;
      } catch {}
      if (server.exitCode !== null) throw Error(`Server exited: ${logs}`);
      await delay(100);
    }
    if (!ready) throw Error(`Isolated server did not start (${config.name})`);
  };
  const restart = async () => {
    await stopServer();
    server = startServer();
    await waitReady();
  };
  try {
    await waitReady();
    const activation = await api("POST", "/api/session", {
      location: { directory: `${root}/project` },
      model: { providerID: "proof-local", id: "probe" },
      title: `Activate ${config.name}`,
    });
    await api("POST", `/api/session/${activation.data.id}/prompt`, {
      text: `Activate ${config.name}`,
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
          item.id === "command-gate" &&
          item.state?.status === "active" &&
          typeof item.source?.path === "string" &&
          item.source.path.startsWith(gateDir),
      ) &&
      plugins.every(
        (item) =>
          item.source?.type === "builtin" ||
          (item.source?.type === "local" &&
            item.source.path.startsWith(gateDir)),
      );
    let layoutCapture;
    const rpc = async (method, input, directory = `${root}/project`) =>
      (
        await api(
          "POST",
          `/api/rpc/command-gate/${method}?location[directory]=${encodeURIComponent(directory)}`,
          { input },
        )
      ).output;
    const clientID = "integration-adapter";
    const launchLifecycleTui = async (sessionID) => {
      await writeFile(
        `${root}/config/opencode/cli.json`,
        JSON.stringify({
          tabs: { mode: "on" },
          plugins: [gateDir, `${here}/clear-fixture`],
        }),
      );
      const quote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;
      const assignments = Object.entries({ ...env, CLEAR_SMOKE_ROOT: root })
        .map(([key, value]) => `${key}=${quote(value)}`)
        .join(" ");
      const script = `${root}/launch-clear-tui.sh`;
      await writeFile(
        script,
        `#!/bin/sh\nexec env -i ${assignments} ${quote(opencode)} --server http://127.0.0.1:${port} --session ${quote(sessionID)} ${quote(`${root}/project`)}\n`,
      );
      const capture = `${root}/clear-tui.capture`;
      const done = exec("python3", [
        `${here}/lifecycle-tui.py`,
        script,
        capture,
      ]);
      void done.catch(() => {});
      return { done, stop: () => writeFile(`${capture}.stop`, "") };
    };
    const lifecycle = config.lifecycle
      ? await runLifecycleCases({
          api,
          rpc,
          root,
          scenario: config.lifecycle,
          restart,
          launchTui: launchLifecycleTui,
          assessorRequests: config.assessorRequests,
        })
      : null;
    const results = [];
    for (const scenario of config.cases) {
      const directory = scenario.directory ?? `${root}/project`;
      const created = await api("POST", "/api/session", {
        location: { directory },
        ...(scenario.child ? { parentID: activation.data.id } : {}),
        model: { providerID: "proof-local", id: "probe" },
        title: `CASE ${scenario.name}`,
      });
      const sessionID = created.data.id;
      if (scenario.environment) {
        await api("PUT", `/api/session/${sessionID}/environment`, {
          variables: scenario.environment,
        });
      }
      if (scenario.goal) {
        await api("PATCH", `/api/session/${sessionID}`, {
          metadata: { goal: scenario.goal },
        });
      }
      if (scenario.human && results.length === 0) {
        const quote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;
        const assignments = Object.entries(env)
          .map(([key, value]) => `${key}=${quote(value)}`)
          .join(" ");
        await writeFile(
          `${root}/launch-tui.sh`,
          `#!/bin/sh\ntrap ${quote(`touch ${quote(`${root}/human-tui.closed`)}`)} EXIT\nenv -i ${assignments} ${quote(opencode)} --server http://127.0.0.1:${port} --session ${quote(sessionID)} ${quote(directory)}\n`,
        );
        console.log(
          config.tuiActions || config.layout
            ? `Automated TUI fixture: ${root}/launch-tui.sh`
            : `Human TUI: sh ${root}/launch-tui.sh; choose Allow once twice for human-once, Trust exact for session for human-session, then Deny for human-deny, and exit.`,
        );
        if (config.tuiActions)
          layoutCapture = exec("python3", [
            `${here}/tui-actions.py`,
            `${root}/launch-tui.sh`,
            root,
          ]);
        if (config.layout)
          layoutCapture = exec("python3", [
            `${here}/tui-layout.py`,
            `${root}/launch-tui.sh`,
            `${root}/tui-layout.json`,
          ]);
        let connected = false;
        for (let index = 0; index < 6000; index++) {
          const events = parseGateEvents(await collectGateText(root, logs));
          connected = events.some(
            (item) =>
              item.kind === "approval-client" && item.clientID !== clientID,
          );
          if (connected) break;
          await delay(100);
        }
        if (!connected)
          throw Error("Human TUI did not connect within ten minutes");
      }
      if (config.name === "approval" && !config.human) {
        await rpc(scenario.approval ? "connect" : "disconnect", { clientID });
      }
      if (scenario.script)
        await writeFile(
          `${directory}/${scenario.approval === "session" ? "trusted.sh" : scenario.approval === "script-deny" ? "denied-script.sh" : "mutable.sh"}`,
          scenario.script,
        );
      await api("POST", `/api/session/${sessionID}/prompt`, {
        text: `CASE ${scenario.name}`,
      });
      let pending = null;
      let reply = null;
      if (scenario.approval) {
        for (let index = 0; index < 100; index++) {
          const listed = await rpc("list", { clientID, sessionID });
          pending = listed.find((item) => item.sessionID === sessionID);
          if (pending) break;
          await delay(50);
        }
        if (!pending) throw Error(`No pending approval for ${scenario.name}`);
        const input = {
          clientID,
          pendingID: pending.pendingID,
          sessionID,
          messageID: pending.messageID,
          callID: pending.callID,
          intentGeneration: pending.intentGeneration,
          fingerprint: pending.fingerprint,
          decision: ["deny", "dismiss", "session"].includes(scenario.approval)
            ? scenario.approval
            : "once",
        };
        const fetched = await rpc("get", {
          clientID,
          pendingID: pending.pendingID,
        });
        if (JSON.stringify(fetched) !== JSON.stringify(pending))
          throw Error("list/get reconciliation disagrees");
        if (
          scenario.approval === "script" ||
          scenario.approval === "script-deny"
        ) {
          await writeFile(
            `${directory}/${scenario.approval === "script-deny" ? "denied-script.sh" : "mutable.sh"}`,
            scenario.approval === "script-deny"
              ? "FIXTURE=fixture-deny touch ask-script-deny.marker\n"
              : "FIXTURE=fixture-ask printf changed > ask-script.marker\n",
          );
        }
        if (scenario.approval === "stale-intent")
          await api("POST", `/api/session/${sessionID}/prompt`, {
            text: `New intent CASE ${scenario.name}`,
            resume: false,
          });
        if (scenario.approval === "stale-goal")
          await api("PATCH", `/api/session/${sessionID}`, {
            metadata: {
              goal: {
                condition: "Different Goal",
                version: 2,
                status: "active",
              },
            },
          });
        if (scenario.approval === "reservation")
          await exec(
            config.aar,
            ["session-event", "--session", sessionID, "--event", "clear"],
            { cwd: directory, env },
          );
        if (scenario.approval === "reconnect")
          await rpc("connect", { clientID: "replacement-adapter" });
        if (scenario.approval === "disconnect")
          await rpc("disconnect", { clientID });
        else if (scenario.approval === "cancel")
          await api("POST", `/api/session/${sessionID}/interrupt?resume=false`);
        else if (scenario.approval === "invalid") {
          const foreign = await rpc("reply", {
            ...input,
            sessionID: activation.data.id,
          });
          const wrongCall = await rpc("reply", {
            ...input,
            callID: "another-call",
          });
          const wrongFingerprint = await rpc("reply", {
            ...input,
            fingerprint: "stale",
          });
          reply = { foreign, wrongCall, wrongFingerprint };
        } else if (scenario.approval !== "timeout") {
          if (scenario.approval === "denial-recovery") input.decision = "deny";
          reply = await rpc("reply", input);
          reply.duplicate = await rpc("reply", input);
          if (scenario.approval === "denial-recovery") {
            let next;
            for (let index = 0; index < 100; index++) {
              next = (await rpc("list", { clientID, sessionID }))[0];
              if (next) break;
              await delay(50);
            }
            if (!next) throw Error("recovery command did not ask");
            await exec(
              config.aar,
              ["session-event", "--session", sessionID, "--event", "clear"],
              { cwd: directory, env },
            );
            reply.recovery = await rpc("reply", {
              clientID,
              pendingID: next.pendingID,
              sessionID,
              messageID: next.messageID,
              callID: next.callID,
              intentGeneration: next.intentGeneration,
              fingerprint: next.fingerprint,
              decision: "once",
            });
          }
        }
      }
      if (scenario.human) {
        let finished = false;
        for (let index = 0; index < 6050; index++) {
          const context = await api("GET", `/api/session/${sessionID}/context`);
          if (config.tuiActions) {
            const events = parseGateEvents(logs).filter(
              (event) =>
                event.session === sessionID && event.kind === "human-response",
            );
            await writeFile(
              `${root}/ui-progress.json`,
              JSON.stringify({
                name: scenario.name,
                responses: events.length,
                finished: JSON.stringify(context).includes("FINISHED"),
              }),
            );
          }
          if (JSON.stringify(context).includes("FINISHED")) {
            finished = true;
            break;
          }
          await delay(100);
        }
        if (!finished)
          throw Error("Human case did not finish within its bounded deadline");
      } else {
        await api(
          "POST",
          `/api/experimental/session/${sessionID}/wait`,
          undefined,
          scenario.name === "fixture-timeout" ? 30000 : 20000,
        );
      }
      const remaining = scenario.approval
        ? await rpc("list", { clientID, sessionID })
        : [];
      const context = await api("GET", `/api/session/${sessionID}/context`);
      const calls = config.modelRequests.filter(
        (item) => item.name === scenario.name,
      );
      const markerPath = scenario.marker
        ? path.resolve(directory, scenario.marker)
        : null;
      const marker = markerPath
        ? await access(markerPath)
            .then(() => true)
            .catch(() => false)
        : null;
      results.push({
        name: scenario.name,
        sessionID,
        pending,
        reply,
        remaining,
        sideEffect: marker ? await readFile(markerPath, "utf8") : null,
        marker,
        markerContent:
          marker && scenario.name === "invocation"
            ? await readFile(markerPath, "utf8")
            : null,
        expectOutput: scenario.expectOutput ?? null,
        modelCalls: calls.filter((item) => item.call).length,
        toolResult: calls.flatMap((item) => item.toolResults).join("\n"),
        finished: JSON.stringify(context).includes("FINISHED"),
      });
    }
    if (layoutCapture) await layoutCapture;
    if (config.human) {
      console.log(
        "Human-response scenarios finished; please exit the temporary TUI.",
      );
      let closed = false;
      for (let index = 0; index < 6000; index++) {
        closed = await access(`${root}/human-tui.closed`)
          .then(() => true)
          .catch(() => false);
        if (closed) break;
        await delay(100);
      }
      if (!closed) throw Error("Temporary human TUI did not exit");
    }
    let bypass = null;
    if (config.bypass) {
      const bypassSession = (
        await api("POST", "/api/session", {
          location: { directory: `${root}/project` },
          title: "Human shell bypass",
        })
      ).data.id;
      await api("POST", `/api/session/${bypassSession}/shell`, {
        command: "touch human-bypass.marker",
      });
      bypass = {
        sessionID: bypassSession,
        marker: await access(`${root}/project/human-bypass.marker`)
          .then(() => true)
          .catch(() => false),
      };
    }
    const gateEvents = parseGateEvents(await collectGateText(root, logs));
    for (const result of results) {
      result.events = gateEvents.filter(
        (event) => event.session === result.sessionID,
      );
    }
    if (bypass) {
      bypass.events = gateEvents.filter(
        (event) => event.session === bypass.sessionID,
      );
    }
    const auditRecords = [];
    const auditDir = `${root}/reviewer-state/audit`;
    const auditFiles = await readdir(auditDir).catch(() => []);
    for (const file of auditFiles) {
      auditRecords.push(
        JSON.parse(await readFile(path.join(auditDir, file), "utf8")),
      );
    }
    return {
      name: config.name,
      lifecycle,
      inventoryOK,
      canonicalWorkdir: await realpath(`${root}/project/other`).catch(
        () => null,
      ),
      layout: config.layout
        ? JSON.parse(await readFile(`${root}/tui-layout.json`, "utf8"))
        : null,
      project: `${root}/project`,
      cases: results,
      bypass,
      auditRecords,
      gateEvents,
    };
  } finally {
    await stopServer();
    await writeFile(`${root}/server.log`, logs).catch(() => {});
  }
}

async function collectGateText(root, captured) {
  let text = captured;
  const logDir = `${root}/data/opencode/log`;
  const entries = await readdir(logDir).catch(() => []);
  for (const entry of entries) {
    if (!entry.endsWith(".log")) continue;
    text += await readFile(path.join(logDir, entry), "utf8").catch(() => "");
  }
  return text;
}

function parseGateEvents(text) {
  return text
    .split("\n")
    .filter((line) => line.includes("[command-gate] "))
    .map((line) => {
      const rest = line.slice(line.indexOf("[command-gate] ") + 15);
      const space = rest.indexOf(" ");
      const kind = space === -1 ? rest.trim() : rest.slice(0, space);
      const payload = space === -1 ? "" : rest.slice(space + 1);
      let detail = {};
      try {
        detail = JSON.parse(payload);
      } catch {}
      return { kind, ...detail };
    });
}
