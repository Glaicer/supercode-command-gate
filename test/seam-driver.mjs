import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  copyFile,
  realpath,
  writeFile,
} from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runLifecycleCases } from "./lifecycle-driver.mjs";
import { createHash } from "node:crypto";
import { preparePacked } from "./packed-release.mjs";
import { longCommand } from "./long-command.mjs";
import {
  runConcurrencyCases,
  runGrantRaceCases,
} from "./concurrency-driver.mjs";

import { runRtkCases } from "./rtk-driver.mjs";
const exec = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const gateDir = path.dirname(here);
const opencode =
  process.env.OPENCODE_BIN ?? "/home/glaicer/.opencode/bin/opencode";
const reviewer = process.env.AAR_SOURCE ?? path.join(gateDir, "reviewer");
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
  const expectedVersion = options.expectedVersion ?? "2.0.22";
  if (version !== expectedVersion)
    throw Error(`Expected OpenCode ${expectedVersion}, got ${version}`);
  const root =
    process.env.SEAM_ROOT ??
    (await mkdtemp("/tmp/opencode/command-gate-seam-"));
  if (process.env.SEAM_ROOT) await mkdir(root, { recursive: true });
  const aar = `${root}/aar`;
  if (process.env.AAR_PREBUILT) {
    await copyFile(process.env.AAR_PREBUILT, aar);
    await chmod(aar, 0o755);
  } else {
    if (process.env.GATE_PACKED === "1")
      throw Error(
        "Packed smoke requires AAR_PREBUILT pointing to a separate existing Reviewer binary",
      );
    await exec("go", ["build", "-o", aar, "./cmd/aar"], { cwd: reviewer });
  }
  const reviewerCommit = process.env.AAR_PREBUILT
    ? null
    : (
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
        const readableDenial = text.includes("denied.marker");
        if (readableDenial)
          risks.push({
            ...risk,
            category: "network",
            severity: "low",
            likelihood: "possible",
            reversible: true,
            affectsProtectedPaths: false,
            evidence: "The command may contact a remote service",
          });
        const uncertainties = readableDenial
          ? ["Backup availability is unknown", "Remote behavior is unknown"]
          : text.includes("compound-all.marker")
            ? ["Deterministic fixture uncertainty"]
            : [];
        if (text.includes("COMMAND_GATE_LONG_COMMAND")) {
          risks.push({
            ...risk,
            category: "network",
            severity: "low",
            likelihood: "possible",
            reversible: true,
            affectsProtectedPaths: false,
            evidence: "Secondary deterministic fixture risk",
          });
          uncertainties.push("Deterministic fixture uncertainty");
        }
        response.writeHead(200, { "content-type": "application/json" });
        response.end(
          JSON.stringify({
            choices: [
              {
                message: {
                  content: JSON.stringify({ risks, uncertainties }),
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
      if (scenario?.stabilizeMs) await delay(scenario.stabilizeMs);
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
            tool_calls: Array.from(
              { length: scenario.parallel ?? 1 },
              (_, index) => ({
                index,
                id: `call_${scenario.name.replaceAll("-", "_")}_${modelRequests.length}_${index}`,
                type: "function",
                function: {
                  name: scenario.call.tool,
                  arguments: JSON.stringify({
                    ...scenario.call.arguments,
                    ...(scenario.commands
                      ? commandArguments(scenario.commands[toolResults.length])
                      : {}),
                  }),
                },
              }),
            ),
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

  let packed = null;
  const boot = (config) => bootHost({ ...config, packed });
  const evidence = {
    version,
    root,
    reviewerSourceCommit: reviewerCommit,
    reviewerArtifact: process.env.AAR_PREBUILT ?? "built from source",
    reviewerSha256: createHash("sha256")
      .update(await readFile(aar))
      .digest("hex"),
  };
  try {
    packed = process.env.GATE_PACKED === "1" ? await preparePacked(root) : null;
    evidence.packed = packed?.evidence ?? null;
    if (options.diagnostics) {
      evidence.diagnostics = [];
      for (const name of [
        "healthy",
        "missing",
        "passthrough",
        "healthy-passthrough",
      ]) {
        evidence.diagnostics.push(
          await boot({
            name,
            root: `${root}/${name}`,
            baseURL,
            aar,
            modelRequests,
            cases: [],
            diagnostics: true,
            ...(["missing", "passthrough"].includes(name)
              ? { binaryPath: `${root}/missing-aar` }
              : {}),
            ...(name.includes("passthrough")
              ? { pluginOptions: { onReviewerFailure: "passthrough" } }
              : {}),
          }),
        );
      }
      await writeFile(
        `${root}/results.json`,
        JSON.stringify(evidence, null, 2),
      );
      console.log(`Diagnostics evidence: ${root}/results.json`);
      return evidence;
    }
    if (options.integrity) {
      cases = [
        "late-tool",
        "late-background",
        "late-shell-command",
        "late-shell-cwd",
        "late-shell-env",
        "late-shell-replace-env",
        "late-shell-shell",
      ].map((name) => ({
        name,
        call: { tool: "shell", arguments: { command: `touch ${name}.marker` } },
        marker: `${name}.marker`,
      }));
      evidence.integrity = await boot({
        name: "integrity",
        root: `${root}/integrity`,
        baseURL,
        aar,
        modelRequests,
        cases,
        integrity: true,
      });
      cases = [
        {
          name: "early-shell",
          call: {
            tool: "shell",
            arguments: { command: "touch early-shell.marker" },
          },
          marker: "other/early-shell.marker",
        },
        ...["sh", "zsh", "fish", "pwsh"].map((shell) => ({
          name: `unsupported-${shell}`,
          call: {
            tool: "shell",
            arguments: { command: `touch unsupported-${shell}.marker` },
          },
          marker: `unsupported-${shell}.marker`,
        })),
      ];
      evidence.early = await boot({
        name: "early",
        root: `${root}/early`,
        baseURL,
        aar,
        modelRequests,
        cases,
        integrityBefore: true,
      });
      await writeFile(
        `${root}/results.json`,
        JSON.stringify(evidence, null, 2),
      );
      console.log(`Integrity evidence: ${root}/results.json`);
      return evidence;
    }
    if (options.rtk) {
      evidence.rtk = await runRtkCases({
        root,
        boot,
        setCases: (value) => {
          cases = value;
        },
        baseURL,
        aar,
        modelRequests,
      });
      await writeFile(
        `${root}/results.json`,
        JSON.stringify(evidence, null, 2),
      );
      console.log(`RTK evidence: ${root}/results.json`);
      return evidence;
    }
    if (options.grantRaces) {
      cases = [
        "race-goal",
        "race-intent",
        "race-cancel",
        "race-unload",
        "pre-goal",
        "pre-intent",
        "pre-cancel",
        "pre-unload",
      ].map((name) => ({
        name,
        call: { tool: "shell", arguments: { command: `bash ${name}.sh` } },
      }));
      const raceRoot = `${root}/grant-races`;
      await mkdir(raceRoot, { recursive: true });
      const binaryPath = `${raceRoot}/fixture-aar`;
      await writeFile(
        binaryPath,
        `#!/bin/sh
if [ "$1" = "grant" ]; then
  if [ -f '${raceRoot}/'$3.before ]; then
    echo $$ > '${raceRoot}/'$3.ready
    while [ ! -f '${raceRoot}/'$3.release ]; do sleep 0.02; done
    result=$('${aar}' "$@") || exit $?
  else
    result=$('${aar}' "$@") || exit $?
    echo $$ > '${raceRoot}/'$3.ready
    while [ ! -f '${raceRoot}/'$3.release ]; do sleep 0.02; done
  fi
  printf '%s\\n' "$result"
  exit 0
fi
exec '${aar}' "$@"
`,
      );
      await chmod(binaryPath, 0o755);
      evidence.grantRaces = await boot({
        name: "grant-races",
        root: raceRoot,
        baseURL,
        aar,
        binaryPath,
        modelRequests,
        cases: [],
        grantRaces: cases,
        pluginOptions: { approvalMode: "interactive" },
      });
      await writeFile(
        `${root}/results.json`,
        JSON.stringify(evidence, null, 2),
      );
      console.log(`Grant race evidence: ${root}/results.json`);
      return evidence;
    }
    if (options.concurrency) {
      cases = [
        "concurrent-identical",
        "concurrent-main",
        "concurrent-child",
        "concurrent-location",
      ].map((name) => ({
        name,
        parallel: name === "concurrent-identical" ? 2 : 1,
        call: {
          tool: "shell",
          arguments: {
            command: `FIXTURE=fixture-ask printf 'run\\n' >> ${name}.marker`,
          },
        },
      }));
      evidence.concurrency = await boot({
        name: "concurrency",
        root: `${root}/concurrency`,
        baseURL,
        aar,
        modelRequests,
        cases: [],
        concurrency: cases,
        pluginOptions: {
          approvalTimeoutMs: 10000,
          approvalMode: "interactive",
        },
      });
      await writeFile(
        `${root}/results.json`,
        JSON.stringify(evidence, null, 2),
      );
      console.log(`Concurrency evidence: ${root}/results.json`);
      return evidence;
    }
    if (options.nativeUnload) {
      cases = [
        { ...single("native-unload"), unloadPermission: true },
        {
          ...single("native-running"),
          unloadRunning: true,
          call: {
            tool: "shell",
            arguments: {
              command: "printf started > native-running.marker; sleep 10",
            },
          },
        },
      ];
      evidence.nativeUnload = await boot({
        name: "native-unload",
        root: `${root}/native-unload`,
        baseURL,
        aar,
        modelRequests,
        cases,
        rules: () => [
          { action: "*", resource: "*", effect: "allow" },
          {
            action: "shell",
            resource: "*native-unload.marker*",
            effect: "ask",
          },
        ],
      });
      await writeFile(
        `${root}/results.json`,
        JSON.stringify(evidence, null, 2),
      );
      console.log(`Native unload evidence: ${root}/results.json`);
      return evidence;
    }
    if (options.cancellation) {
      cases = ["fixture-timeout", "fixture-cancel", "fixture-unload"].map(
        (name) => ({
          ...single(name),
          cancellation: name !== "fixture-timeout",
          ownedProcess: true,
        }),
      );
      evidence.cancellation = await boot({
        name: "cancellation",
        root: `${root}/cancellation`,
        baseURL,
        binaryPath: await writeCheckFixture(`${root}/cancellation`),
        modelRequests,
        cases,
        pluginOptions: { timeoutMs: 1500 },
      });
      await writeFile(
        `${root}/results.json`,
        JSON.stringify(evidence, null, 2),
      );
      console.log(`Cancellation evidence: ${root}/results.json`);
      return evidence;
    }
    if (options.unavailableAlerts) {
      const bootRoot = `${root}/unavailable`;
      const fixture = `${here}/unavailable-reviewer.mjs`;
      const series = (name, commands) => ({
        stabilizeMs: 200,
        name,
        call: { tool: "shell", arguments: { command: commands[0] } },
        commands,
        repeat: commands.length,
        marker: `${name}.marker`,
        expectMarker: false,
      });
      cases = options.tuiUnavailable
        ? [
            {
              ...series("unavailable-ui", [
                "touch unavailable-ui.marker assessor-fail",
              ]),
              human: true,
            },
          ]
        : [
            series("assessor-outages", [
              "touch assessor-outages.marker assessor-fail",
              "touch assessor-outages.marker assessor-fail",
              "pwd",
              "touch assessor-outages.marker assessor-fail",
              "printf recovery",
              "touch assessor-outages.marker assessor-fail",
            ]),
            series("transport-outages", [
              "touch transport-outages.marker transport-fail",
              "touch transport-outages.marker transport-fail",
              "pwd",
              "touch transport-outages.marker transport-fail",
            ]),
            series("unavailable-ask", [
              "touch unavailable-ask.marker assessor-ask",
            ]),
            series("policy-refusal", [
              "touch policy-refusal.marker policy-deny",
              "touch policy-refusal.marker policy-ask",
            ]),
          ];
      evidence.unavailable = await boot({
        name: "unavailable",
        root: bootRoot,
        baseURL,
        binaryPath: fixture,
        modelRequests,
        cases,
        unavailableAlerts: true,
        tuiUnavailable: options.tuiUnavailable,
        human: options.tuiUnavailable,
      });
      if (!options.tuiUnavailable) {
        const fresh = {
          ...series("fresh-unavailable", [
            "touch fresh-unavailable.marker fresh-fail",
          ]),
          approval: "once",
          adapter: true,
        };
        cases = [fresh];
        evidence.freshUnavailable = await boot({
          name: "fresh-unavailable",
          root: `${root}/fresh-unavailable`,
          baseURL,
          binaryPath: fixture,
          modelRequests,
          cases,
          unavailableAlerts: true,
          adapterControl: true,
          pluginOptions: { approvalMode: "interactive" },
        });
      }
      await writeFile(
        `${root}/results.json`,
        JSON.stringify(evidence, null, 2),
      );
      return evidence;
    }
    if (options.failures) {
      for (const [name, pluginOptions] of [
        ["default", {}],
        ["passthrough", { onReviewerFailure: "passthrough" }],
        ["invalid", { onReviewerFailure: "typo" }],
      ]) {
        cases = checkFailureCases();
        evidence[name] = await boot({
          name,
          root: `${root}/${name}`,
          baseURL,
          binaryPath: await writeCheckFixture(`${root}/${name}`),
          modelRequests,
          cases,
          pluginOptions: { timeoutMs: 1500, ...pluginOptions },
        });
      }
      cases = [
        {
          name: "background-invalid-option",
          call: {
            tool: "shell",
            arguments: {
              command: "touch background-invalid.marker",
              background: true,
            },
          },
          marker: "background-invalid.marker",
          expectMarker: false,
        },
      ];
      evidence.backgroundInvalid = await boot({
        name: "background-invalid",
        root: `${root}/background-invalid`,
        baseURL,
        aar,
        modelRequests,
        cases,
        pluginOptions: { allowBackground: "yes" },
      });
      evidence.startupFailures = [];
      for (const mode of ["deny", "passthrough"]) {
        for (const failure of ["missing", "unhealthy", "contract", "config"]) {
          const name = `${mode}-${failure}`;
          const bootRoot = `${root}/${name}`;
          let binaryPath = `${bootRoot}/missing-aar`;
          if (failure === "unhealthy")
            binaryPath = await writeDoctorFixture(bootRoot);
          if (failure === "contract") {
            binaryPath = await writeCheckFixture(bootRoot);
            const source = await readFile(binaryPath, "utf8");
            await writeFile(
              binaryPath,
              source.replace("aar-contract-v1", "unsupported-contract"),
            );
          }
          cases = [single(name)];
          evidence.startupFailures.push(
            await boot({
              name,
              root: bootRoot,
              baseURL,
              binaryPath,
              modelRequests,
              cases,
              pluginOptions: {
                onReviewerFailure: mode,
                ...(failure === "config" ? { timeoutMs: -1 } : {}),
              },
            }),
          );
        }
      }
      await writeFile(
        `${root}/results.json`,
        JSON.stringify(evidence, null, 2),
      );
      console.log(`Failure evidence: ${root}/results.json`);
      return evidence;
    }
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
        pluginOptions: { approvalMode: "interactive" },
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
      if (options.layout || options.longHuman)
        cases = cases.map((scenario) => ({
          ...scenario,
          call: {
            tool: "shell",
            arguments: { command: longCommand(scenario.marker) },
          },
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
        layoutDismiss: options.layoutDismiss,
        longHuman: options.longHuman,
        tuiActions: options.tuiActions,
        pluginOptions: {
          approvalTimeoutMs: options.human ? 600000 : 2000,
          approvalMode: "interactive",
          ...(options.passthrough ? { onReviewerFailure: "passthrough" } : {}),
        },
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
          pluginOptions: {
            approvalTimeoutMs: 2000,
            approvalMode: "interactive",
          },
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
    if (options.neverAsk) {
      cases = ["never-ask-adapter", "never-ask-no-adapter"].map((name) => ({
        name,
        call: {
          tool: "shell",
          arguments: {
            command: `FIXTURE=fixture-ask sh -c 'echo once >> ${name}-denied.marker'`,
          },
        },
        marker: `${name}-denied.marker`,
        adapter: name === "never-ask-adapter",
        watchPending: true,
        repeat: 2,
      }));
      evidence.neverAsk = await boot({
        name: "never-ask",
        root: `${root}/never-ask`,
        baseURL,
        aar,
        modelRequests,
        cases,
        adapterControl: true,
        pluginOptions: { onReviewerFailure: "passthrough" },
      });
      evidence.assessorRequests = assessorRequests;
      await writeFile(
        `${root}/results.json`,
        JSON.stringify(evidence, null, 2),
      );
      console.log(`Never-ask evidence: ${root}/results.json`);
      return evidence;
    }
    if (options.backgroundGrants) {
      const sequence = (name, first, second) => ({
        name,
        call: { tool: "shell", arguments: { command: `bash ${name}.sh` } },
        commands: [
          { command: `bash ${name}.sh`, background: first },
          { command: `bash ${name}.sh`, background: second },
        ],
        script: `FIXTURE=fixture-ask printf 'once\n' >> ${name}.marker\n`,
        scriptFile: `${name}.sh`,
        marker: `${name}.marker`,
        repeat: 2,
      });
      cases = [
        {
          name: "bg-ask-once",
          call: {
            tool: "shell",
            arguments: { command: "bash bg-ask-once.sh", background: true },
          },
          script: "FIXTURE=fixture-ask printf 'once\n' >> bg-ask-once.marker\n",
          scriptFile: "bg-ask-once.sh",
          marker: "bg-ask-once.marker",
          approval: "once",
        },
        { ...sequence("bg-trust-bg", true, true), approval: "session" },
        {
          ...sequence("bg-trust-fg-asks", true, false),
          approval: "multi",
          replies: ["session", "deny"],
        },
        {
          ...sequence("fg-trust-bg-asks", false, true),
          approval: "multi",
          replies: ["session", "deny"],
        },
      ];
      evidence.backgroundInteractive = await boot({
        name: "approval",
        root: `${root}/background-interactive`,
        baseURL,
        aar,
        modelRequests,
        cases,
        pluginOptions: {
          allowBackground: true,
          approvalMode: "interactive",
          approvalTimeoutMs: 2000,
        },
      });
      cases = [
        {
          name: "bg-never-ask",
          call: {
            tool: "shell",
            arguments: {
              command:
                "FIXTURE=fixture-ask sh -c 'echo once >> bg-never-ask.marker'",
              background: true,
            },
          },
          marker: "bg-never-ask.marker",
          adapter: true,
          watchPending: true,
          repeat: 2,
        },
      ];
      evidence.backgroundNeverAsk = await boot({
        name: "background-never-ask",
        root: `${root}/background-never-ask`,
        baseURL,
        aar,
        modelRequests,
        cases,
        adapterControl: true,
        pluginOptions: { allowBackground: true },
      });
      cases = [
        {
          name: "bg-passthrough",
          call: {
            tool: "shell",
            arguments: {
              command: "touch bg-passthrough.marker fixture-nonzero",
              background: true,
            },
          },
          marker: "bg-passthrough.marker",
          expectMarker: true,
        },
      ];
      evidence.backgroundPassthrough = await boot({
        name: "background-passthrough",
        root: `${root}/background-passthrough`,
        baseURL,
        binaryPath: await writeCheckFixture(`${root}/background-passthrough`),
        modelRequests,
        cases,
        pluginOptions: {
          allowBackground: true,
          onReviewerFailure: "passthrough",
          timeoutMs: 1500,
        },
      });
      cases = [
        {
          name: "bg-default-reject",
          call: {
            tool: "shell",
            arguments: {
              command: "touch bg-default-reject.marker",
              background: true,
            },
          },
          marker: "bg-default-reject.marker",
          expectMarker: false,
        },
      ];
      evidence.backgroundDefault = await boot({
        name: "background-default",
        root: `${root}/background-default`,
        baseURL,
        aar,
        modelRequests,
        cases,
      });
      evidence.assessorRequests = assessorRequests.map((body) =>
        JSON.stringify(body.messages),
      );
      await writeFile(
        `${root}/results.json`,
        JSON.stringify(evidence, null, 2),
      );
      console.log(`Background grants evidence: ${root}/results.json`);
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
    cases = [
      {
        name: "background-allow",
        call: {
          tool: "shell",
          arguments: {
            command: "touch background-allow.marker",
            background: true,
          },
        },
        marker: "background-allow.marker",
        expectMarker: true,
      },
      {
        name: "background-deny",
        call: {
          tool: "shell",
          arguments: {
            command: "printf '%s' fixture-deny; touch background-deny.marker",
            background: true,
          },
        },
        marker: "background-deny.marker",
        expectMarker: false,
      },
      {
        name: "foreground-unchanged",
        call: {
          tool: "shell",
          arguments: { command: "touch foreground-unchanged.marker" },
        },
        marker: "foreground-unchanged.marker",
        expectMarker: true,
      },
    ];
    evidence.background = await boot({
      name: "background",
      root: `${root}/background`,
      baseURL,
      aar,
      modelRequests,
      cases,
      pluginOptions: { allowBackground: true },
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
    await packed?.close();
  }
}

async function probeMarker(markerPath, waitMs) {
  const deadline = Date.now() + waitMs;
  for (;;) {
    if (
      await access(markerPath)
        .then(() => true)
        .catch(() => false)
    )
      return true;
    if (Date.now() >= deadline) return false;
    await delay(50);
  }
}

function commandArguments(step) {
  return typeof step === "string" ? { command: step } : (step ?? {});
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
    "fixture-schema",
    "fixture-fingerprint",
    "fixture-source",
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
  *fixture-schema*) printf '%s\\n' '${invalid.replace("aar-decision-v1", "wrong-schema")}' ;;
  *fixture-fingerprint*) printf '%s\\n' '${invalid.replace('"maybe"', '"allow"')}' ;;
  *fixture-source*) printf '%s\\n' '${invalid.replace('"maybe"', '"allow"').replace('"assessor"', '"unavailable"')}' ;;
  *fixture-timeout*|*fixture-cancel*|*fixture-unload*)
    case "$input" in *fixture-cancel*) token=fixture-cancel ;; *fixture-unload*) token=fixture-unload ;; *) token=fixture-timeout ;; esac
    trap '' TERM
    echo $$ > '${root}/'$token.pid
    sleep 5
    touch '${root}/'$token.late
    ;;
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

async function bootHost(config) {
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
    XDG_CACHE_HOME: config.packed?.cache ?? `${root}/cache`,
    ...(config.packed
      ? { NPM_CONFIG_CACHE: `${config.packed.cache}/npm` }
      : {}),
    XDG_STATE_HOME: `${root}/state`,
    OPENCODE_CONFIG_DIR: `${root}/config/opencode`,
    OPENCODE_SERVER_PASSWORD: "disposable-seam-only",
    PROOF_MODEL_KEY: "dummy-loopback-only",
    AAR_STATE_DIR: `${root}/reviewer-state`,
    AAR_CONFIG: `${root}/aar.toml`,
  };
  const target = config.packed?.target ?? gateDir;
  const installation = config.packed
    ? await config.packed.install(opencode, env, `${root}/project`)
    : null;
  const binaryPath = config.binaryPath ?? config.aar;
  await writeFile(
    `${root}/aar.toml`,
    `[policy]\nprofile = "balanced"\n[assessor]\nmodel = "seam"\nbaseUrl = "${config.baseURL}"\nonUnavailable = "deny"\n`,
  );
  await writeFile(
    `${root}/config/opencode/cli.json`,
    JSON.stringify({ plugins: [target] }),
  );
  await writeFile(
    `${root}/config/opencode/opencode.json`,
    JSON.stringify({
      plugins: [
        ...(config.integrityBefore ? [`${here}/integrity-fixture`] : []),
        {
          package: target,
          options: { binaryPath, ...(config.pluginOptions ?? {}) },
        },
        ...(config.lifecycle ? [`${here}/admission-fixture`] : []),
        ...(config.integrity ? [`${here}/integrity-fixture`] : []),
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
          item.features?.tui === true &&
          (config.packed
            ? item.source?.type === "package" &&
              item.source.target === target &&
              item.source.version === config.packed.evidence.version
            : typeof item.source?.path === "string" &&
              item.source.path.startsWith(gateDir)),
      ) &&
      plugins.every(
        (item) =>
          item.source?.type === "builtin" ||
          (item.source?.type === "package" && item.source.target === target) ||
          (item.source?.type === "local" &&
            [
              gateDir,
              `${here}/admission-fixture`,
              `${here}/integrity-fixture`,
            ].some((directory) => item.source.path.startsWith(directory))),
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
    if (config.diagnostics) {
      const quote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;
      const assignments = Object.entries(env)
        .map(([key, value]) => `${key}=${quote(value)}`)
        .join(" ");
      const launcher = `${root}/launch-diagnostics.sh`;
      await writeFile(
        launcher,
        `#!/bin/sh\nexec env -i ${assignments} ${quote(opencode)} --server http://127.0.0.1:${port} --session ${quote(activation.data.id)} ${quote(`${root}/project`)}\n`,
      );
      await exec(
        "python3",
        [`${here}/tui-diagnostics.py`, launcher, `${root}/diagnostics.capture`],
        { timeout: 25000 },
      );
    }
    const launchLifecycleTui = async (sessionID) => {
      await writeFile(
        `${root}/config/opencode/cli.json`,
        JSON.stringify({
          tabs: { mode: "on" },
          plugins: [target, `${here}/clear-fixture`],
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
    const concurrency = config.concurrency
      ? await runConcurrencyCases({ api, rpc, root, cases: config.concurrency })
      : null;
    const grantRaces = config.grantRaces
      ? await runGrantRaceCases({ api, rpc, root, cases: config.grantRaces })
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
          `#!/bin/sh\ntrap ${quote(`touch ${quote(`${root}/human-tui.closed`)}`)} EXIT\n${config.longHuman ? `stty size > ${quote(`${root}/human-terminal-size.txt`)}\n` : ""}env -i ${assignments} ${quote(opencode)} --server http://127.0.0.1:${port} --session ${quote(sessionID)} ${quote(directory)}\n`,
        );
        console.log(
          config.tuiActions || config.layout || config.tuiUnavailable
            ? `Automated TUI fixture: ${root}/launch-tui.sh`
            : config.longHuman
              ? `Human long-command TUI: sh ${root}/launch-tui.sh; inspect Details and every Full command page, return using Actions (Escape dismisses the entire request), select Allow once on the FIRST request, then Deny on the SECOND request, and exit.`
              : `Human TUI: sh ${root}/launch-tui.sh; choose Allow once twice for human-once, Trust exact for session for human-session, then Deny for human-deny, and exit.`,
        );
        if (config.tuiUnavailable)
          layoutCapture = exec("python3", [
            `${here}/tui-unavailable.py`,
            `${root}/launch-tui.sh`,
            root,
          ]);
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
            ...(config.layoutDismiss ? ["dismiss"] : []),
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
      if (config.adapterControl) {
        await rpc(scenario.adapter ? "connect" : "disconnect", { clientID });
      }
      if (scenario.script)
        await writeFile(
          `${directory}/${scenario.scriptFile ?? (scenario.approval === "session" ? "trusted.sh" : scenario.approval === "script-deny" ? "denied-script.sh" : "mutable.sh")}`,
          scenario.script,
        );
      if (config.longHuman || config.layout)
        await writeFile(
          `${root}/${scenario.name}.command`,
          scenario.call.arguments.command,
        );
      let maxPending = 0;
      const pendingWatch = scenario.watchPending
        ? setInterval(() => {
            rpc("list", { clientID, sessionID })
              .then((listed) => {
                maxPending = Math.max(maxPending, listed.length);
              })
              .catch(() => {});
          }, 25)
        : null;
      await api("POST", `/api/session/${sessionID}/prompt`, {
        text: `CASE ${scenario.name}`,
      });
      if (scenario.unloadPermission) {
        let permission;
        for (let index = 0; index < 150; index++) {
          permission = (
            await api("GET", `/api/session/${sessionID}/permission`)
          ).data[0];
          if (permission) break;
          await delay(20);
        }
        if (!permission)
          throw Error("Native permission did not follow Reviewer allow");
        await api("POST", "/api/location/reload");
        await api(
          "POST",
          `/api/session/${sessionID}/permission/${permission.id}/reply`,
          { decision: "once" },
        ).catch(() => null);
      }
      if (scenario.unloadRunning) {
        let started = false;
        for (let index = 0; index < 150; index++) {
          started = await access(`${directory}/${scenario.marker}`)
            .then(() => true)
            .catch(() => false);
          if (started) break;
          await delay(20);
        }
        if (!started) throw Error("Native shell did not start before unload");
        await api("POST", "/api/location/reload");
      }
      if (scenario.cancellation) {
        let pid;
        for (let index = 0; index < 100; index++) {
          pid = await readFile(`${root}/${scenario.name}.pid`, "utf8").catch(
            () => null,
          );
          if (pid) break;
          await delay(10);
        }
        if (!pid) throw Error("Reviewer did not start before cancellation");
        if (scenario.name === "fixture-unload")
          await api("POST", "/api/location/reload");
        else
          await api("POST", `/api/session/${sessionID}/interrupt?resume=false`);
      }
      let pending = null;
      let reply = null;
      let pendings = null;
      if (scenario.approval === "multi") {
        pendings = [];
        reply = [];
        for (const decision of scenario.replies) {
          let next = null;
          for (let index = 0; index < 100; index++) {
            const listed = await rpc("list", { clientID, sessionID });
            next = listed.find((item) => item.sessionID === sessionID);
            if (next) break;
            await delay(50);
          }
          if (!next)
            throw Error(
              `No pending approval for ${scenario.name} (${decision})`,
            );
          pendings.push(next);
          reply.push(
            await rpc("reply", {
              clientID,
              pendingID: next.pendingID,
              sessionID,
              messageID: next.messageID,
              callID: next.callID,
              intentGeneration: next.intentGeneration,
              fingerprint: next.fingerprint,
              decision,
            }),
          );
        }
        pending = pendings[0];
      }
      if (scenario.approval && scenario.approval !== "multi") {
        for (let index = 0; index < 100; index++) {
          const listed = await rpc("list", { clientID, sessionID });
          pending = listed.find((item) => item.sessionID === sessionID);
          if (pending) break;
          await delay(50);
        }
        if (!pending)
          throw Error(
            `No pending approval for ${scenario.name}: ${JSON.stringify(await api("GET", `/api/session/${sessionID}/context`))}`,
          );
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
      if (pendingWatch) clearInterval(pendingWatch);
      const remaining =
        scenario.approval || scenario.watchPending
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
        ? await probeMarker(
            markerPath,
            scenario.call?.arguments?.background === true ? 5000 : 0,
          )
        : null;
      let ownedRunning = null;
      let lateEffect = null;
      if (scenario.ownedProcess) {
        const pid = (
          await readFile(`${root}/${scenario.name}.pid`, "utf8")
        ).trim();
        ownedRunning = await readFile(`/proc/${pid}/stat`, "utf8")
          .then((stat) => !/\) Z /.test(stat))
          .catch(() => false);
        await delay(5200);
        lateEffect = await access(`${root}/${scenario.name}.late`)
          .then(() => true)
          .catch(() => false);
      }
      results.push({
        name: scenario.name,
        command: scenario.call?.arguments.command ?? null,
        ownedRunning,
        lateEffect,
        sessionID,
        pending,
        pendings,
        reply,
        remaining,
        ...(config.unavailableAlerts
          ? { alerts: await rpc("alerts", { sessionID }) }
          : {}),
        maxPending: scenario.watchPending ? maxPending : null,
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
        ...(scenario.ownedProcess || scenario.unloadPermission
          ? { context }
          : {}),
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
      concurrency,
      grantRaces,
      inventoryOK,
      installation,
      inventory: plugins,
      diagnostics: config.diagnostics
        ? await readFile(`${root}/diagnostics.capture`, "utf8")
        : null,
      status: await rpc("status", {}),
      canonicalWorkdir: await realpath(`${root}/project/other`).catch(
        () => null,
      ),
      unavailableUI: config.tuiUnavailable
        ? JSON.parse(await readFile(`${root}/unavailable-ui.json`, "utf8"))
        : null,
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
