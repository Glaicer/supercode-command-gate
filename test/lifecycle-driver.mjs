import { readFile, writeFile, mkdir, symlink, rename } from "node:fs/promises";

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function runLifecycleCases({
  api,
  rpc: scopedRpc,
  root,
  scenario,
  restart,
  launchTui,
  assessorRequests,
}) {
  let directory = `${root}/project`;
  const rpc = (method, input) => scopedRpc(method, input, directory);
  const clientID = "lifecycle-adapter";
  await rpc("connect", { clientID });
  let sessionID = (
    await api("POST", "/api/session", {
      location: { directory },
      model: { providerID: "proof-local", id: "probe" },
      title: "Lifecycle native calls",
    })
  ).data.id;
  const admitted = await api("POST", `/api/session/${sessionID}/prompt`, {
    id: "msg_z",
    text: "CASE lifecycle-native — late-admission-original",
    resume: false,
  });
  await writeFile(
    `${directory}/lifecycle.sh`,
    "FIXTURE=fixture-ask printf 'run\\n' >> lifecycle.marker\n",
  );
  const calls = [];
  const run = async (name, decision = "dismiss", boundary) => {
    await rpc("connect", { clientID });
    const assessorStart = assessorRequests.length;
    const markerDirectory = scenario.call.arguments.workdir ?? directory;
    const sideEffectBefore = await readFile(
      `${markerDirectory}/lifecycle.marker`,
      "utf8",
    ).catch(() => "");
    scenario.remaining = 1;
    scenario.token = `TURN_${calls.length}_END`;
    await api("POST", `/api/session/${sessionID}/synthetic`, {
      text: `CASE lifecycle-native — synthetic continuation ${scenario.token}, not admission`,
    });
    let pending;
    for (let index = 0; index < 60; index++) {
      pending = (await rpc("list", { clientID, sessionID }))[0];
      if (pending) break;
      if (index > 3 && scenario.remaining === 0) {
        const context = await api("GET", `/api/session/${sessionID}/context`);
        const last = context.data?.at(-1);
        if (last?.type === "idle") break;
      }
      await delay(50);
    }
    let reply;
    let staleRemaining;
    let sessionAttempt;
    if (pending) {
      if (boundary) {
        await boundary();
        staleRemaining = await rpc("list", { clientID, sessionID });
      }
      if (decision === "reject-session") {
        sessionAttempt = await rpc("reply", {
          clientID,
          pendingID: pending.pendingID,
          sessionID,
          messageID: pending.messageID,
          callID: pending.callID,
          intentGeneration: pending.intentGeneration,
          fingerprint: pending.fingerprint,
          decision: "session",
        });
        decision = "dismiss";
      }
      reply = await rpc("reply", {
        clientID,
        pendingID: pending.pendingID,
        sessionID,
        messageID: pending.messageID,
        callID: pending.callID,
        intentGeneration: pending.intentGeneration,
        fingerprint: pending.fingerprint,
        decision,
      });
    }
    if (pending && !boundary && !reply.accepted)
      throw new Error(
        `${name}: approval rejected: ${JSON.stringify({ pending, reply })}`,
      );
    if (name !== "pending-deletion")
      await api("POST", `/api/experimental/session/${sessionID}/wait`);
    const context =
      name === "pending-deletion"
        ? null
        : await api("GET", `/api/session/${sessionID}/context`);
    const assessments = assessorRequests
      .slice(assessorStart)
      .map((body) =>
        JSON.parse(
          body.messages.find((message) => message.role === "user").content,
        ),
      );
    const targets = await Promise.all(
      ["target-one", "target-two"].map((name) =>
        readFile(`${directory}/${name}`, "utf8").catch(() => null),
      ),
    );
    const result = {
      name,
      sessionID,
      pending,
      reply,
      sessionAttempt,
      staleRemaining,
      context,
      assessments,
      sideEffectBefore,
      sideEffect: await readFile(
        `${markerDirectory}/lifecycle.marker`,
        "utf8",
      ).catch(() => ""),
      targets,
      dynamicMarker: await readFile(
        `${directory}/dynamic.marker`,
        "utf8",
      ).catch(() => null),
    };
    calls.push(result);
    return result;
  };
  await run("seed", "session");
  await run("synthetic-reuse");
  await api("POST", `/api/session/${sessionID}/prompt`, {
    id: "msg_y",
    text: "CASE lifecycle-native — custom-ID admission",
    resume: false,
  });
  await run("custom-id-admission", "session");
  const clear = await rpc("clear", { clientID, sessionID });
  await run("after-clear");
  await run("pending-admission", "session", () =>
    api("POST", `/api/session/${sessionID}/prompt`, {
      id: "msg_a",
      text: "CASE lifecycle-native — replacement admitted intent",
      resume: false,
    }),
  );
  await run("pending-goal", "session", async () => {
    await api("PATCH", `/api/session/${sessionID}`, {
      metadata: {
        goal: {
          condition: "Inspect disposable project",
          status: "active",
          version: 1,
        },
      },
    });
    await delay(200);
  });
  await run("goal-seed", "session");
  await api("PATCH", `/api/session/${sessionID}`, {
    metadata: {
      goal: {
        condition: "Inspect disposable project",
        status: "active",
        version: 2,
      },
    },
  });
  await run("goal-replaced", "session");
  await api("PATCH", `/api/session/${sessionID}`, { metadata: { goal: null } });
  await run("goal-cleared", "session");
  await api("POST", `/api/session/${sessionID}/prompt`, {
    text: "CASE lifecycle-native — replacement admitted intent",
    resume: false,
  });
  await run("same-text-new-admission", "session");
  const pluginAdmission = (
    await api(
      "POST",
      `/api/rpc/command-gate-fixture/admit?location[directory]=${encodeURIComponent(directory)}`,
      {
        input: {
          sessionID,
          text: "CASE lifecycle-native — programmatic public admission",
        },
      },
    )
  ).output;
  await run("plugin-admission", "session");
  await api("POST", `/api/session/${sessionID}/compact`, {});
  await api("POST", `/api/experimental/session/${sessionID}/wait`);
  await run("compaction-reuse");
  await writeFile(
    `${directory}/lifecycle.sh`,
    "FIXTURE=fixture-ask printf 'changed\\n' >> lifecycle.marker\n",
  );
  await run("changed-script");
  await writeFile(`${directory}/helper.sh`, "HELPER=one\n");
  await writeFile(
    `${directory}/lifecycle.sh`,
    "source ./helper.sh\nFIXTURE=fixture-ask printf 'run\\n' >> lifecycle.marker\n",
  );
  await run("dependency-seed", "session");
  await writeFile(`${directory}/helper.sh`, "HELPER=two\n");
  await run("changed-dependency");
  scenario.call.arguments.command = "bash lifecycle.sh ";
  await run("changed-bytes");
  scenario.call.arguments.command = "bash lifecycle.sh";
  await mkdir(`${directory}/other`, { recursive: true });
  await writeFile(
    `${directory}/other/lifecycle.sh`,
    "FIXTURE=fixture-ask printf 'run\\n' >> lifecycle.marker\n",
  );
  scenario.call.arguments.workdir = `${directory}/other`;
  await run("changed-cwd");
  delete scenario.call.arguments.workdir;
  await writeFile(`${directory}/target-one`, "one");
  await writeFile(`${directory}/target-two`, "two");
  await symlink(`${directory}/target-one`, `${directory}/fixture-ask-target`);
  scenario.call.arguments.command =
    "printf 'fixture-ask\\n' >> fixture-ask-target";
  await run("symlink-seed", "session");
  await run("symlink-reuse");
  await symlink(`${directory}/target-two`, `${directory}/target-next`);
  await rename(`${directory}/target-next`, `${directory}/fixture-ask-target`);
  await run("changed-symlink");
  await symlink("/etc", `${directory}/target-next`);
  await rename(`${directory}/target-next`, `${directory}/fixture-ask-target`);
  await run("fresh-hard-deny");
  scenario.call.arguments.command = "FIXTURE=fixture-ask touch dynamic.marker";
  await run("dynamic-ineligible", "reject-session");
  scenario.call.arguments.command = "bash missing-fixture-ask.sh";
  await run("missing-script-ineligible", "reject-session");
  scenario.call.arguments.command = "bash lifecycle.sh";
  await run("policy-seed", "session");
  await writeFile(`${directory}/.aar.toml`, "[grants]\nsessionTrust = false\n");
  await run("configuration-ineligible");
  await writeFile(`${directory}/.aar.toml`, '[policy]\nprofile = "balanced"\n');
  await run("changed-policy", "session");
  await restart();
  await rpc("connect", { clientID });
  await run("restart", "session");
  await run("restart-reuse");
  await api("POST", "/api/location/reload");
  await rpc("connect", { clientID });
  await run("reload", "session");
  await rpc("connect", { clientID: "reconnected-adapter" });
  await run("reconnect", "session");
  const parentID = sessionID;
  sessionID = (
    await api("POST", "/api/session", {
      location: { directory },
      parentID,
      model: { providerID: "proof-local", id: "probe" },
    })
  ).data.id;
  const childID = sessionID;
  await run("child-inherits", "session");
  await run("child-reuse");
  await api("POST", `/api/session/${parentID}/prompt`, {
    text: "CASE lifecycle-native — new parent intent",
    resume: false,
  });
  await run("parent-new-intent", "session");
  sessionID = parentID;
  await run("parent-isolation");
  sessionID = childID;
  await run("child-after-parent-call-reuse");
  const childAdmission = await api("POST", `/api/session/${sessionID}/prompt`, {
    text: "CASE lifecycle-native — child own public admission",
    resume: false,
  });
  await run("child-own-admission", "session");
  await run("child-own-reuse");
  const owningDirectory = directory;
  directory = `${root}/project-two`;
  await writeFile(
    `${directory}/lifecycle.sh`,
    await readFile(`${owningDirectory}/lifecycle.sh`),
  );
  await writeFile(
    `${directory}/helper.sh`,
    await readFile(`${owningDirectory}/helper.sh`),
  );
  sessionID = (
    await api("POST", "/api/session", {
      location: { directory },
      model: { providerID: "proof-local", id: "probe" },
      title: "Other location",
    })
  ).data.id;
  await api("POST", `/api/session/${sessionID}/prompt`, {
    text: "CASE lifecycle-native — another location",
    resume: false,
  });
  await run("location-isolation", "session");
  const foreignClear = await rpc("clear", { clientID, sessionID: childID });
  directory = owningDirectory;
  sessionID = childID;
  await run("foreign-clear-refused-reuse");
  sessionID = (
    await api("POST", "/api/session", {
      location: { directory },
      parentID,
      model: { providerID: "proof-local", id: "probe" },
    })
  ).data.id;
  await run("sibling-isolation");
  sessionID = childID;
  await rpc("clear", { clientID, sessionID });
  await run("pending-clear", "session", () =>
    rpc("clear", { clientID, sessionID }),
  );
  await run("after-child-clear", "deny");
  await run("denial-suppressed");
  await rpc("clear", { clientID, sessionID });
  await run("denial-cleared");
  await run("pending-deletion", "session", async () => {
    await api("DELETE", `/api/session/${sessionID}`);
    await delay(200);
  });
  sessionID = (
    await api("POST", "/api/session", {
      location: { directory },
      model: { providerID: "proof-local", id: "probe" },
      title: "Lifecycle TUI clear",
    })
  ).data.id;
  const tuiSessionID = sessionID;
  await api("POST", `/api/session/${sessionID}/prompt`, {
    text: "CASE lifecycle-native — TUI clear context",
    resume: false,
  });
  const tui = await launchTui(sessionID);
  const waitFile = async (name) => {
    for (let index = 0; index < 120; index++) {
      const text = await readFile(`${root}/${name}`, "utf8").catch(() => null);
      if (text) return JSON.parse(text);
      await delay(100);
    }
    throw new Error(`TUI fixture did not report ${name}`);
  };
  let tuiReady, tabClosed, nativeClear;
  try {
    tuiReady = await waitFile("tui-ready.json");
    await delay(500);
    await run("tui-clear-seed", "session");
    await writeFile(`${root}/tab.trigger`, "");
    tabClosed = await waitFile("tab-closed.json");
    await run("tab-close-reuse");
    await writeFile(`${root}/clear.trigger`, "");
    nativeClear = await waitFile("clear-done.json");
    await run("native-clear");
    nativeClear.command = await waitFile("clear-command.json");
  } finally {
    await tui.stop();
    await tui.done;
  }
  return {
    sessionID,
    parentID,
    childID,
    tuiSessionID,
    admitted,
    pluginAdmission,
    childAdmission,
    calls,
    clear,
    foreignClear,
    tuiReady,
    tabClosed,
    nativeClear,
  };
}
