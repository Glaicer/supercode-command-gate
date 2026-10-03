import assert from "node:assert/strict";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, writeFile } from "node:fs/promises";

const exec = promisify(execFile);

export async function runLifecycle({
  api,
  root,
  env,
  here,
  restart,
  launchTui,
  anchor,
}) {
  const location = `${root}/project`;
  const rpc = async (method, input, directory = location) =>
    (
      await api(
        "POST",
        `/api/rpc/command-gate-proof/${method}?location[directory]=${encodeURIComponent(directory)}`,
        { input },
      )
    ).output;
  const aar = (args, request) =>
    new Promise((resolve, reject) => {
      const child = spawn(`${root}/aar`, args, {
        cwd: location,
        env,
        timeout: 10000,
        stdio: ["pipe", "pipe", "pipe"],
      });
      let stdout = "",
        stderr = "";
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      child.on("error", reject);
      child.on("close", (code) => {
        if (code !== 0) return reject(Error(stderr));
        try {
          resolve(JSON.parse(stdout));
        } catch (error) {
          reject(error);
        }
      });
      child.stdin.end(request ? JSON.stringify(request) : undefined);
    });
  const requestFor = (sessionID, directory = location) => ({
    schemaVersion: "aar-request-v1",
    command: "touch lifecycle.marker",
    cwd: directory,
    workspaceRoot: directory,
    env: { HOME: env.HOME },
    session: { id: sessionID, host: "opencode", intentId: "" },
    intent: { goal: null, latestUserRequest: null, purpose: null },
  });
  const seed = async (request) => {
    const initial = await rpc("check", request, request.workspaceRoot);
    assert.equal(
      initial.decision.decision,
      "ask",
      "Lifecycle fixture requires a real reserved ask",
    );
    assert.equal(initial.decision.grantEligible, true);
    await aar([
      "grant",
      "--session",
      request.session.id,
      "--fingerprint",
      initial.decision.requestFingerprint,
      "--scope",
      "session",
    ]);
    return rpc("check", initial.request, request.workspaceRoot);
  };
  const tui = async (sessionID, options = {}) => {
    await writeFile(
      `${root}/config/opencode/cli.json`,
      JSON.stringify({ plugins: [{ package: here, options }] }),
    );
    const script = await launchTui(sessionID, "launch-lifecycle-tui.sh");
    await exec(
      "python3",
      [
        `${here}/tui-smoke.py`,
        script,
        `${root}/tui-${options.smokeClear ? "clear" : "connect"}.capture`,
      ],
      { timeout: 15000 },
    );
  };
  const lifecycle = [];
  const request = requestFor(anchor);
  for (const name of [
    "idle",
    "synthetic",
    "compaction",
    "new-intent",
    "plugin-admission",
    "goal-change",
    "clear",
    "reconnect",
    "reload",
    "restart",
    "end",
  ]) {
    if (name === "reconnect") await tui(anchor);
    await rpc("invalidate", { sessionID: anchor, event: "clear" });
    if (["idle", "synthetic", "compaction"].includes(name))
      await api("POST", `/api/session/${anchor}/prompt`, {
        text: `Lifecycle intent baseline ${name}`,
        resume: false,
      });
    const before = await seed(request);
    assert.equal(before.decision.source, "grant");
    if (name === "idle")
      await api("POST", `/api/experimental/session/${anchor}/wait`);
    if (name === "synthetic")
      await api("POST", `/api/session/${anchor}/synthetic`, {
        text: "Synthetic is not user admission",
        resume: false,
      });
    if (name === "compaction") {
      await api("POST", `/api/session/${anchor}/compact`, {});
      await api("POST", `/api/experimental/session/${anchor}/wait`);
    }
    if (name === "new-intent")
      await api("POST", `/api/session/${anchor}/prompt`, {
        text: "New admitted request",
        resume: false,
      });
    if (name === "plugin-admission")
      await rpc("admit", {
        sessionID: anchor,
        text: "Programmatic admission is user intent",
      });
    if (name === "goal-change")
      await api("PATCH", `/api/session/${anchor}`, {
        metadata: {
          goal: {
            condition: "Inspect only this disposable project",
            status: "active",
            version: 1,
          },
        },
      });
    if (name === "clear") await tui(anchor, { smokeClear: true });
    if (name === "reconnect") await tui(anchor);
    if (name === "reload") await api("POST", "/api/location/reload");
    if (name === "restart") await restart();
    let after;
    if (name === "end") {
      await api("DELETE", `/api/session/${anchor}`);
      for (let i = 0; i < 50; i++) {
        const decision = await aar(["check"], before.request);
        after = { request: before.request, decision };
        if (decision.source !== "grant") break;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    } else after = await rpc("check", before.request);
    lifecycle.push({ name, before, after });
  }
  const create = async (directory, parentID) =>
    (
      await api("POST", "/api/session", {
        location: { directory },
        ...(parentID ? { parentID } : {}),
        title: "Lifecycle ownership",
      })
    ).data;
  const parent = await create(location);
  await api("POST", `/api/session/${parent.id}/prompt`, {
    text: "Parent admitted intent",
    resume: false,
  });
  const parentBefore = await seed(requestFor(parent.id));
  const child = await create(location, parent.id);
  const childInitial = await rpc("check", requestFor(child.id));
  const childBefore = await seed(childInitial.request);
  await api("POST", `/api/session/${parent.id}/prompt`, {
    text: "Replacement parent intent",
    resume: false,
  });
  const childAfter = await rpc("check", childBefore.request);
  const otherLocation = `${root}/project-two`;
  const other = await create(otherLocation);
  await api("POST", `/api/session/${other.id}/prompt`, {
    text: "Other location intent",
    resume: false,
  });
  const otherAfter = await rpc(
    "check",
    requestFor(other.id, otherLocation),
    otherLocation,
  );
  let foreignError;
  try {
    await rpc("check", requestFor(parent.id), otherLocation);
  } catch (error) {
    foreignError = String(error);
  }
  const events = (await readFile(`${root}/events.jsonl`, "utf8"))
    .trim()
    .split("\n")
    .map(JSON.parse);
  await writeFile(
    `${root}/config/opencode/cli.json`,
    JSON.stringify({ plugins: [here] }),
  );
  return {
    lifecycle,
    lifecycleEvents: events,
    ownership: {
      parent,
      parentBefore,
      child,
      childInitial,
      childBefore,
      childAfter,
      other,
      otherAfter,
      foreignError,
    },
  };
}
