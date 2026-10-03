import { readFile, writeFile } from "node:fs/promises";

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function runConcurrencyCases({ api, rpc, root, cases }) {
  const clientID = "concurrency-adapter";
  const directory = `${root}/project`;
  const otherDirectory = `${root}/project-two`;
  const create = async (scenario, location = directory, parentID) => {
    const sessionID = (
      await api("POST", "/api/session", {
        location: { directory: location },
        model: { providerID: "proof-local", id: "probe" },
        ...(parentID ? { parentID } : {}),
      })
    ).data.id;
    await rpc("connect", { clientID }, location);
    return { scenario, sessionID, location };
  };
  const start = (item) =>
    api("POST", `/api/session/${item.sessionID}/prompt`, {
      text: `CASE ${item.scenario.name}`,
    });
  const pendingFor = async (item, previous) => {
    for (let index = 0; index < 150; index++) {
      const pending = (
        await rpc(
          "list",
          { clientID, sessionID: item.sessionID },
          item.location,
        )
      ).find((entry) => entry.pendingID !== previous);
      if (pending) return pending;
      await delay(20);
    }
    throw Error(`No pending request for ${item.scenario.name}`);
  };
  const reply = (item, pending, decision, overrides = {}) =>
    rpc("reply", { ...pending, decision, ...overrides }, item.location);
  const wait = (item) =>
    api("POST", `/api/experimental/session/${item.sessionID}/wait`);
  const marker = (item) =>
    readFile(`${item.location}/${item.scenario.name}.marker`, "utf8").catch(
      () => "",
    );

  const identical = await create(cases[0]);
  await start(identical);
  const first = await pendingFor(identical);
  const accepted = await reply(identical, first, "once");
  const second = await pendingFor(identical, first.pendingID);
  const duplicate = await reply(identical, first, "once");
  const mixedCall = await reply(identical, second, "once", {
    callID: first.callID,
  });
  await reply(identical, second, "dismiss");
  await wait(identical);

  const main = await create(cases[1]);
  const child = await create(cases[2], directory, main.sessionID);
  const other = await create(cases[3], otherDirectory);
  await Promise.all([main, child, other].map(start));
  const [mainPending, childPending, otherPending] = await Promise.all(
    [main, child, other].map((item) => pendingFor(item)),
  );
  const wrongLocation = await reply(other, mainPending, "once");
  const wrongSession = await reply(main, childPending, "once", {
    sessionID: main.sessionID,
  });
  const otherApproved = await reply(other, otherPending, "once");
  const childApproved = await reply(child, childPending, "once");
  await reply(main, mainPending, "dismiss");
  await Promise.all([main, child, other].map(wait));
  const independent = await Promise.all(
    [main, child, other].map(async (item) => ({
      name: item.scenario.name,
      marker: await marker(item),
      pending: await rpc(
        "list",
        { clientID, sessionID: item.sessionID },
        item.location,
      ),
      context: await api("GET", `/api/session/${item.sessionID}/context`),
    })),
  );
  return {
    identical: {
      accepted,
      duplicate,
      mixedCall,
      marker: await marker(identical),
      first,
      second,
    },
    wrongLocation,
    wrongSession,
    otherApproved,
    childApproved,
    independent,
  };
}

export async function runGrantRaceCases({ api, rpc, root, cases }) {
  const clientID = "race-adapter";
  const results = [];
  for (const scenario of cases) {
    await rpc("connect", { clientID });
    const sessionID = (
      await api("POST", "/api/session", {
        location: { directory: `${root}/project` },
        model: { providerID: "proof-local", id: "probe" },
      })
    ).data.id;
    await writeFile(
      `${root}/project/${scenario.name}.sh`,
      `FIXTURE=fixture-ask printf 'run\\n' >> ${scenario.name}.marker\n`,
    );
    if (scenario.name.startsWith("pre-"))
      await writeFile(`${root}/${sessionID}.before`, "");
    await api("POST", `/api/session/${sessionID}/prompt`, {
      text: `CASE ${scenario.name}`,
    });
    let pending;
    for (let index = 0; index < 150; index++) {
      pending = (await rpc("list", { clientID, sessionID }))[0];
      if (pending) break;
      await delay(20);
    }
    if (!pending) throw Error(`Missing pending approval for ${scenario.name}`);
    const accepted = await rpc("reply", { ...pending, decision: "session" });
    let pid;
    for (let index = 0; index < 150; index++) {
      pid = await readFile(`${root}/${sessionID}.ready`, "utf8").catch(
        () => null,
      );
      if (pid) break;
      await delay(20);
    }
    if (!pid) throw Error(`Grant barrier did not start for ${scenario.name}`);
    if (scenario.name.endsWith("-goal"))
      await api("PATCH", `/api/session/${sessionID}`, {
        metadata: {
          goal: { condition: "Replacement Goal", status: "active", version: 2 },
        },
      });
    if (scenario.name.endsWith("-intent"))
      await api("POST", `/api/session/${sessionID}/prompt`, {
        text: `CASE ${scenario.name} new intent`,
        resume: false,
      });
    if (scenario.name.endsWith("-cancel"))
      await api("POST", `/api/session/${sessionID}/interrupt?resume=false`);
    if (scenario.name.endsWith("-unload"))
      await api("POST", "/api/location/reload");
    await writeFile(`${root}/${sessionID}.release`, "");
    await api("POST", `/api/experimental/session/${sessionID}/wait`);
    const stale = await rpc("reply", { ...pending, decision: "session" });
    const context = await api("GET", `/api/session/${sessionID}/context`);
    await rpc("connect", { clientID });
    scenario.remaining = 1;
    scenario.token = `RETRY_${scenario.name}`;
    await api("POST", `/api/session/${sessionID}/synthetic`, {
      text: `CASE ${scenario.name} ${scenario.token}`,
    });
    let retry;
    for (let index = 0; index < 150; index++) {
      retry = (await rpc("list", { clientID, sessionID }))[0];
      if (retry) break;
      await delay(20);
    }
    if (!retry)
      throw Error(`Stale grant continued without approval: ${scenario.name}`);
    await rpc("reply", { ...retry, decision: "dismiss" });
    await api("POST", `/api/experimental/session/${sessionID}/wait`);
    await delay(100);
    results.push({
      name: scenario.name,
      accepted,
      stale,
      retry,
      pending: await rpc("list", { clientID, sessionID }),
      ownedRunning: await readFile(`/proc/${pid.trim()}/stat`, "utf8")
        .then((stat) => !/\) Z /.test(stat))
        .catch(() => false),
      marker: await readFile(
        `${root}/project/${scenario.name}.marker`,
        "utf8",
      ).catch(() => ""),
      context,
    });
  }
  return results;
}
