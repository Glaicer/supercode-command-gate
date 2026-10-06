import assert from "node:assert/strict";
import { test } from "node:test";
import tui from "../src/tui.ts";

const tick = () => new Promise((resolve) => setImmediate(resolve));

test("operational alerts are dismissible, session scoped and deduplicated without replies", async () => {
  let changed;
  let close;
  let route = { type: "session", sessionID: "one" };
  let alerts = [
    {
      id: "outage-one",
      sessionID: "one",
      component: "assessor",
      reason: "Command Risk Assessor unavailable",
    },
  ];
  const shown = [];
  const replies = [];
  const rpc = {
    connect: async () => ({}),
    disconnect: async () => ({}),
    status: async () => ({ healthy: true, failureMode: "deny" }),
    alerts: async ({ sessionID }) =>
      alerts.filter((item) => item.sessionID === sessionID),
    list: async () => [],
    reply: async (input) => replies.push(input),
    events: {
      on: (_, handler) => {
        changed = handler;
        return () => {};
      },
    },
  };
  const dispose = tui.setup({
    options: {},
    client: { rpc: () => rpc },
    location: { directory: "/project" },
    renderer: { width: 120, height: 40, on() {}, off() {} },
    keymap: {
      layer() {},
      commands: () => [{ id: "clear", slash: { name: "clear" }, run() {} }],
    },
    ui: {
      toast: { show() {} },
      router: { current: () => route },
      slot: ({ render }) => {
        render();
        return () => {};
      },
      dialog: {
        alert: (input) => {
          shown.push(input);
          return new Promise((resolve) => {
            close = resolve;
          });
        },
        clear: () => close?.(),
        set() {},
      },
    },
  });
  try {
    await tick();
    assert.equal(shown.length, 1);
    assert.equal(shown[0].title, "Command Gate unavailable");
    assert.match(shown[0].message, /Command Risk Assessor unavailable/);
    assert.match(shown[0].message, /command was not executed/i);
    changed({ location: { directory: "/project" } });
    await tick();
    assert.equal(shown.length, 1);
    close();
    await tick();
    changed({ location: { directory: "/project" } });
    await tick();
    assert.equal(shown.length, 1);
    alerts = [
      ...alerts,
      {
        id: "outage-two",
        sessionID: "two",
        component: "reviewer",
        reason: "Reviewer unavailable",
      },
    ];
    changed({ location: { directory: "/other" } });
    await tick();
    assert.equal(shown.length, 1);
    route = { type: "session", sessionID: "two" };
    changed({ location: { directory: "/project" } });
    await tick();
    assert.equal(shown.length, 2);
    close();
    await tick();
    assert.deepEqual(replies, []);
  } finally {
    dispose();
  }
});

test("late operational alerts cannot open after the active session or location changes", async () => {
  for (const navigation of ["session", "location"]) {
    let resolveAlerts;
    let changed;
    let route = { type: "session", sessionID: "one" };
    const location = { directory: "/project" };
    const shown = [];
    let requested = false;
    const rpc = {
      connect: async () => ({}),
      disconnect: async () => ({}),
      status: async () => ({ healthy: true, failureMode: "deny" }),
      alerts: async () => {
        if (!requested) {
          requested = true;
          return new Promise((resolve) => {
            resolveAlerts = resolve;
          });
        }
        return [
          {
            id: "outage-one",
            sessionID: "one",
            component: "assessor",
            reason: "Assessor unavailable",
          },
        ];
      },
      list: async () => [],
      events: {
        on: (_, handler) => {
          changed = handler;
          return () => {};
        },
      },
    };
    const dispose = tui.setup({
      options: {},
      client: { rpc: () => rpc },
      location,
      renderer: { width: 120, height: 40, on() {}, off() {} },
      keymap: {
        layer() {},
        commands: () => [{ id: "clear", slash: { name: "clear" }, run() {} }],
      },
      ui: {
        toast: { show() {} },
        router: { current: () => route },
        slot: ({ render }) => {
          render();
          return () => {};
        },
        dialog: {
          alert: (input) => {
            shown.push(input);
            return Promise.resolve();
          },
          clear() {},
          set() {},
        },
      },
    });
    try {
      await tick();
      assert.equal(typeof resolveAlerts, "function");
      if (navigation === "session")
        route = { type: "session", sessionID: "two" };
      else location.directory = "/other";
      resolveAlerts([
        {
          id: "outage-one",
          sessionID: "one",
          component: "assessor",
          reason: "Assessor unavailable",
        },
      ]);
      await tick();
      assert.deepEqual(shown, [], navigation);
      route = { type: "session", sessionID: "one" };
      location.directory = "/project";
      changed({ location: { directory: "/project" } });
      await tick();
      assert.equal(
        shown.length,
        1,
        "skipped alert remains available in its original context",
      );
    } finally {
      dispose();
    }
  }
});
