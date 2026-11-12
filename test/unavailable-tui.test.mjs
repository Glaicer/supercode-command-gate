import assert from "node:assert/strict";
import { test } from "node:test";
import tui from "../src/tui.ts";

const tick = () => new Promise((resolve) => setImmediate(resolve));

const rpcUnavailable = {
  _tag: "RpcError",
  type: "rpc.unavailable",
  message: "RPC is unavailable: command-gate",
};
const rpcUnavailableMessage =
  "rpc.unavailable: RPC is unavailable: command-gate";

function setupTui(overrides = {}) {
  const toasts = [];
  const commands = [];
  const rpc = {
    connect: async () => ({}),
    disconnect: async () => ({}),
    status: async () => ({ healthy: true, failureMode: "deny" }),
    alerts: async () => [],
    list: async () => [],
    events: { on: () => () => {} },
    ...overrides,
  };
  const dispose = tui.setup({
    options: {},
    client: { rpc: () => rpc },
    location: { directory: "/project" },
    renderer: { width: 120, height: 40, on() {}, off() {} },
    keymap: {
      layer: (factory) => commands.push(...factory().commands),
      commands: () => [{ id: "clear", slash: { name: "clear" }, run() {} }],
    },
    ui: {
      toast: { show: (input) => toasts.push(input) },
      router: { current: () => ({ type: "session", sessionID: "one" }) },
      slot: ({ render }) => {
        render();
        return () => {};
      },
      dialog: { confirm: async () => false, clear() {}, set() {} },
    },
  });
  return { rpc, toasts, commands, dispose };
}

test("startup RPC unavailability retries silently and recovers on the heartbeat", async (t) => {
  t.mock.timers.enable({ apis: ["setInterval", "Date"], now: 0 });
  let attempts = 0;
  let listed = 0;
  const harness = setupTui({
    connect: async () => {
      if (++attempts === 1) throw rpcUnavailable;
      return {};
    },
    list: async () => {
      listed++;
      return [];
    },
  });
  try {
    await tick();
    assert.deepEqual(harness.toasts, []);
    assert.equal(listed, 0);
    t.mock.timers.tick(5000);
    await tick();
    assert.equal(attempts, 2);
    assert.equal(listed, 1);
    assert.deepEqual(harness.toasts, []);
  } finally {
    harness.dispose();
  }
});

test("RPC failures after the first connect produce readable error toasts", async (t) => {
  t.mock.timers.enable({ apis: ["setInterval", "Date"], now: 0 });
  const harness = setupTui();
  try {
    await tick();
    harness.rpc.connect = async () => {
      throw rpcUnavailable;
    };
    for (let retry = 0; retry < 2; retry++) {
      t.mock.timers.tick(5000);
      await tick();
      assert.equal(harness.toasts.length, retry + 1);
      assert.deepEqual(harness.toasts[retry], {
        title: "Command Gate approval unavailable",
        message: rpcUnavailableMessage,
        variant: "error",
      });
    }
  } finally {
    harness.dispose();
  }
});

test("persistent startup unavailability warns once after 30 seconds and keeps retrying", async (t) => {
  t.mock.timers.enable({ apis: ["setInterval", "Date"], now: 0 });
  let attempts = 0;
  let listed = 0;
  const harness = setupTui({
    connect: async () => {
      attempts++;
      throw rpcUnavailable;
    },
    list: async () => {
      listed++;
      return [];
    },
  });
  try {
    await tick();
    for (let elapsed = 5; elapsed <= 60; elapsed += 5) {
      t.mock.timers.tick(5000);
      await tick();
      assert.equal(harness.toasts.length, elapsed < 30 ? 0 : 1);
    }
    assert.equal(attempts, 13);
    assert.deepEqual(harness.toasts[0], {
      title: "Command Gate approval unavailable",
      message: rpcUnavailableMessage,
      variant: "error",
    });
    harness.rpc.connect = async () => ({});
    t.mock.timers.tick(5000);
    await tick();
    assert.equal(listed, 1);
    harness.rpc.connect = async () => {
      throw rpcUnavailable;
    };
    t.mock.timers.tick(5000);
    await tick();
    assert.equal(harness.toasts.length, 2);
  } finally {
    harness.dispose();
  }
});

test("other startup errors surface immediately and status failures are never suppressed", async () => {
  for (const [method, error] of [
    ["connect", { type: "rpc.invalid_input", message: "Invalid client" }],
    ["connect", { type: "rpc.internal", message: "Internal failure" }],
    ["status", rpcUnavailable],
  ]) {
    const harness = setupTui({
      [method]: async () => {
        throw error;
      },
    });
    try {
      await tick();
      assert.equal(harness.toasts.length, 1);
      assert.equal(
        harness.toasts[0].message,
        `${error.type}: ${error.message}`,
      );
    } finally {
      harness.dispose();
    }
  }
});

test("shared error formatting handles health commands and bounded unknown values", async () => {
  const circular = { reason: "circular" };
  circular.self = circular;
  const unserializable = { count: 1n };
  const harness = setupTui();
  try {
    await tick();
    const health = harness.commands.find(
      (command) => command.id === "command-gate.health",
    );
    for (const [error, expected] of [
      [new Error("Disconnected"), "Disconnected"],
      [rpcUnavailable, rpcUnavailableMessage],
      [{ type: "rpc.internal" }, "rpc.internal"],
      [{ message: "No response" }, "No response"],
      [{ reason: "No response" }, '{"reason":"No response"}'],
      ["plain error", "plain error"],
      [null, "null"],
      [circular, /circular/i],
      [unserializable, /.+/],
      [{ reason: "x".repeat(10000) }, /^\{"reason":"x/],
    ]) {
      harness.rpc.status = async () => {
        throw error;
      };
      await health.run();
      const { message } = harness.toasts.at(-1);
      if (expected instanceof RegExp) assert.match(message, expected);
      else assert.equal(message, expected);
      assert.doesNotMatch(message, /\[object Object\]/);
      assert.ok(message.length <= 300);
    }
  } finally {
    harness.dispose();
  }
});

test("approval reply failures use readable shared error formatting", async () => {
  const harness = setupTui({
    list: async () => [
      {
        pendingID: "pending-one",
        command: "echo hello",
        preview: "echo hello",
        cwd: "/project",
        effectSummary: "Needs approval",
      },
    ],
    reply: async () => {
      throw rpcUnavailable;
    },
  });
  try {
    await tick();
    assert.equal(harness.toasts.length, 1);
    assert.equal(harness.toasts[0].message, rpcUnavailableMessage);
  } finally {
    harness.dispose();
  }
});

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
