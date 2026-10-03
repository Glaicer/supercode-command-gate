import { test } from "node:test";
import assert from "node:assert/strict";
import { GateState, authorizingKey, goalFromMetadata } from "./state.ts";

const identity = {
  location: "/workspace",
  sessionID: "ses_1",
  messageID: "msg_1",
  callID: "call_1",
};
const record = {
  ...identity,
  command: "pwd",
  cwd: "/workspace",
  shell: "/bin/bash",
  intentId: "msg_0",
};

test("goals come only from active session metadata, never from guesswork", () => {
  assert.equal(
    goalFromMetadata({ goal: { condition: "Inspect only", status: "active" } }),
    "Inspect only",
  );
  assert.equal(
    goalFromMetadata({ goal: { condition: "Inspect only" } }),
    "Inspect only",
  );
  assert.equal(
    goalFromMetadata({ goal: { condition: "Inspect only", status: "done" } }),
    null,
  );
  assert.equal(goalFromMetadata({ goal: {} }), null);
  assert.equal(goalFromMetadata(undefined), null);
  assert.equal(goalFromMetadata({ goal: "not-an-object" }), null);
});

test("owning intent resolves per session with parent inheritance only as a fallback", () => {
  const state = new GateState();
  state.admit("ses_parent", "msg_p", "parent intent");
  assert.deepEqual(state.intentFor("ses_child", "ses_parent"), {
    id: "msg_p",
    text: "parent intent",
  });
  state.admit("ses_child", "msg_c", "child intent");
  assert.deepEqual(state.intentFor("ses_child", "ses_parent"), {
    id: "msg_c",
    text: "child intent",
  });
  assert.equal(state.intentFor("ses_other", undefined), undefined);
  assert.equal(state.intentFor("ses_other", "ses_missing"), undefined);
});

test("authorizing state is keyed by location/session/message/call identity, not by command text", () => {
  const state = new GateState();
  assert.equal(state.claim(record), null);
  const duplicate = state.claim({
    ...record,
    command: "touch other.marker",
    cwd: "/elsewhere",
  });
  assert.equal(duplicate?.callID, "call_1");
  const otherCall = state.claim({ ...record, callID: "call_2" });
  assert.equal(otherCall, null);
  const sameTextOtherSession = state.claim({
    ...record,
    sessionID: "ses_2",
    messageID: "msg_2",
    callID: "call_3",
  });
  assert.equal(sameTextOtherSession, null);
  state.release(identity);
  assert.equal(state.claim(record), null);
});

test("authorizing state stays bounded without a process-global slot", () => {
  const state = new GateState();
  for (let index = 0; index < 600; index++) {
    state.claim({
      ...record,
      sessionID: `ses_${index}`,
      messageID: `msg_${index}`,
      callID: `call_${index}`,
    });
  }
  assert.equal(
    state.authorizingFor({
      ...identity,
      sessionID: "ses_0",
      messageID: "msg_0",
      callID: "call_0",
    }),
    undefined,
  );
  assert.ok(
    state.authorizingFor({
      ...identity,
      sessionID: "ses_599",
      messageID: "msg_599",
      callID: "call_599",
    }),
  );
});

test("identity keys separate the location dimension", () => {
  assert.notEqual(
    authorizingKey(identity),
    authorizingKey({ ...identity, location: "/other" }),
  );
});
