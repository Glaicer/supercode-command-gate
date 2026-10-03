import { Rpc } from "@opencode/plugin/rpc";

export const Proof = Rpc.define({
  id: "command-gate-proof",
  events: {},
  methods: {
    connect: {
      input: {
        type: "object",
        properties: { clientID: { type: "string" } },
        required: ["clientID"],
        additionalProperties: false,
      },
      output: { type: "object" },
    },
    clientReport: {
      input: { type: "object" },
      output: { type: "object" },
    },
    check: {
      input: { type: "object" },
      output: { type: "object" },
    },
    invalidate: {
      input: {
        type: "object",
        properties: {
          sessionID: { type: "string" },
          event: { type: "string", enum: ["clear", "end", "reconnect"] },
        },
        required: ["sessionID", "event"],
        additionalProperties: false,
      },
      output: { type: "object" },
    },
    admit: {
      input: {
        type: "object",
        properties: { sessionID: { type: "string" }, text: { type: "string" } },
        required: ["sessionID", "text"],
        additionalProperties: false,
      },
      output: { type: "object" },
    },
    list: {
      input: { type: "object", additionalProperties: false },
      output: { type: "array", items: { type: "object" } },
    },
    reply: {
      input: {
        type: "object",
        properties: {
          pendingID: { type: "string" },
          decision: { type: "string", enum: ["deny", "once", "session"] },
        },
        required: ["pendingID", "decision"],
        additionalProperties: false,
      },
      output: { type: "object" },
    },
  },
});
