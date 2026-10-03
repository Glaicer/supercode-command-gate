import { Rpc } from "@opencode/plugin/rpc";

const client = { clientID: { type: "string", minLength: 1 } } as const;
const binding = {
  ...client,
  pendingID: { type: "string", minLength: 1 },
  sessionID: { type: "string", minLength: 1 },
  messageID: { type: "string", minLength: 1 },
  callID: { type: "string", minLength: 1 },
  intentGeneration: { type: "string", minLength: 1 },
  fingerprint: { type: "string", minLength: 1 },
} as const;
const object = (properties: object, required: string[]) => ({
  type: "object",
  properties,
  required,
  additionalProperties: false,
});

export const Approvals = Rpc.define({
  id: "command-gate",
  events: {
    changed: { schema: { type: "object", additionalProperties: false } },
  },
  methods: {
    connect: {
      input: object(client, ["clientID"]),
      output: { type: "object" },
    },
    disconnect: {
      input: object(client, ["clientID"]),
      output: { type: "object" },
    },
    list: {
      input: object({ ...client, sessionID: { type: "string" } }, ["clientID"]),
      output: { type: "array", items: { type: "object" } },
    },
    get: {
      input: object({ ...client, pendingID: { type: "string" } }, [
        "clientID",
        "pendingID",
      ]),
      output: { type: ["object", "null"] },
    },
    reply: {
      input: object(
        {
          ...binding,
          decision: { type: "string", enum: ["once", "deny", "dismiss"] },
        },
        [...Object.keys(binding), "decision"],
      ),
      output: { type: "object" },
    },
  },
});
