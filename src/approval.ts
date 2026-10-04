import { randomUUID } from "node:crypto";
import type { CallIdentity } from "./state.ts";
import type { Request } from "./request.ts";
import type { Decision } from "./reviewer.ts";
import { redactText } from "./approval-text.ts";

export const CLIENT_LEASE_MS = 15000;
export const CLIENT_HEARTBEAT_MS = 5000;
export const DEFAULT_APPROVAL_TIMEOUT_MS = 600000;

export type PendingApproval = CallIdentity & {
  pendingID: string;
  clientID: string;
  intentGeneration: string;
  fingerprint: string;
  command: string;
  cwd: string;
  effectSummary: string;
  preview: string;
  assessment: unknown;
  grantEligible: boolean;
  purpose: null;
  expiresAt: number;
};
export type ApprovalReply = Pick<
  PendingApproval,
  | "pendingID"
  | "clientID"
  | "sessionID"
  | "messageID"
  | "callID"
  | "intentGeneration"
  | "fingerprint"
> & { decision: "once" | "session" | "deny" | "dismiss" };

type Waiting = {
  payload: PendingApproval;
  finish: (decision: string) => void;
};

function maskCommand(command: string): string {
  const masked = redactText(command);
  return masked.length > 240 ? `${masked.slice(0, 237)}...` : masked;
}

export class ApprovalQueue {
  #clients = new Map<string, number>();
  #pending = new Map<string, Waiting>();
  #changed: () => void;

  constructor(changed: () => void) {
    this.#changed = changed;
  }

  connect(clientID: string): boolean {
    const fresh = Date.now() >= (this.#clients.get(clientID) ?? 0);
    this.#clients.set(clientID, Date.now() + CLIENT_LEASE_MS);
    return fresh;
  }

  available(): boolean {
    return [...this.#clients.keys()].some((clientID) =>
      this.connected(clientID),
    );
  }

  connected(clientID: string): boolean {
    return Date.now() < (this.#clients.get(clientID) ?? 0);
  }

  disconnect(clientID: string): void {
    this.#clients.delete(clientID);
    for (const item of this.#pending.values()) {
      if (item.payload.clientID === clientID) item.finish("disconnected");
    }
  }

  list(clientID: string, sessionID?: string): PendingApproval[] {
    return [...this.#pending.values()]
      .filter(
        ({ payload }) =>
          payload.clientID === clientID &&
          (!sessionID || payload.sessionID === sessionID),
      )
      .map(({ payload }) => payload);
  }

  get(clientID: string, pendingID: string): PendingApproval | null {
    const item = this.#pending.get(pendingID)?.payload;
    return item?.clientID === clientID ? item : null;
  }

  reply(input: ApprovalReply): boolean {
    const item = this.#pending.get(input.pendingID);
    if (
      !item ||
      !["once", "session", "deny", "dismiss"].includes(input.decision)
    )
      return false;
    const keys = [
      "clientID",
      "sessionID",
      "messageID",
      "callID",
      "intentGeneration",
      "fingerprint",
    ] as const;
    if (keys.some((key) => item.payload[key] !== input[key])) return false;
    if (input.decision === "session" && !item.payload.grantEligible)
      return false;
    if (
      Date.now() >= item.payload.expiresAt ||
      Date.now() >= (this.#clients.get(input.clientID) ?? 0)
    ) {
      item.finish("expired");
      return false;
    }
    item.finish(input.decision);
    return true;
  }

  cancel(pendingID: string): void {
    this.#pending.get(pendingID)?.finish("stale");
  }

  invalidate(sessionID: string): void {
    for (const item of this.#pending.values()) {
      if (item.payload.sessionID === sessionID) item.finish("stale");
    }
  }

  close(): void {
    for (const item of this.#pending.values()) item.finish("unavailable");
    this.#clients.clear();
  }

  wait(
    call: CallIdentity,
    request: Request,
    decision: Decision,
    intentGeneration: string,
    timeoutMs: number,
    signal: AbortSignal,
  ): Promise<string> {
    const clientID = [...this.#clients].find(
      ([, expires]) => expires > Date.now(),
    )?.[0];
    if (!clientID || signal.aborted) return Promise.resolve("unavailable");
    return new Promise((resolve) => {
      const pendingID = randomUUID();
      const payload: PendingApproval = {
        ...call,
        pendingID,
        clientID,
        intentGeneration,
        fingerprint: decision.requestFingerprint,
        command: request.command,
        cwd: request.cwd,
        effectSummary: decision.reason.replace(/\s+/g, " ").trim(),
        preview: maskCommand(request.command),
        assessment: decision.assessment,
        grantEligible: decision.grantEligible,
        purpose: request.intent.purpose,
        expiresAt: Date.now() + timeoutMs,
      };
      const finish = (response: string) => {
        if (!this.#pending.delete(pendingID)) return;
        clearTimeout(deadline);
        clearInterval(lease);
        signal.removeEventListener("abort", abort);
        this.#changed();
        resolve(response);
      };
      const abort = () => finish("cancelled");
      const deadline = setTimeout(() => finish("timeout"), timeoutMs);
      const lease = setInterval(() => {
        if (Date.now() >= (this.#clients.get(clientID) ?? 0))
          finish("disconnected");
      }, 1000);
      this.#pending.set(pendingID, { payload, finish });
      signal.addEventListener("abort", abort, { once: true });
      this.#changed();
    });
  }
}
