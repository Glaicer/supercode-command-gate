export type Intent = { id: string; text: string };

export type CallIdentity = {
  location: string;
  sessionID: string;
  messageID: string;
  callID: string;
};

export type AuthorizingRecord = CallIdentity & {
  command: string;
  cwd: string;
  shell: string;
  intentId: string | null;
};

const MAX_AUTHORIZING_RECORDS = 512;

export function authorizingKey(identity: CallIdentity): string {
  return [
    identity.location,
    identity.sessionID,
    identity.messageID,
    identity.callID,
  ].join("\u0000");
}

export function goalFromMetadata(metadata: unknown): string | null {
  if (!metadata || typeof metadata !== "object") return null;
  const raw = (metadata as Record<string, unknown>).goal;
  if (!raw || typeof raw !== "object") return null;
  const goal = raw as Record<string, unknown>;
  if (typeof goal.condition !== "string" || goal.condition === "") return null;
  if (goal.status !== undefined && goal.status !== "active") return null;
  return goal.condition;
}

export class GateState {
  #intents = new Map<string, Intent>();
  #authorizing = new Map<string, AuthorizingRecord>();

  admit(sessionID: string, messageID: string, text: string): void {
    this.#intents.set(sessionID, { id: messageID, text });
  }

  forgetIntent(sessionID: string): void {
    this.#intents.delete(sessionID);
  }

  intentFor(
    sessionID: string,
    parentID: string | undefined,
  ): Intent | undefined {
    return (
      this.#intents.get(sessionID) ??
      (parentID ? this.#intents.get(parentID) : undefined)
    );
  }

  claim(record: AuthorizingRecord): AuthorizingRecord | null {
    const key = authorizingKey(record);
    const prior = this.#authorizing.get(key);
    if (prior) return prior;
    this.#authorizing.set(key, record);
    while (this.#authorizing.size > MAX_AUTHORIZING_RECORDS) {
      const oldest = this.#authorizing.keys().next();
      if (oldest.done) break;
      this.#authorizing.delete(oldest.value);
    }
    return null;
  }

  release(identity: CallIdentity): void {
    this.#authorizing.delete(authorizingKey(identity));
  }

  authorizingFor(identity: CallIdentity): AuthorizingRecord | undefined {
    return this.#authorizing.get(authorizingKey(identity));
  }
}
