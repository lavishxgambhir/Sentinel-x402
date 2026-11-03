import crypto from 'node:crypto';

/** One-use merchant challenges shared by the demo route and held-out probes. */
export class ChallengeRegistry {
  constructor({ ttlMs = 10 * 60_000, maxStored = 256 } = {}) {
    this.ttlMs = ttlMs;
    this.maxStored = maxStored;
    this.entries = new Map();
  }

  issue(value, now = Date.now()) {
    this.prune(now);
    const challengeId = crypto.randomUUID();
    const expiresAt = now + this.ttlMs;
    this.entries.set(challengeId, { ...structuredClone(value), expiresAt });
    return { challengeId, expiresAt };
  }

  consume(challengeId, now = Date.now()) {
    const stored = this.entries.get(challengeId);
    if (!stored) return null;
    this.entries.delete(challengeId);
    if (stored.expiresAt <= now) return null;
    return structuredClone(stored);
  }

  clear() { this.entries.clear(); }

  prune(now = Date.now()) {
    for (const [id, stored] of this.entries) {
      if (stored.expiresAt <= now) this.entries.delete(id);
    }
    while (this.entries.size >= this.maxStored) {
      this.entries.delete(this.entries.keys().next().value);
    }
  }
}
