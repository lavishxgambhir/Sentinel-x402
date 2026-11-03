import fs from 'node:fs';
import path from 'node:path';
import { sha256Hex } from '../core/x402.mjs';

export const AUDIT_GENESIS = '0'.repeat(64);
export const MAX_AUDIT_ENTRIES = 1000;
const HASH = /^[0-9a-f]{64}$/;

function rowHash(row) {
  const { hash, ...body } = row;
  return sha256Hex(body);
}

export class AuditLog {
  constructor(file, { retention = MAX_AUDIT_ENTRIES } = {}) {
    this.file = file;
    this.retention = Math.max(1, Math.floor(retention));
    this.head = AUDIT_GENESIS;
    this.lastHash = AUDIT_GENESIS;
    this.nextSequence = 1;
    this.entries = [];
    this.legacyMigrated = false;
    this.loadError = null;

    if (!file || !fs.existsSync(file)) return;
    let saved;
    try {
      saved = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (error) {
      this.loadError = `Audit file cannot be parsed: ${error.message}`;
      return;
    }

    if (Array.isArray(saved)) {
      this.legacyMigrated = true;
      for (const old of saved) {
        const { seq, prev, hash, ...event } = old && typeof old === 'object' && !Array.isArray(old) ? old : { legacyValue: old };
        this.addInMemory(event);
      }
      return;
    }

    if (!saved || typeof saved !== 'object' || saved.version !== 2 || !Array.isArray(saved.entries)) {
      this.loadError = 'Audit file has an unsupported format';
      return;
    }
    this.head = saved.head;
    this.lastHash = saved.lastHash;
    this.nextSequence = saved.nextSequence;
    this.entries = saved.entries;
  }

  addInMemory(event) {
    const { seq, prev, hash, ...content } = event;
    const row = {
      ...content,
      seq: this.nextSequence,
      prev: this.lastHash
    };
    row.hash = rowHash(row);
    this.entries.push(row);
    this.lastHash = row.hash;
    this.nextSequence += 1;
    while (this.entries.length > this.retention) this.head = this.entries.shift().hash;
    return row;
  }

  verifyChain() {
    if (this.loadError) return { ok: false, checked: 0, error: this.loadError };
    if (!HASH.test(this.head) || !HASH.test(this.lastHash)) {
      return { ok: false, checked: 0, error: 'Invalid audit anchor or tail hash' };
    }
    if (this.entries.length > this.retention) {
      return { ok: false, checked: 0, error: 'Audit retention limit exceeded' };
    }
    let expectedPrev = this.head;
    let previousSequence = null;
    for (const [index, row] of this.entries.entries()) {
      if (!row || typeof row !== 'object' || Array.isArray(row)) {
        return { ok: false, checked: index, error: `Audit entry ${index} is malformed` };
      }
      if (!Number.isSafeInteger(row.seq) || row.seq < 1 || (previousSequence !== null && row.seq !== previousSequence + 1)) {
        return { ok: false, checked: index, error: `Audit sequence breaks at entry ${index}` };
      }
      if (row.prev !== expectedPrev || row.hash !== rowHash(row)) {
        return { ok: false, checked: index, error: `Audit hash chain breaks at entry ${index}` };
      }
      expectedPrev = row.hash;
      previousSequence = row.seq;
    }
    if (this.lastHash !== expectedPrev) {
      return { ok: false, checked: this.entries.length, error: 'Audit tail hash differs from final entry' };
    }
    if (!Number.isSafeInteger(this.nextSequence) || this.nextSequence !== (previousSequence ?? 0) + 1) {
      return { ok: false, checked: this.entries.length, error: 'Audit next sequence is inconsistent' };
    }
    return {
      ok: true,
      checked: this.entries.length,
      head: this.head,
      lastHash: this.lastHash,
      nextSequence: this.nextSequence,
      legacyMigrated: this.legacyMigrated
    };
  }

  persist() {
    if (!this.file) return;
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const temp = `${this.file}.${process.pid}.${Date.now()}.tmp`;
    const saved = {
      version: 2,
      head: this.head,
      lastHash: this.lastHash,
      nextSequence: this.nextSequence,
      entries: this.entries
    };
    try {
      fs.writeFileSync(temp, JSON.stringify(saved, null, 2));
      fs.renameSync(temp, this.file);
    } finally {
      if (fs.existsSync(temp)) fs.rmSync(temp, { force: true });
    }
  }

  append(entry) {
    const integrity = this.verifyChain();
    if (!integrity.ok) throw new Error(`Cannot append to invalid audit chain: ${integrity.error}`);
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error('Audit event must be an object');
    const { at, seq, prev, hash, ...event } = entry;
    const row = this.addInMemory({ at: new Date().toISOString(), ...event });
    this.persist();
    this.legacyMigrated = false;
    return row;
  }

  list(limit = 100) {
    return this.entries.slice(-Math.max(1, Math.min(500, Number(limit) || 100)));
  }

  reset() {
    this.head = AUDIT_GENESIS;
    this.lastHash = AUDIT_GENESIS;
    this.nextSequence = 1;
    this.entries = [];
    this.loadError = null;
    this.legacyMigrated = false;
    this.persist();
  }
}
