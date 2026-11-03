import { GuardLedger } from '../state/guard-ledger.mjs';
import { ChallengeRegistry } from '../state/challenge-registry.mjs';

// JSONB cannot represent the maps, sets, and BigInts used by the guard ledger.
// The tagged encoding is private to the server; no client-provided value is
// decoded through this path.
function pack(value) {
  if (typeof value === 'bigint') return { $type: 'bigint', value: value.toString() };
  if (value instanceof Date) return { $type: 'date', value: value.toISOString() };
  if (value instanceof Map) return { $type: 'map', value: [...value].map(([key, item]) => [pack(key), pack(item)]) };
  if (value instanceof Set) return { $type: 'set', value: [...value].map(pack) };
  if (Array.isArray(value)) return value.map(pack);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value)
      .filter(([, item]) => item !== undefined)
      .map(([key, item]) => [key, pack(item)]));
  }
  return value;
}

function unpack(value) {
  if (Array.isArray(value)) return value.map(unpack);
  if (!value || typeof value !== 'object') return value;
  if (value.$type === 'bigint') return BigInt(value.value);
  if (value.$type === 'date') return new Date(value.value);
  if (value.$type === 'map') return new Map(value.value.map(([key, item]) => [unpack(key), unpack(item)]));
  if (value.$type === 'set') return new Set(value.value.map(unpack));
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, unpack(item)]));
}

function ownState(instance, except = []) {
  const excluded = new Set(except);
  return Object.fromEntries(Object.entries(instance).filter(([key]) => !excluded.has(key)));
}

export function serializeRuntime(runtime) {
  const state = {
    version: 1,
    arena: ownState(runtime.arena, ['audit', 'intentAuthority', 'basePolicy']),
    ledger: ownState(runtime.ledger),
    challenges: ownState(runtime.challenges),
    evaluationReports: runtime.evaluationReports,
    audit: ownState(runtime.audit, ['file', 'retention'])
  };
  return JSON.stringify(pack(state));
}

export function hydrateRuntime(runtime, serialized) {
  const saved = unpack(typeof serialized === 'string' ? JSON.parse(serialized) : serialized);
  if (!saved || saved.version !== 1 || !saved.arena || !saved.ledger || !saved.challenges || !saved.audit) {
    throw new Error('Stored Sentinel state has an unsupported format');
  }

  const arenaLedger = saved.arena.guardLedger;
  for (const [key, value] of Object.entries(saved.arena)) {
    if (key !== 'guardLedger' && Object.hasOwn(runtime.arena, key)) runtime.arena[key] = value;
  }
  runtime.arena.guardLedger = Object.assign(new GuardLedger(), arenaLedger);
  runtime.ledger = Object.assign(new GuardLedger(), saved.ledger);
  runtime.challenges = Object.assign(new ChallengeRegistry(), saved.challenges);
  runtime.evaluationReports = saved.evaluationReports;
  for (const key of ['head', 'lastHash', 'nextSequence', 'entries', 'legacyMigrated', 'loadError']) {
    if (Object.hasOwn(saved.audit, key)) runtime.audit[key] = saved.audit[key];
  }
  if (!runtime.audit.verifyChain().ok) throw new Error('Stored Sentinel audit chain failed integrity verification');
  return runtime;
}
