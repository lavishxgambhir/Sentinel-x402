import test from 'node:test';
import assert from 'node:assert/strict';
import { ChallengeRegistry } from '../src/state/challenge-registry.mjs';

test('merchant challenges are single-use and expire at their boundary', () => {
  const registry = new ChallengeRegistry({ ttlMs: 100 });
  const issued = registry.issue({ resource: '/premium' }, 1_000);
  assert.equal(registry.consume(issued.challengeId, 1_099).resource, '/premium');
  assert.equal(registry.consume(issued.challengeId, 1_099), null);
  const expired = registry.issue({ resource: '/premium' }, 1_000);
  assert.equal(registry.consume(expired.challengeId, 1_100), null);
});
