import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import { AuditLog } from '../src/app/audit-log.mjs';
import { SentinelRuntime } from '../src/app/demo-runtime.mjs';
import { hydrateRuntime, serializeRuntime } from '../src/app/runtime-state.mjs';
import { IntentAuthority } from '../src/security/intent-authority.mjs';

const policy = JSON.parse(fs.readFileSync(new URL('../policy.json', import.meta.url), 'utf8'));
const authority = new IntentAuthority();
const makeRuntime = () => new SentinelRuntime({
  policy, audit: new AuditLog(null), port: null,
  adminToken: 'test-admin', intentAuthority: authority, serverless: true
});

test('durable state keeps one-use challenges, arena scores, audit, and BigInt ledger values', () => {
  const first = makeRuntime();
  const challenge = first.issueArenaChallenge();
  first.ledger.spentByDay.set('2026-11-01', 50000n);
  first.ledger.knownRecipients.add('0x1111111111111111111111111111111111111111');
  first.arena.setTrainingMode('merchant-timeout');
  first.audit.append({ type: 'state_test' });

  const restored = hydrateRuntime(makeRuntime(), JSON.parse(serializeRuntime(first)));
  assert.equal(restored.ledger.spentByDay.get('2026-11-01'), 50000n);
  assert.equal(restored.ledger.knownRecipients.size, 1);
  assert.equal(restored.arena.snapshot().trainingMode, 'merchant-timeout');
  assert.equal(restored.audit.verifyChain().ok, true);

  const changed = structuredClone(challenge.paymentRequired);
  changed.accepts[0].maxTimeoutSeconds += 1;
  const result = restored.submitArenaChallenge({ challengeId: challenge.challengeId, paymentRequired: changed });
  assert.equal(result.item.outcomeType, 'bypass');
  const savedAgain = hydrateRuntime(makeRuntime(), serializeRuntime(restored));
  assert.equal(savedAgain.arena.snapshot().scores.red, 1);
  assert.equal(savedAgain.submitArenaChallenge({ challengeId: challenge.challengeId, paymentRequired: changed }).status, 400);
});

test('serverless agent control completes the dry-run 402 to 200 flow', async () => {
  const runtime = makeRuntime();
  const { status, result } = await runtime.runAgentFlow();
  assert.equal(status, 200);
  assert.equal(result.http.firstStatus, 402);
  assert.equal(result.http.secondStatus, 200);
  assert.equal(result.wallet.signed, true);
  assert.equal(result.wallet.broadcast, false);
  const restored = hydrateRuntime(makeRuntime(), serializeRuntime(runtime));
  assert.equal(restored.ledger.snapshot(policy).approvalsIssued, 1);
  assert.equal(restored.audit.verifyChain().ok, true);
});
