import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { RedBlueArena } from '../src/demo/arena.mjs';
import { IntentAuthority } from '../src/security/intent-authority.mjs';
import { makePaymentRequired } from '../src/demo/attacks.mjs';
import { capabilityProfile, applicableResearchTests, compareAgainstOriginal } from '../src/research/paper-analysis.mjs';

const policy = JSON.parse(fs.readFileSync(new URL('../policy.json', import.meta.url), 'utf8'));

test('research profiler discovers x402 features and applicable mutations', () => {
  const pr = makePaymentRequired('normal');
  const p = capabilityProfile(pr);
  assert.equal(p.x402Version, 2);
  assert.deepEqual(p.networks, ['eip155:84532']);
  assert.ok(applicableResearchTests(pr).some(x => x.id === 'wrong-party'));
  assert.ok(applicableResearchTests(pr).some(x => x.id === 'flow'));
});

test('ground truth is anchored to original merchant challenge, not Blue policy', () => {
  const original = makePaymentRequired('normal');
  const changed = structuredClone(original);
  changed.accepts[0].payTo = '0x9999999999999999999999999999999999999999';
  const truth = compareAgainstOriginal(original, changed);
  assert.equal(truth.classification, 'attack');
  assert.equal(truth.expected, 'block');
});

test('false positive is not counted as a true bypass', () => {
  const arena = new RedBlueArena(policy, null, new IntentAuthority());
  arena.setPolicy({ maxPerPayment: '1000', merchant: { maxAmount: '1000', payTo: policy.merchants['api.safe.test'].payTo } });
  const original = makePaymentRequired('normal');
  const item = arena.submit({ originalPaymentRequired: original, paymentRequired: structuredClone(original), requestedUrl: original.resource.url });
  assert.equal(item.classification, 'legitimate');
  assert.equal(item.guard.action, 'block');
  assert.equal(item.outcomeType, 'false-positive');
  const s = arena.snapshot('judge');
  assert.equal(s.metrics.falsePositives, 1);
  assert.equal(s.metrics.guardBypasses, 0);
  assert.equal(s.scores.red, 1);
});
