import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import { SentinelRuntime } from '../src/app/demo-runtime.mjs';
import { compareAgainstOriginal } from '../src/research/paper-analysis.mjs';
import { makePaymentRequired } from '../src/demo/attacks.mjs';

const policy = JSON.parse(fs.readFileSync(new URL('../policy.json', import.meta.url), 'utf8'));

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

test('referee treats equivalent URL spellings as the same protected resource', () => {
  const original = makePaymentRequired('normal');
  const received = clone(original);
  received.resource.url = 'https://API.SAFE.TEST:443/premium-data#presentation';

  const truth = compareAgainstOriginal(original, received);

  assert.equal(truth.expected, 'allow');
  assert.equal(truth.classification, 'legitimate');
});

test('referee expects malformed x402 requirements to be blocked', () => {
  const original = makePaymentRequired('normal');
  const malformedCases = [
    payment => { payment.accepts[0].amount = 50000; },
    payment => { payment.accepts[0].amount = '0xc350'; },
    payment => { payment.accepts[0].amount = '-1'; },
    payment => { payment.accepts[0].maxTimeoutSeconds = '60'; },
    payment => { payment.accepts = Array.from({ length: 100 }, () => clone(original.accepts[0])); },
    payment => { payment.accepts = { not: 'an array' }; }
  ];

  for (const mutate of malformedCases) {
    const received = clone(original);
    mutate(received);
    const truth = compareAgainstOriginal(original, received);
    assert.equal(truth.expected, 'block');
    assert.deepEqual(truth.violations, ['MALFORMED_REQUIREMENTS']);
  }
});

test('arena rejects malformed submissions with a stable client error', () => {
  const runtime = new SentinelRuntime({
    policy,
    audit: { append() {} },
    port: 4173,
    adminToken: 'test-token'
  });

  const result = runtime.submitArenaChallenge({
    challengeId: 'unused',
    paymentRequired: { x402Version: 2, accepts: {} }
  });

  assert.deepEqual(result, {
    ok: false,
    status: 400,
    error: 'Invalid paymentRequired shape'
  });
});
