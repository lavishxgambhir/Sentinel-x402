import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { RedBlueArena, refereePayment } from '../src/demo/arena.mjs';
import { makePaymentRequired } from '../src/demo/attacks.mjs';
import { IntentAuthority } from '../src/security/intent-authority.mjs';

const policy = JSON.parse(fs.readFileSync(new URL('../policy.json', import.meta.url), 'utf8'));

test('referee allows a normal payment', () => {
  assert.equal(refereePayment(makePaymentRequired('normal'), policy, 'https://api.safe.test/premium-data').expected, 'allow');
});

test('referee blocks overpayment and wrong-party attacks', () => {
  assert.equal(refereePayment(makePaymentRequired('overpay'), policy, 'https://api.safe.test/premium-data').expected, 'block');
  assert.equal(refereePayment(makePaymentRequired('wrong-party'), policy, 'https://api.safe.test/premium-data').expected, 'block');
});

test('arena automatically scores guard correctness', () => {
  const arena = new RedBlueArena(policy, null, new IntentAuthority());
  const safe = arena.submit({ paymentRequired: makePaymentRequired('normal'), originalPaymentRequired: makePaymentRequired('normal'), requestedUrl:'https://api.safe.test/premium-data' });
  assert.equal(safe.guard.action, 'allow');
  assert.equal(arena.snapshot().scores.blue, 1);
  const attack = arena.submit({ paymentRequired: makePaymentRequired('wrong-party'), originalPaymentRequired: makePaymentRequired('normal'), requestedUrl:'https://api.safe.test/premium-data' });
  assert.equal(attack.guard.action, 'block');
  assert.equal(arena.snapshot().scores.blue, 2);
  assert.equal(arena.snapshot().metrics.attackBlockRate, 100);
  assert.equal(arena.snapshot().metrics.legitPassRate, 100);
});

test('one-second timeout wins only in the labeled vulnerable arena fixture', () => {
  const arena = new RedBlueArena(policy, null, new IntentAuthority());
  const original = makePaymentRequired('normal');
  const changed = structuredClone(original);
  changed.accepts[0].maxTimeoutSeconds += 1;
  const submit = paymentRequired => arena.submit({
    originalPaymentRequired: original,
    paymentRequired,
    requestedUrl: original.resource.url,
    redLabel: 'Timeout +1 second'
  });

  const secure = submit(changed);
  assert.equal(secure.groundTruth.expected, 'block');
  assert.equal(secure.guard.action, 'block');
  assert.ok(secure.guard.reasonCodes.includes('INTENT_TIMEOUT'));
  assert.equal(secure.wallet.signed, false);

  arena.setTrainingMode('merchant-timeout');
  const vulnerable = submit(changed);
  assert.equal(vulnerable.trainingMode, 'merchant-timeout');
  assert.equal(vulnerable.intentPermit.maxTimeoutSeconds, original.accepts[0].maxTimeoutSeconds + 1);
  assert.equal(vulnerable.groundTruth.expected, 'block');
  assert.equal(vulnerable.guard.action, 'allow');
  assert.equal(vulnerable.outcomeType, 'bypass');
  assert.equal(vulnerable.wallet.signed, true);
  assert.equal(vulnerable.wallet.broadcast, false);
  assert.equal(arena.snapshot().scores.red, 1);

  const wrongParty = submit(makePaymentRequired('wrong-party'));
  assert.equal(wrongParty.guard.action, 'block');
  arena.setTrainingMode('secure');
  assert.equal(submit(changed).outcomeType, 'attack-blocked');
  assert.throws(() => arena.setTrainingMode('anything-else'));
  assert.equal(arena.snapshot().trainingMode, 'secure');
  arena.setTrainingMode('merchant-timeout');
  arena.reset();
  assert.equal(arena.snapshot().trainingMode, 'secure');
});

test('live snapshots cap history without changing full judge history', () => {
  const arena = new RedBlueArena(policy, null, new IntentAuthority());
  for (let index = 0; index < 14; index += 1) {
    arena.submit({
      paymentRequired: makePaymentRequired('normal'),
      originalPaymentRequired: makePaymentRequired('normal'),
      requestedUrl: 'https://api.safe.test/premium-data'
    });
  }
  assert.equal(arena.snapshot('red', 12).requests.length, 12);
  assert.equal(arena.snapshot('judge', 1).requests.length, 1);
  assert.equal(arena.snapshot('judge').requests.length, 14);
  assert.equal(arena.snapshot('judge', 1).requests[0].round, 14);
});

test('blue can change policy between rounds', () => {
  const arena = new RedBlueArena(policy);
  arena.setPolicy({ merchant:{ maxAmount:'1000' } });
  const round = arena.submit({ paymentRequired: makePaymentRequired('normal'), originalPaymentRequired: makePaymentRequired('normal'), requestedUrl:'https://api.safe.test/premium-data' });
  assert.equal(round.guard.action, 'block');
});

test('blue policy edits retain the seeded closure payee for the demo', () => {
  const arena = new RedBlueArena(policy);
  arena.setPolicy({ merchant: { payTo: ['0x1111111111111111111111111111111111111111'] } });
  assert.ok(arena.publicPolicy().merchants['api.safe.test'].payTo.includes('0x2222222222222222222222222222222222222222'));
});

test('Blue policy rejects malformed input without partially changing the live policy', () => {
  const arena = new RedBlueArena(policy);
  const before = arena.publicPolicy();
  const invalidPatches = [
    { maxPerPayment: '100000.100' },
    { dailyBudget: '-1' },
    { maxTimeoutSeconds: '60.5' },
    { maxTimeoutSeconds: 3601 },
    { allowedNetworks: [] },
    { merchant: { maxAmount: '0x50000' } },
    { merchant: { payTo: ['not-a-wallet'] } }
  ];

  for (const patch of invalidPatches) {
    assert.throws(() => arena.setPolicy(patch));
    assert.deepEqual(arena.publicPolicy(), before);
  }
});

test('Blue policy accepts valid atomic-unit integer limits', () => {
  const arena = new RedBlueArena(policy);
  const updated = arena.setPolicy({
    maxPerPayment: '49000',
    dailyBudget: '1000000',
    maxTimeoutSeconds: '60',
    allowedNetworks: ['eip155:84532'],
    merchant: {
      maxAmount: '49000',
      payTo: ['0x1111111111111111111111111111111111111111']
    }
  });

  assert.equal(updated.maxPerPayment, '49000');
  assert.equal(updated.merchants['api.safe.test'].maxAmount, '49000');
});
