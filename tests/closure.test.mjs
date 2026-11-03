import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateClosure } from '../src/security/relationship-check.mjs';
import { evaluateRecipientRisk } from '../src/security/recipient-risk.mjs';
import { propertyTagsFor } from '../src/security/security-properties.mjs';

const wallet = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const payee = '0x2222222222222222222222222222222222222222';
const relay = '0x3333333333333333333333333333333333333333';
const graph = { enabled: true, source: 'seeded-demo-graph', maxHops: 3, edges: [{ from: payee, to: relay }, { from: relay, to: wallet }] };

test('seeded closure graph distinguishes returning, related, and unrelated recipients', () => {
  const block = evaluateClosure(payee, wallet, graph);
  assert.equal(block.verdict, 'block');
  assert.deepEqual(block.path, [payee, relay, wallet]);
  assert.equal(evaluateClosure(relay, payee, graph).verdict, 'review');
  assert.equal(evaluateClosure('0x1111111111111111111111111111111111111111', wallet, graph).verdict, 'allow');
});

test('approved-looking payee is blocked by seeded closure evidence', () => {
  const risk = evaluateRecipientRisk(payee, { walletAddress: wallet, risk: { closure: graph } });
  assert.equal(risk.hardBlock, true);
  assert.equal(risk.closure.verdict, 'block');
  assert.equal(risk.signals[0].code, 'WALLET_CLOSURE');
});

test('reason codes map to named security properties', () => {
  assert.deepEqual(propertyTagsFor(['INTENT_RECIPIENT', 'BUDGET', 'COMPLIANCE']).map(x => x.id), ['P3', 'P4', 'P8']);
});
