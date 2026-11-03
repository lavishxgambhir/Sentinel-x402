import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { IntentAuthority } from '../src/security/intent-authority.mjs';
import { createIntent } from '../src/core/intent.mjs';
import { evaluatePaymentRequired, issueApproval, settleDryRun } from '../src/security/payment-guard.mjs';
import { GuardLedger } from '../src/state/guard-ledger.mjs';
import { makePaymentRequired, constants } from '../src/demo/attacks.mjs';

const policy = JSON.parse(fs.readFileSync(new URL('../policy.json', import.meta.url), 'utf8'));
const NOW = new Date('2026-10-31T08:00:00.000Z');

function setup() {
  const authority = new IntentAuthority();
  const ledger = new GuardLedger();
  const intent = createIntent();
  const permit = authority.issue(intent, policy, NOW);
  return { authority, ledger, intent, permit };
}

test('signed intent permit allows a matching x402 demand', () => {
  const { authority, ledger, permit } = setup();
  const payment = makePaymentRequired('normal');
  const result = evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, now: NOW, intentPermit: permit, intentAuthority: authority });
  assert.equal(result.decision, 'allow');
  assert.ok(result.permit?.permitId);
});

test('a validly signed permit cannot be altered after issuance', () => {
  const { authority, ledger, permit } = setup();
  permit.body.payment.maxAmount = '999999999';
  const payment = makePaymentRequired('normal');
  const result = evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, now: NOW, intentPermit: permit, intentAuthority: authority });
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('PERMIT_SIGNATURE'));
});

test('wrong-party demand is blocked by intent binding even before signing', () => {
  const { authority, ledger, permit } = setup();
  const payment = makePaymentRequired('wrong-party');
  const result = evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, now: NOW, intentPermit: permit, intentAuthority: authority });
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('INTENT_RECIPIENT'));
});

test('overpayment is blocked by signed intent ceiling', () => {
  const { authority, ledger, permit } = setup();
  const payment = makePaymentRequired('overpay');
  const result = evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, now: NOW, intentPermit: permit, intentAuthority: authority });
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('INTENT_AMOUNT'));
});

test('intent permit is single-use at settlement boundary', () => {
  const { authority, ledger, permit } = setup();
  const payment = makePaymentRequired('normal');
  const evaluation = evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, now: NOW, intentPermit: permit, intentAuthority: authority });
  const payload = issueApproval(evaluation, payment, policy, ledger, NOW);
  assert.equal(settleDryRun(payload, policy, ledger, NOW, { permitMaxUses: 1 }).settled, true);
  const evaluation2 = evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, now: NOW, intentPermit: permit, intentAuthority: authority });
  assert.equal(evaluation2.decision, 'block');
  assert.ok(evaluation2.reasonCodes.includes('PERMIT_USES'));
});

test('post-approval recipient mutation is blocked even with a valid permit', () => {
  const { authority, ledger, permit } = setup();
  const payment = makePaymentRequired('normal');
  const evaluation = evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, now: NOW, intentPermit: permit, intentAuthority: authority });
  const payload = issueApproval(evaluation, payment, policy, ledger, NOW);
  payload.payload.authorization.to = constants.EVIL_PAYEE;
  const result = settleDryRun(payload, policy, ledger, NOW, { permitMaxUses: 1 });
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('RECIPIENT'));
});

test('signed intent binds the HTTP method and canonical resource URL', () => {
  const { authority, ledger, permit } = setup();
  const payment = makePaymentRequired('normal');
  const wrongMethod = evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, requestedMethod: 'POST', now: NOW, intentPermit: permit, intentAuthority: authority });
  assert.equal(wrongMethod.decision, 'block');
  assert.ok(wrongMethod.reasonCodes.includes('PERMIT_METHOD'));

  const querySwap = structuredClone(payment);
  querySwap.resource.url = 'https://api.safe.test/premium-data?tier=admin';
  const wrongUrl = evaluatePaymentRequired(querySwap, policy, ledger, { requestedUrl: querySwap.resource.url, requestedMethod: 'GET', now: NOW, intentPermit: permit, intentAuthority: authority });
  assert.equal(wrongUrl.decision, 'block');
  assert.ok(wrongUrl.reasonCodes.includes('PERMIT_RESOURCE_URL'));
});

test('changing policy invalidates a previously issued permit', () => {
  const { authority, ledger, permit } = setup();
  const payment = makePaymentRequired('normal');
  const tightened = structuredClone(policy);
  tightened.dailyBudget = '900000';
  const result = evaluatePaymentRequired(payment, tightened, ledger, { requestedUrl: payment.resource.url, requestedMethod: 'GET', now: NOW, intentPermit: permit, intentAuthority: authority });
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('PERMIT_POLICY_DIGEST'));
});

test('expired signed intent permit is rejected', () => {
  const { authority, ledger, permit } = setup();
  const payment = makePaymentRequired('normal');
  const later = new Date(NOW.getTime() + 10 * 60 * 1000);
  const result = evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, requestedMethod: 'GET', now: later, intentPermit: permit, intentAuthority: authority });
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('PERMIT_SIGNATURE'));
});

test('payment flow swap from authorization to upfront is rejected', () => {
  const { authority, ledger, permit } = setup();
  const payment = makePaymentRequired('payment-flow-swap');
  const result = evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, requestedMethod: 'GET', now: NOW, intentPermit: permit, intentAuthority: authority });
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('PAYMENT_FLOW') || result.reasonCodes.includes('INTENT_FLOW'));
});

test('asset transfer method swap from eip3009 to permit2 is rejected', () => {
  const { authority, ledger, permit } = setup();
  const payment = makePaymentRequired('transfer-method-swap');
  const result = evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, requestedMethod: 'GET', now: NOW, intentPermit: permit, intentAuthority: authority });
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('TRANSFER_METHOD') || result.reasonCodes.includes('INTENT_TRANSFER_METHOD'));
});

test('post-authorization settlement correspondence detects recipient/network/asset divergence', () => {
  const { authority, ledger, permit } = setup();
  const payment = makePaymentRequired('normal');
  const evaluation = evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, requestedMethod: 'GET', now: NOW, intentPermit: permit, intentAuthority: authority });
  const payload = issueApproval(evaluation, payment, policy, ledger, NOW);
  const result = settleDryRun(payload, policy, ledger, NOW, {
    permitMaxUses: 1,
    actualAmount: payload.payload.authorization.value,
    actualRecipient: constants.EVIL_PAYEE,
    actualNetwork: 'eip155:1',
    actualAsset: '0x8888888888888888888888888888888888888888'
  });
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('SETTLED_RECIPIENT'));
  assert.ok(result.reasonCodes.includes('SETTLED_NETWORK'));
  assert.ok(result.reasonCodes.includes('SETTLED_ASSET'));
});
