import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { IntentAuthority } from '../src/security/intent-authority.mjs';
import { createIntent } from '../src/core/intent.mjs';
import { evaluatePaymentRequired, issueApproval, settleDryRun } from '../src/security/payment-guard.mjs';
import { GuardLedger } from '../src/state/guard-ledger.mjs';
import { RedBlueArena } from '../src/demo/arena.mjs';
import { makePaymentRequired } from '../src/demo/attacks.mjs';

const basePolicy = JSON.parse(fs.readFileSync(new URL('../policy.json', import.meta.url), 'utf8'));
const NOW = new Date('2026-10-31T08:00:00.000Z');

function authorized(payment, policy = basePolicy, ledger = new GuardLedger(), requestedUrl = payment.resource.url) {
  const authority = new IntentAuthority();
  const permit = authority.issue(createIntent(), policy, NOW);
  const evaluation = evaluatePaymentRequired(payment, policy, ledger, {
    requestedUrl, requestedMethod: 'GET', now: NOW, intentPermit: permit, intentAuthority: authority
  });
  return { authority, permit, evaluation, ledger };
}

test('configured guard requires an independently signed permit', () => {
  const payment = makePaymentRequired('normal');
  const result = evaluatePaymentRequired(payment, basePolicy, new GuardLedger(), { requestedUrl: payment.resource.url, now: NOW });
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('PERMIT_REQUIRED'));
});

test('requested query is bound to the payment resource and signed intent', () => {
  const payment = makePaymentRequired('normal');
  const { evaluation } = authorized(payment, basePolicy, new GuardLedger(), `${payment.resource.url}?tier=admin`);
  assert.equal(evaluation.decision, 'block');
  assert.ok(evaluation.reasonCodes.includes('RESOURCE_BINDING'));
});

test('pending approvals reserve budget before settlement', () => {
  const policy = structuredClone(basePolicy);
  policy.dailyBudget = '50000';
  const payment = makePaymentRequired('normal');
  const ledger = new GuardLedger();
  const first = authorized(payment, policy, ledger);
  const second = authorized(payment, policy, ledger);
  assert.equal(first.evaluation.decision, 'allow');
  assert.equal(second.evaluation.decision, 'allow');

  const payload = issueApproval(first.evaluation, payment, policy, ledger, NOW);
  assert.equal(ledger.reservedToday(NOW), 50000n);
  assert.throws(() => issueApproval(second.evaluation, payment, policy, ledger, NOW), /budget exhausted/i);

  const secondRecheck = evaluatePaymentRequired(payment, policy, ledger, {
    requestedUrl: payment.resource.url, now: NOW,
    intentPermit: second.permit, intentAuthority: second.authority
  });
  assert.equal(secondRecheck.decision, 'block');
  assert.ok(secondRecheck.reasonCodes.includes('BUDGET'));

  assert.equal(settleDryRun(payload, policy, ledger, NOW).settled, true);
  assert.equal(ledger.reservedToday(NOW), 0n);
  assert.equal(ledger.spentToday(NOW), 50000n);
});

test('failed settlement releases reservation and invalidates the approval', () => {
  const payment = makePaymentRequired('normal');
  const { evaluation, ledger } = authorized(payment);
  const payload = issueApproval(evaluation, payment, basePolicy, ledger, NOW);
  const correctRecipient = payload.payload.authorization.to;
  payload.payload.authorization.to = '0x9999999999999999999999999999999999999999';
  const failed = settleDryRun(payload, basePolicy, ledger, NOW);
  assert.equal(failed.decision, 'block');
  assert.equal(ledger.reservedToday(NOW), 0n);

  payload.payload.authorization.to = correctRecipient;
  const retry = settleDryRun(payload, basePolicy, ledger, NOW);
  assert.equal(retry.decision, 'block');
  assert.ok(retry.reasonCodes.includes('RESERVATION'));
});

test('malformed settlement also releases its pending reservation', () => {
  const payment = makePaymentRequired('normal');
  const { evaluation, ledger } = authorized(payment);
  const payload = issueApproval(evaluation, payment, basePolicy, ledger, NOW);
  payload.payload.authorization.value = 'not-an-amount';
  const result = settleDryRun(payload, basePolicy, ledger, NOW);
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('MALFORMED_AUTHORIZATION'));
  assert.equal(ledger.reservedToday(NOW), 0n);
});

test('settlement cannot alter approval metadata or authorization validity', () => {
  const payment = makePaymentRequired('normal');
  const first = authorized(payment);
  const payload = issueApproval(first.evaluation, payment, basePolicy, first.ledger, NOW);
  payload.guard.binding.permitId = 'forged-permit-id';
  const changedBinding = settleDryRun(payload, basePolicy, first.ledger, NOW);
  assert.equal(changedBinding.decision, 'block');
  assert.ok(changedBinding.reasonCodes.includes('APPROVAL_BINDING'));
  assert.equal(first.ledger.permitUses('forged-permit-id'), 0);

  const second = authorized(payment);
  const payload2 = issueApproval(second.evaluation, payment, basePolicy, second.ledger, NOW);
  payload2.payload.authorization.validBefore = String(Number(payload2.payload.authorization.validBefore) + 3600);
  const changedWindow = settleDryRun(payload2, basePolicy, second.ledger, NOW);
  assert.equal(changedWindow.decision, 'block');
  assert.ok(changedWindow.reasonCodes.includes('TIME_WINDOW'));
});

test('approval issued under stale policy cannot settle', () => {
  const payment = makePaymentRequired('normal');
  const { evaluation, ledger } = authorized(payment);
  const payload = issueApproval(evaluation, payment, basePolicy, ledger, NOW);
  const tightened = structuredClone(basePolicy);
  tightened.maxPerPayment = '1';
  const result = settleDryRun(payload, tightened, ledger, NOW);
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('POLICY_DIGEST'));
  assert.equal(ledger.reservedToday(NOW), 0n);
});

test('approval cannot settle after its signed intent permit expires', () => {
  const policy = structuredClone(basePolicy);
  policy.intentPermitTtlSeconds = 30;
  const now = new Date('2026-10-31T08:00:00.000Z');
  const payment = makePaymentRequired('normal');
  const { evaluation, ledger } = authorized(payment, policy, new GuardLedger(), payment.resource.url);
  const payload = issueApproval(evaluation, payment, policy, ledger, now);
  const result = settleDryRun(payload, policy, ledger, new Date(now.getTime() + 31_000));
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('PERMIT_TIME'));
  assert.equal(ledger.reservedToday(now), 0n);
});

test('arena refuses an untrusted round without a baseline', () => {
  const arena = new RedBlueArena(basePolicy, null, new IntentAuthority());
  assert.throws(() => arena.submit({ paymentRequired: makePaymentRequired('normal') }), /originalPaymentRequired/);
});
