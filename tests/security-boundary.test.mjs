import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { intentFromPaymentRequired } from '../src/core/intent.mjs';
import { encodePaymentRequiredHeader } from '../src/core/x402.mjs';
import { makePaymentRequired } from '../src/demo/attacks.mjs';
import { SentinelRuntime } from '../src/app/demo-runtime.mjs';
import { evaluatePublicGuardRequest } from '../src/security/guard-request.mjs';
import { IntentAuthority } from '../src/security/intent-authority.mjs';
import { evaluatePaymentRequired, issueApproval, settleDryRun } from '../src/security/payment-guard.mjs';
import { GuardLedger } from '../src/state/guard-ledger.mjs';

const policy = JSON.parse(fs.readFileSync(new URL('../policy.json', import.meta.url), 'utf8'));
const payment = makePaymentRequired('normal');
const NOW = new Date('2026-10-31T08:00:00.000Z');

function setup(maxUses = 1) {
  const authority = new IntentAuthority();
  const ledger = new GuardLedger();
  const permit = authority.issue(intentFromPaymentRequired(payment, { maxUses }), policy, NOW);
  const context = { requestedUrl: payment.resource.url, now: NOW, intentPermit: permit, intentAuthority: authority };
  return { authority, ledger, permit, context };
}

test('Red cannot create two approvals from a single-use permit before settlement', () => {
  const { ledger, permit, context } = setup();
  const first = evaluatePaymentRequired(payment, policy, ledger, context);
  const second = evaluatePaymentRequired(payment, policy, ledger, context);
  assert.equal(first.decision, 'allow');
  assert.equal(second.decision, 'allow');
  let signerCalls = 0;
  const approveAndSign = evaluation => {
    const approval = issueApproval(evaluation, payment, policy, ledger, NOW);
    signerCalls += 1;
    return approval;
  };
  const approval = approveAndSign(first);
  assert.equal(ledger.permitUses(permit.body.permitId), 1);
  assert.throws(() => approveAndSign(second), /remaining uses/i);
  assert.equal(signerCalls, 1);
  assert.equal(ledger.reservedToday(NOW), BigInt(payment.accepts[0].amount));
  const recheck = evaluatePaymentRequired(payment, policy, ledger, context);
  assert.equal(recheck.decision, 'block');
  assert.ok(recheck.reasonCodes.includes('PERMIT_USES'));
  assert.equal(settleDryRun(approval, policy, ledger, NOW).settled, true);
});

test('an explicitly two-use signed permit allows exactly two approvals', () => {
  const { ledger, permit, context } = setup(2);
  const first = evaluatePaymentRequired(payment, policy, ledger, context);
  const second = evaluatePaymentRequired(payment, policy, ledger, context);
  const approval1 = issueApproval(first, payment, policy, ledger, NOW);
  const approval2 = issueApproval(second, payment, policy, ledger, NOW);
  assert.equal(ledger.permitUses(permit.body.permitId), 2);
  assert.throws(() => issueApproval(second, payment, policy, ledger, NOW), /remaining uses/i);
  assert.equal(settleDryRun(approval1, policy, ledger, NOW).settled, true);
  assert.equal(settleDryRun(approval2, policy, ledger, NOW).settled, true);
});

test('Red cannot backdate the public guard request to revive an expired permit', () => {
  const { authority, permit, ledger } = setup();
  const late = new Date(NOW.getTime() + 301_000);
  const base = { paymentRequired: payment, requestedUrl: payment.resource.url, intentPermit: permit };
  const forged = evaluatePublicGuardRequest({ ...base, now: NOW.toISOString() }, {
    policy, ledger, intentAuthority: authority, clock: () => late
  });
  assert.equal(forged.decision, 'block');
  assert.ok(forged.reasonCodes.includes('UNTRUSTED_TIMESTAMP'));
  const expired = evaluatePublicGuardRequest(base, { policy, ledger, intentAuthority: authority, clock: () => late });
  assert.equal(expired.decision, 'block');
  const invalid = evaluatePublicGuardRequest(base, {
    policy, ledger, intentAuthority: authority, clock: () => new Date('invalid')
  });
  assert.equal(invalid.decision, 'block');
  assert.ok(invalid.reasonCodes.includes('INVALID_EVALUATION_TIME'));
  assert.equal(ledger.permitUses(permit.body.permitId), 0);
});

test('the signed intent blocks a longer timeout even within the broader wallet policy', () => {
  const { ledger, context } = setup();
  const changed = structuredClone(payment);
  changed.accepts[0].maxTimeoutSeconds += 1;
  assert.ok(changed.accepts[0].maxTimeoutSeconds <= policy.maxTimeoutSeconds);
  const evaluation = evaluatePaymentRequired(changed, policy, ledger, context);
  assert.equal(evaluation.decision, 'block');
  assert.ok(evaluation.reasonCodes.includes('INTENT_TIMEOUT'));
  assert.throws(() => issueApproval(evaluation, changed, policy, ledger, NOW), /blocked payment/i);
});

test('malformed payment fields fail closed without creating a signing payload', () => {
  const { ledger, context } = setup();
  const mutations = [
    offer => { offer.network = '__proto__'; },
    offer => { offer.payTo = { address: offer.payTo }; },
    offer => { offer.asset = [offer.asset]; },
    offer => { offer.extra = []; },
    offer => { offer.amount = { value: '50000' }; }
  ];
  let signerCalls = 0;
  for (const mutate of mutations) {
    const candidate = structuredClone(payment);
    mutate(candidate.accepts[0]);
    const result = evaluatePaymentRequired(candidate, policy, ledger, context);
    assert.equal(result.decision, 'block');
    assert.ok(result.reasonCodes.includes('MALFORMED_REQUIREMENTS'));
    assert.throws(() => { issueApproval(result, candidate, policy, ledger, NOW); signerCalls += 1; }, /blocked payment/i);
  }
  for (const candidate of [{ ...payment, accepts: {} }, { ...payment, accepts: [[]] }, []]) {
    const result = evaluatePaymentRequired(candidate, policy, ledger, context);
    assert.equal(result.decision, 'block');
  }
  assert.equal(signerCalls, 0);
});

test('agent flow never reaches its wallet stage for malformed or expired challenges', async () => {
  const audit = { append() {} };
  const runtime = new SentinelRuntime({ policy, audit, port: 4173, adminToken: 'test-token' });
  const originalFetch = globalThis.fetch;
  let calls = 0;
  const challengeResponse = required => ({
    status: 402,
    headers: { get(name) { return name === 'payment-required' ? encodePaymentRequiredHeader(required) : null; } }
  });
  try {
    const malformed = structuredClone(payment);
    malformed.accepts[0].payTo = { address: payment.accepts[0].payTo };
    globalThis.fetch = async () => { calls += 1; return challengeResponse(malformed); };
    const rejected = await runtime.runAgentFlow();
    assert.equal(rejected.status, 403);
    assert.equal(rejected.result.wallet.signed, false);
    assert.equal(calls, 1);

    calls = 0;
    const normalIssue = runtime.intentAuthority.issue.bind(runtime.intentAuthority);
    runtime.intentAuthority.issue = (intent, currentPolicy) => normalIssue(intent, currentPolicy, new Date(Date.now() - 600_000));
    globalThis.fetch = async () => { calls += 1; return challengeResponse(payment); };
    const expired = await runtime.runAgentFlow();
    assert.equal(expired.status, 403);
    assert.equal(expired.result.wallet.signed, false);
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
