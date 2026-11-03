import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluatePaymentRequired, issueApproval, settleDryRun } from '../src/security/payment-guard.mjs';
import { GuardLedger } from '../src/state/guard-ledger.mjs';
import { makePaymentRequired, constants } from '../src/demo/attacks.mjs';
import { runSuite } from '../src/cli/demo-runner.mjs';
import { IntentAuthority } from '../src/security/intent-authority.mjs';
import { createIntent } from '../src/core/intent.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const policy = JSON.parse(fs.readFileSync(path.resolve(__dirname, '..', 'policy.json'), 'utf8'));
const NOW = new Date('2026-10-31T08:00:00.000Z');

function evaluate(id, ledger = new GuardLedger()) {
  const payment = makePaymentRequired(id);
  const requestedUrl = id === 'resource-swap' ? 'https://api.safe.test/premium-data' : payment.resource.url;
  const authority = new IntentAuthority();
  const intentPermit = authority.issue(createIntent(), policy, NOW);
  return { payment, ledger, evaluation: evaluatePaymentRequired(payment, policy, ledger, { requestedUrl, now: NOW, intentPermit, intentAuthority: authority }) };
}

test('normal payment is allowed', () => {
  assert.equal(evaluate('normal').evaluation.decision, 'allow');
});

test('overpayment is blocked', () => {
  const result = evaluate('overpay').evaluation;
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('AMOUNT_LIMIT'));
});

test('wrong recipient is blocked', () => {
  const result = evaluate('wrong-party').evaluation;
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('RECIPIENT'));
});

test('resource swap is blocked', () => {
  const result = evaluate('resource-swap').evaluation;
  assert.equal(result.decision, 'block');
  assert.ok(result.reasonCodes.includes('RESOURCE_BINDING') || result.reasonCodes.includes('PERMIT_RESOURCE_URL'));
});

test('guard does not blindly choose poisoned first offer', () => {
  const result = evaluate('malicious-first-offer').evaluation;
  assert.equal(result.decision, 'allow');
  assert.equal(result.selectedIndex, 1);
});

test('recipient mutation after approval is blocked at settlement', () => {
  const { payment, ledger, evaluation } = evaluate('normal');
  const payload = issueApproval(evaluation, payment, policy, ledger, NOW);
  payload.payload.authorization.to = constants.EVIL_PAYEE;
  const settlement = settleDryRun(payload, policy, ledger, NOW);
  assert.equal(settlement.decision, 'block');
  assert.ok(settlement.reasonCodes.includes('RECIPIENT'));
});

test('same authorization cannot settle twice', () => {
  const { payment, ledger, evaluation } = evaluate('normal');
  const payload = issueApproval(evaluation, payment, policy, ledger, NOW);
  assert.equal(settleDryRun(payload, policy, ledger, NOW).settled, true);
  const replay = settleDryRun(payload, policy, ledger, NOW);
  assert.equal(replay.decision, 'block');
  assert.ok(replay.reasonCodes.includes('REPLAY'));
});

test('daily budget is enforced cumulatively', () => {
  const ledger = new GuardLedger();
  const payment = makePaymentRequired('normal');
  payment.accepts[0].amount = '50000';
  for (let i = 0; i < 20; i++) {
    const authority = new IntentAuthority();
    const intentPermit = authority.issue(createIntent(), policy, NOW);
    const evaluation = evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, now: NOW, intentPermit, intentAuthority: authority });
    assert.equal(evaluation.decision, 'allow');
    const payload = issueApproval(evaluation, payment, policy, ledger, NOW);
    assert.equal(settleDryRun(payload, policy, ledger, NOW).settled, true);
  }
  const authority = new IntentAuthority();
  const intentPermit = authority.issue(createIntent(), policy, NOW);
  const blocked = evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, now: NOW, intentPermit, intentAuthority: authority });
  assert.equal(blocked.decision, 'block');
  assert.ok(blocked.reasonCodes.includes('BUDGET'));
});

test('full adversarial suite matches expected decisions', () => {
  const suite = runSuite(policy);
  assert.equal(suite.passed, suite.total);
});
