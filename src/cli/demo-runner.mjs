import { evaluatePaymentRequired, issueApproval, settleDryRun } from '../security/payment-guard.mjs';
import { GuardLedger } from '../state/guard-ledger.mjs';
import { makePaymentRequired, scenarioCatalog, constants } from '../demo/attacks.mjs';
import { IntentAuthority } from '../security/intent-authority.mjs';
import { createIntent } from '../core/intent.mjs';

export function runScenario(id, policy, ledger = new GuardLedger(), now = new Date()) {
  const paymentRequired = makePaymentRequired(id);
  const requestedUrl = id === 'resource-swap'
    ? 'https://api.safe.test/premium-data'
    : paymentRequired.resource.url;

  const intentAuthority = new IntentAuthority();
  const intentPermit = intentAuthority.issue(createIntent(), policy, now);
  const evaluation = evaluatePaymentRequired(paymentRequired, policy, ledger, { requestedUrl, now, intentPermit, intentAuthority });
  const result = {
    scenario: scenarioCatalog.find((item) => item.id === id),
    requestedUrl,
    paymentRequired,
    evaluation,
    approval: null,
    settlement: null,
    attackStep: null,
    ledger: ledger.snapshot(policy, now)
  };

  if (evaluation.decision === 'allow') {
    const approval = issueApproval(evaluation, paymentRequired, policy, ledger, now);
    result.approval = approval;

    if (id === 'post-approval-swap') {
      approval.payload.authorization.to = constants.EVIL_PAYEE;
      result.attackStep = 'Attacker changed authorization.to after approval.';
      result.settlement = settleDryRun(approval, policy, ledger, now);
    } else if (id === 'replay') {
      const first = settleDryRun(approval, policy, ledger, now);
      const second = settleDryRun(approval, policy, ledger, now);
      result.attackStep = 'First settlement succeeds; identical authorization is replayed.';
      result.settlement = { first, replay: second };
    } else {
      result.settlement = settleDryRun(approval, policy, ledger, now);
    }
  }

  result.ledger = ledger.snapshot(policy, now);
  return result;
}

export function runSuite(policy) {
  const rows = [];
  for (const scenario of scenarioCatalog) {
    const isolatedLedger = new GuardLedger();
    const result = runScenario(scenario.id, policy, isolatedLedger, new Date('2026-10-31T08:00:00.000Z'));

    let actual;
    if (scenario.id === 'replay') actual = result.settlement?.replay?.decision ?? 'block';
    else if (scenario.id === 'post-approval-swap') actual = result.settlement?.decision ?? result.evaluation.decision;
    else actual = result.evaluation.decision;

    rows.push({
      id: scenario.id,
      label: scenario.label,
      kind: scenario.kind,
      expected: scenario.expected,
      actual,
      pass: actual === scenario.expected,
      reasonCodes:
        scenario.id === 'replay'
          ? result.settlement?.replay?.reasonCodes ?? []
          : scenario.id === 'post-approval-swap'
            ? result.settlement?.reasonCodes ?? []
            : result.evaluation.reasonCodes ?? [],
      selectedIndex: result.evaluation.selectedIndex ?? null
    });
  }

  return {
    total: rows.length,
    passed: rows.filter((row) => row.pass).length,
    rows
  };
}
