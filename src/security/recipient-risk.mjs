import { normalizeAddress } from '../core/x402.mjs';
import { evaluateClosure } from './relationship-check.mjs';

export function evaluateRecipientRisk(recipient, policy = {}, ledger = null, now = new Date()) {
  const address = String(normalizeAddress(recipient)).toLowerCase();
  const blocked = new Set((policy.risk?.blockedRecipients ?? []).map(x => String(normalizeAddress(x)).toLowerCase()));
  const watch = new Set((policy.risk?.watchRecipients ?? []).map(x => String(normalizeAddress(x)).toLowerCase()));
  const signals = [];
  let score = 0;
  let hardBlock = false;

  if (blocked.has(address)) {
    hardBlock = true;
    score = 100;
    signals.push({ code: 'RECIPIENT_BLOCKLIST', severity: 'block', detail: 'Recipient is on the configured compliance blocklist' });
  }
  if (watch.has(address)) {
    score = Math.max(score, 60);
    signals.push({ code: 'RECIPIENT_WATCHLIST', severity: 'review', detail: 'Recipient is on the configured watchlist' });
  }

  const closure = evaluateClosure(address, policy.walletAddress, policy.risk?.closure);
  if (closure.verdict === 'block') {
    hardBlock = true;
    score = 100;
    signals.push({ code: 'WALLET_CLOSURE', severity: 'block', detail: closure.reason, path: closure.path, source: closure.source });
  } else if (closure.verdict === 'review') {
    hardBlock = true; // A review needs a human decision; this demo has no review queue.
    score = Math.max(score, 70);
    signals.push({ code: 'WALLET_RELATIONSHIP_REVIEW', severity: 'review', detail: closure.reason, path: closure.path, source: closure.source });
  }

  if (ledger?.isKnownRecipient && !ledger.isKnownRecipient(address) && policy.risk?.reviewNewRecipients) {
    score = Math.max(score, 35);
    signals.push({ code: 'NEW_RECIPIENT', severity: 'review', detail: 'Recipient has not previously received a settled payment from this wallet' });
  }

  const maxCount = Number(policy.risk?.maxPaymentsPerMinute ?? 0);
  if (maxCount > 0 && ledger?.recentPaymentCount) {
    const count = ledger.recentPaymentCount(60_000, now);
    if (count >= maxCount) {
      score = Math.max(score, 70);
      signals.push({ code: 'VELOCITY_COUNT', severity: 'review', detail: `Payment velocity ${count}/minute reached policy threshold ${maxCount}` });
    }
  }

  return { hardBlock, score, signals, closure, source: 'local-policy-adapter' };
}
