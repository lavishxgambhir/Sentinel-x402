import { evaluatePaymentRequired } from './payment-guard.mjs';

/** Public guard boundary: the caller never chooses the clock used for permits. */
export function evaluatePublicGuardRequest(body, { policy, ledger, intentAuthority, clock = () => new Date() }) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { decision: 'block', reason: 'Expected a JSON request object', reasonCodes: ['MALFORMED_REQUEST'] };
  }
  if (Object.hasOwn(body, 'now')) {
    return { decision: 'block', reason: 'Caller-supplied evaluation time is not trusted', reasonCodes: ['UNTRUSTED_TIMESTAMP'] };
  }
  return evaluatePaymentRequired(body.paymentRequired, policy, ledger, {
    requestedUrl: body.requestedUrl,
    requestedMethod: body.requestedMethod ?? 'GET',
    now: clock(),
    intentPermit: body.intentPermit ?? null,
    intentAuthority
  });
}
