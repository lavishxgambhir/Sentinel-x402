import { canonicalResourceUrl, validatePaymentRequiredShape } from '../core/x402.mjs';

const norm = (v) => String(v ?? '').toLowerCase();

export const selectedResearch = [
  {
    id: 'x402scope-2026',
    title: 'When HTTP 402 Meets the Blockchain: Risks on Emerging x402 Payments',
    date: '2026-07-21',
    adaptation: 'Sentinel Scope',
    idea: 'Discover target capabilities first, then generate only rule-relevant black-box mutations and score with observable evidence.'
  },
  {
    id: 'aport-vault-2026',
    title: 'APort Vault: Benchmarking AI Agent Payment Authorization with the Open Agent Passport',
    date: '2026-09-18',
    adaptation: 'Execution Trace',
    idea: 'Keep the authorization check deterministic and separate the observable stages instead of collapsing everything into a single pass/fail number.'
  }
];

export function capabilityProfile(paymentRequired) {
  const offers = Array.isArray(paymentRequired?.accepts) ? paymentRequired.accepts : [];
  const uniq = (xs) => [...new Set(xs.filter(Boolean).map(String))];
  return {
    x402Version: paymentRequired?.x402Version ?? null,
    resource: paymentRequired?.resource?.url ?? null,
    offerCount: offers.length,
    schemes: uniq(offers.map(o => o.scheme)),
    networks: uniq(offers.map(o => o.network)),
    assets: uniq(offers.map(o => o.asset)),
    recipients: uniq(offers.map(o => o.payTo)),
    paymentFlows: uniq(offers.map(o => o.extra?.paymentFlow ?? 'authorization')),
    transferMethods: uniq(offers.map(o => o.extra?.assetTransferMethod ?? 'eip3009')),
    maxTimeoutSeconds: offers.length ? Math.max(...offers.map(o => Number(o.maxTimeoutSeconds ?? 0))) : 0,
    supportsMultipleOffers: offers.length > 1
  };
}

const TESTS = [
  { id:'overpay', rule:'SR1', label:'Amount binding', impact:'Overpayment', needs:()=>true, mutate:'amount', summary:'Raise the required amount while keeping the rest of the challenge unchanged.' },
  { id:'wrong-party', rule:'SR1', label:'Recipient binding', impact:'Wrong-party payment', needs:()=>true, mutate:'payTo', summary:'Replace the merchant recipient with an attacker-controlled address.' },
  { id:'network', rule:'SR1', label:'Network binding', impact:'Cross-network confusion', needs:p=>p.networks.length>0, mutate:'network', summary:'Move the payment to a different CAIP-2 network.' },
  { id:'asset', rule:'SR1', label:'Asset binding', impact:'Asset substitution', needs:p=>p.assets.length>0, mutate:'asset', summary:'Swap the token contract while preserving the quoted price.' },
  { id:'resource', rule:'SR1', label:'Resource binding', impact:'Cross-resource reuse', needs:p=>Boolean(p.resource), mutate:'resource', summary:'Reuse the payment challenge for a different protected endpoint.' },
  { id:'query-swap', rule:'SR1', label:'Query binding', impact:'Wrong paid item', needs:p=>Boolean(p.resource), mutate:'resource.query', summary:'Change only the item query parameter while keeping the same merchant and path.' },
  { id:'closure', rule:'P8', label:'Wallet loop', impact:'Approved-looking loop payee', needs:p=>p.recipients.length>0, mutate:'payTo', summary:'Use a policy-approved recipient linked back to the payer in the explicitly synthetic wallet graph.' },
  { id:'timeout', rule:'SR3', label:'Freshness window', impact:'Stale/overlong authorization', needs:p=>p.maxTimeoutSeconds>0, mutate:'timeout', summary:'Expand the authorization window beyond the legitimate challenge.' },
  { id:'flow', rule:'SR7', label:'Verify/settle semantics', impact:'TOCTOU / payment-flow swap', needs:p=>p.paymentFlows.length>0, mutate:'paymentFlow', summary:'Change when economic commitment occurs, e.g. authorization to upfront.' },
  { id:'transfer', rule:'SR8', label:'Execution semantics', impact:'Transfer-method confusion', needs:p=>p.transferMethods.length>0, mutate:'transferMethod', summary:'Change the on-chain transfer primitive, e.g. EIP-3009 to Permit2.' },
  { id:'malicious-first-offer', rule:'SR1', label:'Offer selection', impact:'Poisoned first offer', needs:()=>true, mutate:'accepts[]', summary:'Place a malicious offer first while leaving a safe offer available.' },
  { id:'replay', rule:'SR3/SR5', label:'Single-use authorization', impact:'Replay / duplicate grant', mode:'automated', needs:()=>true, mutate:'nonce/payment identity', summary:'A real replay needs an already-used permit. Run the stateful replay probe in Judge → Held-out Red Team.' }
];

export function applicableResearchTests(paymentRequired) {
  const profile = capabilityProfile(paymentRequired);
  return TESTS.filter(t => t.needs(profile)).map(t => ({ ...t, applicable:true }));
}

function offerComparable(o) {
  return {
    scheme: String(o?.scheme ?? ''),
    network: String(o?.network ?? ''),
    amount: String(o?.amount ?? ''),
    asset: norm(o?.asset),
    payTo: norm(o?.payTo),
    timeout: Number(o?.maxTimeoutSeconds ?? 0),
    flow: String(o?.extra?.paymentFlow ?? 'authorization'),
    transfer: String(o?.extra?.assetTransferMethod ?? 'eip3009')
  };
}

export function compareAgainstOriginal(originalPaymentRequired, receivedPaymentRequired) {
  if (!originalPaymentRequired || !receivedPaymentRequired) {
    return { expected:'block', classification:'attack', violations:['BASELINE_MISSING'], reason:'Original merchant challenge is missing.' };
  }

  try {
    validatePaymentRequiredShape(originalPaymentRequired);
  } catch {
    return {
      expected: 'block',
      classification: 'attack',
      violations: ['BASELINE_MALFORMED'],
      reason: 'The server-owned merchant baseline is not valid x402 data.'
    };
  }

  try {
    validatePaymentRequiredShape(receivedPaymentRequired);
  } catch {
    return {
      expected: 'block',
      classification: 'attack',
      violations: ['MALFORMED_REQUIREMENTS'],
      reason: 'Received payment requirements are not valid x402 data.'
    };
  }

  const violations = [];
  if (String(receivedPaymentRequired.x402Version) !== String(originalPaymentRequired.x402Version)) violations.push('X402_VERSION');
  if (
    canonicalResourceUrl(receivedPaymentRequired.resource.url)
    !== canonicalResourceUrl(originalPaymentRequired.resource.url)
  ) {
    violations.push('RESOURCE_BINDING');
  }

  const originals = (originalPaymentRequired.accepts ?? []).map(offerComparable);
  const received = (receivedPaymentRequired.accepts ?? []).map(offerComparable);
  let safeOffer = false;
  for (const r of received) {
    for (const o of originals) {
      const amountOk = (()=>{ try { return BigInt(r.amount) <= BigInt(o.amount) && BigInt(r.amount) > 0n; } catch { return false; } })();
      if (
        r.scheme === o.scheme && r.network === o.network && r.asset === o.asset && r.payTo === o.payTo &&
        r.flow === o.flow && r.transfer === o.transfer && r.timeout <= o.timeout && amountOk
      ) { safeOffer = true; break; }
    }
    if (safeOffer) break;
  }
  if (!safeOffer) violations.push('NO_BASELINE_EQUIVALENT_OFFER');
  return {
    expected: violations.length ? 'block' : 'allow',
    classification: violations.length ? 'attack' : 'legitimate',
    violations,
    reason: violations.length ? 'Received payment terms no longer contain a safe baseline-equivalent offer.' : 'Received payment retains at least one safe offer equivalent to the original merchant challenge.'
  };
}

export function buildExecutionTrace({ classification, guardAction, guardReasonCodes = [], walletSigned = false, settled = false, recipientCompliant = null, arenaMode = true }) {
  const unpermittedTransfer = Boolean(settled && classification === 'attack');
  return [
    { id:'request', label:'Payment request', state:'observed', detail:'x402 PAYMENT-REQUIRED received' },
    { id:'policy', label:'Policy decision', state:guardAction === 'allow' ? 'allow' : 'block', detail:guardReasonCodes.length ? guardReasonCodes.join(', ') : 'Policy matched' },
    { id:'sign', label:'Wallet authorization', state:walletSigned ? 'signed' : 'not-signed', detail:walletSigned ? (arenaMode ? 'Dry-run signer boundary opened' : 'Signer boundary opened') : 'Signer was never called' },
    { id:'settle', label:'Settlement', state:settled ? 'settled' : (arenaMode ? 'not-broadcast' : 'not-settled'), detail:settled ? 'Economic state changed' : (arenaMode ? 'Arena evaluation only' : 'No settlement observed') },
    { id:'recipient', label:'Recipient compliance', state:recipientCompliant === false ? 'violation' : recipientCompliant === true ? 'compliant' : 'not-applicable', detail:unpermittedTransfer ? 'Unauthorized value moved' : classification === 'attack' ? 'Attack contained before transfer' : 'No unpermitted transfer observed' }
  ];
}
