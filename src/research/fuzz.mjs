import { canonicalResourceUrl, validatePaymentRequiredShape } from '../core/x402.mjs';
import { evaluatePaymentRequired } from '../security/payment-guard.mjs';
import { GuardLedger } from '../state/guard-ledger.mjs';
import { IntentAuthority } from '../security/intent-authority.mjs';
import { intentFromPaymentRequired } from '../core/intent.mjs';

const clone = value => structuredClone(value);

function seedNumber(seed) {
  if (typeof seed === 'number' && Number.isFinite(seed)) return seed >>> 0;
  let hash = 2166136261;
  for (const char of String(seed)) {
    hash ^= char.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function randomFor(seed) {
  let state = seedNumber(seed);
  return () => {
    state += 0x6d2b79f5;
    let value = state;
    value = Math.imul(value ^ value >>> 15, value | 1);
    value ^= value + Math.imul(value ^ value >>> 7, value | 61);
    return ((value ^ value >>> 14) >>> 0) / 4294967296;
  };
}

function alternateAddress(original, random) {
  let address;
  do {
    address = `0x${Array.from({ length: 5 }, () => Math.floor(random() * 0x100000000).toString(16).padStart(8, '0')).join('')}`;
  } while (address.toLowerCase() === String(original).toLowerCase());
  return address;
}

function alternateResource(original, kind) {
  const url = new URL(original);
  if (kind === 'path') url.pathname = `${url.pathname.replace(/\/$/, '')}/sentinel-unauthorized`;
  else url.searchParams.set('sentinel_scope', url.searchParams.get('sentinel_scope') === 'attacker' ? 'attacker-2' : 'attacker');
  return url.toString();
}

function nextAmount(amount, factor) {
  const value = BigInt(amount);
  return (value * BigInt(factor) + 1n).toString();
}

function withMutation(base, id, label, description, mutate, options = {}) {
  const paymentRequired = clone(base);
  const request = { paymentRequired, requestedUrl: base.resource.url, requestedMethod: 'GET' };
  mutate(request);
  return {
    id, label, description,
    kind: options.kind ?? 'attack',
    expectedDecision: options.expectedDecision ?? 'block',
    expectedSelectedIndex: options.expectedSelectedIndex ?? null,
    rule: options.rule ?? 'SR1',
    ...request
  };
}

/**
 * Generate bounded, deterministic x402 metadata mutations. Every request starts
 * from one observed merchant offer; this generator never signs or settles funds.
 */
export function generateAttackCases(paymentRequired, { seed = 402, trials = 8, offerIndex = 0, attackCount = null, honestCount = null } = {}) {
  validatePaymentRequiredShape(paymentRequired);
  if (!Number.isInteger(offerIndex) || offerIndex < 0 || offerIndex >= paymentRequired.accepts.length) {
    throw new Error('offerIndex must identify an offer in the baseline challenge');
  }
  if (!Number.isInteger(trials) || trials < 0 || trials > 30) throw new Error('trials must be between 0 and 30');
  for (const [label, count] of [['attackCount', attackCount], ['honestCount', honestCount]]) {
    if (count !== null && (!Number.isInteger(count) || count < 1 || count > 1000)) throw new Error(`${label} must be between 1 and 1000`);
  }

  const random = randomFor(seed);
  const base = clone(paymentRequired);
  base.accepts = [clone(paymentRequired.accepts[offerIndex])];
  const offer = base.accepts[0];
  if (BigInt(offer.amount) <= 0n) throw new Error('baseline offer amount must be positive');
  const changedRecipient = alternateAddress(offer.payTo, random);
  const changedAsset = alternateAddress(offer.asset, random);
  const changedNetwork = offer.network === 'eip155:1' ? 'eip155:84532' : 'eip155:1';
  const changedScheme = offer.scheme === 'upto' ? 'exact' : 'upto';
  const changedFlow = offer.extra?.paymentFlow === 'upfront' ? 'authorization' : 'upfront';
  const changedTransfer = offer.extra?.assetTransferMethod === 'permit2' ? 'eip3009' : 'permit2';
  const timeout = Math.max(offer.maxTimeoutSeconds + 1, offer.maxTimeoutSeconds * 4);

  const cases = [
    withMutation(base, 'baseline', 'Legitimate baseline', 'The observed merchant challenge is unchanged.', () => {}, { kind: 'legitimate', expectedDecision: 'allow', expectedSelectedIndex: 0 }),
    withMutation(base, 'discount', 'Legitimate lower price', 'A lower price should remain within the delegated ceiling.', request => {
      const original = BigInt(offer.amount);
      request.paymentRequired.accepts[0].amount = (original > 1n ? original / 2n : original).toString();
    }, { kind: 'legitimate', expectedDecision: 'allow', expectedSelectedIndex: 0 }),
    withMutation(base, 'shorter-timeout', 'Legitimate shorter timeout', 'A shorter authorization window should remain safe.', request => {
      request.paymentRequired.accepts[0].maxTimeoutSeconds = Math.max(1, Math.floor(offer.maxTimeoutSeconds / 2));
    }, { kind: 'legitimate', expectedDecision: 'allow', expectedSelectedIndex: 0 }),
    withMutation(base, 'overcharge', 'Overcharge', 'Increase price while preserving merchant identity.', request => { request.paymentRequired.accepts[0].amount = nextAmount(offer.amount, 10); }),
    withMutation(base, 'recipient-swap', 'Recipient swap', 'Move the payment to an attacker-controlled recipient.', request => { request.paymentRequired.accepts[0].payTo = changedRecipient; }),
    withMutation(base, 'asset-swap', 'Asset swap', 'Change the token contract without changing price.', request => { request.paymentRequired.accepts[0].asset = changedAsset; }),
    withMutation(base, 'network-swap', 'Network swap', 'Move the payment to a different chain.', request => { request.paymentRequired.accepts[0].network = changedNetwork; }),
    withMutation(base, 'resource-path-swap', 'Resource path swap', 'Reuse the demand against another protected path.', request => { request.paymentRequired.resource.url = alternateResource(base.resource.url, 'path'); }),
    withMutation(base, 'resource-query-swap', 'Resource query swap', 'Change only the paid resource query.', request => { request.paymentRequired.resource.url = alternateResource(base.resource.url, 'query'); }),
    withMutation(base, 'requested-url-swap', 'Requested URL swap', 'Keep the merchant challenge but request a different URL.', request => { request.requestedUrl = alternateResource(base.resource.url, 'query'); }),
    withMutation(base, 'scheme-swap', 'Scheme swap', 'Change the economic meaning of the offer.', request => { request.paymentRequired.accepts[0].scheme = changedScheme; }),
    withMutation(base, 'flow-swap', 'Payment flow swap', 'Change when economic commitment happens.', request => { request.paymentRequired.accepts[0].extra = { ...offer.extra, paymentFlow: changedFlow }; }),
    withMutation(base, 'transfer-swap', 'Transfer method swap', 'Change the EVM transfer primitive.', request => { request.paymentRequired.accepts[0].extra = { ...offer.extra, assetTransferMethod: changedTransfer }; }),
    withMutation(base, 'timeout-stretch', 'Timeout stretch', 'Extend the authorization lifetime.', request => { request.paymentRequired.accepts[0].maxTimeoutSeconds = timeout; }, { rule: 'SR3' }),
    withMutation(base, 'zero-amount', 'Zero amount', 'Submit a malformed economic amount.', request => { request.paymentRequired.accepts[0].amount = '0'; }),
    withMutation(base, 'malformed-amount', 'Malformed amount', 'Submit a fractional atomic amount.', request => { request.paymentRequired.accepts[0].amount = '1.5'; }),
    withMutation(base, 'poisoned-first-offer', 'Poisoned first offer', 'Put a hostile offer before an unchanged safe offer.', request => {
      request.paymentRequired.accepts = [{ ...clone(offer), payTo: changedRecipient }, clone(offer)];
    }, { expectedDecision: 'allow', expectedSelectedIndex: 1 }),
    withMutation(base, 'poisoned-last-offer', 'Poisoned last offer', 'Leave a safe offer first and append a hostile offer.', request => {
      request.paymentRequired.accepts = [clone(offer), { ...clone(offer), payTo: changedRecipient }];
    }, { expectedDecision: 'allow', expectedSelectedIndex: 0 })
  ];

  const mutators = [
    request => { request.paymentRequired.accepts[0].amount = nextAmount(offer.amount, 2 + Math.floor(random() * 30)); },
    request => { request.paymentRequired.accepts[0].payTo = alternateAddress(offer.payTo, random); },
    request => { request.paymentRequired.accepts[0].asset = alternateAddress(offer.asset, random); },
    request => { request.paymentRequired.accepts[0].network = changedNetwork; },
    request => { request.paymentRequired.accepts[0].maxTimeoutSeconds = timeout + Math.floor(random() * 1000); },
    request => { request.paymentRequired.accepts[0].extra = { ...request.paymentRequired.accepts[0].extra, paymentFlow: changedFlow }; },
    request => { request.paymentRequired.resource.url = alternateResource(base.resource.url, 'query'); }
  ];
  for (let index = 0; index < trials; index++) {
    const selected = new Set();
    while (selected.size < 2 + Math.floor(random() * 3)) selected.add(Math.floor(random() * mutators.length));
    cases.push(withMutation(base, `compound-${String(index + 1).padStart(2, '0')}`, `Compound mutation ${index + 1}`, 'Seeded combination for bypass discovery and minimization.', request => {
      for (const mutatorIndex of selected) mutators[mutatorIndex](request);
    }));
  }

  const baseAttackCount = cases.filter(item => item.kind === 'attack').length;
  const baseHonestCount = cases.filter(item => item.kind === 'legitimate').length;
  if (attackCount !== null && attackCount < baseAttackCount) throw new Error(`attackCount must be at least ${baseAttackCount} for this trial count`);
  if (honestCount !== null && honestCount < baseHonestCount) throw new Error(`honestCount must be at least ${baseHonestCount}`);

  for (let index = baseHonestCount; index < (honestCount ?? baseHonestCount); index++) {
    cases.push(withMutation(base, `fuzz-honest-${String(index + 1).padStart(4, '0')}`, `Honest variation ${index + 1}`, 'A price and validity window inside the observed authorization ceiling.', request => {
      const fraction = 1n + BigInt(Math.floor(random() * 999999));
      request.paymentRequired.accepts[0].amount = (1n + (BigInt(offer.amount) - 1n) * fraction / 1000000n).toString();
      request.paymentRequired.accepts[0].maxTimeoutSeconds = 1 + Math.floor(random() * offer.maxTimeoutSeconds);
    }, { kind: 'legitimate', expectedDecision: 'allow', expectedSelectedIndex: 0 }));
  }
  for (let index = baseAttackCount; index < (attackCount ?? baseAttackCount); index++) {
    const selected = new Set();
    while (selected.size < 1 + Math.floor(random() * 4)) selected.add(Math.floor(random() * mutators.length));
    cases.push(withMutation(base, `fuzz-attack-${String(index + 1).padStart(4, '0')}`, `Attack variation ${index + 1}`, 'Seeded metadata mutation against the same legitimate baseline.', request => {
      for (const mutatorIndex of selected) mutators[mutatorIndex](request);
    }));
  }

  return { seed, baseline: base, canonicalResource: canonicalResourceUrl(base.resource.url), cases };
}

export function scoreFuzzCase(testCase, observed) {
  if (observed.error) return 'error';
  if (testCase.kind === 'legitimate') return observed.decision === 'allow' ? 'legitimate-pass' : 'false-positive';
  if (testCase.expectedDecision === 'block') return observed.decision === 'block' ? 'attack-blocked' : 'bypass';
  if (observed.decision === 'block') return 'false-positive';
  if (observed.selectedIndex === null || observed.selectedIndex === undefined) return 'unverifiable-selection';
  return observed.selectedIndex === testCase.expectedSelectedIndex ? 'safe-selection' : 'bypass';
}

/** In-process, signed-permit version for the authorized local demo endpoint. */
export function runFuzz({ paymentRequired, policy, intentAuthority = new IntentAuthority(), seed = 402, trials = 8, offerIndex = 0, attackCount = null, honestCount = null }) {
  if (!policy) throw new Error('runFuzz requires a policy');
  const generated = generateAttackCases(paymentRequired, { seed, trials, offerIndex, attackCount, honestCount });
  const permit = intentAuthority.issue(intentFromPaymentRequired(generated.baseline), policy);
  const results = generated.cases.map(testCase => {
    const evaluated = evaluatePaymentRequired(testCase.paymentRequired, policy, new GuardLedger(), {
      requestedUrl: testCase.requestedUrl,
      requestedMethod: testCase.requestedMethod,
      intentPermit: permit,
      intentAuthority
    });
    const observed = {
      decision: evaluated.decision,
      selectedIndex: evaluated.selectedIndex ?? null,
      reasonCodes: evaluated.reasonCodes ?? []
    };
    return {
      id: testCase.id, label: testCase.label, kind: testCase.kind, rule: testCase.rule,
      expectedDecision: testCase.expectedDecision,
      expectedSelectedIndex: testCase.expectedSelectedIndex,
      observed, outcome: scoreFuzzCase(testCase, observed)
    };
  });
  const attacks = results.filter(result => result.kind === 'attack');
  const legitimate = results.filter(result => result.kind === 'legitimate');
  const contained = attacks.filter(result => ['attack-blocked', 'safe-selection'].includes(result.outcome)).length;
  const allowed = legitimate.filter(result => result.outcome === 'legitimate-pass').length;
  return {
    seed, baseline: generated.baseline,
    metrics: {
      attackCases: attacks.length, attackContained: contained,
      attackContainmentRate: attacks.length ? Math.round(contained / attacks.length * 1000) / 10 : null,
      legitimateCases: legitimate.length, legitimateAllowed: allowed,
      legitimatePassRate: legitimate.length ? Math.round(allowed / legitimate.length * 1000) / 10 : null,
      bypasses: results.filter(result => result.outcome === 'bypass').length,
      falsePositives: results.filter(result => result.outcome === 'false-positive').length
    },
    results
  };
}
