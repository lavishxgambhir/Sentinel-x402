import { intentFromPaymentRequired } from '../core/intent.mjs';
import { buildMerchantChallenge } from '../demo/merchant.mjs';
import { evaluatePaymentRequired, issueApproval, settleDryRun } from '../security/payment-guard.mjs';
import { IntentAuthority } from '../security/intent-authority.mjs';
import { GuardLedger } from '../state/guard-ledger.mjs';
import { ChallengeRegistry } from '../state/challenge-registry.mjs';
import { evaluatePublicGuardRequest } from '../security/guard-request.mjs';

const clone = value => structuredClone(value);
const HELD_OUT_RESOURCE = 'https://api.safe.test/premium-data?range=1d&symbol=NVDA';

// These oracle helpers deliberately live outside the guard's parser and URL
// canonicalizer. The benchmark must still catch a regression in either one.
function authorizedUrl(value) {
  const url = new URL(value);
  url.hash = '';
  url.searchParams.sort();
  return url.href;
}

function authorizedAtomic(value) {
  if (typeof value !== 'string' || !/^[0-9]+$/.test(value)) throw new Error('Invalid atomic amount');
  return BigInt(value);
}

function authorizedAddress(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) throw new Error('Invalid address');
  return value.toLowerCase();
}

function validChallenge(value) {
  if (!value || value.x402Version !== 2 || typeof value.resource?.url !== 'string'
    || !Array.isArray(value.accepts) || value.accepts.length < 1 || value.accepts.length > 16) return false;
  return value.accepts.every(offer => {
    try {
      return offer !== null && typeof offer === 'object' && !Array.isArray(offer)
        && typeof offer.scheme === 'string' && /^[a-z][a-z0-9_-]{0,63}$/i.test(offer.scheme)
        && typeof offer.network === 'string' && /^[a-z0-9]{1,32}:[a-zA-Z0-9-]{1,64}$/.test(offer.network)
        && typeof offer.asset === 'string' && typeof offer.payTo === 'string'
        && Boolean(authorizedAddress(offer.asset)) && Boolean(authorizedAddress(offer.payTo))
        && authorizedAtomic(offer.amount) >= 0n
        && Number.isInteger(offer.maxTimeoutSeconds) && offer.maxTimeoutSeconds > 0
        && (offer.extra === undefined || (offer.extra !== null && typeof offer.extra === 'object' && !Array.isArray(offer.extra)))
        && (offer.extra?.paymentFlow === undefined || typeof offer.extra.paymentFlow === 'string')
        && (offer.extra?.assetTransferMethod === undefined || typeof offer.extra.assetTransferMethod === 'string');
    } catch { return false; }
  });
}

function seedNumber(seed) {
  if (typeof seed === 'number' && Number.isFinite(seed)) return seed >>> 0;
  let hash = 2166136261;
  for (const character of String(seed)) {
    hash ^= character.charCodeAt(0);
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

function makeBaseline() {
  return buildMerchantChallenge({ resourceUrl: HELD_OUT_RESOURCE }).paymentRequired;
}

function severityFor(fields = []) {
  if (fields.some(field => /payTo|asset|network|replay|post-approval|permit-race|signature/.test(field))) return 'CRITICAL';
  if (fields.some(field => /resource|method|flow|transfer/.test(field))) return 'HIGH';
  if (fields.some(field => /timeout|budget|amount|policy/.test(field))) return 'MEDIUM';
  return 'LOW / QUALITY';
}

function isCriticalIntentBypass(item) {
  return item.kind === 'attack' && item.observed.decision === 'allow'
    && item.mutationFields.some(field => /payTo|asset|network|resource|replay|post-approval|permit-race|transferMethod|signature/.test(field));
}

function findingCategory(item) {
  if (item.truth.category !== 'INTENT_MISMATCH') return item.truth.category;
  const fields = item.mutationFields.join(' ');
  if (/timeout/.test(fields)) return 'TIMEOUT_EXCEEDS_ORIGINAL';
  if (/resource/.test(fields)) return 'RESOURCE_INTENT_MISMATCH';
  if (/payTo/.test(fields)) return 'RECIPIENT_INTENT_MISMATCH';
  if (/asset/.test(fields)) return 'ASSET_INTENT_MISMATCH';
  if (/network/.test(fields)) return 'NETWORK_INTENT_MISMATCH';
  if (/transferMethod/.test(fields)) return 'TRANSFER_METHOD_MISMATCH';
  return item.truth.category;
}

/**
 * Independent semantic referee for held-out cases. It intentionally does not
 * call Sentinel's production evaluator. It derives authorization only from the
 * original challenge and its independently specified payment contract.
 */
export function refereeHeldOutCase({ original, paymentRequired, requestedUrl, requestedMethod = 'GET' }) {
  if (!validChallenge(original) || !validChallenge(paymentRequired)) {
    return { expected: 'block', classification: 'attack', category: 'MALFORMED_REQUIREMENTS' };
  }

  if (String(requestedMethod).toUpperCase() !== 'GET') {
    return { expected: 'block', classification: 'attack', category: 'METHOD_BINDING' };
  }

  let originalResource;
  let receivedResource;
  let requestedResource;
  try {
    originalResource = authorizedUrl(original.resource.url);
    receivedResource = authorizedUrl(paymentRequired.resource.url);
    requestedResource = authorizedUrl(requestedUrl ?? paymentRequired.resource.url);
  } catch {
    return { expected: 'block', classification: 'attack', category: 'RESOURCE_BINDING' };
  }
  if (originalResource !== receivedResource || originalResource !== requestedResource) {
    return { expected: 'block', classification: 'attack', category: 'RESOURCE_BINDING' };
  }

  const originalOffers = original.accepts.map(offer => ({
    scheme: String(offer.scheme),
    network: String(offer.network),
    asset: String(offer.asset).toLowerCase(),
    payTo: authorizedAddress(offer.payTo),
    amount: authorizedAtomic(offer.amount),
    timeout: Number(offer.maxTimeoutSeconds),
    flow: String(offer.extra?.paymentFlow ?? 'authorization'),
    transfer: String(offer.extra?.assetTransferMethod ?? 'eip3009')
  }));

  for (const received of paymentRequired.accepts) {
    let amount;
    try { amount = authorizedAtomic(received.amount); } catch { continue; }
    const compatible = originalOffers.some(originalOffer => (
      String(received.scheme) === originalOffer.scheme
      && String(received.network) === originalOffer.network
      && String(received.asset).toLowerCase() === originalOffer.asset
      && authorizedAddress(received.payTo) === originalOffer.payTo
      && String(received.extra?.paymentFlow ?? 'authorization') === originalOffer.flow
      && String(received.extra?.assetTransferMethod ?? 'eip3009') === originalOffer.transfer
      && Number.isInteger(received.maxTimeoutSeconds)
      && received.maxTimeoutSeconds > 0
      && received.maxTimeoutSeconds <= originalOffer.timeout
      && amount > 0n
      && amount <= originalOffer.amount
    ));
    if (compatible) return { expected: 'allow', classification: 'legitimate', category: 'AUTHORIZED_SEMANTICS' };
  }
  return { expected: 'block', classification: 'attack', category: 'INTENT_MISMATCH' };
}

function caseFromMutation({ original, id, level, label, mutationFields, mutate, legitimate = false }) {
  const paymentRequired = clone(original);
  const request = { paymentRequired, requestedUrl: original.resource.url, requestedMethod: 'GET' };
  mutate(request);
  const truth = refereeHeldOutCase({ original, ...request });
  const intendedKind = legitimate ? 'legitimate' : 'attack';
  if (truth.classification !== intendedKind) {
    throw new Error(`Held-out generator mislabeled ${id}: referee says ${truth.classification}`);
  }
  return {
    id,
    level,
    label,
    kind: truth.classification,
    mutationFields,
    severity: legitimate ? 'LOW / QUALITY' : severityFor(mutationFields),
    ...request,
    truth
  };
}

function semanticMutations(original, random) {
  const alternateRecipient = alternateAddress(original.accepts[0].payTo, random);
  return [
    ['semantic-query-value', 'Semantic query value swap', ['resource.query'], request => {
      const url = new URL(request.paymentRequired.resource.url);
      url.searchParams.set('symbol', 'ATTACKER');
      request.paymentRequired.resource.url = url.toString();
      request.requestedUrl = url.toString();
    }],
    ['semantic-duplicate-query', 'Duplicate query parameter', ['resource.query.duplicate'], request => {
      const url = new URL(request.paymentRequired.resource.url);
      url.searchParams.append('symbol', 'ATTACKER');
      request.paymentRequired.resource.url = url.toString();
      request.requestedUrl = url.toString();
    }],
    ['semantic-empty-query', 'Unexpected empty query parameter', ['resource.query.empty'], request => {
      const url = new URL(request.paymentRequired.resource.url);
      url.searchParams.append('preview', '');
      request.paymentRequired.resource.url = url.toString();
      request.requestedUrl = url.toString();
    }],
    ['semantic-encoded-value', 'Encoded different query value', ['resource.query.encoding'], request => {
      const url = 'https://api.safe.test/premium-data?range=1d&symbol=ATT%41CKER';
      request.paymentRequired.resource.url = url;
      request.requestedUrl = url;
    }],
    ['semantic-encoded-path', 'Encoded path substitution', ['resource.path.encoding'], request => {
      const url = new URL(request.paymentRequired.resource.url);
      url.pathname = '/premium-data%2Fadmin';
      request.paymentRequired.resource.url = url.toString();
      request.requestedUrl = url.toString();
    }],
    ['semantic-trailing-slash', 'Trailing path variation', ['resource.path'], request => {
      const url = new URL(request.paymentRequired.resource.url);
      url.pathname = '/premium-data/';
      request.paymentRequired.resource.url = url.toString();
      request.requestedUrl = url.toString();
    }],
    ['semantic-method', 'HTTP method substitution', ['method'], request => { request.requestedMethod = 'POST'; }],
    ['semantic-flow', 'Flow change with same price', ['paymentFlow'], request => {
      request.paymentRequired.accepts[0].extra.paymentFlow = 'upfront';
    }],
    ['semantic-transfer', 'Transfer method change with same price', ['transferMethod'], request => {
      request.paymentRequired.accepts[0].extra.assetTransferMethod = 'permit2';
    }],
    ['semantic-recipient', 'Recipient change with same price', ['payTo'], request => {
      request.paymentRequired.accepts[0].payTo = alternateRecipient;
    }],
    ['malformed-prototype-network', 'Prototype-key network', ['network.malformed'], request => {
      request.paymentRequired.accepts[0].network = '__proto__';
    }],
    ['malformed-recipient-object', 'Object in recipient field', ['payTo.malformed'], request => {
      request.paymentRequired.accepts[0].payTo = { address: alternateRecipient };
    }],
    ['malformed-offer-array', 'Array in offer field', ['accepts.malformed'], request => {
      request.paymentRequired.accepts[0] = [];
    }]
  ];
}

export function generateHeldOutCases({ seed = 402, attacks = 300, legitimate = 300 } = {}) {
  for (const [label, value] of [['attacks', attacks], ['legitimate', legitimate]]) {
    if (!Number.isInteger(value) || value < 1 || value > 2_000) throw new Error(`${label} must be an integer between 1 and 2000`);
  }
  const original = makeBaseline();
  const random = randomFor(seed);
  const offer = original.accepts[0];
  const attackCases = [];
  const legitimateCases = [];
  const singleMutations = [
    ['level1-amount', 'Amount increase', ['amount'], request => { request.paymentRequired.accepts[0].amount = (BigInt(offer.amount) + 1n + BigInt(Math.floor(random() * 50000))).toString(); }],
    ['level1-recipient', 'Recipient change', ['payTo'], request => { request.paymentRequired.accepts[0].payTo = alternateAddress(offer.payTo, random); }],
    ['level1-asset', 'Asset change', ['asset'], request => { request.paymentRequired.accepts[0].asset = alternateAddress(offer.asset, random); }],
    ['level1-network', 'Network change', ['network'], request => { request.paymentRequired.accepts[0].network = 'eip155:1'; }],
    ['level1-timeout', 'Timeout increase', ['timeout'], request => { request.paymentRequired.accepts[0].maxTimeoutSeconds = offer.maxTimeoutSeconds + 1; }]
  ];
  const compoundMutators = [
    ['amount', request => { request.paymentRequired.accepts[0].amount = (BigInt(offer.amount) * 2n).toString(); }],
    ['payTo', request => { request.paymentRequired.accepts[0].payTo = alternateAddress(offer.payTo, random); }],
    ['asset', request => { request.paymentRequired.accepts[0].asset = alternateAddress(offer.asset, random); }],
    ['network', request => { request.paymentRequired.accepts[0].network = 'eip155:1'; }],
    ['timeout', request => { request.paymentRequired.accepts[0].maxTimeoutSeconds = offer.maxTimeoutSeconds + 60; }],
    ['resource.query', request => {
      const url = new URL(request.paymentRequired.resource.url); url.searchParams.set('symbol', 'ATTACKER');
      request.paymentRequired.resource.url = url.toString(); request.requestedUrl = url.toString();
    }],
    ['paymentFlow', request => { request.paymentRequired.accepts[0].extra.paymentFlow = 'upfront'; }],
    ['transferMethod', request => { request.paymentRequired.accepts[0].extra.assetTransferMethod = 'permit2'; }]
  ];
  const semantic = semanticMutations(original, random);

  for (let index = 0; attackCases.length < attacks; index++) {
    if (index < singleMutations.length) {
      const [id, label, fields, mutate] = singleMutations[index];
      attackCases.push(caseFromMutation({ original, id, level: 1, label, mutationFields: fields, mutate }));
      continue;
    }
    if (index < singleMutations.length + semantic.length) {
      const [id, label, fields, mutate] = semantic[index - singleMutations.length];
      attackCases.push(caseFromMutation({ original, id, level: 3, label, mutationFields: fields, mutate }));
      continue;
    }
    const selected = new Set();
    const count = 2 + Math.floor(random() * 3);
    while (selected.size < count) selected.add(Math.floor(random() * compoundMutators.length));
    attackCases.push(caseFromMutation({
      original,
      id: `level2-compound-${String(attackCases.length + 1).padStart(4, '0')}`,
      level: 2,
      label: `Compound authorization mutation ${attackCases.length + 1}`,
      mutationFields: [...selected].map(position => compoundMutators[position][0]),
      mutate: request => { for (const position of selected) compoundMutators[position][1](request); }
    }));
  }

  const legitimateMutations = [
    ['legit-query-order', 'Equivalent query ordering', ['resource.query.order'], request => {
      request.paymentRequired.resource.url = 'https://api.safe.test/premium-data?symbol=NVDA&range=1d';
      request.requestedUrl = request.paymentRequired.resource.url;
    }],
    ['legit-url-normalization', 'Equivalent URL normalization', ['resource.url.normalization'], request => {
      request.paymentRequired.resource.url = 'HTTPS://API.SAFE.TEST:443/premium-data?symbol=NVDA&range=1d#ignored';
      request.requestedUrl = request.paymentRequired.resource.url;
    }],
    ['legit-encoded-query', 'Equivalent encoded query value', ['resource.query.encoding'], request => {
      request.paymentRequired.resource.url = 'https://api.safe.test/premium-data?symbol=N%56DA&range=1d';
      request.requestedUrl = request.paymentRequired.resource.url;
    }],
    ['legit-normalized-path', 'Equivalent dot-segment path', ['resource.path.normalization'], request => {
      request.paymentRequired.resource.url = 'https://api.safe.test/tmp/../premium-data?range=1d&symbol=NVDA';
      request.requestedUrl = request.paymentRequired.resource.url;
    }],
    ['legit-lower-price', 'Authorized lower amount', ['amount.lower'], request => {
      request.paymentRequired.accepts[0].amount = (1n + BigInt(Math.floor(random() * (Number(offer.amount) - 1)))).toString();
    }],
    ['legit-exact-ceiling', 'Exact authorized amount', ['amount.exact'], () => {}],
    ['legit-timeout-boundary', 'Exact timeout boundary', ['timeout.exact'], () => {}],
    ['legit-safe-second-offer', 'Safe offer after hostile offer', ['accepts.selection'], request => {
      request.paymentRequired.accepts = [
        { ...clone(offer), payTo: alternateAddress(offer.payTo, random) },
        clone(offer)
      ];
    }]
  ];
  for (let index = 0; legitimateCases.length < legitimate; index++) {
    const [id, label, fields, mutate] = legitimateMutations[index % legitimateMutations.length];
    legitimateCases.push(caseFromMutation({
      original,
      id: `${id}-${String(legitimateCases.length + 1).padStart(4, '0')}`,
      level: 3,
      label,
      mutationFields: fields,
      mutate,
      legitimate: true
    }));
  }
  return { seed, original, attackCases, legitimateCases };
}

function observedEvaluation(testCase, policy) {
  const authority = new IntentAuthority();
  const ledger = new GuardLedger();
  const permit = authority.issue(intentFromPaymentRequired(testCase.original), policy);
  const evaluation = evaluatePaymentRequired(testCase.paymentRequired, policy, ledger, {
    requestedUrl: testCase.requestedUrl,
    requestedMethod: testCase.requestedMethod,
    intentPermit: permit,
    intentAuthority: authority
  });
  return { decision: evaluation.decision, reasonCodes: evaluation.reasonCodes ?? [], selectedIndex: evaluation.selectedIndex ?? null };
}

/** Independent state-machine oracle for authorization boundaries. */
export function refereeStatefulCase({
  signatureValid = true, challengeConsumed = false, permitUses = 0, maxUses = 1,
  nonceUsed = false, policyMatches = true, executionMatchesApproval = true,
  budget = null, pending = 0n, amount = 0n,
  nowSeconds = null, validAfterSeconds = 0, validBeforeSeconds = 300
} = {}) {
  let category = 'AUTHORIZED_STATE';
  if (!signatureValid) category = 'INVALID_PERMIT_SIGNATURE';
  else if (challengeConsumed) category = 'CHALLENGE_REPLAY';
  else if (permitUses >= maxUses) category = 'PERMIT_REPLAY';
  else if (nonceUsed) category = 'NONCE_REPLAY';
  else if (!policyMatches) category = 'STALE_POLICY';
  else if (!executionMatchesApproval) category = 'POST_APPROVAL_MUTATION';
  else if (nowSeconds !== null && (nowSeconds < validAfterSeconds || nowSeconds > validBeforeSeconds)) category = 'PERMIT_EXPIRED';
  else if (budget !== null && BigInt(pending) + BigInt(amount) > BigInt(budget)) category = 'BUDGET_EXCEEDED';
  const expected = category === 'AUTHORIZED_STATE' ? 'allow' : 'block';
  return { expected, classification: expected === 'allow' ? 'legitimate' : 'attack', category };
}

function statefulResults(original, policy) {
  const results = [];
  const execute = ({ id, label, fields, facts, operation, kind = 'attack' }) => {
    const truth = refereeStatefulCase(facts);
    if (truth.classification !== kind) throw new Error(`Stateful referee disagrees with ${id}`);
    const outcome = operation();
    results.push({
      id,
      level: 4,
      label,
      kind,
      mutationFields: fields,
      severity: kind === 'legitimate' ? 'LOW / QUALITY' : severityFor(fields),
      truth,
      observed: outcome,
      stateful: true
    });
  };

  execute({ id: 'stateful-permit-replay', label: 'Single-use permit replay', fields: ['replay', 'permit'], facts: { permitUses: 1 }, operation: () => {
    const authority = new IntentAuthority(); const ledger = new GuardLedger();
    const permit = authority.issue(intentFromPaymentRequired(original), policy);
    const first = evaluatePaymentRequired(original, policy, ledger, { requestedUrl: original.resource.url, intentPermit: permit, intentAuthority: authority });
    const payload = issueApproval(first, original, policy, ledger);
    settleDryRun(payload, policy, ledger);
    const replay = evaluatePaymentRequired(original, policy, ledger, { requestedUrl: original.resource.url, intentPermit: permit, intentAuthority: authority });
    return { decision: replay.decision, reasonCodes: replay.reasonCodes ?? [] };
  }});

  execute({ id: 'stateful-approval-reuse-before-settlement', label: 'Two approvals from one permit before settlement',
    fields: ['permit-race', 'replay'], facts: { permitUses: 1 }, operation: () => {
      const authority = new IntentAuthority(); const ledger = new GuardLedger();
      const permit = authority.issue(intentFromPaymentRequired(original), policy);
      const context = { requestedUrl: original.resource.url, intentPermit: permit, intentAuthority: authority };
      const first = evaluatePaymentRequired(original, policy, ledger, context);
      const second = evaluatePaymentRequired(original, policy, ledger, context);
      issueApproval(first, original, policy, ledger);
      try {
        issueApproval(second, original, policy, ledger);
        return { decision: 'allow', reasonCodes: [] };
      } catch {
        return { decision: 'block', reasonCodes: ['PERMIT_USES'] };
      }
    }
  });

  execute({ id: 'stateful-fake-time', label: 'Caller backdates an expired permit', fields: ['permit.expiry', 'timestamp'],
    facts: { nowSeconds: 301 }, operation: () => {
      const authority = new IntentAuthority(); const ledger = new GuardLedger();
      const issuedAt = new Date('2026-10-31T08:00:00.000Z');
      const permit = authority.issue(intentFromPaymentRequired(original), policy, issuedAt);
      const evaluation = evaluatePublicGuardRequest({
        paymentRequired: original, requestedUrl: original.resource.url, intentPermit: permit,
        now: issuedAt.toISOString()
      }, { policy, ledger, intentAuthority: authority, clock: () => new Date(issuedAt.getTime() + 301_000) });
      return { decision: evaluation.decision, reasonCodes: evaluation.reasonCodes ?? [] };
    }
  });

  execute({ id: 'stateful-nonce-replay', label: 'Settled authorization nonce replay', fields: ['nonce.replay'], facts: { nonceUsed: true }, operation: () => {
    const authority = new IntentAuthority(); const ledger = new GuardLedger();
    const permit = authority.issue(intentFromPaymentRequired(original), policy);
    const first = evaluatePaymentRequired(original, policy, ledger, {
      requestedUrl: original.resource.url, intentPermit: permit, intentAuthority: authority
    });
    const payload = issueApproval(first, original, policy, ledger);
    settleDryRun(payload, policy, ledger);
    const replay = settleDryRun(payload, policy, ledger);
    return { decision: replay.settled ? 'allow' : 'block', reasonCodes: replay.reasonCodes ?? [] };
  }});

  execute({ id: 'stateful-invalid-signature', label: 'Permit tampering after signature', fields: ['permit.signature'], facts: { signatureValid: false }, operation: () => {
    const authority = new IntentAuthority(); const ledger = new GuardLedger();
    const permit = authority.issue(intentFromPaymentRequired(original), policy);
    permit.body.payment.maxAmount = (BigInt(permit.body.payment.maxAmount) + 1n).toString();
    const evaluation = evaluatePaymentRequired(original, policy, ledger, {
      requestedUrl: original.resource.url, intentPermit: permit, intentAuthority: authority
    });
    return { decision: evaluation.decision, reasonCodes: evaluation.reasonCodes ?? [] };
  }});

  execute({ id: 'stateful-first-permit-use', label: 'First permit use', fields: ['permit.first-use'], facts: { permitUses: 0 }, kind: 'legitimate', operation: () => {
    const authority = new IntentAuthority(); const ledger = new GuardLedger();
    const permit = authority.issue(intentFromPaymentRequired(original), policy);
    const first = evaluatePaymentRequired(original, policy, ledger, {
      requestedUrl: original.resource.url, intentPermit: permit, intentAuthority: authority
    });
    if (first.decision !== 'allow') return { decision: 'block', reasonCodes: first.reasonCodes ?? [] };
    const settled = settleDryRun(issueApproval(first, original, policy, ledger), policy, ledger);
    return { decision: settled.settled ? 'allow' : 'block', reasonCodes: settled.reasonCodes ?? [] };
  }});

  execute({ id: 'stateful-challenge-replay', label: 'Consumed merchant challenge replay', fields: ['challenge.replay'], facts: { challengeConsumed: true }, operation: () => {
    const registry = new ChallengeRegistry();
    const { challengeId } = registry.issue({ paymentRequired: original });
    const first = registry.consume(challengeId);
    const second = registry.consume(challengeId);
    return { decision: first && second ? 'allow' : 'block', reasonCodes: second ? [] : ['CHALLENGE_REPLAY'] };
  }});

  execute({ id: 'stateful-budget-drain', label: 'Reserved budget drain', fields: ['budget', 'concurrency'], facts: {
    budget: BigInt(original.accepts[0].amount) * 20n, pending: BigInt(original.accepts[0].amount) * 20n, amount: BigInt(original.accepts[0].amount)
  }, operation: () => {
    const budgetPolicy = clone(policy); budgetPolicy.dailyBudget = '1000000';
    const authority = new IntentAuthority(); const ledger = new GuardLedger();
    const pending = [];
    for (let index = 0; index < 20; index++) {
      const permit = authority.issue(intentFromPaymentRequired(original), budgetPolicy);
      const evaluation = evaluatePaymentRequired(original, budgetPolicy, ledger, { requestedUrl: original.resource.url, intentPermit: permit, intentAuthority: authority });
      pending.push(issueApproval(evaluation, original, budgetPolicy, ledger));
    }
    const permit = authority.issue(intentFromPaymentRequired(original), budgetPolicy);
    const overflow = evaluatePaymentRequired(original, budgetPolicy, ledger, { requestedUrl: original.resource.url, intentPermit: permit, intentAuthority: authority });
    return { decision: overflow.decision, reasonCodes: overflow.reasonCodes ?? [], pendingApprovals: pending.length };
  }});

  for (const [kind, pendingCount, amount, id] of [
    ['legitimate', 19, original.accepts[0].amount, 'stateful-budget-exact-limit'],
    ['attack', 20, '1', 'stateful-budget-over-by-one']
  ]) {
    execute({ id, label: kind === 'legitimate' ? 'Exact daily budget boundary' : 'Daily budget plus one atomic unit',
      fields: ['budget.boundary'], kind, facts: {
        budget: BigInt(original.accepts[0].amount) * 20n,
        pending: BigInt(original.accepts[0].amount) * BigInt(pendingCount), amount: BigInt(amount)
      }, operation: () => {
        const budgetPolicy = clone(policy);
        budgetPolicy.dailyBudget = (BigInt(original.accepts[0].amount) * 20n).toString();
        const authority = new IntentAuthority(); const ledger = new GuardLedger();
        for (let index = 0; index < pendingCount; index++) {
          const permit = authority.issue(intentFromPaymentRequired(original), budgetPolicy);
          const evaluation = evaluatePaymentRequired(original, budgetPolicy, ledger, {
            requestedUrl: original.resource.url, intentPermit: permit, intentAuthority: authority
          });
          issueApproval(evaluation, original, budgetPolicy, ledger);
        }
        const paymentRequired = clone(original);
        paymentRequired.accepts[0].amount = amount;
        const permit = authority.issue(intentFromPaymentRequired(original), budgetPolicy);
        const evaluation = evaluatePaymentRequired(paymentRequired, budgetPolicy, ledger, {
          requestedUrl: original.resource.url, intentPermit: permit, intentAuthority: authority
        });
        return { decision: evaluation.decision, reasonCodes: evaluation.reasonCodes ?? [] };
      }
    });
  }

  execute({ id: 'stateful-permit-race', label: 'Single-use permit contention', fields: ['permit-race'], facts: { permitUses: 1 }, operation: () => {
    const authority = new IntentAuthority(); const ledger = new GuardLedger();
    const permit = authority.issue(intentFromPaymentRequired(original), policy);
    const first = evaluatePaymentRequired(original, policy, ledger, { requestedUrl: original.resource.url, intentPermit: permit, intentAuthority: authority });
    const second = evaluatePaymentRequired(original, policy, ledger, { requestedUrl: original.resource.url, intentPermit: permit, intentAuthority: authority });
    const firstPayload = issueApproval(first, original, policy, ledger);
    try {
      const secondPayload = issueApproval(second, original, policy, ledger);
      const firstSettlement = settleDryRun(firstPayload, policy, ledger);
      const secondSettlement = settleDryRun(secondPayload, policy, ledger);
      return {
        decision: firstSettlement.settled && secondSettlement.settled ? 'allow' : 'block',
        reasonCodes: secondSettlement.reasonCodes ?? []
      };
    } catch {
      return { decision: 'block', reasonCodes: ['PERMIT_USES'] };
    }
  }});

  execute({ id: 'stateful-stale-policy', label: 'Stale policy settlement', fields: ['policy', 'stale-policy'], facts: { policyMatches: false }, operation: () => {
    const authority = new IntentAuthority(); const ledger = new GuardLedger();
    const permit = authority.issue(intentFromPaymentRequired(original), policy);
    const evaluation = evaluatePaymentRequired(original, policy, ledger, { requestedUrl: original.resource.url, intentPermit: permit, intentAuthority: authority });
    const payload = issueApproval(evaluation, original, policy, ledger);
    const newerPolicy = clone(policy); newerPolicy.maxPerPayment = '1';
    const result = settleDryRun(payload, newerPolicy, ledger);
    return { decision: result.decision, reasonCodes: result.reasonCodes ?? [] };
  }});

  execute({ id: 'stateful-post-approval', label: 'Post-approval recipient mutation', fields: ['post-approval', 'payTo'], facts: { executionMatchesApproval: false }, operation: () => {
    const authority = new IntentAuthority(); const ledger = new GuardLedger();
    const permit = authority.issue(intentFromPaymentRequired(original), policy);
    const evaluation = evaluatePaymentRequired(original, policy, ledger, { requestedUrl: original.resource.url, intentPermit: permit, intentAuthority: authority });
    const payload = issueApproval(evaluation, original, policy, ledger);
    payload.payload.authorization.to = '0x9999999999999999999999999999999999999999';
    const result = settleDryRun(payload, policy, ledger);
    return { decision: result.decision, reasonCodes: result.reasonCodes ?? [] };
  }});
  for (const [kind, seconds, id] of [
    ['legitimate', 299, 'stateful-permit-before-expiry'],
    ['attack', 301, 'stateful-permit-after-expiry']
  ]) {
    execute({ id, label: `Permit at ${seconds} seconds`, fields: ['permit.expiry'], facts: { nowSeconds: seconds }, kind, operation: () => {
      const authority = new IntentAuthority(); const ledger = new GuardLedger();
      const issuedAt = new Date('2026-10-31T08:00:00.000Z');
      const permit = authority.issue(intentFromPaymentRequired(original), policy, issuedAt);
      const checkedAt = new Date(issuedAt.getTime() + seconds * 1000);
      const evaluation = evaluatePaymentRequired(original, policy, ledger, {
        requestedUrl: original.resource.url, requestedMethod: 'GET', now: checkedAt,
        intentPermit: permit, intentAuthority: authority
      });
      return { decision: evaluation.decision, reasonCodes: evaluation.reasonCodes ?? [] };
    }});
  }
  return results;
}

function adaptiveResults(original, policy) {
  const strategies = new Map([
    ['recipient', ['adaptive-recipient', ['payTo'], request => { request.paymentRequired.accepts[0].payTo = '0x9999999999999999999999999999999999999999'; }]],
    ['resource', ['adaptive-resource', ['resource.query'], request => { const url = new URL(request.paymentRequired.resource.url); url.searchParams.set('symbol', 'ATTACKER'); request.paymentRequired.resource.url = url.toString(); request.requestedUrl = url.toString(); }]],
    ['flow', ['adaptive-flow', ['paymentFlow'], request => { request.paymentRequired.accepts[0].extra.paymentFlow = 'upfront'; }]],
    ['transfer', ['adaptive-transfer', ['transferMethod'], request => { request.paymentRequired.accepts[0].extra.assetTransferMethod = 'permit2'; }]]
  ]);
  const priorReasonCodes = [];
  const results = [];
  let next = 'recipient';
  while (strategies.size) {
    const [id, fields, mutate] = strategies.get(next);
    strategies.delete(next);
    const index = results.length;
    const testCase = caseFromMutation({ original, id, level: 5, label: `Adaptive strategy ${index + 1}`, mutationFields: fields, mutate });
    const observed = observedEvaluation({ ...testCase, original }, policy);
    const result = { ...testCase, observed, adaptiveHistory: [...priorReasonCodes], strategyChosenAfter: priorReasonCodes.at(-1) ?? 'initial probe' };
    priorReasonCodes.push(...observed.reasonCodes);
    results.push(result);
    // Only the public decision and returned reason categories guide the next
    // probe. No policy object or private ledger state is inspected here.
    const last = observed.reasonCodes.join(' ');
    const preferred = /RECIPIENT/.test(last) ? 'resource'
      : /RESOURCE/.test(last) ? 'flow'
        : /FLOW/.test(last) ? 'transfer' : null;
    next = preferred && strategies.has(preferred) ? preferred : strategies.keys().next().value;
  }
  return results;
}

function rates(results) {
  const attack = results.filter(result => result.kind === 'attack');
  const legitimate = results.filter(result => result.kind === 'legitimate');
  const truePositive = attack.filter(result => result.observed.decision === 'block').length;
  const falseNegative = attack.filter(result => result.observed.decision === 'allow').length;
  const trueNegative = legitimate.filter(result => result.observed.decision === 'allow').length;
  const falsePositive = legitimate.filter(result => result.observed.decision === 'block').length;
  const percentage = (numerator, denominator) => denominator ? Math.round(numerator / denominator * 10_000) / 100 : null;
  const precision = truePositive + falsePositive ? truePositive / (truePositive + falsePositive) : 1;
  const recall = attack.length ? truePositive / attack.length : 1;
  const specificity = legitimate.length ? trueNegative / legitimate.length : 1;
  const f1 = precision + recall ? 2 * precision * recall / (precision + recall) : 0;
  return {
    attacks: attack.length,
    legitimate: legitimate.length,
    truePositive,
    trueNegative,
    falsePositive,
    falseNegative,
    attackContainmentRate: percentage(truePositive, attack.length),
    bypassRate: percentage(falseNegative, attack.length),
    legitimatePassRate: percentage(trueNegative, legitimate.length),
    falsePositiveRate: percentage(falsePositive, legitimate.length),
    overallAccuracy: percentage(truePositive + trueNegative, results.length),
    precision: Math.round(precision * 10_000) / 100,
    attackRecall: Math.round(recall * 10_000) / 100,
    specificity: Math.round(specificity * 10_000) / 100,
    f1Score: Math.round(f1 * 10_000) / 100,
    observedBypassUpperBound95: falseNegative === 0 && attack.length ? Math.round(3 / attack.length * 10_000) / 100 : null
  };
}

export function finaliseHeldOut(result) {
  const metrics = rates(result.results);
  const failures = result.results.filter(item => item.truth.expected !== item.observed.decision);
  const criticalBypasses = failures.filter(isCriticalIntentBypass);
  const severity = Object.fromEntries(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW / QUALITY'].map(level => [level, {
    total: result.results.filter(item => item.severity === level).length,
    failures: failures.filter(item => item.severity === level).length
  }]));
  const passed = metrics.attackContainmentRate >= 95
    && metrics.legitimatePassRate >= 97
    && metrics.falsePositiveRate <= 3
    && metrics.bypassRate <= 5
    && criticalBypasses.length === 0;
  return {
    ...result,
    metrics,
    failures,
    criticalBypasses,
    severity,
    thresholds: { attackContainmentRate: '>= 95%', legitimatePassRate: '>= 97%', falsePositiveRate: '<= 3%', bypassRate: '<= 5%', criticalIntentBypasses: '0' },
    status: passed ? 'PASS' : 'FAIL',
    passed
  };
}

export function runHeldOut({ policy, seed = 402, attacks = 300, legitimate = 300 } = {}) {
  if (!policy) throw new Error('runHeldOut requires a policy');
  const reservedStatefulAndAdaptiveCases = 16;
  const reservedLegitimateBoundaryCases = 3;
  if (!Number.isInteger(attacks) || attacks <= reservedStatefulAndAdaptiveCases) {
    throw new Error(`attacks must be greater than ${reservedStatefulAndAdaptiveCases} to include held-out stateful and adaptive cases`);
  }
  if (!Number.isInteger(legitimate) || legitimate <= reservedLegitimateBoundaryCases) {
    throw new Error(`legitimate must be greater than ${reservedLegitimateBoundaryCases} to include boundary cases`);
  }
  const generated = generateHeldOutCases({
    seed,
    attacks: attacks - reservedStatefulAndAdaptiveCases,
    legitimate: legitimate - reservedLegitimateBoundaryCases
  });
  const staticResults = [...generated.attackCases, ...generated.legitimateCases].map(testCase => ({
    ...testCase,
    observed: observedEvaluation({ ...testCase, original: generated.original }, policy)
  }));
  const stateful = statefulResults(generated.original, policy);
  const adaptive = adaptiveResults(generated.original, policy);
  return finaliseHeldOut({
    suite: 'HELD-OUT RED TEAM',
    generatedAt: new Date().toISOString(),
    seed,
    requestedCounts: { attacks, legitimate },
    original: generated.original,
    results: [...staticResults, ...stateful, ...adaptive]
  });
}

export function summarizeHeldOut(report) {
  return {
    suite: report.suite,
    seed: report.seed,
    generatedAt: report.generatedAt,
    status: report.status,
    passed: report.passed,
    metrics: report.metrics,
    criticalBypasses: report.criticalBypasses.map(item => ({ id: item.id, severity: item.severity, mutationFields: item.mutationFields })),
    severity: report.severity,
    statefulChecks: report.results.filter(item => item.level === 4).map(item => ({
      id: item.id,
      expected: item.truth.expected,
      actual: item.observed.decision,
      passed: item.truth.expected === item.observed.decision,
      reasonCodes: item.observed.reasonCodes ?? []
    })),
    securityChecks: report.results.filter(item =>
      ['stateful-approval-reuse-before-settlement', 'stateful-fake-time'].includes(item.id)
      || item.id.startsWith('malformed-')
    ).map(item => ({
      id: item.id,
      expected: item.truth.expected,
      actual: item.observed.decision,
      passed: item.truth.expected === item.observed.decision,
      reasonCodes: item.observed.reasonCodes ?? []
    })),
    failures: report.failures.map(item => ({
      id: item.id,
      seed: report.seed,
      level: item.level,
      label: item.label,
      expected: item.truth.expected,
      actual: item.observed.decision,
      failureCategory: findingCategory(item),
      mutationFields: item.mutationFields,
      severity: item.severity,
      reasonCodes: item.observed.reasonCodes
    })),
    thresholds: report.thresholds,
    statisticalNote: report.metrics.observedBypassUpperBound95 === null
      ? 'Observed failures prevent a zero-failure upper-bound statement.'
      : `0/${report.metrics.attacks} observed attack bypasses; approximate controlled-sample 95% upper bound is ${report.metrics.observedBypassUpperBound95}% (rule of three), not a real-world guarantee.`
  };
}
