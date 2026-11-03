import crypto from 'node:crypto';
import { evaluatePaymentRequired } from '../security/payment-guard.mjs';
import { GuardLedger } from '../state/guard-ledger.mjs';
import { normalizeAddress, parseAtomic } from '../core/x402.mjs';
import { intentFromPaymentRequired } from '../core/intent.mjs';
import { compareAgainstOriginal, buildExecutionTrace } from '../research/paper-analysis.mjs';

const clone = (v) => JSON.parse(JSON.stringify(v));
const norm = (v) => typeof v === 'string' ? v.toLowerCase() : v;
const safeUrl = (v) => { try { return new URL(v); } catch { return null; } };

function atomicPolicyValue(value, field) {
  const normalized = String(value ?? '').trim();
  try {
    parseAtomic(normalized, field);
  } catch {
    throw new Error(`${field} must be a non-negative atomic-unit integer`);
  }
  return normalized;
}

function boundedWholeNumber(value, field, minimum, maximum) {
  const normalized = String(value ?? '').trim();
  if (!/^\d+$/.test(normalized)) {
    throw new Error(`${field} must be a whole number between ${minimum} and ${maximum}`);
  }
  const parsed = Number(normalized);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${field} must be a whole number between ${minimum} and ${maximum}`);
  }
  return parsed;
}

function nonEmptyStrings(values, field) {
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error(`${field} must contain at least one value`);
  }
  if (values.some(value => typeof value !== 'string')) {
    throw new Error(`${field} must contain only strings`);
  }
  const normalized = values.map(value => value.trim());
  if (normalized.some(value => value.length === 0)) {
    throw new Error(`${field} cannot contain an empty value`);
  }
  return normalized;
}

function recipientAddresses(values, field) {
  const normalized = nonEmptyStrings(values, field);
  if (normalized.some(value => !/^0x[0-9a-fA-F]{40}$/.test(value))) {
    throw new Error(`${field} must contain 0x-prefixed 20-byte wallet addresses`);
  }
  return normalized;
}

export function refereePayment(paymentRequired, policy, requestedUrl) {
  try {
    if (!paymentRequired || paymentRequired.x402Version !== 2) throw new Error('bad x402 version');
    if (!paymentRequired.resource?.url || !Array.isArray(paymentRequired.accepts) || !paymentRequired.accepts.length) throw new Error('malformed payment requirement');
    const requested = safeUrl(requestedUrl ?? paymentRequired.resource.url);
    const resource = safeUrl(paymentRequired.resource.url);
    if (!requested || !resource) return { expected: 'block', reason: 'Invalid resource URL' };
    if (requested.origin !== resource.origin || requested.pathname !== resource.pathname) return { expected: 'block', reason: 'Resource binding mismatch' };
    const merchant = Object.hasOwn(policy.merchants ?? {}, resource.hostname)
      ? policy.merchants[resource.hostname] : null;
    if (!merchant) return { expected: 'block', reason: 'Unknown merchant' };
    if (merchant.allowedPaths && !merchant.allowedPaths.includes(resource.pathname)) return { expected: 'block', reason: 'Resource path is not approved' };

    const maxGlobal = parseAtomic(String(policy.maxPerPayment));
    const maxMerchant = merchant.maxAmount ? parseAtomic(String(merchant.maxAmount)) : maxGlobal;
    const max = maxMerchant < maxGlobal ? maxMerchant : maxGlobal;
    const recipients = new Set((merchant.payTo ?? []).map(x => norm(normalizeAddress(x))));
    const schemes = new Set(policy.allowedSchemes ?? []);
    const networks = new Set(policy.allowedNetworks ?? []);
    const flows = new Set(policy.allowedPaymentFlows ?? ['authorization']);
    const transferMethods = new Set(policy.allowedAssetTransferMethods ?? ['eip3009']);

    for (const offer of paymentRequired.accepts) {
      let amount; try { amount = parseAtomic(String(offer.amount)); } catch { continue; }
      const assets = new Set((policy.allowedAssets?.[offer.network] ?? []).map(norm));
      if (!schemes.has(offer.scheme)) continue;
      if (!flows.has(String(offer.extra?.paymentFlow ?? 'authorization'))) continue;
      if (!transferMethods.has(String(offer.extra?.assetTransferMethod ?? 'eip3009'))) continue;
      if (!networks.has(offer.network)) continue;
      if (!assets.has(norm(offer.asset))) continue;
      if (!recipients.has(norm(normalizeAddress(offer.payTo)))) continue;
      if (amount <= 0n || amount > max) continue;
      if (!Number.isInteger(offer.maxTimeoutSeconds) || offer.maxTimeoutSeconds > Number(policy.maxTimeoutSeconds)) continue;
      return { expected: 'allow', reason: 'Payment matches the configured intent contract' };
    }
    return { expected: 'block', reason: 'No offered payment matches the configured intent contract' };
  } catch (error) {
    return { expected: 'block', reason: `Malformed request: ${error.message}` };
  }
}

export class RedBlueArena {
  constructor(policy, audit = null, intentAuthority = null) {
    this.basePolicy = clone(policy);
    this.intentAuthority = intentAuthority;
    this.policy = clone(policy);
    this.audit = audit;
    this.reset();
  }

  reset() {
    this.trainingMode = 'secure';
    this.round = 0;
    this.blueScore = 0;
    this.redScore = 0;
    this.guardCorrect = 0;
    this.guardTotal = 0;
    this.guardBypasses = 0;
    this.falsePositives = 0;
    this.attackBlocked = 0;
    this.attackTotal = 0;
    this.legitAllowed = 0;
    this.legitTotal = 0;
    this.protectedAtomic = 0n;
    this.unauthorizedValueSettled = 0n;
    this.requests = [];
    this.guardLedger = new GuardLedger();
    this.policy = clone(this.basePolicy);
  }

  setPolicy(patch = {}) {
    if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
      throw new Error('Policy update must be an object');
    }

    // Validate every supplied value before changing state. A bad form field
    // must never leave the live demo with a partially updated policy.
    const validated = {
      maxPerPayment: patch.maxPerPayment === undefined
        ? undefined
        : atomicPolicyValue(patch.maxPerPayment, 'maxPerPayment'),
      dailyBudget: patch.dailyBudget === undefined
        ? undefined
        : atomicPolicyValue(patch.dailyBudget, 'dailyBudget'),
      maxTimeoutSeconds: patch.maxTimeoutSeconds === undefined
        ? undefined
        : boundedWholeNumber(patch.maxTimeoutSeconds, 'maxTimeoutSeconds', 1, 3600),
      allowedNetworks: patch.allowedNetworks === undefined
        ? undefined
        : nonEmptyStrings(patch.allowedNetworks, 'allowedNetworks'),
      allowedPaymentFlows: patch.allowedPaymentFlows === undefined
        ? undefined
        : nonEmptyStrings(patch.allowedPaymentFlows, 'allowedPaymentFlows'),
      allowedAssetTransferMethods: patch.allowedAssetTransferMethods === undefined
        ? undefined
        : nonEmptyStrings(patch.allowedAssetTransferMethods, 'allowedAssetTransferMethods')
    };

    if (patch.merchant !== undefined && (!patch.merchant || typeof patch.merchant !== 'object' || Array.isArray(patch.merchant))) {
      throw new Error('merchant must be an object');
    }
    const merchant = patch.merchant ?? {};
    validated.merchantMaxAmount = merchant.maxAmount === undefined
      ? undefined
      : atomicPolicyValue(merchant.maxAmount, 'merchant.maxAmount');
    validated.merchantPayTo = merchant.payTo === undefined
      ? undefined
      : recipientAddresses(merchant.payTo, 'merchant.payTo');

    const next = clone(this.policy);
    if (validated.maxPerPayment !== undefined) next.maxPerPayment = validated.maxPerPayment;
    if (validated.dailyBudget !== undefined) next.dailyBudget = validated.dailyBudget;
    if (validated.maxTimeoutSeconds !== undefined) next.maxTimeoutSeconds = validated.maxTimeoutSeconds;
    if (validated.allowedNetworks !== undefined) next.allowedNetworks = validated.allowedNetworks;
    if (validated.allowedPaymentFlows !== undefined) next.allowedPaymentFlows = validated.allowedPaymentFlows;
    if (validated.allowedAssetTransferMethods !== undefined) next.allowedAssetTransferMethods = validated.allowedAssetTransferMethods;
    if (patch.merchant) {
      const host = 'api.safe.test';
      next.merchants[host] ??= {};
      if (validated.merchantMaxAmount !== undefined) next.merchants[host].maxAmount = validated.merchantMaxAmount;
      if (validated.merchantPayTo !== undefined) {
        const seededPayee = this.basePolicy.risk?.closure?.edges?.[0]?.from;
        const demoPayee = this.basePolicy.merchants?.[host]?.payTo?.find(value => norm(value) === norm(seededPayee));
        next.merchants[host].payTo = [...new Set([...validated.merchantPayTo, ...(demoPayee ? [demoPayee] : [])])];
      }
    }
    this.policy = next;
    this.audit?.append({ type: 'policy_update', policy: clone(this.publicPolicy()) });
    return this.publicPolicy();
  }

  publicPolicy() {
    return {
      maxPerPayment: this.policy.maxPerPayment,
      dailyBudget: this.policy.dailyBudget,
      maxTimeoutSeconds: this.policy.maxTimeoutSeconds,
      allowedNetworks: this.policy.allowedNetworks,
      allowedAssets: this.policy.allowedAssets,
      allowedPaymentFlows: this.policy.allowedPaymentFlows,
      allowedAssetTransferMethods: this.policy.allowedAssetTransferMethods,
      merchants: this.policy.merchants
    };
  }

  setTrainingMode(mode) {
    if (mode !== 'secure' && mode !== 'merchant-timeout') {
      throw new Error('Training mode must be secure or merchant-timeout');
    }
    this.trainingMode = mode;
    this.audit?.append({ type: 'arena_training_mode', mode });
    return mode;
  }

  snapshot(role = 'judge', historyLimit = 60) {
    const limit = Number.isSafeInteger(historyLimit) && historyLimit > 0
      ? Math.min(historyLimit, 60) : 60;
    const requests = this.requests.slice(-limit).map(item => {
      const copy = clone(item);
      if (role === 'blue' && copy.status === 'evaluated') {
        copy.redLabel = null;
        copy.redNote = null;
      }
      return copy;
    });
    return {
      round: this.round,
      trainingMode: this.trainingMode,
      scores: { blue: this.blueScore, red: this.redScore },
      metrics: {
        guardCorrect: this.guardCorrect,
        guardTotal: this.guardTotal,
        guardBypasses: this.guardBypasses,
        falsePositives: this.falsePositives,
        attackBlocked: this.attackBlocked,
        attackTotal: this.attackTotal,
        legitAllowed: this.legitAllowed,
        legitTotal: this.legitTotal,
        attackBlockRate: this.attackTotal ? Math.round(this.attackBlocked / this.attackTotal * 1000) / 10 : 100,
        legitPassRate: this.legitTotal ? Math.round(this.legitAllowed / this.legitTotal * 1000) / 10 : 100,
        protectedAtomic: this.protectedAtomic.toString(),
        unauthorizedValueSettled: this.unauthorizedValueSettled.toString()
      },
      policy: this.publicPolicy(),
      requests
    };
  }

  submit({ attacker = 'Red Team', redLabel = 'Custom mutation', redNote = '', originalPaymentRequired, paymentRequired, requestedUrl }) {
    if (!paymentRequired) throw new Error('paymentRequired is required');
    if (!originalPaymentRequired) throw new Error('A server-owned originalPaymentRequired is required');
    const truth = compareAgainstOriginal(originalPaymentRequired, paymentRequired);
    let intentPermit = null;
    if (this.intentAuthority && originalPaymentRequired) {
      const intent = intentFromPaymentRequired(originalPaymentRequired, { resourceUrl: requestedUrl ?? originalPaymentRequired.resource.url });
      // Deliberately vulnerable arena fixture: a confused permit issuer trusts
      // the received merchant timeout. The independent referee still compares
      // against the server-held original. Production permit issuance is untouched.
      if (this.trainingMode === 'merchant-timeout') {
        const receivedTimeout = paymentRequired.accepts?.[0]?.maxTimeoutSeconds;
        if (Number.isSafeInteger(receivedTimeout) && receivedTimeout > 0) {
          intent.maxTimeoutSeconds = receivedTimeout;
        }
      }
      intentPermit = this.intentAuthority.issue(intent, this.policy);
    }
    const guard = evaluatePaymentRequired(paymentRequired, this.policy, this.guardLedger, { requestedUrl, requestedMethod: 'GET', intentPermit, intentAuthority: this.intentAuthority });
    const guardExpected = truth.expected;
    const guardAction = guard.decision === 'allow' ? 'allow' : 'block';
    const guardCorrect = guardAction === guardExpected;
    const isAttack = guardExpected === 'block';
    let amount = 0n;
    try { amount = parseAtomic(String(paymentRequired.accepts?.[0]?.amount ?? '0')); } catch {}

    this.round += 1;
    this.guardTotal += 1;
    let outcomeType = 'unknown';
    if (isAttack && guardAction === 'block') outcomeType = 'attack-blocked';
    else if (isAttack && guardAction === 'allow') outcomeType = 'bypass';
    else if (!isAttack && guardAction === 'allow') outcomeType = 'legitimate-pass';
    else if (!isAttack && guardAction === 'block') outcomeType = 'false-positive';

    if (guardCorrect) {
      this.guardCorrect += 1;
      this.blueScore += 1;
    } else {
      this.redScore += 1;
      if (outcomeType === 'bypass') this.guardBypasses += 1;
      if (outcomeType === 'false-positive') this.falsePositives += 1;
    }
    if (isAttack) {
      this.attackTotal += 1;
      if (guardAction === 'block') { this.attackBlocked += 1; this.protectedAtomic += amount; }
    } else {
      this.legitTotal += 1;
      if (guardAction === 'allow') this.legitAllowed += 1;
    }

    const item = {
      id: crypto.randomUUID(),
      round: this.round,
      trainingMode: this.trainingMode,
      createdAt: new Date().toISOString(),
      attacker: String(attacker).slice(0, 48),
      redLabel: String(redLabel).slice(0, 80),
      redNote: String(redNote).slice(0, 240),
      requestedUrl,
      originalPaymentRequired: originalPaymentRequired ? clone(originalPaymentRequired) : null,
      paymentRequired: clone(paymentRequired),
      truth,
      classification: isAttack ? 'attack' : 'legitimate',
      outcomeType,
      groundTruth: truth,
      intentPermit: intentPermit ? { permitId: intentPermit.body.permitId, keyId: intentPermit.body.keyId, maxAmount: intentPermit.body.payment.maxAmount, maxTimeoutSeconds: intentPermit.body.payment.maxTimeoutSeconds, payTo: intentPermit.body.payment.payTo, resource: intentPermit.body.resource, paymentFlows: intentPermit.body.payment.paymentFlows, assetTransferMethods: intentPermit.body.payment.assetTransferMethods, validBefore: intentPermit.body.validBefore } : null,
      guard: {
        action: guardAction,
        decision: guard.decision,
        reason: guard.reason,
        reasonCodes: guard.reasonCodes ?? [],
        riskScore: guard.riskScore,
        selectedIndex: guard.selectedIndex ?? null,
        correct: guardCorrect,
        checks: guard.offers?.[guard.selectedIndex ?? 0]?.checks ?? [],
        propertyTags: guard.propertyTags ?? [],
        recipientRisk: guard.offers?.[guard.selectedIndex ?? 0]?.recipientRisk ?? null,
        closure: guard.offers?.[guard.selectedIndex ?? 0]?.recipientRisk?.closure ?? null
      },
      wallet: {
        signed: guardAction === 'allow',
        broadcast: false,
        mode: 'arena-evaluation'
      },
      executionTrace: buildExecutionTrace({
        classification: isAttack ? 'attack' : 'legitimate',
        guardAction,
        guardReasonCodes: guard.reasonCodes ?? [],
        walletSigned: guardAction === 'allow',
        settled: false,
        recipientCompliant: isAttack ? false : true,
        arenaMode: true
      }),
      status: 'evaluated'
    };
    this.requests.push(item);
    this.audit?.append({ type: 'arena_round', round: item.round, classification: item.classification, guardAction, guardCorrect, redLabel: item.redLabel, amount: amount.toString(), reasonCodes: item.guard.reasonCodes });
    return clone(item);
  }
}
