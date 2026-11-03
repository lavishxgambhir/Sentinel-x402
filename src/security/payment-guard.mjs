import crypto from 'node:crypto';
import {
  canonicalJson,
  canonicalResourceUrl,
  makeAuthorizationNonce,
  normalizeAddress,
  parseAtomic,
  sha256Hex,
  validatePaymentRequiredShape
} from '../core/x402.mjs';
import { evaluateRecipientRisk } from './recipient-risk.mjs';
import { propertyTagsFor } from './security-properties.mjs';

function makeCheck(code, ok, label, detail) {
  return { code, ok, label, detail };
}

function withPropertyTags(result, checks = []) {
  const reasonCodes = result.reasonCodes ?? [];
  return {
    ...result,
    // Block decisions cite only the violated properties; allow decisions cite
    // the full set of evaluated invariants.
    propertyTags: propertyTagsFor(reasonCodes, reasonCodes.length ? [] : checks)
  };
}

function asLowercaseSet(values = []) {
  return new Set(
    values.map(value => (typeof value === 'string' ? value.toLowerCase() : value))
  );
}

function parseUrl(value) {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function paymentFlow(offer) {
  return String(offer?.extra?.paymentFlow ?? 'authorization');
}

function transferMethod(offer) {
  return String(offer?.extra?.assetTransferMethod ?? 'eip3009');
}

function verifyIntentPermit(context, paymentRequired, policy, ledger, now) {
  const permit = context.intentPermit;
  const authority = context.intentAuthority;

  if (!permit) {
    const permitRequired = policy.requirePermit === true;
    return {
      supplied: false,
      valid: !permitRequired,
      checks: permitRequired
        ? [makeCheck('PERMIT_REQUIRED', false, 'Signed intent permit required', 'No permit supplied')]
        : [],
      permit: null
    };
  }

  if (!authority?.verify) {
    return {
      supplied: true,
      valid: false,
      checks: [
        makeCheck(
          'PERMIT_AUTHORITY',
          false,
          'Trusted intent authority',
          'No authority verifier configured'
        )
      ],
      permit: null
    };
  }

  const verification = authority.verify(permit, now);
  if (!verification.ok) {
    return {
      supplied: true,
      valid: false,
      checks: [
        makeCheck(
          'PERMIT_SIGNATURE',
          false,
          'Intent permit signature',
          verification.reason
        )
      ],
      permit: null
    };
  }

  const permitBody = verification.permit;
  const resource = parseUrl(paymentRequired.resource.url);
  const requestedMethod = String(context.requestedMethod ?? 'GET').toUpperCase();

  let canonicalUrl = null;
  try {
    canonicalUrl = canonicalResourceUrl(paymentRequired.resource.url);
  } catch {
    // Shape validation happens before this function. Keeping the fallback makes
    // this function safe if it is reused independently later.
  }

  const usedCount = ledger.permitUses(permitBody.permitId);
  const maxUses = Number(permitBody.maxUses ?? 1);
  const checks = [
    makeCheck(
      'PERMIT_SUBJECT',
      normalizeAddress(permitBody.subject) === normalizeAddress(policy.walletAddress),
      'Intent permit wallet',
      permitBody.subject
    ),
    makeCheck(
      'PERMIT_METHOD',
      requestedMethod === permitBody.resource.method,
      'Intent HTTP method binding',
      `${permitBody.resource.method} ↔ ${requestedMethod}`
    ),
    makeCheck(
      'PERMIT_RESOURCE_ORIGIN',
      resource?.origin === permitBody.resource.origin,
      'Intent origin binding',
      `${permitBody.resource.origin} ↔ ${resource?.origin}`
    ),
    makeCheck(
      'PERMIT_RESOURCE_PATH',
      resource?.pathname === permitBody.resource.pathname,
      'Intent path binding',
      `${permitBody.resource.pathname} ↔ ${resource?.pathname}`
    ),
    makeCheck(
      'PERMIT_RESOURCE_URL',
      canonicalUrl === permitBody.resource.canonicalUrl,
      'Intent full URL binding',
      `${permitBody.resource.canonicalUrl} ↔ ${canonicalUrl}`
    ),
    makeCheck(
      'PERMIT_POLICY_DIGEST',
      permitBody.policyDigest === sha256Hex(policy),
      'Policy version binding',
      permitBody.policyDigest
    ),
    makeCheck(
      'PERMIT_USES',
      usedCount < maxUses,
      'Intent permit remaining uses',
      `${usedCount}/${maxUses}`
    )
  ];

  return {
    supplied: true,
    valid: checks.every(item => item.ok),
    checks,
    permit: permitBody
  };
}

function permitChecksForOffer(offer, permitBody) {
  if (!permitBody) return [];

  const amount = parseAtomic(String(offer.amount));
  const maxAmount = parseAtomic(String(permitBody.payment.maxAmount));
  const allowedNetworks = new Set(permitBody.payment.networks ?? []);
  const allowedSchemes = new Set(permitBody.payment.schemes ?? []);
  const allowedFlows = new Set(permitBody.payment.paymentFlows ?? ['authorization']);
  const allowedTransfers = new Set(
    permitBody.payment.assetTransferMethods ?? ['eip3009']
  );
  const allowedAssets = asLowercaseSet(
    permitBody.payment.assets?.[offer.network] ?? []
  );
  const allowedRecipients = asLowercaseSet(
    (permitBody.payment.payTo ?? []).map(normalizeAddress)
  );

  return [
    makeCheck('INTENT_SCHEME', allowedSchemes.has(offer.scheme), 'Intent scheme', offer.scheme),
    makeCheck(
      'INTENT_FLOW',
      allowedFlows.has(paymentFlow(offer)),
      'Intent payment flow',
      paymentFlow(offer)
    ),
    makeCheck(
      'INTENT_TRANSFER_METHOD',
      allowedTransfers.has(transferMethod(offer)),
      'Intent asset transfer method',
      transferMethod(offer)
    ),
    makeCheck('INTENT_NETWORK', allowedNetworks.has(offer.network), 'Intent network', offer.network),
    makeCheck(
      'INTENT_ASSET',
      allowedAssets.has(String(offer.asset).toLowerCase()),
      'Intent asset',
      offer.asset
    ),
    makeCheck(
      'INTENT_RECIPIENT',
      allowedRecipients.has(String(normalizeAddress(offer.payTo)).toLowerCase()),
      'Intent recipient',
      offer.payTo
    ),
    makeCheck(
      'INTENT_AMOUNT',
      amount <= maxAmount,
      'Intent amount ceiling',
      `${offer.amount} <= ${permitBody.payment.maxAmount}`
    ),
    makeCheck(
      'INTENT_TIMEOUT',
      offer.maxTimeoutSeconds <= permitBody.payment.maxTimeoutSeconds,
      'Intent timeout ceiling',
      `${offer.maxTimeoutSeconds}s <= ${permitBody.payment.maxTimeoutSeconds}s`
    )
  ];
}

function evaluateOffer({
  offer,
  index,
  policy,
  merchantPolicy,
  ledger,
  now,
  remainingBudget,
  globalMax,
  bindingChecks,
  permitBody
}) {
  let amount;
  try {
    amount = parseAtomic(offer.amount, `accepts[${index}].amount`);
  } catch {
    amount = -1n;
  }

  const allowedSchemes = new Set(policy.allowedSchemes ?? []);
  const allowedNetworks = new Set(policy.allowedNetworks ?? []);
  const allowedFlows = new Set(policy.allowedPaymentFlows ?? ['authorization']);
  const allowedTransferMethods = new Set(
    policy.allowedAssetTransferMethods ?? ['eip3009']
  );
  const allowedAssets = asLowercaseSet(policy.allowedAssets?.[offer.network] ?? []);
  const merchantRecipients = asLowercaseSet(merchantPolicy?.payTo ?? []);

  const merchantMax = merchantPolicy?.maxAmount
    ? parseAtomic(String(merchantPolicy.maxAmount), 'merchant.maxAmount')
    : globalMax;
  const effectiveMax = merchantMax < globalMax ? merchantMax : globalMax;

  const recipientRisk = evaluateRecipientRisk(offer.payTo, policy, ledger, now);
  const relationshipChecks = recipientRisk.signals
    .filter(signal =>
      signal.code === 'WALLET_CLOSURE' || signal.code === 'WALLET_RELATIONSHIP_REVIEW'
    )
    .map(signal =>
      makeCheck(signal.code, false, 'Wallet relationship screen', signal.detail)
    );

  const checks = [
    ...bindingChecks,
    makeCheck('SCHEME', allowedSchemes.has(offer.scheme), 'Allowed scheme', offer.scheme),
    makeCheck(
      'PAYMENT_FLOW',
      allowedFlows.has(paymentFlow(offer)),
      'Allowed payment flow',
      paymentFlow(offer)
    ),
    makeCheck(
      'TRANSFER_METHOD',
      allowedTransferMethods.has(transferMethod(offer)),
      'Allowed asset transfer method',
      transferMethod(offer)
    ),
    makeCheck('NETWORK', allowedNetworks.has(offer.network), 'Allowed network', offer.network),
    makeCheck(
      'ASSET',
      allowedAssets.has(String(offer.asset).toLowerCase()),
      'Allowed asset',
      offer.asset
    ),
    makeCheck(
      'RECIPIENT',
      merchantRecipients.has(String(normalizeAddress(offer.payTo)).toLowerCase()),
      'Expected recipient',
      offer.payTo
    ),
    makeCheck(
      'COMPLIANCE',
      !recipientRisk.hardBlock,
      'Recipient compliance screening',
      recipientRisk.signals.map(signal => signal.code).join(', ') || 'clear'
    ),
    ...relationshipChecks,
    makeCheck('POSITIVE_AMOUNT', amount > 0n, 'Positive amount', offer.amount),
    makeCheck(
      'AMOUNT_LIMIT',
      amount >= 0n && amount <= effectiveMax,
      'Per-payment limit',
      `${offer.amount} <= ${effectiveMax}`
    ),
    makeCheck(
      'BUDGET',
      amount >= 0n && remainingBudget >= amount,
      'Daily budget remaining',
      `${remainingBudget >= 0n ? remainingBudget : 0n} atomic units remaining`
    ),
    makeCheck(
      'TIMEOUT',
      offer.maxTimeoutSeconds <= Number(policy.maxTimeoutSeconds),
      'Timeout limit',
      `${offer.maxTimeoutSeconds}s <= ${policy.maxTimeoutSeconds}s`
    ),
    ...permitChecksForOffer(offer, permitBody)
  ];

  const failed = checks.filter(item => !item.ok);
  return {
    index,
    offer,
    amount: amount >= 0n ? amount : null,
    allowed: failed.length === 0,
    checks,
    failedCodes: failed.map(item => item.code),
    recipientRisk
  };
}

export function evaluatePaymentRequired(paymentRequired, policy, ledger, context = {}) {
  const now = context.now ?? new Date();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    return withPropertyTags({
      decision: 'block', riskScore: 100, reason: 'Invalid evaluation time',
      reasonCodes: ['INVALID_EVALUATION_TIME'], offers: []
    });
  }

  try {
    validatePaymentRequiredShape(paymentRequired);
  } catch (error) {
    return withPropertyTags({
      decision: 'block',
      riskScore: 100,
      reason: error.message,
      reasonCodes: ['MALFORMED_REQUIREMENTS'],
      offers: []
    });
  }

  const requestedUrl = context.requestedUrl ?? paymentRequired.resource.url;
  const requestedResource = parseUrl(requestedUrl);
  const merchantResource = parseUrl(paymentRequired.resource.url);

  if (!requestedResource || !merchantResource) {
    return withPropertyTags({
      decision: 'block',
      riskScore: 100,
      reason: 'Invalid resource URL',
      reasonCodes: ['INVALID_RESOURCE_URL'],
      offers: []
    });
  }

  const permitResult = verifyIntentPermit(
    context,
    paymentRequired,
    policy,
    ledger,
    now
  );

  if (!permitResult.valid) {
    const failedChecks = permitResult.checks.filter(item => !item.ok);
    return withPropertyTags(
      {
        decision: 'block',
        riskScore: 100,
        reason: 'Trusted intent permit failed validation',
        reasonCodes: failedChecks.map(item => item.code),
        offers: [],
        permit: permitResult
      },
      permitResult.checks
    );
  }

  const merchantPolicy = Object.hasOwn(policy.merchants ?? {}, merchantResource.hostname)
    ? policy.merchants[merchantResource.hostname] : null;
  const globalMax = parseAtomic(String(policy.maxPerPayment), 'policy.maxPerPayment');
  const dailyBudget = parseAtomic(String(policy.dailyBudget), 'policy.dailyBudget');
  const remainingBudget = ledger.remainingBudget(dailyBudget, now);

  const requestedCanonicalUrl = canonicalResourceUrl(requestedUrl);
  const merchantCanonicalUrl = canonicalResourceUrl(paymentRequired.resource.url);
  const bindingChecks = [
    makeCheck(
      'RESOURCE_BINDING',
      requestedCanonicalUrl === merchantCanonicalUrl,
      'Full resource URL binding',
      `${requestedCanonicalUrl} ↔ ${merchantCanonicalUrl}`
    ),
    makeCheck(
      'KNOWN_MERCHANT',
      Boolean(merchantPolicy),
      'Known merchant',
      merchantResource.hostname
    ),
    ...permitResult.checks
  ];

  if (merchantPolicy?.allowedPaths) {
    bindingChecks.push(
      makeCheck(
        'ALLOWED_PATH',
        merchantPolicy.allowedPaths.includes(merchantResource.pathname),
        'Allowed resource path',
        merchantResource.pathname
      )
    );
  }

  const offerResults = paymentRequired.accepts.map((offer, index) =>
    evaluateOffer({
      offer,
      index,
      policy,
      merchantPolicy,
      ledger,
      now,
      remainingBudget,
      globalMax,
      bindingChecks,
      permitBody: permitResult.permit
    })
  );

  const allowedOffers = offerResults
    .filter(item => item.allowed)
    .sort((left, right) => {
      if (left.amount === right.amount) return left.index - right.index;
      return left.amount < right.amount ? -1 : 1;
    });

  if (allowedOffers.length === 0) {
    const failedCodes = [...new Set(offerResults.flatMap(item => item.failedCodes))];
    return withPropertyTags(
      {
        decision: 'block',
        riskScore: Math.min(100, 35 + failedCodes.length * 8),
        reason: 'No payment offer satisfies wallet intent and policy',
        reasonCodes: failedCodes,
        requestedUrl,
        resource: paymentRequired.resource,
        offers: offerResults,
        policyDigest: sha256Hex(policy),
        permit: permitResult.supplied
          ? {
              permitId: permitResult.permit?.permitId,
              keyId: permitResult.permit?.keyId
            }
          : null
      },
      offerResults.flatMap(item => item.checks)
    );
  }

  const selected = allowedOffers[0];
  return withPropertyTags(
    {
      decision: 'allow',
      riskScore: selected.recipientRisk.score,
      reason: 'A policy- and intent-compliant payment offer is available',
      reasonCodes: [],
      selectedIndex: selected.index,
      selected: selected.offer,
      requestedUrl,
      resource: paymentRequired.resource,
      offers: offerResults,
      policyDigest: sha256Hex(policy),
      permit: permitResult.supplied
        ? {
            permitId: permitResult.permit.permitId,
            keyId: permitResult.permit.keyId,
            digest: sha256Hex(permitResult.permit),
            maxUses: Number(permitResult.permit.maxUses),
            validAfter: Number(permitResult.permit.validAfter),
            validBefore: Number(permitResult.permit.validBefore)
          }
        : null
    },
    selected.checks
  );
}

export function issueApproval(evaluation, paymentRequired, policy, ledger, now = new Date()) {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new Error('Invalid approval time');
  if (evaluation.decision !== 'allow' || !evaluation.selected) {
    throw new Error('Cannot approve a blocked payment');
  }

  if (evaluation.policyDigest !== sha256Hex(policy)) {
    throw new Error('Policy changed after evaluation');
  }

  if (policy.requirePermit === true && !evaluation.permit?.digest) {
    throw new Error('Signed intent permit is required for approval');
  }
  const approvalSeconds = Math.floor(now.getTime() / 1000);
  if (evaluation.permit && (approvalSeconds < evaluation.permit.validAfter || approvalSeconds > evaluation.permit.validBefore)) {
    throw new Error('Intent permit expired before approval');
  }

  validatePaymentRequiredShape(paymentRequired);

  const selectedOffer = paymentRequired.accepts?.[evaluation.selectedIndex] ?? {};
  if (sha256Hex(selectedOffer) !== sha256Hex(evaluation.selected)) {
    throw new Error('Selected offer changed after evaluation');
  }

  if (paymentRequired.resource?.url !== evaluation.resource?.url) {
    throw new Error('Resource changed after evaluation');
  }

  const approvalId = crypto.randomUUID();
  const nonce = makeAuthorizationNonce();
  const issuedAt = Math.floor(now.getTime() / 1000);
  const expiresAt =
    issuedAt +
    Math.min(evaluation.selected.maxTimeoutSeconds, Number(policy.maxTimeoutSeconds));

  const binding = {
    resource: paymentRequired.resource.url,
    requirementsDigest: sha256Hex(evaluation.selected),
    policyDigest: evaluation.policyDigest,
    permitDigest: evaluation.permit?.digest ?? null,
    permitId: evaluation.permit?.permitId ?? null,
    permitMaxUses: evaluation.permit?.maxUses ?? null,
    permitValidBefore: evaluation.permit?.validBefore ?? null
  };

  const authorization = {
    from: normalizeAddress(policy.walletAddress),
    to: normalizeAddress(evaluation.selected.payTo),
    value: String(evaluation.selected.amount),
    validAfter: String(issuedAt - 1),
    validBefore: String(expiresAt),
    nonce
  };

  const approval = {
    approvalId,
    createdAt: now.toISOString(),
    binding,
    accepted: evaluation.selected,
    authorization
  };

  ledger.reserve(approvalId, parseAtomic(authorization.value), policy.dailyBudget, now, expiresAt);
  try {
    if (binding.permitId) {
      ledger.consumePermitForApproval(binding.permitId, approvalId, binding.permitMaxUses);
    }
    ledger.saveApproval(approvalId, approval);
  } catch (error) {
    ledger.rollbackPermitClaim(approvalId);
    ledger.release(approvalId);
    throw error;
  }

  return {
    x402Version: 2,
    resource: paymentRequired.resource,
    accepted: evaluation.selected,
    payload: {
      authorization,
      signature: 'DRY_RUN_NOT_BROADCAST'
    },
    guard: {
      approvalId,
      binding,
      note: 'Demo adapter: a real wallet signs only after the guard permits this exact authorization.'
    }
  };
}

export function validateBeforeSettlement(
  paymentPayload,
  policy,
  ledger,
  now = new Date(),
  settlementContext = {}
) {
  const approvalId = paymentPayload?.guard?.approvalId;
  const approval = approvalId ? ledger.getApproval(approvalId) : null;

  if (!approval) {
    return withPropertyTags({
      decision: 'block',
      reasonCodes: ['UNKNOWN_APPROVAL'],
      reason: 'No matching guard approval'
    });
  }

  const authorization = paymentPayload?.payload?.authorization;
  if (!authorization) {
    return withPropertyTags({
      decision: 'block',
      reasonCodes: ['MISSING_AUTHORIZATION'],
      reason: 'Authorization is missing'
    });
  }

  const checks = [];
  const acceptedDigest = sha256Hex(paymentPayload.accepted ?? {});
  const resourceUrl = paymentPayload?.resource?.url;

  checks.push(
    makeCheck(
      'APPROVAL_BINDING',
      acceptedDigest === approval.binding.requirementsDigest,
      'Approved offer unchanged',
      acceptedDigest
    )
  );
  checks.push(
    makeCheck(
      'APPROVAL_BINDING',
      sha256Hex(paymentPayload?.guard?.binding ?? {}) === sha256Hex(approval.binding),
      'Approval metadata unchanged',
      approvalId
    )
  );
  checks.push(
    makeCheck(
      'RESOURCE_BINDING',
      resourceUrl === approval.binding.resource,
      'Approved resource unchanged',
      resourceUrl
    )
  );
  checks.push(
    makeCheck(
      'POLICY_DIGEST',
      sha256Hex(policy) === approval.binding.policyDigest,
      'Policy unchanged since approval',
      approval.binding.policyDigest
    )
  );
  checks.push(
    makeCheck(
      'FROM',
      normalizeAddress(authorization.from) === normalizeAddress(policy.walletAddress),
      'Expected payer',
      authorization.from
    )
  );
  checks.push(
    makeCheck(
      'RECIPIENT',
      normalizeAddress(authorization.to) === normalizeAddress(approval.authorization.to),
      'Recipient unchanged',
      authorization.to
    )
  );
  checks.push(
    makeCheck(
      'AMOUNT',
      String(authorization.value) === String(approval.authorization.value),
      'Amount unchanged',
      authorization.value
    )
  );
  checks.push(
    makeCheck(
      'NONCE',
      authorization.nonce === approval.authorization.nonce,
      'Nonce unchanged',
      authorization.nonce
    )
  );
  checks.push(
    makeCheck(
      'REPLAY',
      !ledger.isNonceUsed(authorization.nonce),
      'Nonce not previously used',
      authorization.nonce
    )
  );

  if (approval.binding.permitId) {
    checks.push(
      makeCheck(
        'PERMIT_REPLAY',
        ledger.hasPermitClaim(approval.binding.permitId, approvalId),
        'Approval owns a consumed permit use',
        approval.binding.permitId
      )
    );
    checks.push(
      makeCheck(
        'PERMIT_TIME',
        Number.isSafeInteger(Number(approval.binding.permitValidBefore)) &&
          Math.floor(now.getTime() / 1000) <= Number(approval.binding.permitValidBefore),
        'Intent permit has not expired',
        String(approval.binding.permitValidBefore)
      )
    );
  }

  const nowSeconds = Math.floor(now.getTime() / 1000);
  const validAfter = Number(authorization.validAfter);
  const validBefore = Number(authorization.validBefore);

  checks.push(
    makeCheck(
      'TIME_WINDOW',
      String(authorization.validAfter) === String(approval.authorization.validAfter) &&
        String(authorization.validBefore) === String(approval.authorization.validBefore),
      'Authorization time bounds unchanged',
      `${authorization.validAfter}..${authorization.validBefore}`
    )
  );
  checks.push(
    makeCheck(
      'TIME_WINDOW',
      nowSeconds >= validAfter && nowSeconds <= validBefore,
      'Authorization time window',
      `${validAfter}..${validBefore}`
    )
  );

  const reservation = ledger.getReservation(approvalId, now);
  const remainingBudget = ledger.remainingBudget(policy.dailyBudget, now);
  const amount = parseAtomic(String(authorization.value), 'authorization.value');

  checks.push(
    makeCheck(
      'RESERVATION',
      Boolean(reservation) && reservation.amount === amount,
      'Approval budget reservation',
      reservation?.amount?.toString() ?? 'missing'
    )
  );

  const ownReservation =
    reservation?.day === ledger.dayKey(now) ? reservation.amount : 0n;
  checks.push(
    makeCheck(
      'BUDGET',
      remainingBudget + ownReservation >= amount,
      'Budget re-check at settlement',
      `${remainingBudget + ownReservation} available including this approval`
    )
  );

  if (paymentFlow(paymentPayload.accepted) === 'authorization' && settlementContext.actualAmount !== undefined) {
    const actualAmount = parseAtomic(
      String(settlementContext.actualAmount),
      'settlement.actualAmount'
    );

    if (paymentPayload.accepted.scheme === 'exact') {
      checks.push(
        makeCheck(
          'SETTLED_AMOUNT',
          actualAmount === amount,
          'Exact scheme settlement amount',
          `${actualAmount} == ${amount}`
        )
      );
    }

    if (paymentPayload.accepted.scheme === 'upto') {
      checks.push(
        makeCheck(
          'SETTLED_AMOUNT',
          actualAmount <= amount,
          'Upto scheme settlement ceiling',
          `${actualAmount} <= ${amount}`
        )
      );
    }
  }

  if (settlementContext.actualRecipient !== undefined) {
    checks.push(
      makeCheck(
        'SETTLED_RECIPIENT',
        normalizeAddress(settlementContext.actualRecipient) ===
          normalizeAddress(authorization.to),
        'Settled recipient correspondence',
        settlementContext.actualRecipient
      )
    );
  }

  if (settlementContext.actualNetwork !== undefined) {
    checks.push(
      makeCheck(
        'SETTLED_NETWORK',
        String(settlementContext.actualNetwork) === String(paymentPayload.accepted.network),
        'Settled network correspondence',
        settlementContext.actualNetwork
      )
    );
  }

  if (settlementContext.actualAsset !== undefined) {
    checks.push(
      makeCheck(
        'SETTLED_ASSET',
        String(settlementContext.actualAsset).toLowerCase() ===
          String(paymentPayload.accepted.asset).toLowerCase(),
        'Settled asset correspondence',
        settlementContext.actualAsset
      )
    );
  }

  const failedChecks = checks.filter(item => !item.ok);
  return withPropertyTags(
    {
      decision: failedChecks.length ? 'block' : 'allow',
      reasonCodes: failedChecks.map(item => item.code),
      reason: failedChecks.length
        ? 'Settlement blocked by final guard re-check'
        : 'Settlement is still policy compliant',
      checks
    },
    checks
  );
}

export function settleDryRun(
  paymentPayload,
  policy,
  ledger,
  now = new Date(),
  settlementContext = {}
) {
  let finalCheck;

  try {
    finalCheck = validateBeforeSettlement(
      paymentPayload,
      policy,
      ledger,
      now,
      settlementContext
    );
  } catch (error) {
    ledger.release(paymentPayload?.guard?.approvalId);
    return withPropertyTags({
      decision: 'block',
      reasonCodes: ['MALFORMED_AUTHORIZATION'],
      reason: error.message,
      settled: false
    });
  }

  if (finalCheck.decision !== 'allow') {
    ledger.release(paymentPayload?.guard?.approvalId);
    return { ...finalCheck, settled: false };
  }

  const authorization = paymentPayload.payload.authorization;
  ledger.markNonceUsed(authorization.nonce);

  const actualAmount =
    settlementContext.actualAmount !== undefined
      ? String(settlementContext.actualAmount)
      : String(authorization.value);

  ledger.recordSpend(BigInt(actualAmount), now, authorization.to);
  ledger.release(paymentPayload.guard.approvalId);

  return {
    ...finalCheck,
    settled: true,
    transaction: {
      mode: 'dry-run',
      from: authorization.from,
      to: authorization.to,
      amount: actualAmount,
      authorizedAmount: authorization.value,
      nonce: authorization.nonce,
      receiptHash: sha256Hex(
        canonicalJson({
          auth: authorization,
          approvalId: paymentPayload.guard.approvalId,
          actualAmount
        })
      )
    }
  };
}
