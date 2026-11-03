import crypto from 'node:crypto';

import { createIntent } from '../core/intent.mjs';
import { decodePaymentRequiredHeader, validatePaymentRequiredShape } from '../core/x402.mjs';
import { buildMerchantChallenge } from '../demo/merchant.mjs';
import { RedBlueArena } from '../demo/arena.mjs';
import { runFuzz } from '../research/fuzz.mjs';
import { runHeldOut, summarizeHeldOut } from '../research/heldout.mjs';
import {
  evaluatePaymentRequired,
  issueApproval,
  settleDryRun
} from '../security/payment-guard.mjs';
import { IntentAuthority } from '../security/intent-authority.mjs';
import { GuardLedger } from '../state/guard-ledger.mjs';
import { ChallengeRegistry } from '../state/challenge-registry.mjs';
import { evaluatePublicGuardRequest } from '../security/guard-request.mjs';


function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

export function encodeBase64Json(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
}

export function decodeBase64Json(value) {
  return JSON.parse(Buffer.from(String(value), 'base64').toString('utf8'));
}

/**
 * Holds the mutable state used by the interactive demo.  HTTP handlers should
 * call this class rather than manipulate the arena, ledger, or challenge map.
 */
export class SentinelRuntime {
  constructor({ policy, audit, port, adminToken, intentAuthority = null, serverless = false }) {
    this.audit = audit;
    this.port = port;
    this.adminToken = adminToken;
    this.intentAuthority = intentAuthority ?? new IntentAuthority();
    this.serverless = serverless;
    this.arena = new RedBlueArena(policy, audit, this.intentAuthority);
    this.ledger = new GuardLedger();
    this.challenges = new ChallengeRegistry();
    this.evaluationReports = { known: null, heldout: null, multi: null };
  }

  isAdmin(request) {
    const supplied = request.headers['x-sentinel-admin-token'];
    if (typeof supplied !== 'string') return false;

    const actual = Buffer.from(supplied);
    const expected = Buffer.from(this.adminToken);
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  }

  issueArenaChallenge() {
    const challenge = buildMerchantChallenge();
    const { challengeId, expiresAt } = this.challenges.issue({
      paymentRequired: clone(challenge.paymentRequired),
      requestedUrl: challenge.paymentRequired.resource.url
    });

    return {
      challengeId,
      expiresAt: new Date(expiresAt).toISOString(),
      ...challenge
    };
  }

  submitArenaChallenge(body) {
    try {
      validatePaymentRequiredShape(body.paymentRequired);
    } catch {
      return {
        ok: false,
        status: 400,
        error: 'Invalid paymentRequired shape'
      };
    }

    const stored = this.challenges.consume(body.challengeId);
    if (!stored) {
      return {
        ok: false,
        status: 400,
        error: 'Unknown or expired challengeId; fetch a fresh merchant challenge'
      };
    }

    // A challenge is one-use even when the submitted mutation is rejected.
    const item = this.arena.submit({
      attacker: body.attacker,
      redLabel: body.redLabel,
      redNote: body.redNote,
      originalPaymentRequired: stored.paymentRequired,
      requestedUrl: stored.requestedUrl,
      paymentRequired: body.paymentRequired
    });

    return { ok: true, status: 201, item, state: this.arena.snapshot('red', 12) };
  }

  resetArena() {
    this.arena.reset();
    this.ledger = new GuardLedger();
    this.challenges.clear();
    this.audit.append({ type: 'arena_reset' });
    return this.arena.snapshot('judge');
  }

  issueIntent(body) {
    const intent = createIntent(body.intent ?? body ?? {});
    const permit = this.intentAuthority.issue(intent, this.arena.policy);
    this.audit.append({
      type: 'intent_permit_issued',
      permitId: permit.body.permitId,
      purposeHash: permit.body.purposeHash,
      resource: permit.body.resource
    });
    return { intent, permit };
  }

  evaluateGuard(body) {
    const evaluation = evaluatePublicGuardRequest(body, {
      policy: this.arena.policy, ledger: this.ledger, intentAuthority: this.intentAuthority
    });
    this.audit.append({
      type: 'guard_evaluation',
      decision: evaluation.decision,
      reasonCodes: evaluation.reasonCodes ?? []
    });
    return evaluation;
  }

  runFuzz(body) {
    const source = body.paymentRequired ?? buildMerchantChallenge().paymentRequired;
    const attackCount = Math.max(23, Math.min(500, Number(body.attackCount ?? body.trials ?? 23)));
    const honestCount = Math.max(3, Math.min(500, Number(body.honestCount ?? 3)));
    const seed = Number.isSafeInteger(Number(body.seed)) ? Number(body.seed) : 402;
    const report = runFuzz({
      paymentRequired: source,
      policy: this.arena.policy,
      intentAuthority: this.intentAuthority,
      seed,
      attackCount,
      honestCount
    });
    this.audit.append({
      type: 'authorized_attack_lab',
      seed: report.seed,
      attackCases: report.metrics.attackCases,
      honestCases: report.metrics.legitimateCases,
      bypasses: report.metrics.bypasses,
      falsePositives: report.metrics.falsePositives
    });
    this.evaluationReports.known = {
      seed: report.seed,
      metrics: report.metrics,
      status: report.metrics.bypasses === 0 && report.metrics.falsePositives === 0 ? 'PASS' : 'FAIL'
    };
    return report;
  }

  runHeldOut(body = {}) {
    const seed = Number(body.seed ?? 42);
    const attacks = Number(body.attacks ?? 300);
    const legitimate = Number(body.legitimate ?? 300);
    if (!Number.isSafeInteger(seed) || seed < 1 || seed > 2000) throw new Error('seed must be an integer between 1 and 2000');
    const report = summarizeHeldOut(runHeldOut({ policy: this.arena.policy, seed, attacks, legitimate }));
    this.evaluationReports.heldout = report;
    this.audit.append({
      type: 'heldout_evaluation', seed, status: report.status,
      attacks: report.metrics.attacks, legitimate: report.metrics.legitimate,
      bypasses: report.metrics.falseNegative, falsePositives: report.metrics.falsePositive,
      criticalBypasses: report.criticalBypasses.length
    });
    return report;
  }

  runHeldOutMulti(body = {}) {
    const attacks = Number(body.attacks ?? 300);
    const legitimate = Number(body.legitimate ?? 300);
    const seeds = [1, 7, 42, 99, 402, 1337, 2026];
    const reports = seeds.map(seed => summarizeHeldOut(runHeldOut({
      policy: this.arena.policy, seed, attacks, legitimate
    })));
    const metrics = reports.map(report => report.metrics);
    const mean = key => Math.round(metrics.reduce((sum, item) => sum + item[key], 0) / metrics.length * 100) / 100;
    const result = {
      status: reports.every(report => report.passed) ? 'PASS' : 'FAIL',
      seeds,
      totalAttacks: metrics.reduce((sum, item) => sum + item.attacks, 0),
      totalLegitimate: metrics.reduce((sum, item) => sum + item.legitimate, 0),
      totalBypasses: metrics.reduce((sum, item) => sum + item.falseNegative, 0),
      totalFalsePositives: metrics.reduce((sum, item) => sum + item.falsePositive, 0),
      criticalBypasses: reports.reduce((sum, item) => sum + item.criticalBypasses.length, 0),
      meanAttackContainmentRate: mean('attackContainmentRate'),
      minAttackContainmentRate: Math.min(...metrics.map(item => item.attackContainmentRate)),
      maxAttackContainmentRate: Math.max(...metrics.map(item => item.attackContainmentRate)),
      meanLegitimatePassRate: mean('legitimatePassRate'),
      reports: reports.map(item => ({ seed: item.seed, status: item.status, metrics: item.metrics, failures: item.failures }))
    };
    this.evaluationReports.multi = result;
    return result;
  }

  merchantChallengeResponse(signatureHeader) {
    const challenge = buildMerchantChallenge();
    if (!signatureHeader) {
      return {
        status: 402,
        body: { error: 'payment_required', resource: challenge.paymentRequired.resource },
        headers: { 'PAYMENT-REQUIRED': challenge.header }
      };
    }

    let paymentPayload;
    try {
      paymentPayload = decodeBase64Json(signatureHeader);
    } catch {
      return {
        status: 402,
        body: { error: 'invalid_payment_signature' },
        headers: { 'PAYMENT-REQUIRED': challenge.header }
      };
    }

    const settlement = settleDryRun(paymentPayload, this.arena.policy, this.ledger);
    if (!settlement.settled) {
      return {
        status: 402,
        body: { error: settlement.reason, reasonCodes: settlement.reasonCodes },
        headers: { 'PAYMENT-REQUIRED': challenge.header }
      };
    }

    this.audit.append({
      type: 'merchant_delivery',
      amount: paymentPayload.payload.authorization.value,
      payTo: paymentPayload.payload.authorization.to,
      receiptHash: settlement.transaction.receiptHash
    });

    return {
      status: 200,
      body: {
        ok: true,
        premiumData: { symbol: 'NVDA', signal: 'demo-only', confidence: 0.94 },
        payment: settlement.transaction
      },
      headers: {
        'PAYMENT-RESPONSE': encodeBase64Json({
          success: true,
          transaction: settlement.transaction.receiptHash,
          network: 'eip155:84532',
          payer: paymentPayload.payload.authorization.from
        })
      }
    };
  }

  async runAgentFlow() {
    const intent = createIntent();
    const intentPermit = this.intentAuthority.issue(intent, this.arena.policy);
    const merchantUrl = this.serverless ? null : `http://127.0.0.1:${this.port}/merchant/premium-data`;
    const firstResponse = this.serverless ? this.merchantChallengeResponse() : await fetch(merchantUrl);
    const paymentRequiredHeader = this.serverless
      ? firstResponse.headers['PAYMENT-REQUIRED']
      : firstResponse.headers.get('payment-required');

    if (firstResponse.status !== 402 || !paymentRequiredHeader) {
      throw new Error('Merchant did not return a valid x402 402 challenge');
    }

    let paymentRequired;
    try {
      paymentRequired = decodePaymentRequiredHeader(paymentRequiredHeader);
    } catch {
      const result = {
        ok: false,
        stage: 'sentinel',
        http: { firstStatus: firstResponse.status },
        reason: 'Malformed merchant payment requirements',
        wallet: { signed: false, broadcast: false }
      };
      this.audit.append({ type: 'agent_flow', outcome: 'blocked', reasonCodes: ['MALFORMED_REQUIREMENTS'] });
      return { status: 403, result };
    }
    const evaluation = evaluatePaymentRequired(paymentRequired, this.arena.policy, this.ledger, {
      requestedUrl: intent.resourceUrl,
      requestedMethod: intent.method,
      intentPermit,
      intentAuthority: this.intentAuthority
    });

    if (evaluation.decision !== 'allow') {
      const result = {
        ok: false,
        stage: 'sentinel',
        http: { firstStatus: firstResponse.status },
        intent,
        intentPermit: { body: intentPermit.body, signature: intentPermit.signature },
        paymentRequired,
        evaluation,
        wallet: { signed: false, broadcast: false }
      };
      this.audit.append({
        type: 'agent_flow', outcome: 'blocked', reasonCodes: evaluation.reasonCodes ?? []
      });
      return { status: 403, result };
    }

    let paymentPayload;
    try {
      paymentPayload = issueApproval(evaluation, paymentRequired, this.arena.policy, this.ledger);
    } catch (error) {
      const result = {
        ok: false,
        stage: 'sentinel',
        http: { firstStatus: firstResponse.status },
        reason: error.message,
        evaluation,
        wallet: { signed: false, broadcast: false }
      };
      this.audit.append({ type: 'agent_flow', outcome: 'blocked', reasonCodes: ['APPROVAL_REJECTED'] });
      return { status: 403, result };
    }
    const secondResponse = this.serverless
      ? this.merchantChallengeResponse(encodeBase64Json(paymentPayload))
      : await fetch(merchantUrl, { headers: { 'PAYMENT-SIGNATURE': encodeBase64Json(paymentPayload) } });
    const resourceBody = this.serverless ? secondResponse.body : await secondResponse.json().catch(() => ({}));
    const paymentResponseHeader = this.serverless
      ? secondResponse.headers['PAYMENT-RESPONSE']
      : secondResponse.headers.get('payment-response');
    const settled = secondResponse.status === 200;
    const result = {
      ok: settled,
      stage: settled ? 'resource-delivered' : 'merchant-rejected',
      http: {
        firstStatus: firstResponse.status,
        secondStatus: secondResponse.status,
        paymentRequiredHeader,
        paymentResponseHeader
      },
      intent,
      intentPermit: { body: intentPermit.body, signature: intentPermit.signature },
      paymentRequired,
      evaluation,
      paymentPayload,
      wallet: { signed: true, broadcast: false, mode: 'dry-run EIP-3009-shaped authorization' },
      resource: resourceBody
    };
    this.audit.append({
      type: 'agent_flow',
      outcome: settled ? 'allowed' : 'blocked',
      amount: paymentPayload.payload.authorization.value,
      payTo: paymentPayload.payload.authorization.to,
      paymentResponse: paymentResponseHeader
    });
    return { status: settled ? 200 : 403, result };
  }

}
