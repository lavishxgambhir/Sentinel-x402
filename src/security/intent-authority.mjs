import crypto from 'node:crypto';
import { canonicalJson, canonicalResourceUrl, sha256Hex, normalizeAddress } from '../core/x402.mjs';

function toB64(buffer) { return Buffer.from(buffer).toString('base64'); }
function fromB64(value) { return Buffer.from(String(value), 'base64'); }

export class IntentAuthority {
  constructor({ privateKey, publicKey } = {}) {
    if (privateKey && publicKey) {
      this.privateKey = privateKey;
      this.publicKey = publicKey;
    } else {
      const pair = crypto.generateKeyPairSync('ed25519');
      this.privateKey = pair.privateKey;
      this.publicKey = pair.publicKey;
    }
    this.publicKeyPem = this.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    this.keyId = sha256Hex(this.publicKeyPem).slice(0, 16);
  }

  issue(intent, policy, now = new Date()) {
    if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new Error('Invalid permit issue time');
    const maxUses = intent.maxUses ?? 1;
    if (!Number.isSafeInteger(maxUses) || maxUses < 1 || maxUses > 100) {
      throw new Error('Intent maxUses must be an integer between 1 and 100');
    }
    if (!Number.isSafeInteger(intent.maxTimeoutSeconds) || intent.maxTimeoutSeconds < 1) {
      throw new Error('Intent maxTimeoutSeconds must be a positive whole number');
    }
    const issuedAt = Math.floor(now.getTime() / 1000);
    const configuredTtl = Number(policy.intentPermitTtlSeconds ?? 300);
    if (!Number.isSafeInteger(configuredTtl) || configuredTtl < 1) {
      throw new Error('Intent permit TTL must be a positive whole number');
    }
    const ttl = Math.max(30, Math.min(900, configuredTtl));
    const resource = new URL(intent.resourceUrl);
    const body = {
      version: 1,
      permitId: crypto.randomUUID(),
      keyId: this.keyId,
      subject: normalizeAddress(policy.walletAddress),
      issuedAt,
      validAfter: issuedAt - 1,
      validBefore: issuedAt + ttl,
      maxUses,
      resource: {
        method: String(intent.method ?? 'GET').toUpperCase(),
        origin: resource.origin,
        pathname: resource.pathname,
        canonicalUrl: canonicalResourceUrl(intent.resourceUrl)
      },
      payment: {
        maxAmount: String(intent.maxAmount),
        maxTimeoutSeconds: intent.maxTimeoutSeconds,
        payTo: [normalizeAddress(intent.expectedPayTo)],
        networks: [String(intent.network)],
        assets: { [String(intent.network)]: [String(intent.asset).toLowerCase()] },
        schemes: [String(intent.scheme ?? 'exact')],
        paymentFlows: [String(intent.paymentFlow ?? 'authorization')],
        assetTransferMethods: [String(intent.assetTransferMethod ?? 'eip3009')]
      },
      purpose: String(intent.purpose ?? ''),
      purposeHash: sha256Hex(String(intent.purpose ?? '')),
      policyDigest: sha256Hex(policy),
      nonce: `0x${crypto.randomBytes(16).toString('hex')}`
    };
    const signature = crypto.sign(null, Buffer.from(canonicalJson(body)), this.privateKey);
    return { body, signature: toB64(signature), publicKey: this.publicKeyPem };
  }

  verify(permit, now = new Date()) {
    if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
      return { ok: false, reason: 'Invalid verification time' };
    }
    if (!permit?.body || typeof permit.signature !== 'string') {
      return { ok: false, reason: 'Intent permit is missing or malformed' };
    }
    let publicKey;
    try {
      const pem = permit.publicKey || this.publicKeyPem;
      publicKey = crypto.createPublicKey(pem);
    } catch {
      return { ok: false, reason: 'Intent permit public key is invalid' };
    }
    const fingerprint = sha256Hex(permit.publicKey || this.publicKeyPem).slice(0, 16);
    if (permit.body.keyId !== fingerprint || fingerprint !== this.keyId) {
      return { ok: false, reason: 'Intent permit was not issued by the trusted policy authority' };
    }
    let valid = false;
    try {
      valid = crypto.verify(null, Buffer.from(canonicalJson(permit.body)), publicKey, fromB64(permit.signature));
    } catch {}
    if (!valid) return { ok: false, reason: 'Intent permit signature is invalid' };
    if (!Number.isSafeInteger(permit.body.maxUses) || permit.body.maxUses < 1 || permit.body.maxUses > 100
      || !Number.isSafeInteger(permit.body.validAfter) || !Number.isSafeInteger(permit.body.validBefore)
      || permit.body.validAfter > permit.body.validBefore
      || !Number.isSafeInteger(permit.body.payment?.maxTimeoutSeconds)
      || permit.body.payment.maxTimeoutSeconds < 1) {
      return { ok: false, reason: 'Intent permit use limit or time window is invalid' };
    }
    const nowSeconds = Math.floor(now.getTime() / 1000);
    if (nowSeconds < Number(permit.body.validAfter) || nowSeconds > Number(permit.body.validBefore)) {
      return { ok: false, reason: 'Intent permit is outside its validity window' };
    }
    return { ok: true, permit: permit.body };
  }

  publicInfo() {
    return { keyId: this.keyId, publicKey: this.publicKeyPem, algorithm: 'Ed25519' };
  }
}
