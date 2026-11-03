import crypto from 'node:crypto';

export const MAX_HEADER_BYTES = 64 * 1024;

export function normalizeAddress(value) {
  if (typeof value !== 'string') return value;
  return /^0x[0-9a-fA-F]{40}$/.test(value) ? value.toLowerCase() : value;
}


export function canonicalResourceUrl(value) {
  const url = new URL(String(value));
  url.hash = '';
  url.searchParams.sort();
  return url.toString();
}

export function parseAtomic(value, field = 'amount') {
  if (typeof value !== 'string' || !/^[0-9]+$/.test(value)) {
    throw new Error(`${field} must be a non-negative integer string`);
  }
  return BigInt(value);
}

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])])
    );
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function sha256Hex(value) {
  const text = typeof value === 'string' ? value : canonicalJson(value);
  return crypto.createHash('sha256').update(text).digest('hex');
}

export function encodePaymentRequiredHeader(paymentRequired) {
  return Buffer.from(JSON.stringify(paymentRequired), 'utf8').toString('base64');
}

export function decodePaymentRequiredHeader(header) {
  if (typeof header !== 'string' || header.length === 0) {
    throw new Error('PAYMENT-REQUIRED header is missing');
  }
  const estimatedBytes = Math.ceil((header.length * 3) / 4);
  if (estimatedBytes > MAX_HEADER_BYTES) {
    throw new Error('PAYMENT-REQUIRED header is too large');
  }
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(header, 'base64').toString('utf8'));
  } catch {
    throw new Error('PAYMENT-REQUIRED header is not valid base64 JSON');
  }
  validatePaymentRequiredShape(parsed);
  return parsed;
}

export function validatePaymentRequiredShape(value) {
  const isRecord = item => item !== null && typeof item === 'object' && !Array.isArray(item);
  const identifier = item => typeof item === 'string' && /^[a-z][a-z0-9_-]{0,63}$/i.test(item)
    && !['constructor', 'prototype', '__proto__'].includes(item.toLowerCase());
  const address = item => typeof item === 'string' && /^0x[0-9a-fA-F]{40}$/.test(item);
  if (!isRecord(value)) throw new Error('PaymentRequired must be an object');
  if (value.x402Version !== 2) throw new Error('Only x402Version 2 is supported by this guard');
  if (!isRecord(value.resource) || typeof value.resource.url !== 'string' || value.resource.url.length > 4096) {
    throw new Error('resource.url must be a URL string');
  }
  let url;
  try { url = new URL(value.resource.url); } catch { throw new Error('resource.url must be an absolute URL'); }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) {
    throw new Error('resource.url must be an HTTP(S) URL without credentials');
  }
  if (value.resource.serviceName !== undefined && typeof value.resource.serviceName !== 'string') {
    throw new Error('resource.serviceName must be a string');
  }
  if (!Array.isArray(value.accepts) || value.accepts.length === 0) throw new Error('accepts must contain at least one offer');
  if (value.accepts.length > 16) throw new Error('too many payment offers');
  for (const [index, offer] of value.accepts.entries()) {
    if (!isRecord(offer)) throw new Error(`accepts[${index}] must be an object`);
    for (const field of ['scheme', 'network', 'amount', 'asset', 'payTo', 'maxTimeoutSeconds']) {
      if (offer[field] === undefined || offer[field] === null) throw new Error(`accepts[${index}].${field} is required`);
    }
    if (!identifier(offer.scheme)) throw new Error(`accepts[${index}].scheme must be a valid string`);
    if (typeof offer.network !== 'string' || !/^[a-z0-9]{1,32}:[a-zA-Z0-9-]{1,64}$/.test(offer.network)) {
      throw new Error(`accepts[${index}].network must be a CAIP-2 string`);
    }
    if (!address(offer.asset) || !address(offer.payTo)) {
      throw new Error(`accepts[${index}].asset and payTo must be EVM addresses`);
    }
    parseAtomic(offer.amount, `accepts[${index}].amount`);
    if (!Number.isSafeInteger(offer.maxTimeoutSeconds) || offer.maxTimeoutSeconds <= 0) {
      throw new Error(`accepts[${index}].maxTimeoutSeconds must be a positive integer`);
    }
    if (offer.extra !== undefined && !isRecord(offer.extra)) {
      throw new Error(`accepts[${index}].extra must be an object`);
    }
    for (const field of ['paymentFlow', 'assetTransferMethod']) {
      if (offer.extra?.[field] !== undefined && !identifier(offer.extra[field])) {
        throw new Error(`accepts[${index}].extra.${field} must be a valid string`);
      }
    }
  }
  return true;
}

export function makeAuthorizationNonce() {
  return `0x${crypto.randomBytes(32).toString('hex')}`;
}
