import test from 'node:test';
import assert from 'node:assert/strict';
import { decodePaymentRequiredHeader, encodePaymentRequiredHeader } from '../src/core/x402.mjs';
import { makePaymentRequired } from '../src/demo/attacks.mjs';

test('PAYMENT-REQUIRED header round-trips x402 v2 JSON', () => {
  const original = makePaymentRequired('normal');
  const encoded = encodePaymentRequiredHeader(original);
  assert.deepEqual(decodePaymentRequiredHeader(encoded), original);
});

test('malformed header is rejected', () => {
  assert.throws(() => decodePaymentRequiredHeader('%%%not-base64-json%%%'));
});
