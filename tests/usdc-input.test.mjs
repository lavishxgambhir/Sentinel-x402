import test from 'node:test';
import assert from 'node:assert/strict';

import { atomicToUsdc, usdcToAtomic } from '../public/usdc.js';
import { money } from '../public/shared.js';

test('Blue USDC inputs convert decimal strings without floating-point rounding', () => {
  assert.equal(usdcToAtomic('0.05'), '50000');
  assert.equal(usdcToAtomic('0.049'), '49000');
  assert.equal(usdcToAtomic('50'), '50000000');
  assert.equal(usdcToAtomic('100000.100'), '100000100000');
  assert.equal(usdcToAtomic('1.000001'), '1000001');
  assert.equal(atomicToUsdc('50000'), '0.05');
  assert.equal(atomicToUsdc('49000'), '0.049');
  assert.equal(atomicToUsdc('100000100000'), '100000.1');
});

test('Blue USDC input rejects malformed, negative, or over-precise values', () => {
  for (const value of ['', '-1', '1e3', '0x10', '1.0000001', '.5', '1.', 'five']) {
    assert.throws(() => usdcToAtomic(value));
  }
});

test('USDC display does not lose precision for large atomic values', () => {
  assert.equal(money('100000100000'), '$100000.1');
  assert.equal(money('999999999999999999999999'), '$999999999999999999.999999');
  assert.equal(money('not-an-amount'), '$—');
});
