import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { finaliseHeldOut, generateHeldOutCases, refereeHeldOutCase, refereeStatefulCase, runHeldOut, summarizeHeldOut } from '../src/research/heldout.mjs';

const policy = JSON.parse(fs.readFileSync(new URL('../policy.json', import.meta.url), 'utf8'));

test('held-out cases are reproducible and the referee judges the original authorization', () => {
  const first = generateHeldOutCases({ seed: 42, attacks: 24, legitimate: 12 });
  const second = generateHeldOutCases({ seed: 42, attacks: 24, legitimate: 12 });
  assert.deepEqual(first, second);
  assert.equal(first.attackCases.length, 24);
  assert.equal(first.legitimateCases.length, 12);
  assert.equal(first.attackCases.find(item => item.id === 'level1-timeout').truth.expected, 'block');
  assert.equal(first.legitimateCases.find(item => item.id.startsWith('legit-query-order')).truth.expected, 'allow');
  const changed = structuredClone(first.original);
  changed.accepts[0].payTo = '0x9999999999999999999999999999999999999999';
  assert.equal(refereeHeldOutCase({ original: first.original, paymentRequired: changed }).expected, 'block');
});

test('held-out report counts every result and records actual mismatches', () => {
  const report = summarizeHeldOut(runHeldOut({ policy, seed: 42, attacks: 30, legitimate: 30 }));
  const m = report.metrics;
  assert.equal(m.attacks, 30);
  assert.equal(m.legitimate, 30);
  assert.equal(m.truePositive + m.falseNegative, 30);
  assert.equal(m.trueNegative + m.falsePositive, 30);
  assert.equal(report.failures.length, m.falsePositive + m.falseNegative);
  assert.ok(report.failures.every(item => item.seed === 42 && item.failureCategory));
});

test('a critical intent bypass overrides otherwise passing aggregate rates', () => {
  const blocked = Array.from({ length: 99 }, (_, index) => ({
    id: `blocked-${index}`, kind: 'attack', severity: 'HIGH', mutationFields: ['resource.query'],
    truth: { expected: 'block' }, observed: { decision: 'block' }
  }));
  const legitimate = Array.from({ length: 100 }, (_, index) => ({
    id: `legitimate-${index}`, kind: 'legitimate', severity: 'LOW / QUALITY', mutationFields: [],
    truth: { expected: 'allow' }, observed: { decision: 'allow' }
  }));
  const bypass = {
    id: 'resource-bypass', kind: 'attack', severity: 'HIGH', mutationFields: ['resource.query'],
    truth: { expected: 'block' }, observed: { decision: 'allow' }
  };
  const report = finaliseHeldOut({ results: [...blocked, bypass, ...legitimate] });
  assert.equal(report.metrics.attackContainmentRate, 99);
  assert.equal(report.metrics.legitimatePassRate, 100);
  assert.equal(report.criticalBypasses.length, 1);
  assert.equal(report.status, 'FAIL');
});

test('stateful referee resolves exact budget, replay, and expiry boundaries independently', () => {
  assert.equal(refereeStatefulCase({ budget: 100n, pending: 90n, amount: 10n }).expected, 'allow');
  assert.equal(refereeStatefulCase({ budget: 100n, pending: 100n, amount: 1n }).category, 'BUDGET_EXCEEDED');
  assert.equal(refereeStatefulCase({ permitUses: 1, maxUses: 1 }).category, 'PERMIT_REPLAY');
  assert.equal(refereeStatefulCase({ nowSeconds: 299 }).expected, 'allow');
  assert.equal(refereeStatefulCase({ nowSeconds: 301 }).category, 'PERMIT_EXPIRED');
});
