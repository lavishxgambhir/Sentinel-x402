import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { makePaymentRequired } from '../src/demo/attacks.mjs';
import { generateAttackCases, runFuzz, scoreFuzzCase } from '../src/research/fuzz.mjs';
import { minimizeBypass, mutationPaths } from '../src/research/minimize.mjs';
import { parseArgs, renderMarkdown, runAttackLab, scopedUrl } from '../src/cli/redteam.mjs';

const policy = JSON.parse(fs.readFileSync(new URL('../policy.json', import.meta.url), 'utf8'));

test('seeded attacks are reproducible and derived from the observed baseline', () => {
  const baseline = makePaymentRequired('normal');
  baseline.resource.url = 'https://api.safe.test/premium-data?plan=basic';
  const a = generateAttackCases(baseline, { seed: 'judge-demo', trials: 4 });
  const b = generateAttackCases(baseline, { seed: 'judge-demo', trials: 4 });
  assert.deepEqual(a, b);
  assert.equal(a.cases[0].paymentRequired.resource.url, baseline.resource.url);
  assert.ok(a.cases.some(item => item.id === 'resource-query-swap'));
  assert.equal(a.cases.find(item => item.id === 'poisoned-first-offer').expectedSelectedIndex, 1);
  assert.equal(a.cases.filter(item => item.id.startsWith('compound-')).length, 4);
});

test('local signed-permit fuzz run contains attacks while passing legitimate controls', () => {
  const result = runFuzz({ paymentRequired: makePaymentRequired('normal'), policy, seed: 11, trials: 3 });
  assert.equal(result.metrics.attackContained, result.metrics.attackCases);
  assert.equal(result.metrics.legitimateAllowed, result.metrics.legitimateCases);
  assert.equal(result.metrics.bypasses, 0);
  assert.equal(result.results.find(item => item.id === 'poisoned-first-offer').outcome, 'safe-selection');
});

test('selection must be observable before a poisoned-offer result can be called safe', () => {
  const attack = { kind: 'attack', expectedDecision: 'allow', expectedSelectedIndex: 1 };
  assert.equal(scoreFuzzCase(attack, { decision: 'allow', selectedIndex: null }), 'unverifiable-selection');
  assert.equal(scoreFuzzCase(attack, { decision: 'allow', selectedIndex: 0 }), 'bypass');
  assert.equal(scoreFuzzCase(attack, { decision: 'allow', selectedIndex: 1 }), 'safe-selection');
});

test('minimization reduces a compound bypass to the responsible mutation', async () => {
  const original = { paymentRequired: { accepts: [{ amount: '50000', payTo: 'merchant', asset: 'usdc' }] }, requestedUrl: 'https://example.test/data' };
  const candidate = structuredClone(original);
  candidate.paymentRequired.accepts[0].amount = '999999';
  candidate.paymentRequired.accepts[0].payTo = 'attacker';
  candidate.paymentRequired.accepts[0].asset = 'other';
  const minimal = await minimizeBypass(original, candidate, trial => trial.paymentRequired.accepts[0].payTo === 'attacker');
  assert.deepEqual(minimal.paths, ['paymentRequired.accepts[0].payTo']);
  assert.equal(minimal.attempts > 0, true);
  assert.equal(minimal.reduced, true);
  assert.deepEqual(mutationPaths(original, minimal.candidate), minimal.paths);
});

test('attack lab accepts only localhost guard routes', () => {
  assert.throws(() => scopedUrl('https://target.example/guard/evaluate', {}, 'target'), /must use localhost/);
  assert.throws(() => scopedUrl('https://other.example/guard/evaluate', {}, 'target'), /must use localhost/);
  assert.throws(() => scopedUrl('http://127.0.0.1/api/pay', {}, 'target'), /guard\/evaluate/);
  assert.equal(scopedUrl('http://127.0.0.1/api/guard/evaluate', {}, 'target').hostname, '127.0.0.1');
  assert.equal(parseArgs(['--target', 'http://127.0.0.1:4173/api/guard/evaluate', '--trials', '2']).trials, 2);
});

test('HTTP lab scores a permissive guard and records a minimal witness', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const payment = JSON.parse(init.body).paymentRequired;
    return { status: 200, json: async () => ({ decision: 'allow', selectedIndex: payment.accepts.length > 1 ? 0 : 0, reasonCodes: [] }) };
  };
  try {
    const report = await runAttackLab({ target: 'http://127.0.0.1:4173/api/guard/evaluate', seed: 'minimize-demo', trials: 1, offerIndex: 0, timeoutMs: 3000, minimize: true, noAutoPermit: true });
    assert.equal(report.metrics.legitimateAllowed, 3);
    assert.ok(report.metrics.bypasses >= 1);
    assert.ok(report.results.find(item => item.id === 'compound-01').minimized?.paths.length >= 1);
    assert.match(renderMarkdown(report), /Attack containment/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
