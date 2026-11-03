import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { evaluatePaymentRequired } from '../security/payment-guard.mjs';
import { GuardLedger } from '../state/guard-ledger.mjs';
import { makePaymentRequired } from '../demo/attacks.mjs';
import { IntentAuthority } from '../security/intent-authority.mjs';
import { createIntent } from '../core/intent.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const policy = JSON.parse(fs.readFileSync(path.resolve(__dirname, '..', '..', 'policy.json'), 'utf8'));
const ledger = new GuardLedger();
const payment = makePaymentRequired('normal');
const intentAuthority = new IntentAuthority();
const intentPermit = intentAuthority.issue(createIntent(), policy);
const iterations = Number(process.argv[2] ?? 100000);

for (let i = 0; i < 1000; i++) evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, intentPermit, intentAuthority });
const start = performance.now();
for (let i = 0; i < iterations; i++) evaluatePaymentRequired(payment, policy, ledger, { requestedUrl: payment.resource.url, intentPermit, intentAuthority });
const elapsedMs = performance.now() - start;
console.log(JSON.stringify({
  iterations,
  elapsedMs: Number(elapsedMs.toFixed(2)),
  decisionsPerSecond: Math.round(iterations / (elapsedMs / 1000)),
  averageMicroseconds: Number(((elapsedMs * 1000) / iterations).toFixed(2))
}, null, 2));
