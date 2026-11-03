import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { makePaymentRequired } from '../demo/attacks.mjs';
import { runFuzz } from '../research/fuzz.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const policy = JSON.parse(fs.readFileSync(path.join(projectRoot, 'policy.json'), 'utf8'));

function option(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index < 0) return fallback;
  const value = Number(process.argv[index + 1]);
  if (!Number.isSafeInteger(value) || value < 1 || value > 5_000) {
    throw new Error(`${name} must be an integer between 1 and 5000`);
  }
  return value;
}

const seed = option('--seed', 402);
const attackCount = option('--attacks', 500);
const honestCount = option('--honest', 500);
const report = runFuzz({
  paymentRequired: makePaymentRequired('normal'),
  policy,
  seed,
  attackCount,
  honestCount
});

console.log(JSON.stringify({
  seed: report.seed,
  mode: 'in-process, signed-permit, metadata-only',
  ...report.metrics
}, null, 2));
