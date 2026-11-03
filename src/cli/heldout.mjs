import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runHeldOut, summarizeHeldOut } from '../research/heldout.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const policy = JSON.parse(fs.readFileSync(path.join(root, 'policy.json'), 'utf8'));

function integerOption(args, name, fallback) {
  const index = args.indexOf(name);
  if (index < 0) return fallback;
  const value = Number(args[index + 1]);
  if (!Number.isSafeInteger(value) || value < 1 || value > 2000) {
    throw new Error(`${name} must be an integer between 1 and 2000`);
  }
  return value;
}

function saveReport(report) {
  const directory = path.join(root, 'results');
  fs.mkdirSync(directory, { recursive: true });
  const filename = path.join(directory, `heldout-seed-${report.seed}.json`);
  fs.writeFileSync(filename, `${JSON.stringify(report, null, 2)}\n`);
  return filename;
}

const args = process.argv.slice(2);
const attacks = integerOption(args, '--attacks', 300);
const legitimate = integerOption(args, '--legitimate', 300);
if (args.includes('--multi')) {
  const seeds = [1, 7, 42, 99, 402, 1337, 2026];
  const reports = seeds.map(seed => summarizeHeldOut(runHeldOut({ policy, seed, attacks, legitimate })));
  const values = reports.map(report => report.metrics);
  const mean = key => Math.round(values.reduce((sum, metrics) => sum + metrics[key], 0) / values.length * 100) / 100;
  const aggregate = {
    suite: 'HELD-OUT RED TEAM / MULTI-SEED',
    status: reports.every(report => report.passed) ? 'PASS' : 'FAIL',
    seeds,
    attacksPerSeed: attacks,
    legitimatePerSeed: legitimate,
    totalAttacks: values.reduce((sum, metrics) => sum + metrics.attacks, 0),
    totalLegitimate: values.reduce((sum, metrics) => sum + metrics.legitimate, 0),
    totalBypasses: values.reduce((sum, metrics) => sum + metrics.falseNegative, 0),
    totalFalsePositives: values.reduce((sum, metrics) => sum + metrics.falsePositive, 0),
    criticalBypasses: reports.reduce((sum, report) => sum + report.criticalBypasses.length, 0),
    meanAttackContainmentRate: mean('attackContainmentRate'),
    minAttackContainmentRate: Math.min(...values.map(metrics => metrics.attackContainmentRate)),
    maxAttackContainmentRate: Math.max(...values.map(metrics => metrics.attackContainmentRate)),
    meanLegitimatePassRate: mean('legitimatePassRate'),
    reports: reports.map(report => ({ seed: report.seed, status: report.status, metrics: report.metrics, failures: report.failures }))
  };
  const directory = path.join(root, 'results');
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, 'heldout-multi.json'), `${JSON.stringify(aggregate, null, 2)}\n`);
  console.log(JSON.stringify(aggregate, null, 2));
} else {
  const seed = integerOption(args, '--seed', 42);
  const report = summarizeHeldOut(runHeldOut({ policy, seed, attacks, legitimate }));
  const filename = saveReport(report);
  console.log(JSON.stringify({ ...report, savedTo: filename }, null, 2));
}
