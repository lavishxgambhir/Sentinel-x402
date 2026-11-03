import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { makePaymentRequired } from '../demo/attacks.mjs';
import { generateAttackCases, scoreFuzzCase } from '../research/fuzz.mjs';
import { minimizeBypass, mutationPaths } from '../research/minimize.mjs';
import { compareAgainstOriginal } from '../research/paper-analysis.mjs';
import { intentFromPaymentRequired } from '../core/intent.mjs';
import { canonicalResourceUrl, decodePaymentRequiredHeader, validatePaymentRequiredShape } from '../core/x402.mjs';

const USAGE = `Usage: npm run attack-lab -- --target http://127.0.0.1:4173/api/guard/evaluate [options]

  --challenge URL          Fetch a real 402 PAYMENT-REQUIRED baseline
  --baseline FILE          Load a PaymentRequired JSON baseline
  --permit FILE            Load a signed intent permit JSON
  --admin-token VALUE      Local permit issuance token (or SENTINEL_ADMIN_TOKEN env)
  --seed VALUE             Reproducible mutation seed (default: 402)
  --trials N               Seeded compound mutations, 0-30 (default: 8)
  --offer-index N          Baseline offer to test (default: 0)
  --timeout-ms N           Per-request timeout, 100-10000 (default: 3000)
  --json FILE              Save a machine-readable evidence report
  --markdown FILE          Save a judge-friendly Markdown report
  --no-minimize            Skip bypass minimization requests
  --no-auto-permit         Skip local Sentinel permit issuance
  --help                   Show this help

Only the local /api/guard/evaluate endpoint is tested. No wallet signing or settlement is performed.`;

const VALUES = new Set(['target', 'challenge', 'baseline', 'permit', 'admin-token', 'seed', 'trials', 'offer-index', 'timeout-ms', 'json', 'markdown']);
const FLAGS = new Set(['help', 'no-minimize', 'no-auto-permit']);

export function parseArgs(argv) {
  const options = { seed: '402', trials: 8, offerIndex: 0, timeoutMs: 3000, minimize: true };
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (!arg.startsWith('--')) throw new Error(`Unexpected argument: ${arg}`);
    const name = arg.slice(2);
    if (FLAGS.has(name)) {
      if (name === 'no-minimize') options.minimize = false;
      else if (name === 'no-auto-permit') options.noAutoPermit = true;
      else options.help = true;
      continue;
    }
    if (!VALUES.has(name)) throw new Error(`Unknown option: ${arg}`);
    const value = argv[++index];
    if (!value || value.startsWith('--')) throw new Error(`${arg} requires a value`);
    const key = { 'offer-index': 'offerIndex', 'timeout-ms': 'timeoutMs', 'admin-token': 'adminToken' }[name] ?? name;
    options[key] = value;
  }
  if (options.baseline && options.challenge) throw new Error('Use either --baseline or --challenge');
  for (const [key, min, max] of [['trials', 0, 30], ['offerIndex', 0, 15], ['timeoutMs', 100, 10000]]) {
    const value = Number(options[key]);
    if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${key} must be an integer between ${min} and ${max}`);
    options[key] = value;
  }
  return options;
}

const isLoopback = hostname => ['127.0.0.1', 'localhost', '[::1]'].includes(hostname.toLowerCase());

export function scopedUrl(raw, options, role = 'target') {
  let url;
  try { url = new URL(raw); } catch { throw new Error(`Invalid ${role} URL`); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) throw new Error(`${role} must be an HTTP(S) URL without credentials or fragment`);
  if (role === 'target' && !/(?:^|\/)guard\/evaluate\/?$/.test(url.pathname)) throw new Error('Target must be a /guard/evaluate endpoint');
  if (!isLoopback(url.hostname)) throw new Error(`${role} must use localhost; this hackathon build runs a self-contained Red/Blue simulation`);
  if (role === 'challenge' && options.target) {
    const target = new URL(options.target);
    if (url.hostname.toLowerCase() !== target.hostname.toLowerCase()) throw new Error('Challenge must use the same local host as the target');
  }
  return url;
}

const fetchTimed = (url, init, timeoutMs) => fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });

async function loadBaseline(options) {
  if (options.baseline) {
    const data = JSON.parse(await fs.readFile(options.baseline, 'utf8'));
    const paymentRequired = data.paymentRequired ?? data;
    validatePaymentRequiredShape(paymentRequired);
    return { paymentRequired, source: `file:${options.baseline}` };
  }
  if (options.challenge) {
    const url = scopedUrl(options.challenge, options, 'challenge');
    const response = await fetchTimed(url, { method: 'GET' }, options.timeoutMs);
    const header = response.headers.get('payment-required');
    const paymentRequired = header ? decodePaymentRequiredHeader(header) : ((body) => body.paymentRequired ?? body)(await response.json());
    validatePaymentRequiredShape(paymentRequired);
    return { paymentRequired, source: `http:${url.href}`, status: response.status };
  }
  return { paymentRequired: makePaymentRequired('normal'), source: 'built-in controlled fixture' };
}

async function loadPermit(options, baseline) {
  if (options.permit) {
    const data = JSON.parse(await fs.readFile(options.permit, 'utf8'));
    return { permit: data.permit ?? data, source: `file:${options.permit}` };
  }
  if (options.noAutoPermit) return { permit: null, source: 'disabled by --no-auto-permit' };
  const target = new URL(options.target);
  if (!isLoopback(target.hostname) || !target.pathname.endsWith('/api/guard/evaluate')) return { permit: null, source: 'not provided' };
  const adminToken = options.adminToken ?? process.env.SENTINEL_ADMIN_TOKEN;
  if (!adminToken) throw new Error('Local signed permit needs --admin-token, SENTINEL_ADMIN_TOKEN, or --permit FILE');
  const issueUrl = new URL('/api/intent/issue', target);
  const response = await fetchTimed(issueUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-sentinel-admin-token': adminToken },
    body: JSON.stringify({ intent: intentFromPaymentRequired(baseline) })
  }, options.timeoutMs);
  if (!response.ok) throw new Error(`Local permit issuance failed: HTTP ${response.status}`);
  const data = await response.json();
  if (!data.permit) throw new Error('Local permit endpoint returned no permit');
  return { permit: data.permit, source: 'local Sentinel intent authority' };
}

async function evaluate(target, request, permit, timeoutMs) {
  const started = performance.now();
  try {
    const response = await fetchTimed(target, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...request, ...(permit ? { intentPermit: permit } : {}) })
    }, timeoutMs);
    const data = await response.json();
    if (!['allow', 'block'].includes(data.decision)) throw new Error(`HTTP ${response.status}: missing allow/block decision`);
    return {
      decision: data.decision,
      selectedIndex: Number.isInteger(data.selectedIndex) ? data.selectedIndex : null,
      reasonCodes: Array.isArray(data.reasonCodes) ? data.reasonCodes : [],
      latencyMs: Math.round((performance.now() - started) * 100) / 100,
      httpStatus: response.status
    };
  } catch (error) {
    return { error: error.message, latencyMs: Math.round((performance.now() - started) * 100) / 100 };
  }
}

export const scoreCase = scoreFuzzCase;

function median(values) {
  if (!values.length) return null;
  const sorted = values.toSorted((a, b) => a - b);
  const index = Math.floor(sorted.length / 2);
  return Math.round((sorted.length % 2 ? sorted[index] : (sorted[index - 1] + sorted[index]) / 2) * 100) / 100;
}

function metricsFor(results) {
  const attacks = results.filter(result => result.kind === 'attack');
  const legitimate = results.filter(result => result.kind === 'legitimate');
  const attackContained = attacks.filter(result => ['attack-blocked', 'safe-selection'].includes(result.outcome)).length;
  const legitimateAllowed = legitimate.filter(result => result.outcome === 'legitimate-pass').length;
  return {
    attackCases: attacks.length, attackContained,
    attackContainmentRate: attacks.length ? Math.round(attackContained / attacks.length * 1000) / 10 : null,
    legitimateCases: legitimate.length, legitimateAllowed,
    legitimatePassRate: legitimate.length ? Math.round(legitimateAllowed / legitimate.length * 1000) / 10 : null,
    bypasses: results.filter(result => result.outcome === 'bypass').length,
    falsePositives: results.filter(result => result.outcome === 'false-positive').length,
    unverifiableSelections: results.filter(result => result.outcome === 'unverifiable-selection').length,
    errors: results.filter(result => result.outcome === 'error').length,
    medianLatencyMs: median(results.filter(result => !result.observed.error).map(result => result.observed.latencyMs))
  };
}

function isUnauthorized(baseline, request) {
  if (request.requestedMethod !== baseline.requestedMethod) return true;
  try { if (canonicalResourceUrl(request.requestedUrl) !== canonicalResourceUrl(baseline.requestedUrl)) return true; }
  catch { return true; }
  return compareAgainstOriginal(baseline.paymentRequired, request.paymentRequired).expected === 'block';
}

export function renderMarkdown(report) {
  const { metrics, results } = report;
  const lines = [
    '# Sentinel attack lab report', '',
    `Generated: ${report.generatedAt}`,
    `Target: \`${report.target}\``,
    `Baseline: ${report.baseline.source}`,
    `Seed: \`${report.seed}\``,
    `Permit: ${report.permitSource}`, '',
    '## Score', '',
    `- Attack containment: **${metrics.attackContained}/${metrics.attackCases} (${metrics.attackContainmentRate}%)**`,
    `- Legitimate pass: **${metrics.legitimateAllowed}/${metrics.legitimateCases} (${metrics.legitimatePassRate}%)**`,
    `- True bypasses: **${metrics.bypasses}**`,
    `- False positives: **${metrics.falsePositives}**`,
    `- Unverifiable selections: **${metrics.unverifiableSelections}**`,
    `- Request errors: **${metrics.errors}**`,
    `- Median guard latency: **${metrics.medianLatencyMs ?? 'n/a'} ms**`, '',
    '## Cases', '',
    '| Case | Expected | Observed | Outcome | Reason codes |',
    '|---|---|---|---|---|'
  ];
  for (const result of results) {
    const expected = result.expectedSelectedIndex === null ? result.expectedDecision : `${result.expectedDecision} (offer ${result.expectedSelectedIndex})`;
    const observed = result.observed.error ? `ERROR: ${result.observed.error}` : result.observed.selectedIndex === null ? result.observed.decision : `${result.observed.decision} (offer ${result.observed.selectedIndex})`;
    lines.push(`| ${result.id} | ${expected} | ${observed.replaceAll('|', '\\|')} | ${result.outcome} | ${(result.observed.reasonCodes ?? []).join(', ').replaceAll('|', '\\|')} |`);
    if (result.minimized) lines.push(`| ↳ minimal witness | ${result.minimized.paths.join(', ').replaceAll('|', '\\|')} | ${result.minimized.attempts} extra probes | | |`);
  }
  lines.push('', 'All probes were metadata-only guard evaluations. The lab did not sign or settle a payment.', '');
  return lines.join('\n');
}

export async function runAttackLab(options) {
  if (!options.target) throw new Error('--target is required');
  const target = scopedUrl(options.target, options, 'target');
  const baseline = await loadBaseline(options);
  const generated = generateAttackCases(baseline.paymentRequired, { seed: options.seed, trials: options.trials, offerIndex: options.offerIndex });
  const permit = await loadPermit(options, generated.baseline);
  const baselineRequest = { paymentRequired: generated.baseline, requestedUrl: generated.baseline.resource.url, requestedMethod: 'GET' };
  const results = [];
  for (const testCase of generated.cases) {
    const request = { paymentRequired: testCase.paymentRequired, requestedUrl: testCase.requestedUrl, requestedMethod: testCase.requestedMethod };
    const observed = await evaluate(target, request, permit.permit, options.timeoutMs);
    const outcome = scoreCase(testCase, observed);
    const result = {
      id: testCase.id, label: testCase.label, description: testCase.description, rule: testCase.rule,
      kind: testCase.kind, expectedDecision: testCase.expectedDecision, expectedSelectedIndex: testCase.expectedSelectedIndex,
      mutationPaths: mutationPaths(baselineRequest, request), request, observed, outcome
    };
    if (options.minimize && outcome === 'bypass' && testCase.expectedDecision === 'block' && result.mutationPaths.length > 1) {
      const minimal = await minimizeBypass(baselineRequest, request, async candidate => {
        if (!isUnauthorized(baselineRequest, candidate)) return false;
        const observedCandidate = await evaluate(target, candidate, permit.permit, options.timeoutMs);
        return observedCandidate.decision === 'allow';
      }, { maxAttempts: 24 });
      result.minimized = { paths: minimal.paths, request: minimal.candidate, attempts: minimal.attempts, reduced: minimal.reduced };
    }
    results.push(result);
  }
  return {
    generatedAt: new Date().toISOString(), target: target.href, baseline: { source: baseline.source, paymentRequired: generated.baseline },
    seed: options.seed, trials: options.trials, permitSource: permit.source,
    metrics: metricsFor(results), results
  };
}

async function writeReport(filename, body) {
  await fs.mkdir(path.dirname(path.resolve(filename)), { recursive: true });
  await fs.writeFile(filename, body);
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) { console.log(USAGE); return; }
  if (!options.target) throw new Error(`--target is required\n\n${USAGE}`);
  const report = await runAttackLab(options);
  for (const result of report.results) {
    const detail = (result.observed.error ?? result.observed.reasonCodes.join(', ')) || '-';
    console.log(`${result.id.padEnd(23)} ${result.outcome.padEnd(22)} ${detail}`);
  }
  console.log(`\nAttack containment ${report.metrics.attackContained}/${report.metrics.attackCases} · legitimate pass ${report.metrics.legitimateAllowed}/${report.metrics.legitimateCases} · bypasses ${report.metrics.bypasses} · false positives ${report.metrics.falsePositives} · median ${report.metrics.medianLatencyMs ?? 'n/a'} ms`);
  if (options.json) { await writeReport(options.json, JSON.stringify(report, null, 2) + '\n'); console.log(`JSON report: ${path.resolve(options.json)}`); }
  if (options.markdown) { await writeReport(options.markdown, renderMarkdown(report)); console.log(`Markdown report: ${path.resolve(options.markdown)}`); }
  if (report.metrics.bypasses || report.metrics.falsePositives || report.metrics.unverifiableSelections || report.metrics.errors) process.exitCode = 2;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(`Attack lab: ${error.message}`); process.exitCode = 1; });
}
