import { $, api, stream, short, money, toast, escapeHtml, connectionStatus, busy, roundEvidence } from './shared.js';
import { atomicToUsdc, usdcToAtomic } from './usdc.js';

const LOOP_PAYEE = '0x2222222222222222222222222222222222222222';
let baseline, challengeId, profile, multiOffer;
let profileKey = '';
let selectedPreset = null;
let generatedNote = '';
let loadingBaseline = false;
let lastRenderedRoundId = null;
const field = id => $(`#${id}`);
const editableFields = ['amount', 'payTo', 'network', 'asset', 'resource', 'scheme', 'timeout', 'paymentFlow', 'transferMethod'];
const fieldLabels = {
  amount: 'Amount', payTo: 'Recipient', network: 'Network', asset: 'Asset',
  resource: 'Resource URL', scheme: 'Scheme', timeout: 'Timeout',
  paymentFlow: 'Payment flow', transferMethod: 'Transfer method'
};

function authHeaders() {
  const token = field('adminToken')?.value.trim() || sessionStorage.getItem('sentinelAdminToken');
  return token ? { 'x-sentinel-admin-token': token } : {};
}

function fill(payment) {
  const offer = payment.accepts[0];
  for (const [id, value] of Object.entries({
    amount: atomicToUsdc(offer.amount), payTo: offer.payTo, network: offer.network, asset: offer.asset,
    resource: payment.resource.url, scheme: offer.scheme, timeout: offer.maxTimeoutSeconds,
    paymentFlow: offer.extra?.paymentFlow ?? 'authorization',
    transferMethod: offer.extra?.assetTransferMethod ?? 'eip3009'
  })) field(id).value = value;
}

function baselineValues() {
  const offer = baseline.accepts[0];
  return {
    amount: atomicToUsdc(offer.amount), payTo: offer.payTo, network: offer.network,
    asset: offer.asset, resource: baseline.resource.url, scheme: offer.scheme,
    timeout: String(offer.maxTimeoutSeconds),
    paymentFlow: offer.extra?.paymentFlow ?? 'authorization',
    transferMethod: offer.extra?.assetTransferMethod ?? 'eip3009'
  };
}

function renderMutationPreview() {
  if (!baseline) return;
  const original = baselineValues();
  const changes = editableFields
    .filter(id => field(id).value.trim() !== original[id])
    .map(id => ({ label: fieldLabels[id], before: original[id], after: field(id).value.trim() || 'empty' }));

  if (multiOffer) {
    changes.unshift({ label: 'Offer selection', before: 'One safe offer', after: 'Poisoned offer first; safe offer second' });
  }

  field('mutationCount').textContent = changes.length === 0
    ? 'No changes' : `${changes.length} ${changes.length === 1 ? 'change' : 'changes'}`;
  field('mutationDetails').innerHTML = changes.length === 0
    ? 'The original merchant offer is selected.'
    : changes.map(({ label, before, after }) => `<div class="mutationRow"><b>${escapeHtml(label)}</b><span title="${escapeHtml(before)}">${escapeHtml(short(before, 28))}</span><i aria-hidden="true">→</i><strong title="${escapeHtml(after)}">${escapeHtml(short(after, 28))}</strong></div>`).join('');
}

function selectPreset(id) {
  selectedPreset = id;
  for (const card of field('researchTests').querySelectorAll('button[data-test]')) {
    const selected = card.dataset.test === id;
    card.classList.toggle('selected', selected);
    card.setAttribute('aria-pressed', String(selected));
  }
}

function wholeSeconds(value) {
  const input = String(value ?? '').trim();
  if (!/^\d+$/.test(input) || Number(input) < 1 || Number(input) > 3600) {
    throw new Error('Timeout must be a whole number from 1 to 3600 seconds');
  }
  return Number(input);
}

function paymentFromFields() {
  const payment = structuredClone(baseline);
  const offer = payment.accepts[0];
  payment.resource.url = field('resource').value.trim();
  Object.assign(offer, {
    amount: usdcToAtomic(field('amount').value, 'Amount'), payTo: field('payTo').value.trim(),
    network: field('network').value.trim(), asset: field('asset').value.trim(),
    scheme: field('scheme').value.trim(), maxTimeoutSeconds: wholeSeconds(field('timeout').value),
    extra: { ...offer.extra, paymentFlow: field('paymentFlow').value.trim(), assetTransferMethod: field('transferMethod').value.trim() }
  });
  return payment;
}

function outcome(item) {
  return item.outcomeType === 'bypass' ? 'TRUE BYPASS' :
    item.outcomeType === 'false-positive' ? 'FALSE POSITIVE' :
    item.outcomeType === 'attack-blocked' ? 'ATTACK BLOCKED' : 'LEGITIMATE PASS';
}

function renderBaseline() {
  const offer = baseline.accepts[0];
  field('baseline').innerHTML = [
    ['Amount', money(offer.amount)], ['payTo', short(offer.payTo, 10)],
    ['Resource', baseline.resource.url], ['Network', offer.network]
  ].map(([label, value]) => `<div class="kv"><span>${escapeHtml(label)}</span><span>${escapeHtml(value)}</span></div>`).join('');
}

function renderProfile(report) {
  profile = report;
  const manual = [
    { id: 'timeout-plus-one', rule: 'TRAINING', label: 'Timeout +1 second', summary: '60s → 61s. Red wins only when Blue enables the deliberately vulnerable permit issuer.' },
    ...report.tests.filter(test => test.mode !== 'automated' && test.id !== 'replay')
  ];
  const automated = report.tests.filter(test => test.mode === 'automated' || test.id === 'replay');
  field('capSummary').textContent = `${manual.length} manual mutations · ${automated.length} stateful probe`;
  field('researchTests').innerHTML = [
    ...manual.map(test => `<button type="button" class="attackCard" data-test="${escapeHtml(test.id)}" aria-pressed="${test.id === selectedPreset}"><span class="rule">${escapeHtml(test.rule)}</span><b>${escapeHtml(test.label)}</b><small>${escapeHtml(test.summary)}</small></button>`),
    ...automated.map(test => `<a class="attackCard" href="/judge"><span class="rule">${escapeHtml(test.rule)} · STATEFUL TEST</span><b>${escapeHtml(test.label)} → Judge</b><small>${escapeHtml(test.summary)}</small></a>`)
  ].join('');
}

async function fresh() {
  if (loadingBaseline) return;
  loadingBaseline = true;
  busy(field('fresh'), true);
  field('challengeStatus').textContent = 'Loading merchant challenge…';
  try {
    const response = await api('/api/merchant/challenge');
    const nextKey = JSON.stringify(response.paymentRequired);
    if (nextKey !== profileKey) {
      const nextProfile = await api('/api/research/profile', {
        method: 'POST', body: JSON.stringify({ paymentRequired: response.paymentRequired })
      });
      renderProfile(nextProfile);
      profileKey = nextKey;
    }
    baseline = response.paymentRequired;
    challengeId = response.challengeId;
    multiOffer = null;
    fill(baseline);
    renderBaseline();
    selectPreset(null);
    renderMutationPreview();
    field('label').value = 'Legitimate control';
    field('note').value = '';
    generatedNote = '';
    field('challengeStatus').textContent = `Ready · challenge expires ${new Date(response.expiresAt).toLocaleTimeString()}`;
  } catch (error) {
    field('challengeStatus').textContent = 'Challenge unavailable. Try refresh.';
    throw error;
  } finally {
    loadingBaseline = false;
    busy(field('fresh'), false);
  }
}

function applyPreset(id) {
  const test = id === 'timeout-plus-one'
    ? { label: 'Timeout +1 second', rule: 'TRAINING', summary: 'Test whether the permit issuer binds the server-held original timeout.' }
    : profile.tests.find(item => item.id === id);
  if (test?.mode === 'automated' || id === 'replay') {
    toast('This needs a used permit. Open Judge and run Held-out Red Team.');
    return;
  }
  fill(baseline); multiOffer = null;
  field('label').value = test?.label ?? id;
  generatedNote = test ? `${test.rule}: ${test.summary}` : '';
  field('note').value = generatedNote;
  const values = {
    overpay: ['amount', '50'], 'wrong-party': ['payTo', '0x9999999999999999999999999999999999999999'],
    network: ['network', 'eip155:1'], asset: ['asset', '0x8888888888888888888888888888888888888888'],
    resource: ['resource', 'https://api.safe.test/weather'], timeout: ['timeout', '3600'],
    flow: ['paymentFlow', 'upfront'], transfer: ['transferMethod', 'permit2'],
    closure: ['payTo', LOOP_PAYEE]
  };
  if (id === 'query-swap') {
    const url = new URL(baseline.resource.url); url.searchParams.set('item', 'attacker-selected'); field('resource').value = url.toString();
  } else if (id === 'malicious-first-offer') {
    multiOffer = structuredClone(baseline);
    multiOffer.accepts = [{ ...multiOffer.accepts[0], amount: '1000', payTo: '0x9999999999999999999999999999999999999999' }, structuredClone(baseline.accepts[0])];
  } else if (id === 'timeout-plus-one') {
    field('timeout').value = String(baseline.accepts[0].maxTimeoutSeconds + 1);
  } else if (values[id]) field(values[id][0]).value = values[id][1];
  selectPreset(id);
  renderMutationPreview();
}

function showVerdict(item) {
  const closure = item.guard.closure;
  const mode = item.trainingMode === 'merchant-timeout' ? 'Deliberately vulnerable training fixture' : 'Secure permit binding';
  const reasonCodes = item.guard.reasonCodes ?? [];
  field('verdict').className = `decision ${item.guard.action}`;
  field('verdict').innerHTML = `<div class="big">${outcome(item)}</div><p>${escapeHtml(mode)} · Round ${item.round}</p><p>${escapeHtml(roundEvidence(item))}</p><div class="checks">${reasonCodes.map(code => `<div class="check bad">${escapeHtml(code)}</div>`).join('') || '<div class="check ok">No guard check failed</div>'}</div><p class="subtle">Referee expected ${escapeHtml(item.groundTruth.expected.toUpperCase())} · Sentinel ${escapeHtml(item.guard.action.toUpperCase())} · Simulated signer ${item.wallet.signed ? 'opened' : 'stayed closed'}</p>`;
  field('closure').textContent = closure?.source === 'seeded-demo-graph'
    ? `${closure.verdict.toUpperCase()}: ${closure.reason} · ${(closure.path ?? []).map(address => short(address, 6)).join(' → ')} · synthetic graph`
    : 'No seeded closure result for this decision.';
}

field('fresh').onclick = () => fresh().catch(error => toast(error.message));
field('resetFields').onclick = () => {
  if (!baseline) return;
  fill(baseline);
  multiOffer = null;
  selectPreset(null);
  field('label').value = 'Legitimate control';
  field('note').value = '';
  generatedNote = '';
  renderMutationPreview();
};
for (const id of editableFields) {
  field(id).addEventListener('input', () => {
    if (field('label').value === 'Legitimate control' || selectedPreset) {
      field('label').value = 'Custom mutation';
    }
    if (generatedNote && field('note').value === generatedNote) field('note').value = '';
    generatedNote = '';
    multiOffer = null;
    selectPreset(null);
    renderMutationPreview();
  });
}
field('researchTests').onclick = event => {
  const button = event.target.closest('[data-test]');
  if (button && baseline) applyPreset(button.dataset.test);
};
field('submit').onclick = async () => {
  if (!baseline || !challengeId) return toast('Fetch a fresh merchant challenge first.');
  const button = field('submit'); busy(button, true);
  let submitted = false;
  try {
    const response = await api('/api/arena/submit', { method: 'POST', body: JSON.stringify({
      challengeId, attacker: field('attacker').value, redLabel: field('label').value, redNote: field('note').value,
      paymentRequired: multiOffer ? structuredClone(multiOffer) : paymentFromFields()
    }) });
    challengeId = null;
    multiOffer = null;
    showVerdict(response.item);
    submitted = true;
  } catch (error) { toast(error.message); }
  finally { busy(button, false); }
  if (submitted) fresh().catch(error => toast(`Round saved; baseline refresh failed: ${error.message}`));
};
field('runFuzz').onclick = async () => {
  const button = field('runFuzz'); busy(button, true); field('fuzzReport').textContent = 'Running 500 controlled attacks and 500 controls…';
  try {
    const report = await api('/api/attack/fuzz', { method: 'POST', headers: authHeaders(), body: JSON.stringify({ seed: 402, attackCount: 500, honestCount: 500 }) });
    const m = report.metrics;
    field('fuzzReport').textContent = `${m.attackContained}/${m.attackCases} attacks contained · ${m.legitimateAllowed}/${m.legitimateCases} legitimate controls passed · bypasses ${m.bypasses} · false positives ${m.falsePositives}`;
  } catch (error) { field('fuzzReport').textContent = error.message; } finally { busy(button, false); }
};
field('adminToken').value = sessionStorage.getItem('sentinelAdminToken') ?? '';
field('adminToken').onchange = () => sessionStorage.setItem('sentinelAdminToken', field('adminToken').value.trim());

stream('red', state => {
  const vulnerable = state.trainingMode === 'merchant-timeout';
  field('trainingModeNotice').textContent = vulnerable
    ? 'Training fixture: vulnerable permit issuer active. Timeout +1 second can win this dry-run round.'
    : 'Training fixture: secure permit binding is active. Timeout +1 second should be blocked.';
  field('trainingModeNotice').classList.toggle('vulnerable', vulnerable);
  field('round').textContent = state.round; field('redScore').textContent = state.scores.red; field('blueScore').textContent = state.scores.blue;
  field('abr').textContent = state.metrics.attackTotal ? `${state.metrics.attackBlockRate}%` : '—';
  field('lpr').textContent = state.metrics.legitTotal ? `${state.metrics.legitPassRate}%` : '—';
  const latest = state.requests.at(-1);
  if (latest?.id === lastRenderedRoundId) return;
  lastRenderedRoundId = latest?.id ?? null;
  field('feed').innerHTML = [...state.requests].reverse().map(item => `<div class="event"><div class="eventtop"><strong>Round ${item.round} · ${escapeHtml(item.redLabel)}</strong><span class="tag ${item.guard.correct ? 'allow' : 'block'}">${outcome(item)}</span></div><p>${item.trainingMode === 'merchant-timeout' ? 'Vulnerable fixture' : 'Secure mode'} · Expected ${escapeHtml(item.groundTruth.expected.toUpperCase())} · Sentinel ${escapeHtml(item.guard.action.toUpperCase())}</p></div>`).join('') || '<div class="subtle">No rounds yet.</div>';
  if (latest) showVerdict(latest);
  else {
    field('verdict').className = 'decision';
    field('verdict').innerHTML = '<div class="big">READY</div><p>Choose a mutation.</p>';
    field('closure').textContent = 'The loop graph is synthetic demo data.';
  }
}, connectionStatus);
fresh().catch(error => toast(error.message));
