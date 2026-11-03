import { $, api, stream, short, money, toast, escapeHtml, connectionStatus, busy } from './shared.js';
import { atomicToUsdc, usdcToAtomic } from './usdc.js';
const field = id => $(`#${id}`);
let policyEditorDirty = false;
let lastPolicyKey = '';
let lastRenderedRoundId = null;
const policyFields = ['maxPayment', 'dailyBudget', 'merchantMax', 'timeout', 'payTo', 'network', 'paymentFlow', 'transferMethod'];
for (const id of policyFields) field(id).addEventListener('input', () => { policyEditorDirty = true; });

function token() { return field('adminToken').value.trim(); }
function headers() { return token() ? { 'x-sentinel-admin-token': token() } : {}; }
function saveToken() { sessionStorage.setItem('sentinelAdminToken', token()); }

function wholeSeconds(value) {
  const input = String(value ?? '').trim();
  if (!/^\d+$/.test(input) || Number(input) < 1 || Number(input) > 3600) {
    throw new Error('Max timeout must be a whole number from 1 to 3600 seconds');
  }
  return Number(input);
}

function requiredText(id, label) {
  const value = field(id).value.trim();
  if (!value) throw new Error(`${label} is required`);
  return value;
}

function policyPayload() {
  const payTo = requiredText('payTo', 'Expected recipient');
  if (!/^0x[0-9a-fA-F]{40}$/.test(payTo)) {
    throw new Error('Expected recipient must be a 0x-prefixed 20-byte wallet address');
  }
  return {
    maxPerPayment: usdcToAtomic(field('maxPayment').value, 'Max per payment'),
    dailyBudget: usdcToAtomic(field('dailyBudget').value, 'Daily budget'),
    maxTimeoutSeconds: wholeSeconds(field('timeout').value),
    allowedNetworks: [requiredText('network', 'Allowed network')],
    allowedPaymentFlows: [requiredText('paymentFlow', 'Payment flow')],
    allowedAssetTransferMethods: [requiredText('transferMethod', 'Transfer method')],
    merchant: {
      maxAmount: usdcToAtomic(field('merchantMax').value, 'Merchant max'),
      payTo: [payTo]
    }
  };
}

function loadPolicy(policy, force = false) {
  if (policyEditorDirty && !force) return;
  const merchant = policy.merchants['api.safe.test'];
  const values = {
    maxPayment: atomicToUsdc(policy.maxPerPayment),
    dailyBudget: atomicToUsdc(policy.dailyBudget),
    timeout: policy.maxTimeoutSeconds,
    network: policy.allowedNetworks[0] ?? '',
    paymentFlow: policy.allowedPaymentFlows?.[0] ?? 'authorization',
    transferMethod: policy.allowedAssetTransferMethods?.[0] ?? 'eip3009',
    merchantMax: atomicToUsdc(merchant.maxAmount),
    payTo: merchant.payTo[0] ?? ''
  };
  for (const [id, value] of Object.entries(values)) {
    field(id).value = value;
  }
  policyEditorDirty = false;
  lastPolicyKey = JSON.stringify(policy);
}

field('adminToken').value = sessionStorage.getItem('sentinelAdminToken') ?? '';
field('adminToken').onchange = saveToken;
api('/api/arena/state?role=blue').then(state => {
  if (!policyEditorDirty && !lastPolicyKey) loadPolicy(state.policy);
}).catch(error => toast(error.message));
field('baseline').onclick = async () => {
  const button = field('baseline'); busy(button, true);
  try {
    const response = await api('/api/merchant/challenge');
    const offer = response.paymentRequired.accepts[0];
    Object.assign(field('maxPayment'), { value: atomicToUsdc(offer.amount) });
    Object.assign(field('merchantMax'), { value: atomicToUsdc(offer.amount) });
    Object.assign(field('payTo'), { value: offer.payTo });
    Object.assign(field('network'), { value: offer.network });
    Object.assign(field('timeout'), { value: offer.maxTimeoutSeconds });
    Object.assign(field('paymentFlow'), { value: offer.extra?.paymentFlow ?? 'authorization' });
    Object.assign(field('transferMethod'), { value: offer.extra?.assetTransferMethod ?? 'eip3009' });
    policyEditorDirty = true;
    toast('Merchant baseline loaded as USDC values');
  } catch (error) { toast(error.message); }
  finally { busy(button, false); }
};
field('save').onclick = async () => {
  const button = field('save'); busy(button, true);
  saveToken();
  try {
    const response = await api('/api/arena/policy', {
      method: 'POST', headers: headers(), body: JSON.stringify(policyPayload())
    });
    loadPolicy(response.policy, true);
    toast('Policy applied to future permits');
  } catch (error) { toast(error.message); }
  finally { busy(button, false); }
};
let trainingMode = 'secure';
field('trainingModeButton').onclick = async () => {
  const button = field('trainingModeButton');
  busy(button, true);
  saveToken();
  try {
    const mode = trainingMode === 'secure' ? 'merchant-timeout' : 'secure';
    await api('/api/arena/training-mode', {
      method: 'POST', headers: headers(), body: JSON.stringify({ mode })
    });
    toast(mode === 'secure' ? 'Secure permit binding restored' : 'Training weakness enabled for arena rounds');
  } catch (error) { toast(error.message); }
  finally { busy(button, false); }
};
async function runControl({ endpoint, button, authenticated = false }) {
  if (authenticated) saveToken();
  busy(button, true);
  field('trace').innerHTML = '<div class="subtle">Checking the merchant challenge…</div>';
  try {
    const result = await api(endpoint, { method: 'POST', headers: authenticated ? headers() : {}, body: '{}' });
    field('trace').innerHTML = [['402 challenge', 'observed'], ['Sentinel', 'allow'], ['Wallet', 'signed'], ['Settlement', 'settled'], ['Resource', 'compliant']]
      .map(([label, state], index) => `<div class="stage ${state}"><span>${index + 1}</span><div><b>${label}</b><small>Dry-run control flow</small></div></div>`).join('');
    toast(result.ok ? 'Legitimate 402 → 200 control completed' : 'Control was blocked');
  } catch (error) {
    const signed = error.data?.wallet?.signed === true;
    field('trace').innerHTML = signed
      ? `<div class="stage signed"><span>1</span><div><b>Wallet authorized</b><small>Dry-run authorization was created.</small></div></div><div class="stage block"><span>2</span><div><b>Merchant rejected</b><small>${escapeHtml(error.message)}</small></div></div>`
      : `<div class="stage block"><span>1</span><div><b>Sentinel blocked the control</b><small>${escapeHtml(error.message)} · Wallet not called</small></div></div>`;
    toast(error.message);
  } finally { busy(button, false); }
}

field('publicControl').onclick = () => runControl({
  endpoint: '/api/demo/control', button: field('publicControl')
});
field('legit').onclick = () => runControl({
  endpoint: '/api/agent/run', button: field('legit'), authenticated: true
});

function outcome(item) { return item.outcomeType === 'bypass' ? 'TRUE BYPASS' : item.outcomeType === 'false-positive' ? 'FALSE POSITIVE' : item.outcomeType === 'attack-blocked' ? 'ATTACK BLOCKED' : 'LEGITIMATE PASS'; }
stream('blue', state => {
  trainingMode = state.trainingMode ?? 'secure';
  const vulnerable = trainingMode === 'merchant-timeout';
  field('trainingModeLabel').textContent = vulnerable ? 'Vulnerable fixture' : 'Secure';
  field('trainingModeLabel').classList.toggle('vulnerable', vulnerable);
  field('trainingModeButton').textContent = vulnerable ? 'Restore secure mode' : 'Enable vulnerable mode';
  field('blueScore').textContent = state.scores.blue; field('redScore').textContent = state.scores.red;
  field('abr').textContent = state.metrics.attackTotal ? `${state.metrics.attackBlockRate}%` : '—';
  field('lpr').textContent = state.metrics.legitTotal ? `${state.metrics.legitPassRate}%` : '—';
  field('protected').textContent = money(state.metrics.protectedAtomic); field('bypasses').textContent = state.metrics.guardBypasses;
  field('fp').textContent = state.metrics.falsePositives ?? 0; field('correct').textContent = state.metrics.guardCorrect;
  if (!policyEditorDirty && JSON.stringify(state.policy) !== lastPolicyKey) loadPolicy(state.policy);
  const latest = state.requests.at(-1);
  if (latest?.id === lastRenderedRoundId) return;
  lastRenderedRoundId = latest?.id ?? null;
  field('latest').innerHTML = latest
    ? `<div class="diffbox"><div class="kv"><span>Round</span><span>${latest.round}</span></div><div class="kv"><span>Verdict</span><span>${escapeHtml(outcome(latest))}</span></div><div class="kv"><span>Mode used</span><span>${latest.trainingMode === 'merchant-timeout' ? 'Deliberately vulnerable fixture' : 'Secure permit binding'}</span></div><div class="kv"><span>Signer</span><span>${latest.wallet.signed ? 'Dry-run opened' : 'Stayed closed'}</span></div></div>`
    : 'Waiting for Red Team…';
  field('feed').innerHTML = [...state.requests].reverse().map(item => `<div class="event"><div class="eventtop"><strong>Round ${item.round}</strong><span class="tag ${item.guard.correct ? 'allow' : 'block'}">${outcome(item)}</span></div><p>${escapeHtml((item.guard.reasonCodes ?? []).join(', ') || 'Policy matched')}</p></div>`).join('') || '<div class="subtle">No decisions yet.</div>';
}, connectionStatus);
api('/api/system').then(system => {
  field('authority').innerHTML = `<div class="big">Ed25519</div><p>Authority key <b>${escapeHtml(short(system.authority.keyId, 8))}</b>. Blue controls require the admin token for this deployment.</p>`;
}).catch(error => toast(error.message));
