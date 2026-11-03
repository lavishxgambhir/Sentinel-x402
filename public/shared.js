export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

export function short(value, length = 10) {
  const text = String(value ?? '—');
  return text.length > length * 2 + 3
    ? `${text.slice(0, length)}…${text.slice(-length)}`
    : text;
}

export function escapeHtml(value) {
  const entities = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  return String(value ?? '').replace(/[&<>"']/g, character => entities[character]);
}

export function money(atomic) {
  try {
    const value = BigInt(String(atomic ?? 0));
    const sign = value < 0n ? '-' : '';
    const digits = (value < 0n ? -value : value).toString().padStart(7, '0');
    const whole = digits.slice(0, -6);
    const fraction = digits.slice(-6).replace(/0+$/, '');
    return `$${sign}${whole}${fraction ? `.${fraction}` : '.00'}`;
  } catch {
    return '$—';
  }
}
export async function api(url, opts = {}) {
  const { headers = {}, ...request } = opts;
  const response = await fetch(url, {
    ...request,
    headers: { 'content-type': 'application/json', ...headers }
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(
      body.error || body.reason || body.evaluation?.reason || body.resource?.error || `HTTP ${response.status}`
    );
    error.data = body;
    error.status = response.status;
    throw error;
  }
  return body;
}
export function stream(role, onState, onStatus = () => {}) {
  const query = `/api/arena/state?role=${encodeURIComponent(role)}&limit=${role === 'judge' ? 1 : 12}`;
  let polling = false;
  let timer;
  async function poll() {
    try {
      const response = await fetch(query, { cache: 'no-store' });
      if (!response.ok) throw new Error(`State HTTP ${response.status}`);
      onState(await response.json());
      onStatus('live');
    } catch {
      onStatus('reconnecting');
    } finally {
      if (polling) timer = setTimeout(poll, 2000);
    }
  }
  const events = new EventSource(`/api/arena/events?role=${encodeURIComponent(role)}`);
  events.onopen = () => onStatus('live');
  events.onerror = () => {
    events.close();
    if (!polling) { polling = true; poll(); }
  };
  events.addEventListener('state', event => {
    try { onState(JSON.parse(event.data)); }
    catch (error) { console.error('Invalid arena update', error); }
  });
  return { close() { polling = false; clearTimeout(timer); events.close(); } };
}
export function connectionStatus(state) {
  const indicator = $('#connectionState');
  if (!indicator) return;
  indicator.dataset.state = state;
  indicator.textContent = state === 'live' ? 'Live' : state === 'reconnecting' ? 'Reconnecting' : 'Connecting';
}
export function busy(button, running) {
  button.disabled = running;
  button.setAttribute('aria-busy', String(running));
}
export function toast(message) {
  let element = $('#toast');
  if (!element) {
    element = document.createElement('div');
    element.id = 'toast';
    element.className = 'toast';
    document.body.append(element);
  }
  element.textContent = message;
  element.classList.add('show');
  clearTimeout(element.t);
  element.t = setTimeout(() => element.classList.remove('show'), 2200);
}

export function kv(object, keys) {
  return keys.map(([label, key, format]) =>
    `<div class="kv"><span>${escapeHtml(label)}</span><span>${escapeHtml(format ? format(object?.[key]) : short(object?.[key], 14))}</span></div>`
  ).join('');
}

export function roundEvidence(item) {
  const original = item.originalPaymentRequired?.accepts?.[0]?.maxTimeoutSeconds;
  const received = item.paymentRequired?.accepts?.[0]?.maxTimeoutSeconds;
  if (Number.isInteger(original) && Number.isInteger(received) && received > original) {
    if (item.outcomeType === 'bypass' && item.trainingMode === 'merchant-timeout') {
      return `Original ${original}s → received ${received}s. The deliberately vulnerable issuer signed a ${item.intentPermit?.maxTimeoutSeconds}s permit, so the guard allowed an altered offer.`;
    }
    if (item.guard?.reasonCodes?.includes('INTENT_TIMEOUT')) {
      return `Original ${original}s → received ${received}s. The signed permit kept the ${original}s ceiling, so Sentinel blocked the change before the simulated wallet stage.`;
    }
  }
  return item.groundTruth?.reason ?? item.guard?.reason ?? 'No decision evidence available.';
}
