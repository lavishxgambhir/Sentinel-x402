import { $, api, stream, short, money, escapeHtml, connectionStatus, busy, roundEvidence } from './shared.js';
const field = id => $(`#${id}`);
let lastRenderedRoundId = null;
const outcome = item => item.outcomeType === 'bypass' ? 'TRUE BYPASS' : item.outcomeType === 'false-positive' ? 'FALSE POSITIVE' : item.outcomeType === 'attack-blocked' ? 'ATTACK BLOCKED' : 'LEGITIMATE PASS';
function rows(payment) {
  if (!payment) return '<div class="subtle">No payment requirement.</div>';
  const offer = payment.accepts?.[0] ?? {};
  return [['Amount', money(offer.amount)], ['Timeout', `${offer.maxTimeoutSeconds ?? '—'}s`], ['Recipient', short(offer.payTo, 10)], ['Resource', payment.resource?.url], ['Network', offer.network]]
    .map(([label, value]) => `<div class="kv"><span>${escapeHtml(label)}</span><span>${escapeHtml(value ?? '—')}</span></div>`).join('');
}
function trace(item) {
  return (item.executionTrace ?? []).map((step, index) => `<div class="stage ${escapeHtml(step.state)}"><span>${index + 1}</span><div><b>${escapeHtml(step.label)}</b><small>${escapeHtml(step.detail)}</small></div></div>`).join('');
}
stream('judge', state => {
  const vulnerable = state.trainingMode === 'merchant-timeout';
  field('trainingModeNotice').textContent = vulnerable
    ? 'DELIBERATELY VULNERABLE TRAINING FIXTURE · permit issuer trusts the received timeout · dry-run only'
    : 'SECURE MODE · permit binds the server-held original timeout';
  field('trainingModeNotice').classList.toggle('vulnerable', vulnerable);
  field('blueScore').textContent = state.scores.blue; field('redScore').textContent = state.scores.red; field('round').textContent = state.round;
  field('abr').textContent = state.metrics.attackTotal ? `${state.metrics.attackBlockRate}%` : '—';
  field('lpr').textContent = state.metrics.legitTotal ? `${state.metrics.legitPassRate}%` : '—';
  field('bypasses').textContent = state.metrics.guardBypasses; field('fp').textContent = state.metrics.falsePositives ?? 0;
  field('unauthorized').textContent = money(state.metrics.unauthorizedValueSettled);
  const item = state.requests.at(-1);
  if (item?.id === lastRenderedRoundId) return;
  lastRenderedRoundId = item?.id ?? null;
  if (!item) {
    field('clock').textContent = 'Waiting for first challenge';
    field('roundType').textContent = 'READY';
    field('headline').textContent = 'A payment is judged against the original offer.';
    for (const id of ['expected', 'actual', 'refResult']) field(id).textContent = '—';
    for (const id of ['original', 'received']) field(id).textContent = 'No round yet.';
    field('permit').textContent = 'A permit appears on the first round.';
    field('reason').textContent = 'Waiting for evidence.';
    field('trace').textContent = 'Waiting for a round…';
    field('decision').className = 'judgeDecision';
    field('decision').innerHTML = '<div><div class="word">READY</div><div class="subtle">No arena round has been evaluated.</div></div><div class="pill">Independent referee armed</div>';
    return;
  }
  const control = item.classification === 'legitimate';
  field('clock').textContent = new Date(item.createdAt).toLocaleTimeString();
  field('roundType').textContent = `${control ? 'CONTROL ROUND · LEGITIMATE' : 'ATTACK ROUND · ADVERSARIAL'}${item.trainingMode === 'merchant-timeout' ? ' · VULNERABLE FIXTURE' : ''}`;
  field('headline').textContent = control ? 'Did the valid payment pass?' : 'Did the changed terms reach the signer?';
  field('expected').textContent = control ? 'ALLOW' : 'BLOCK'; field('actual').textContent = item.guard.action.toUpperCase();
  field('refResult').textContent = item.guard.correct ? 'CORRECT' : outcome(item);
  field('original').innerHTML = rows(item.originalPaymentRequired); field('received').innerHTML = rows(item.paymentRequired);
  const permit = item.intentPermit;
  field('permit').innerHTML = permit ? `<div class="kv"><span>Permit</span><span>${escapeHtml(short(permit.permitId, 10))}</span></div><div class="kv"><span>Max amount</span><span>${escapeHtml(money(permit.maxAmount))}</span></div><div class="kv"><span>Timeout ceiling</span><span>${escapeHtml(permit.maxTimeoutSeconds)}s</span></div><div class="kv"><span>Recipient</span><span>${escapeHtml(short(permit.payTo?.[0], 10))}</span></div>` : 'No permit available.';
  const closure = item.guard.closure;
  field('reason').innerHTML = `<p>${escapeHtml(roundEvidence(item))}</p><div class="checks">${(item.guard.reasonCodes ?? []).map(code => `<div class="check bad">${escapeHtml(code)}</div>`).join('') || '<div class="check ok">No guard check failed</div>'}</div><p>Recipient graph: ${escapeHtml(closure?.source === 'seeded-demo-graph' ? `${closure.verdict} · synthetic demo graph` : 'not applicable')}</p>`;
  field('trace').innerHTML = trace(item);
  field('decision').className = `judgeDecision ${item.guard.correct ? 'allow' : 'block'}`;
  field('decision').innerHTML = `<div><div class="word">${outcome(item)}</div><div class="subtle">${item.trainingMode === 'merchant-timeout' ? 'This round used the deliberately vulnerable training fixture.' : 'This round used secure permit binding.'}</div></div><div class="pill">Expected ${control ? 'ALLOW' : 'BLOCK'} · Actual ${item.guard.action.toUpperCase()}</div>`;
}, connectionStatus);

let reports = { known: null, heldout: null, multi: null };
let selectedView = 'known';
const metric = (label, value) => `<div class="evaluationMetric"><span>${escapeHtml(label)}</span><b>${escapeHtml(value ?? '—')}</b></div>`;
const percentage = value => value === null || value === undefined ? '—' : `${value}%`;

function showEvaluation() {
  const panel = field('evaluationPanel');
  for (const [id, view] of [['showKnown', 'known'], ['showHeldout', 'heldout'], ['showMulti', 'multi'], ['showFailures', 'failures']]) {
    const selected = selectedView === view;
    field(id).classList.toggle('selected', selected);
    field(id).setAttribute('aria-pressed', String(selected));
  }
  field('knownSuiteStatus').textContent = reports.known?.status ?? 'NOT RUN';
  field('knownSuiteNumbers').textContent = reports.known
    ? `${reports.known.metrics.attackContained}/${reports.known.metrics.attackCases} attacks contained · ${reports.known.metrics.legitimateAllowed}/${reports.known.metrics.legitimateCases} legitimate allowed · ${reports.known.metrics.bypasses} bypasses · ${reports.known.metrics.falsePositives} false positives`
    : 'Run the known suite to see its result.';
  field('heldoutSuiteStatus').textContent = reports.heldout?.status ?? 'NOT RUN';
  field('heldoutSuiteNumbers').textContent = reports.heldout
    ? `${reports.heldout.metrics.truePositive}/${reports.heldout.metrics.attacks} attacks contained · ${reports.heldout.metrics.trueNegative}/${reports.heldout.metrics.legitimate} legitimate allowed · ${reports.heldout.metrics.falseNegative} bypasses · ${reports.heldout.metrics.falsePositive} false positives · ${reports.heldout.criticalBypasses.length} critical`
    : 'Run the held-out suite to see its result.';
  const report = selectedView === 'known' ? reports.known : reports.heldout;
  if (selectedView === 'multi') {
    panel.innerHTML = reports.multi
      ? `<div class="evaluationGrid">${[
        metric('Status', reports.multi.status),
        metric('Seeds', reports.multi.seeds.join(', ')),
        metric('Total attacks', reports.multi.totalAttacks),
        metric('Total legitimate', reports.multi.totalLegitimate),
        metric('Total bypasses', reports.multi.totalBypasses),
        metric('Total false positives', reports.multi.totalFalsePositives),
        metric('Critical intent bypasses', reports.multi.criticalBypasses),
        metric('Mean containment', percentage(reports.multi.meanAttackContainmentRate)),
        metric('Worst containment', percentage(reports.multi.minAttackContainmentRate)),
        metric('Best containment', percentage(reports.multi.maxAttackContainmentRate)),
        metric('Mean legitimate pass', percentage(reports.multi.meanLegitimatePassRate))
      ].join('')}</div>`
      : '<p class="subtle">Run multi-seed above to calculate the seven-seed result in this server session.</p>';
    return;
  }
  if (selectedView === 'failures') {
    const failures = reports.heldout?.failures ?? [];
    panel.innerHTML = failures.length
      ? failures.map(item => `<div class="failureRow"><b>${escapeHtml(item.id)}</b><span>Seed ${escapeHtml(item.seed)} · ${escapeHtml(item.severity)} · Level ${escapeHtml(item.level)} · ${escapeHtml(item.mutationFields.join(' + '))}</span><small>${escapeHtml(item.failureCategory)} · Expected ${escapeHtml(item.expected.toUpperCase())}, observed ${escapeHtml(item.actual.toUpperCase())}; ${escapeHtml(item.reasonCodes.join(', ') || 'no reason code')}</small></div>`).join('')
      : '<p class="subtle">No held-out failures recorded in this server session.</p>';
    return;
  }
  if (!report) {
    panel.innerHTML = '<p class="subtle">Run this suite to calculate its metrics.</p>';
    return;
  }
  const m = report.metrics;
  panel.innerHTML = selectedView === 'known'
    ? `<div class="evaluationGrid">${[
      metric('Status', report.status), metric('Seed', report.seed),
      metric('Attacks contained', `${m.attackContained}/${m.attackCases}`),
      metric('Legitimate allowed', `${m.legitimateAllowed}/${m.legitimateCases}`),
      metric('Bypasses', m.bypasses), metric('False positives', m.falsePositives),
      metric('Attack containment', percentage(m.attackContainmentRate)),
      metric('Legitimate pass', percentage(m.legitimatePassRate))
    ].join('')}</div>`
    : `<div class="evaluationGrid">${[
      metric('Status', report.status), metric('Seed', report.seed),
      metric('Attacks contained', `${m.truePositive}/${m.attacks}`),
      metric('Legitimate allowed', `${m.trueNegative}/${m.legitimate}`),
      metric('Bypasses', m.falseNegative), metric('False positives', m.falsePositive),
      metric('Attack containment', percentage(m.attackContainmentRate)),
      metric('Bypass rate', percentage(m.bypassRate)),
      metric('Legitimate pass', percentage(m.legitimatePassRate)),
      metric('False positive rate', percentage(m.falsePositiveRate)),
      metric('Critical intent bypasses', report.criticalBypasses.length),
      metric('TP / TN / FP / FN', `${m.truePositive} / ${m.trueNegative} / ${m.falsePositive} / ${m.falseNegative}`),
      metric('Accuracy / F1', `${percentage(m.overallAccuracy)} / ${percentage(m.f1Score)}`)
    ].join('')}</div><p class="subtle">${escapeHtml(report.statisticalNote)}</p><details class="statefulChecks"><summary>Security hardening probes</summary>${(report.securityChecks ?? []).map(item => `<div class="failureRow"><b>${escapeHtml(item.id)}</b><small>Expected ${escapeHtml(item.expected.toUpperCase())} · Sentinel ${escapeHtml(item.actual.toUpperCase())} · ${item.passed ? 'CORRECT' : 'FAILURE'}${item.reasonCodes.length ? ` · ${escapeHtml(item.reasonCodes.join(', '))}` : ''}</small></div>`).join('')}</details><details class="statefulChecks"><summary>All stateful probe results</summary>${(report.statefulChecks ?? []).map(item => `<div class="failureRow"><b>${escapeHtml(item.id)}</b><small>Expected ${escapeHtml(item.expected.toUpperCase())} · Sentinel ${escapeHtml(item.actual.toUpperCase())} · ${item.passed ? 'CORRECT' : 'FAILURE'}${item.reasonCodes.length ? ` · ${escapeHtml(item.reasonCodes.join(', '))}` : ''}</small></div>`).join('')}</details>`;
}

for (const [id, view] of [['showKnown', 'known'], ['showHeldout', 'heldout'], ['showMulti', 'multi'], ['showFailures', 'failures']]) {
  field(id).onclick = () => { selectedView = view; showEvaluation(); };
}
field('evaluationToken').value = sessionStorage.getItem('sentinelAdminToken') ?? '';
field('evaluationToken').onchange = () => sessionStorage.setItem('sentinelAdminToken', field('evaluationToken').value.trim());

async function runEvaluation(kind) {
  const button = field(kind === 'known' ? 'runKnown' : kind === 'multi' ? 'runMulti' : 'runHeldout');
  busy(button, true);
  const label = kind === 'known' ? 'known regression' : kind === 'multi' ? 'seven-seed evaluation' : 'held-out Red Team';
  field('evaluationStatus').textContent = `Running ${label}…`;
  try {
    const adminToken = field('evaluationToken').value.trim() || sessionStorage.getItem('sentinelAdminToken') || '';
    const url = kind === 'known' ? '/api/attack/fuzz' : kind === 'multi' ? '/api/research/heldout/multi' : '/api/research/heldout';
    const body = kind === 'known'
      ? { seed: 402, attackCount: 500, honestCount: 500 }
      : { seed: 42, attacks: 300, legitimate: 300 };
    const result = await api(url, { method: 'POST', headers: { 'x-sentinel-admin-token': adminToken }, body: JSON.stringify(body) });
    reports[kind] = kind === 'known'
      ? { seed: result.seed, metrics: result.metrics,
          status: result.metrics.bypasses === 0 && result.metrics.falsePositives === 0 ? 'PASS' : 'FAIL' }
      : result;
    selectedView = kind;
    field('evaluationStatus').textContent = 'Evaluation complete. Counts are from this server session.';
    showEvaluation();
  } catch (error) {
    field('evaluationStatus').textContent = error.message;
  } finally { busy(button, false); }
}
field('runKnown').onclick = () => runEvaluation('known');
field('runHeldout').onclick = () => runEvaluation('heldout');
field('runMulti').onclick = () => runEvaluation('multi');
api('/api/research/evaluation').then(value => { reports = value; showEvaluation(); }).catch(() => showEvaluation());
