import { $, api } from './shared.js';

async function loadArenaSummary() {
  try {
    const state = await api('/api/arena/state?role=judge&limit=1');
    $('#homeRounds').textContent = String(state.round);
    $('#homeBlockRate').textContent = state.metrics.attackTotal ? `${state.metrics.attackBlockRate}%` : '—';
    $('#homePassRate').textContent = state.metrics.legitTotal ? `${state.metrics.legitPassRate}%` : '—';
  } catch {
    for (const id of ['homeRounds', 'homeBlockRate', 'homePassRate']) {
      $(`#${id}`).textContent = '—';
    }
  }
}

loadArenaSummary();
