import { normalizeAddress } from '../core/x402.mjs';

const address = value => String(normalizeAddress(value ?? '')).toLowerCase();

function shortestPath(start, goal, edges, maxHops, directed) {
  const queue = [[start]];
  const seen = new Set([start]);
  while (queue.length) {
    const path = queue.shift();
    const current = path.at(-1);
    if (current === goal) return path;
    if (path.length - 1 >= maxHops) continue;
    for (const edge of edges) {
      const from = address(edge?.from), to = address(edge?.to);
      const next = from === current ? to : !directed && to === current ? from : null;
      if (!next || seen.has(next)) continue;
      seen.add(next);
      queue.push([...path, next]);
    }
  }
  return null;
}

// The graph is intentionally supplied by demo policy. This is a relationship
// signal, not a claim about real transfers, wallet ownership, or AML status.
export function evaluateClosure(recipient, wallet, config = {}) {
  const source = config.source ?? 'seeded-demo-graph';
  const empty = { verdict: 'allow', path: [], hops: 0, source, reason: 'No seeded wallet relationship found' };
  if (!config.enabled) return { ...empty, reason: 'Closure graph is disabled' };
  const start = address(recipient), goal = address(wallet);
  if (!/^0x[0-9a-f]{40}$/.test(start) || !/^0x[0-9a-f]{40}$/.test(goal)) {
    return { ...empty, reason: 'No valid wallet addresses to compare' };
  }
  if (start === goal) return { verdict: 'block', path: [start], hops: 0, source, reason: 'Recipient is the payer wallet' };
  const edges = Array.isArray(config.edges) ? config.edges : [];
  const maxHops = Math.max(1, Math.min(6, Number(config.maxHops) || 3));
  const path = shortestPath(start, goal, edges, maxHops, true);
  if (path) return { verdict: 'block', path, hops: path.length - 1, source, reason: 'Seeded transfer path returns to payer wallet' };
  const connected = shortestPath(start, goal, edges, maxHops, false);
  if (connected) return { verdict: 'review', path: connected, hops: connected.length - 1, source, reason: 'Seeded graph links recipient and payer wallet' };
  return empty;
}
