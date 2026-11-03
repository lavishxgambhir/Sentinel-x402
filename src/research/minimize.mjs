const clone = value => structuredClone(value);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function leafChanges(original, candidate, path = []) {
  if (same(original, candidate)) return [];
  if (
    original && candidate && typeof original === 'object' && typeof candidate === 'object' &&
    Array.isArray(original) === Array.isArray(candidate) &&
    (!Array.isArray(original) || original.length === candidate.length)
  ) {
    const keys = Array.isArray(original) ? original.map((_, index) => index) : [...new Set([...Object.keys(original), ...Object.keys(candidate)])].sort();
    return keys.flatMap(key => leafChanges(original[key], candidate[key], [...path, key]));
  }
  return [{ path, before: original, after: candidate }];
}

function setPath(object, path, value) {
  let cursor = object;
  for (const key of path.slice(0, -1)) cursor = cursor[key];
  cursor[path.at(-1)] = clone(value);
}

function displayPath(path) {
  return path.map((part, index) => typeof part === 'number' ? `[${part}]` : `${index ? '.' : ''}${part}`).join('');
}

/** Return the changed leaf paths between two request envelopes. */
export function mutationPaths(original, candidate) {
  return leafChanges(original, candidate).map(change => displayPath(change.path));
}

/**
 * Greedy 1-minimization of a bypass. The predicate must verify both that the
 * candidate remains unauthorized and that the target still allows it.
 */
export async function minimizeBypass(original, candidate, stillBypasses, { maxAttempts = 24 } = {}) {
  if (typeof stillBypasses !== 'function') throw new Error('stillBypasses must be a function');
  if (!Number.isInteger(maxAttempts) || maxAttempts < 0) throw new Error('maxAttempts must be non-negative');
  let current = clone(candidate);
  let attempts = 0;
  let reduced = true;
  while (reduced && attempts < maxAttempts) {
    reduced = false;
    for (const change of leafChanges(original, current)) {
      if (attempts >= maxAttempts) break;
      if (!change.path.length || change.before === undefined) continue;
      const trial = clone(current);
      try { setPath(trial, change.path, change.before); } catch { continue; }
      attempts += 1;
      if (await stillBypasses(trial)) {
        current = trial;
        reduced = true;
        break;
      }
    }
  }
  return { candidate: current, paths: mutationPaths(original, current), attempts, reduced: !same(current, candidate) };
}
