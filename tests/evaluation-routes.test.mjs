import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { EventEmitter } from 'node:events';
import { SentinelRuntime } from '../src/app/demo-runtime.mjs';
import { createApiRouter } from '../src/app/routes.mjs';

const policy = JSON.parse(fs.readFileSync(new URL('../policy.json', import.meta.url), 'utf8'));

test('Judge evaluation API requires the admin token and returns a stored held-out report', async () => {
  const audit = { append() {} };
  const runtime = new SentinelRuntime({ policy, audit, port: 4173, adminToken: 'local-test-token' });
  const route = createApiRouter({ runtime, audit, getRealStatus: async () => ({}), research: [], publishArenaState() {} });

  async function call(method, pathname, body, token) {
    const request = new EventEmitter();
    request.method = method;
    request.headers = token ? { 'x-sentinel-admin-token': token } : {};
    request.destroy = () => {};
    const response = {
      status: null,
      body: null,
      writeHead(status) { this.status = status; },
      end(value) { this.body = JSON.parse(value); }
    };
    const result = route(request, response, new URL(pathname, 'http://localhost'));
    if (method === 'POST' && token) queueMicrotask(() => {
      request.emit('data', Buffer.from(JSON.stringify(body)));
      request.emit('end');
    });
    await result;
    return response;
  }

  const denied = await call('POST', '/api/research/heldout', {}, null);
  assert.equal(denied.status, 403);
  const evaluated = await call('POST', '/api/research/heldout', { seed: 42, attacks: 30, legitimate: 30 }, 'local-test-token');
  assert.equal(evaluated.status, 200);
  assert.equal(evaluated.body.metrics.attacks, 30);
  assert.equal(evaluated.body.metrics.legitimate, 30);
  const stored = await call('GET', '/api/research/evaluation');
  assert.equal(stored.status, 200);
  assert.equal(stored.body.heldout.seed, 42);

  const deniedMode = await call('POST', '/api/arena/training-mode', { mode: 'merchant-timeout' });
  assert.equal(deniedMode.status, 403);
  assert.equal(runtime.arena.snapshot().trainingMode, 'secure');
  const enabledMode = await call('POST', '/api/arena/training-mode', { mode: 'merchant-timeout' }, 'local-test-token');
  assert.equal(enabledMode.status, 200);
  assert.equal(runtime.arena.snapshot().trainingMode, 'merchant-timeout');
  runtime.resetArena();
  assert.equal(runtime.arena.snapshot().trainingMode, 'secure');
});
