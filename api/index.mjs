import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { neon } from '@neondatabase/serverless';

import policy from '../policy.json' with { type: 'json' };
import { AuditLog } from '../src/app/audit-log.mjs';
import { SentinelRuntime } from '../src/app/demo-runtime.mjs';
import { createApiRouter } from '../src/app/routes.mjs';
import { MAX_REQUEST_BODY_BYTES, setCommonHeaders } from '../src/app/http.mjs';
import { hydrateRuntime, serializeRuntime } from '../src/app/runtime-state.mjs';
import { selectedResearch } from '../src/research/paper-analysis.mjs';
import { IntentAuthority } from '../src/security/intent-authority.mjs';

export const config = { maxDuration: 60 };

let sqlClient;
let initialized;

function sql() {
  if (!sqlClient) {
    if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not configured');
    sqlClient = neon(process.env.DATABASE_URL);
  }
  return sqlClient;
}

function makeRuntime() {
  const key = process.env.SENTINEL_AUTHORITY_PRIVATE_KEY_B64;
  const adminToken = process.env.SENTINEL_ADMIN_TOKEN;
  if (!key || !adminToken) throw new Error('Sentinel server secrets are not configured');
  const privateKey = crypto.createPrivateKey(Buffer.from(key, 'base64').toString('utf8'));
  const publicKey = crypto.createPublicKey(privateKey);
  return new SentinelRuntime({
    policy,
    audit: new AuditLog(null),
    port: null,
    adminToken,
    intentAuthority: new IntentAuthority({ privateKey, publicKey }),
    serverless: true
  });
}

async function ensureState() {
  if (!initialized) {
    initialized = (async () => {
      await sql()`CREATE TABLE IF NOT EXISTS sentinel_runtime (
        id integer PRIMARY KEY,
        version bigint NOT NULL DEFAULT 0,
        state jsonb NOT NULL,
        updated_at timestamptz NOT NULL DEFAULT now()
      )`;
      const initial = serializeRuntime(makeRuntime());
      await sql()`INSERT INTO sentinel_runtime (id, state)
        VALUES (1, ${initial}::jsonb) ON CONFLICT (id) DO NOTHING`;
    })().catch(error => { initialized = null; throw error; });
  }
  await initialized;
}

function routeUrl(request) {
  const incoming = new URL(request.url, `https://${request.headers.host ?? 'localhost'}`);
  const path = incoming.searchParams.get('sentinelPath') ?? incoming.pathname;
  const url = new URL(path, incoming.origin);
  for (const [key, value] of incoming.searchParams) {
    if (key !== 'sentinelPath') url.searchParams.append(key, value);
  }
  return url;
}

async function requestBody(request) {
  if (request.body !== undefined) {
    const bytes = Buffer.isBuffer(request.body)
      ? request.body : Buffer.from(JSON.stringify(request.body));
    if (bytes.length > MAX_REQUEST_BODY_BYTES) throw new Error('request body too large');
    return bytes;
  }
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > MAX_REQUEST_BODY_BYTES) throw new Error('request body too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function replayRequest(source, body) {
  const request = new EventEmitter();
  request.method = source.method;
  request.headers = source.headers;
  request.url = source.url;
  request.destroy = () => {};
  queueMicrotask(() => {
    if (body.length) request.emit('data', body);
    request.emit('end');
  });
  return request;
}

function captureResponse() {
  return {
    status: 200,
    headers: {},
    body: '',
    headersSent: false,
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    writeHead(status, headers = {}) {
      this.status = status;
      for (const [name, value] of Object.entries(headers)) this.setHeader(name, value);
      this.headersSent = true;
    },
    end(value = '') { this.body += value; }
  };
}

function isReadOnly(request, pathname) {
  return request.method === 'GET' && new Set([
    '/api/system', '/api/real/status', '/api/research/papers',
    '/api/research/evaluation', '/api/arena/state', '/api/audit',
    '/api/audit/export'
  ]).has(pathname);
}

async function dispatch(request, body, url, runtime) {
  const response = captureResponse();
  setCommonHeaders(response);
  const route = createApiRouter({
    runtime,
    audit: runtime.audit,
    research: selectedResearch,
    publishArenaState() {},
    getRealStatus: async () => ({
      mode: 'demo', sdkAvailable: false, network: 'eip155:84532',
      note: 'Shared dry-run simulation on Vercel; no funds are broadcast.'
    })
  });
  try {
    if (!await route(replayRequest(request, body), response, url)) {
      response.writeHead(404, { 'content-type': 'application/json; charset=utf-8' });
      response.end(JSON.stringify({ error: 'not_found' }));
    }
  } catch (error) {
    response.writeHead(400, { 'content-type': 'application/json; charset=utf-8' });
    response.end(JSON.stringify({ error: error.message }));
  }
  return response;
}

export default async function handler(request, response) {
  if (request.method === 'OPTIONS') {
    setCommonHeaders(response);
    response.writeHead(204);
    response.end();
    return;
  }
  const url = routeUrl(request);
  if (url.pathname === '/api/arena/events') {
    response.writeHead(404, { 'content-type': 'application/json; charset=utf-8' });
    response.end(JSON.stringify({ error: 'Use state polling on Vercel' }));
    return;
  }
  try {
    await ensureState();
    const body = await requestBody(request);
    const maxAttempts = isReadOnly(request, url.pathname) ? 1 : 5;
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const [row] = await sql()`SELECT version, state FROM sentinel_runtime WHERE id = 1`;
      const runtime = hydrateRuntime(makeRuntime(), row.state);
      const result = await dispatch(request, body, url, runtime);
      if (maxAttempts > 1) {
        const next = serializeRuntime(runtime);
        const changed = await sql()`UPDATE sentinel_runtime
          SET state = ${next}::jsonb, version = version + 1, updated_at = now()
          WHERE id = 1 AND version = ${row.version} RETURNING version`;
        if (!changed.length) continue;
      }
      response.writeHead(result.status, result.headers);
      response.end(result.body);
      return;
    }
    response.writeHead(409, { 'content-type': 'application/json; charset=utf-8' });
    response.end(JSON.stringify({ error: 'Concurrent update; please retry' }));
  } catch (error) {
    console.error('Sentinel request failed', error);
    response.writeHead(503, { 'content-type': 'application/json; charset=utf-8' });
    response.end(JSON.stringify({ error: 'Sentinel service is temporarily unavailable' }));
  }
}
