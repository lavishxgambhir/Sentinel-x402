import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { selectedResearch } from '../research/paper-analysis.mjs';
import { AuditLog } from './audit-log.mjs';
import { SentinelRuntime } from './demo-runtime.mjs';
import { sendJson, servePublicPage, setCommonHeaders } from './http.mjs';
import { createApiRouter } from './routes.mjs';

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(currentDir, '..', '..');
const publicDir = path.join(projectRoot, 'public');
const policy = JSON.parse(fs.readFileSync(path.join(projectRoot, 'policy.json'), 'utf8'));
const audit = new AuditLog(path.join(projectRoot, 'data', 'audit.json'));
const port = Number(process.env.PORT ?? 4173);
const adminToken = process.env.SENTINEL_ADMIN_TOKEN
  ?? crypto.randomBytes(24).toString('base64url');

const runtime = new SentinelRuntime({ policy, audit, port, adminToken });
const eventClients = new Map();

async function getRealStatus() {
  const env = {
    EVM_PRIVATE_KEY: Boolean(process.env.EVM_PRIVATE_KEY),
    MERCHANT_ADDRESS: Boolean(process.env.MERCHANT_ADDRESS),
    X402_FACILITATOR_URL: Boolean(process.env.X402_FACILITATOR_URL)
  };

  let sdkAvailable = false;
  try {
    await import('@x402/core/client');
    await import('@x402/evm/exact/client');
    sdkAvailable = true;
  } catch {
    // The demo intentionally has no runtime dependency on the official SDK.
  }

  return {
    mode: sdkAvailable && env.EVM_PRIVATE_KEY ? 'testnet-ready' : 'demo',
    sdkAvailable,
    env,
    network: 'eip155:84532',
    note: sdkAvailable
      ? 'Official x402 packages detected.'
      : 'The local dry-run demo works without optional x402 SDK packages.'
  };
}

function publishArenaState() {
  const payloads = new Map();
  for (const [client, role] of eventClients) {
    try {
      if (!payloads.has(role)) {
        payloads.set(role, `event: state\ndata: ${JSON.stringify(runtime.arena.snapshot(role, role === 'judge' ? 1 : 12))}\n\n`);
      }
      client.write(payloads.get(role));
    } catch {
      eventClients.delete(client);
    }
  }
}

function handleArenaEvents(request, response, url) {
  if (request.method !== 'GET' || url.pathname !== '/api/arena/events') return false;

  const role = url.searchParams.get('role') ?? 'judge';
  response.writeHead(200, {
    'content-type': 'text/event-stream; charset=utf-8',
    'cache-control': 'no-cache, no-transform',
    connection: 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  });
  response.write(`event: state\ndata: ${JSON.stringify(runtime.arena.snapshot(role, role === 'judge' ? 1 : 12))}\n\n`);
  eventClients.set(response, role);

  const keepAlive = setInterval(() => {
    try {
      response.write(': ping\n\n');
    } catch {
      // The close listener owns client cleanup.
    }
  }, 15_000);

  request.on('close', () => {
    clearInterval(keepAlive);
    eventClients.delete(response);
  });
  return true;
}

const routeApi = createApiRouter({
  runtime,
  audit,
  getRealStatus,
  research: selectedResearch,
  publishArenaState
});

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || '127.0.0.1'}`);
  setCommonHeaders(response);

  if (request.method === 'OPTIONS') {
    response.writeHead(204);
    response.end();
    return;
  }

  try {
    const handled =
      handleArenaEvents(request, response, url)
      || await routeApi(request, response, url)
      || servePublicPage(request, response, url, publicDir);

    if (!handled) sendJson(response, 404, { error: 'not_found' });
  } catch (error) {
    console.error(error);
    if (!response.headersSent) sendJson(response, 400, { error: error.message });
  }
});

server.listen(port, process.env.HOST ?? '127.0.0.1', () => {
  console.log('\n  KCC Sentinel');
  console.log(`  Local   http://127.0.0.1:${port}`);
  console.log(`  Blue admin token   ${adminToken}`);

  for (const list of Object.values(os.networkInterfaces())) {
    for (const item of list ?? []) {
      if (item.family === 'IPv4' && !item.internal) {
        console.log(`  LAN     http://${item.address}:${port}  → /red /blue /judge`);
      }
    }
  }

  console.log('  Mode    dry-run; no funds are broadcast\n');
});
