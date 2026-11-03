import fs from 'node:fs';
import path from 'node:path';

export const MAX_REQUEST_BODY_BYTES = 512 * 1024;

export function sendJson(response, status, body, headers = {}) {
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...headers
  });
  response.end(JSON.stringify(body, (_key, value) => (
    typeof value === 'bigint' ? value.toString() : value
  ), 2));
}

export function readJson(request, maxBytes = MAX_REQUEST_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;

    request.on('data', chunk => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error('request body too large'));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });

    request.on('end', () => {
      if (chunks.length === 0) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('invalid JSON body'));
      }
    });

    request.on('error', reject);
  });
}

function contentType(filename) {
  if (filename.endsWith('.html')) return 'text/html; charset=utf-8';
  if (filename.endsWith('.js') || filename.endsWith('.mjs')) return 'text/javascript; charset=utf-8';
  if (filename.endsWith('.css')) return 'text/css; charset=utf-8';
  if (filename.endsWith('.svg')) return 'image/svg+xml';
  if (filename.endsWith('.json')) return 'application/json; charset=utf-8';
  return 'application/octet-stream';
}

export function serveFile(response, publicDir, filename) {
  const relativePath = path.relative(publicDir, filename);
  if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) return false;
  if (!fs.existsSync(filename) || !fs.statSync(filename).isFile()) return false;

  response.writeHead(200, {
    'content-type': contentType(filename),
    // During a live demo every refresh should load the matching HTML, JS, and CSS.
    'cache-control': 'no-store'
  });
  fs.createReadStream(filename).pipe(response);
  return true;
}

export function servePublicPage(request, response, url, publicDir) {
  if (request.method !== 'GET') return false;

  const pages = {
    '/': 'index.html',
    '/red': 'red.html',
    '/blue': 'blue.html',
    '/judge': 'judge.html'
  };
  const filename = pages[url.pathname]
    ? path.join(publicDir, pages[url.pathname])
    : path.resolve(publicDir, `.${url.pathname}`);

  return serveFile(response, publicDir, filename);
}

export function setCommonHeaders(response) {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Access-Control-Allow-Origin', '*');
  response.setHeader(
    'Access-Control-Allow-Headers',
    'content-type, payment-signature, x-sentinel-admin-token'
  );
  response.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
}
