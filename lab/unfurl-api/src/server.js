'use strict';

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { fetch } = require('undici');

const port = Number(process.env.N2S_PORT || 3000);
const publicDir = path.join(__dirname, 'public');
const indexHtml = fs.readFileSync(path.join(publicDir, 'index.html'));
const styleCss = fs.readFileSync(path.join(publicDir, 'style.css'));
const allowedHosts = new Set(['127.0.0.1', 'localhost', 'host.docker.internal']);
const MAX_BODY = 16 * 1024;

function send(response, status, type, body) {
  response.writeHead(status, {
    'Content-Type': type,
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  response.end(body);
}

function sendJson(response, status, value) {
  send(response, status, 'application/json; charset=utf-8', JSON.stringify(value));
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        const error = new Error('request body too large');
        error.status = 413;
        reject(error);
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch {
        const error = new Error('invalid JSON');
        error.status = 400;
        reject(error);
      }
    });
    request.on('error', reject);
  });
}

function decodeEntities(value) {
  return value
    .replaceAll('&amp;', '&')
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'");
}

function metaContent(html, property) {
  const pattern = new RegExp(
    `<meta[^>]+(?:property|name)=["']${property}["'][^>]+content=["']([^"']*)["']`,
    'i',
  );
  const reverse = new RegExp(
    `<meta[^>]+content=["']([^"']*)["'][^>]+(?:property|name)=["']${property}["']`,
    'i',
  );
  const match = html.match(pattern) || html.match(reverse);
  return match ? decodeEntities(match[1]) : null;
}

function titleOf(html) {
  const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? decodeEntities(match[1].trim()) : null;
}

function errorCodes(error) {
  const codes = [];
  for (let current = error; current; current = current.cause) {
    if (current.code && !codes.includes(current.code)) codes.push(current.code);
  }
  return codes;
}

async function unfurl(target) {
  const upstream = await fetch(target, {
    redirect: 'follow',
    headers: { 'User-Agent': 'Node2Shell-Unfurl/1.0' },
  });
  const body = Buffer.from(await upstream.arrayBuffer());
  const html = body.toString('utf8');
  return {
    url: target.href,
    final_url: upstream.url,
    status: upstream.status,
    content_type: upstream.headers.get('content-type') || null,
    bytes: body.length,
    title: metaContent(html, 'og:title') || titleOf(html),
    description: metaContent(html, 'og:description') || metaContent(html, 'description'),
    image: metaContent(html, 'og:image'),
    site_name: metaContent(html, 'og:site_name'),
  };
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://lab');
  if (url.pathname === '/health') return send(response, 200, 'text/plain; charset=utf-8', 'PONG\n');
  if (url.pathname === '/') return send(response, 200, 'text/html; charset=utf-8', indexHtml);
  if (url.pathname === '/assets/style.css') return send(response, 200, 'text/css; charset=utf-8', styleCss);
  if (url.pathname !== '/api/unfurl') {
    return sendJson(response, 404, { error: 'not_found' });
  }
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return sendJson(response, 405, { error: 'method_not_allowed' });
  }

  try {
    const body = await readJson(request);
    let target;
    try {
      target = new URL(body.url);
    } catch {
      return sendJson(response, 400, { error: 'invalid_url', message: 'A URL is required.' });
    }
    if (!allowedHosts.has(target.hostname) || !['http:', 'https:'].includes(target.protocol)) {
      return sendJson(response, 400, {
        error: 'url_not_allowed',
        message: 'Only loopback and host-gateway URLs are allowed in this lab.',
      });
    }

    // SINK: consuming the upstream body drives undici's Brotli decoding path.
    const preview = await unfurl(target);
    return sendJson(response, 200, preview);
  } catch (error) {
    const codes = errorCodes(error);
    console.error(
      `unfurl failed name=${error.name} codes=${codes.join(',') || 'none'} message=${error.message}`,
    );
    return sendJson(response, error.status || 502, {
      error: codes[0] || error.name || 'unfurl_failed',
      codes,
      message: error.message,
    });
  }
});

server.listen(port, '0.0.0.0');
