#!/usr/bin/env node
'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

function createServer() {
  const html = fs.readFileSync(path.join(__dirname, 'index.html'));
  const policy = html.toString().match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)[1];
  return http.createServer((req, res) => {
    const headers = {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': policy + "; frame-ancestors 'none'",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'camera=(self), microphone=(), geolocation=()',
    };
    // Limit both the listener and accepted Host values, including DNS rebinding names.
    if (!/^(localhost|127\.0\.0\.1)(:\d+)?$/.test(req.headers.host || '')) {
      res.writeHead(403, headers); res.end('Forbidden host'); return;
    }
    if (!['GET', 'HEAD'].includes(req.method)) {
      res.writeHead(405, { ...headers, Allow: 'GET, HEAD' }); res.end(); return;
    }
    const pathname = req.url.split('?')[0];
    if (pathname !== '/' && pathname !== '/index.html') {
      res.writeHead(404, headers); res.end(); return;
    }
    res.writeHead(200, headers);
    res.end(req.method === 'HEAD' ? undefined : html);
  });
}

if (require.main === module) {
  const port = Number(process.argv[2] || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error('Port must be an integer from 1 to 65535.');
    process.exitCode = 1;
  } else {
    const server = createServer();
    server.on('error', error => { console.error(error.message); process.exitCode = 1; });
    server.listen(port, '127.0.0.1', () => console.log(`QR Secure Send running at http://127.0.0.1:${port}`));
  }
}
module.exports = { createServer };
