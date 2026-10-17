'use strict';
const http = require('node:http');

// Containment release: public token minting is permanently disabled.
// This process never loads Coinbase credentials or contacts Coinbase.
function createServer() {
  return http.createServer((req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const path = new URL(req.url, 'http://localhost').pathname;
    if (req.method === 'GET' && path === '/healthz') {
      res.writeHead(200);
      res.end(JSON.stringify({ status: 'ok', mode: 'token-endpoint-disabled' }));
      return;
    }
    res.writeHead(path === '/generate-jwt' ? 410 : 404);
    res.end(JSON.stringify({ error: path === '/generate-jwt'
      ? 'Token generation endpoint disabled' : 'Not found' }));
  });
}
module.exports = { createServer };
if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error('Invalid PORT configuration');
    process.exitCode = 1;
  } else {
    createServer().listen(port, process.env.HOST || '127.0.0.1', () => {
      console.log('Containment server started; token endpoint disabled');
    });
  }
}
