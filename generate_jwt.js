'use strict';
const crypto = require('node:crypto');

// Server-internal helper only. No HTTP endpoint or CLI ever returns a JWT.
const READ_PATHS = new Set([
  '/v2/accounts',
  '/api/v3/brokerage/accounts',
  '/api/v3/brokerage/orders/historical/batch',
  '/api/v3/brokerage/orders/historical/fills',
  '/api/v3/brokerage/products',
]);
function generateCoinbaseJWT(method, path, env = process.env) {
  if (method !== 'GET' || !READ_PATHS.has(path)) {
    throw new Error('Only approved read-only Coinbase requests are supported');
  }
  const keyName = env.COINBASE_API_KEY_NAME;
  const pem = env.COINBASE_API_PRIVATE_KEY;
  if (!keyName || !pem) throw new Error('Coinbase credentials are not configured');
  if (!/^organizations\/[A-Za-z0-9-]+\/apiKeys\/[A-Za-z0-9-]+$/.test(keyName)) {
    throw new Error('Invalid Coinbase key name');
  }
  let key;
  try {
    key = crypto.createPrivateKey(pem.replace(/\\n/g, '\n'));
    if (key.asymmetricKeyType !== 'ec' ||
        key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new Error();
  } catch {
    throw new Error('A valid ES256 P-256 private key is required');
  }
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'ES256', typ: 'JWT', kid: keyName,
    nonce: crypto.randomBytes(16).toString('hex') };
  const payload = { iss: 'cdp', sub: keyName, nbf: now, exp: now + 120,
    uri: `GET api.coinbase.com${path}` };
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const message = `${encode(header)}.${encode(payload)}`;
  const signature = crypto.sign('sha256', Buffer.from(message),
    { key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  return `${message}.${signature}`;
}
module.exports = { generateCoinbaseJWT };
if (require.main === module) {
  console.error('CLI token output is disabled. Use the helper only inside a trusted backend.');
  process.exitCode = 1;
}
