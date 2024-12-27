const express = require('express');
const { sign } = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = 3000;

// Replace these values with your actual Coinbase API key details
const keyName = 'organizations/ed176d77-4864-487e-a402-a9f4fc13e7d2/apiKeys/9d695fa7-185e-4bd7-9142-3b00e1b6baea';
const privateKey = `-----BEGIN EC PRIVATE KEY-----\\nMHcCAQEEIMPlS+v5lWX2PS/jt7L9Uu92LSCQLrfpnXJ+9o0osVXRoAoGCCqGSM49\\nAwEHoUQDQgAE1wZ3gVV22flC+vJSQSOeh1lHrDSzhHWarA+K5fMPJh2vXjRJQSoq\\nCLfzU96TAqKTgS9ttgQOp9vi6isIg2CViQ==\\n-----END EC PRIVATE KEY-----\\n`;

app.get('/generate-jwt', (req, res) => {
  const method = req.query.method || 'GET';
  const path = req.query.path || '/v2/accounts';

  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 120; // Token valid for 2 minutes
  const nonce = crypto.randomBytes(16).toString('hex');
  const uri = `${method} api.coinbase.com${path}`;

  const payload = {
    iss: 'cdp',
    nbf: iat,
    exp: exp,
    sub: keyName,
    uri: uri,
  };

  const token = sign(payload, privateKey, {
    algorithm: 'ES256',
    header: {
      kid: keyName,
      nonce: nonce,
    },
  });

  res.json({ jwt: token });
});

app.listen(port, () => {
  console.log(`JWT generator server running at http://localhost:${port}`);
});
