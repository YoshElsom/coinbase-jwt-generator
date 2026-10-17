'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { generateCoinbaseJWT } = require('./generate_jwt');
const { createServer } = require('./server');
test('missing credentials fail safely', () => {
  assert.throws(() => generateCoinbaseJWT('GET', '/v2/accounts', {}), /not configured/);
});
test('trading and arbitrary request signing are denied', () => {
  for (const [method, path] of [['POST','/api/v3/brokerage/orders'],
    ['DELETE','/v2/accounts'],['GET','https://evil.invalid'],['GET','/v2/accounts?x=1']]) {
    assert.throws(() => generateCoinbaseJWT(method,path,{}), /read-only/);
  }
});
test('invalid key material never leaks through errors', () => {
  const env = { COINBASE_API_KEY_NAME:'organizations/test/apiKeys/test',
    COINBASE_API_PRIVATE_KEY:'sentinel-not-a-key' };
  assert.throws(() => generateCoinbaseJWT('GET','/v2/accounts',env),
    { message:'A valid ES256 P-256 private key is required' });
});
test('ephemeral P-256 signature, request binding and expiry verify', () => {
  const {privateKey, publicKey} = crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const env = {COINBASE_API_KEY_NAME:'organizations/test/apiKeys/test',
    COINBASE_API_PRIVATE_KEY:privateKey.export({type:'pkcs8',format:'pem'})};
  const token = generateCoinbaseJWT('GET','/v2/accounts',env);
  const [h,p,s] = token.split('.');
  const header=JSON.parse(Buffer.from(h,'base64url'));
  const payload=JSON.parse(Buffer.from(p,'base64url'));
  assert.equal(header.alg,'ES256');
  assert.equal(payload.uri,'GET api.coinbase.com/v2/accounts');
  assert.equal(payload.exp-payload.nbf,120);
  assert.equal(payload.sub,env.COINBASE_API_KEY_NAME);
  assert.equal(Buffer.from(s,'base64url').length,64);
  assert(crypto.verify('sha256',Buffer.from(h+'.'+p),
    {key:publicKey,dsaEncoding:'ieee-p1363'},Buffer.from(s,'base64url')));
  assert.notEqual(token,generateCoinbaseJWT('GET','/v2/accounts',env));
  assert(generateCoinbaseJWT('GET','/v2/accounts',
    {...env,COINBASE_API_PRIVATE_KEY:env.COINBASE_API_PRIVATE_KEY.replace(/\n/g,'\\n')}));
});
test('wrong curve rejected', () => {
  const {privateKey}=crypto.generateKeyPairSync('ec',{namedCurve:'secp384r1'});
  assert.throws(()=>generateCoinbaseJWT('GET','/v2/accounts',{
    COINBASE_API_KEY_NAME:'organizations/test/apiKeys/test',
    COINBASE_API_PRIVATE_KEY:privateKey.export({type:'pkcs8',format:'pem'})}),/P-256/);
});
test('HTTP cannot mint tokens and ignores credentials', async () => {
  const server=createServer();
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    const base='http://127.0.0.1:'+server.address().port;
    for(const method of ['GET','POST']) {
      const res=await fetch(base+'/generate-jwt?method=POST&path=/api/v3/brokerage/orders',{method});
      assert.equal(res.status,410);
      assert.equal(res.headers.get('cache-control'),'no-store');
      assert(!('jwt' in await res.json()));
    }
    assert.equal((await fetch(base+'/healthz')).status,200);
    assert.equal((await fetch(base+'/unknown')).status,404);
  } finally { await new Promise(resolve=>server.close(resolve)); }
});
