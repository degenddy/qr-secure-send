const { test } = require('node:test');
const assert = require('node:assert/strict');
const { app } = require('./test-support/app');
const a = app();
const data = Buffer.alloc(45, 17).toString('base64');
const nonce = 'ab'.repeat(16);

for (const [prefix, version, wallet] of [
  ['QRSEC', 1, false], ['QRSECW', 1, true], ['QRSEC2', 2, false],
  ['QRSECW2', 2, true], ['QRSECW3', 3, true],
]) test(`protocol: ${prefix} preserves all fields in raw and hosted links`, () => {
  const payload = `${prefix}:${wallet ? nonce + ':' : ''}${data}`;
  for (const text of [payload, 'https://example.test/app?v=2#' + payload]) {
    const result = a.context.extractPayload(text);
    assert.equal(result.version, version); assert.equal(result.wallet, wallet);
    assert.equal(result.nonce, wallet ? nonce : null); assert.equal(result.data, data);
  }
});

const malformed = [
  ['non-string object', {}], ['numeric input', 123], ['null input', null],
  ['undefined input', undefined], ['array input', ['QRSEC2:' + data]],
  ['lowercase protocol', 'qrsec2:' + data], ['future wallet version', 'QRSECW6:' + nonce + ':' + data],
  ['unknown protocol', 'QRSECURE:' + data], ['leading prose', 'secret QRSEC2:' + data],
  ['embedded NUL', 'QRSEC2:' + data.slice(0, 4) + '\0' + data.slice(4)],
  ['HTML envelope', '<b>QRSEC2:' + data + '</b>'],
  ['payload in query only', 'https://example.test/?transfer=QRSEC2:' + data],
  ['percent-encoded protocol', 'https://example.test/#QRSEC2%3A' + data],
  ['base64 internal padding', 'QRSEC2:' + 'A'.repeat(28) + '=' + 'A'.repeat(31)],
  ['base64 excess padding', 'QRSEC2:' + 'A'.repeat(57) + '==='],
  ['base64 internal whitespace', 'QRSEC2:' + 'A'.repeat(30) + ' ' + 'A'.repeat(29)],
  ['base64 invalid alphabet', 'QRSEC2:' + '!'.repeat(60)],
  ['incomplete base64 quartet', 'QRSEC2:' + 'A'.repeat(61)],
  ['missing wallet nonce', 'QRSECW3:' + data],
  ['oversized nonce', 'QRSECW3:' + nonce + 'ab:' + data],
  ['uppercase nonce', 'QRSECW3:' + nonce.toUpperCase() + ':' + data],
  ['nonce signing injection', 'QRSECW3:approve all assets:' + data],
  ['additional wallet separator', 'QRSECW3:' + nonce + '::' + data],
  ['oversized overall input', 'https://example.test/' + 'x'.repeat(8192) + '#QRSEC2:' + data],
];
for (const [name, input] of malformed) test(`protocol rejects ${name}`, () => {
  assert.equal(a.context.extractPayload(input), null);
});
for (const [name, input, valid] of [
  ['below minimum packet', Buffer.alloc(43).toString('base64'), false],
  ['minimum authenticated packet', Buffer.alloc(44).toString('base64'), true],
  ['maximum encoded packet', 'A'.repeat(4096), true],
  ['over maximum encoded packet', 'A'.repeat(4100), false],
]) test(`protocol boundary: ${name}`, () => {
  assert.equal(a.context.extractPayload('QRSEC2:' + input) !== null, valid);
});
test('protocol: deterministic malformed-input corpus never throws or becomes executable data', () => {
  let seed = 0x12345678;
  for (let i = 0; i < 500; i++) {
    let input = '';
    for (let j = 0; j < i % 140; j++) {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      input += String.fromCharCode(seed & 255);
    }
    assert.equal(a.context.extractPayload(input), null);
  }
});

const account = '0x' + '12'.repeat(20), signature = '0x' + 'aB'.repeat(65);
for (const [name, value] of [
  ['empty nonce', ''], ['short nonce', 'ab'.repeat(15)], ['long nonce', 'ab'.repeat(17)],
  ['uppercase nonce', nonce.toUpperCase()], ['nonhex nonce', 'zz'.repeat(16)],
  ['nonce with newline', nonce + '\n'], ['nonce with signing prose', 'Please approve: ' + nonce],
]) test(`wallet rejects ${name} before contacting the provider`, async () => {
  let calls = 0;
  const wallet = app({ ethereum: { request: async () => { calls++; return signature; } } });
  await assert.rejects(wallet.context.getWalletSignature(account, value, 3));
  assert.equal(calls, 0);
});
for (const [name, value] of [
  ['null signature', null], ['object signature', {}], ['missing hex prefix', 'ab'.repeat(65)],
  ['short signature', '0x' + 'ab'.repeat(64)], ['long signature', '0x' + 'ab'.repeat(66)],
  ['nonhex signature', '0x' + 'zz'.repeat(65)], ['signature with trailing newline', signature + '\n'],
]) test(`wallet rejects ${name}`, async () => {
  const wallet = app({ ethereum: { request: async () => value } });
  await assert.rejects(wallet.context.getWalletSignature(account, nonce, 3));
});
for (const version of [0, 6, '3']) test(`wallet rejects unsupported version ${JSON.stringify(version)} without signing`, async () => {
  let calls = 0;
  const wallet = app({ ethereum: { request: async () => { calls++; return signature; } } });
  await assert.rejects(wallet.context.getWalletSignature(account, nonce, version));
  assert.equal(calls, 0);
});
for (const version of [1, 2, 3]) test(`wallet v${version} preserves protocol-specific signature casing and request scope`, async () => {
  let request;
  const wallet = app({ ethereum: { request: async value => { request = value; return signature; } } });
  const result = await wallet.context.getWalletSignature(account, nonce, version);
  assert.equal(result, version === 1 ? signature : signature.toLowerCase());
  assert.equal(request.method, 'personal_sign'); assert.equal(request.params[1], account);
  const message = Buffer.from(request.params[0].slice(2), 'hex').toString();
  if (version === 1) assert.equal(message, 'QR Secure Send: ' + nonce);
  else {
    assert.ok(message.startsWith(`QR Secure Send v${version} — encryption key derivation\n`));
    assert.ok(message.endsWith('Transfer: ' + nonce));
    assert.match(message, /Signing exposes/);
  }
});
test('wallet rejection cannot fall back to password-only encryption', async () => {
  const wallet = app({ ethereum: { request: async ({method}) => {
    if (method === 'eth_requestAccounts') return [account];
    throw new Error('User rejected signature');
  } } });
  await wallet.click('send-wallet-connect-btn');
  wallet.el('send-wallet-toggle').checked = true;
  wallet.el('secret').value = 'must stay protected';
  await wallet.click('generate-btn');
  assert.equal(wallet.el('qr-url').textContent, '');
  assert.match(wallet.el('send-error').textContent, /Could not generate/);
});

test('protocol rejects noncanonical base64 padding aliases', () => {
  const canonical = Buffer.alloc(44).toString('base64');
  const alias = canonical.slice(0, -2) + 'B=';
  assert.deepEqual(Buffer.from(alias, 'base64'), Buffer.from(canonical, 'base64'));
  assert.equal(a.context.extractPayload('QRSEC2:' + alias), null);
});
