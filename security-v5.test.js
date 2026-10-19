const { test } = require('node:test');
const assert = require('node:assert/strict');
const { pbkdf2Sync, createCipheriv, createDecipheriv } = require('node:crypto');
const { app } = require('./test-support/app');
const a = app();
const password = 'café';
const signature = '0x' + '11'.repeat(32) + '22'.repeat(32) + '1b';
const nonce = 'ab'.repeat(16);

// Independent OpenSSL implementation: do not call application format helpers.
function seal(plain, version = 5, pass = password) {
  const salt = Buffer.alloc(16, 7), iv = Buffer.alloc(12, 9);
  const cipher = createCipheriv('aes-256-gcm', pbkdf2Sync(pass.normalize('NFC'), salt, 600000, 32, 'sha256'), iv);
  cipher.setAAD(Buffer.from('QR Secure Send v' + version));
  return Buffer.concat([salt, iv, cipher.update(plain), cipher.final(), cipher.getAuthTag()]).toString('base64');
}
function open(data) {
  const packet = Buffer.from(data, 'base64');
  const cipher = createDecipheriv('aes-256-gcm', pbkdf2Sync(password, packet.subarray(0, 16), 600000, 32, 'sha256'), packet.subarray(16, 28));
  cipher.setAAD(Buffer.from('QR Secure Send v5')); cipher.setAuthTag(packet.subarray(-16));
  return Buffer.concat([cipher.update(packet.subarray(28, -16)), cipher.final()]);
}
function envelope(text, mode, capacity) {
  const bytes = Buffer.from(text), out = Buffer.alloc(5 + capacity, 0xa5);
  out[0] = mode; out.writeUInt32BE(bytes.length, 1); bytes.copy(out, 5); return out;
}
for (const [length, bucket] of [[0,128],[1,128],[127,128],[128,128],[129,256],[255,256],[256,256],[257,512],[511,512],[512,512],[513,1024],[1023,1024],[1024,1024],[1025,1536],[1500,1536]]) {
  for (const padded of [false, true]) test(`v5 ${padded ? 'padded' : 'compact'} ${length}-byte boundary round trips`, async () => {
    const text = 'x'.repeat(length), data = await a.context.encryptSecret(text, password, 5, padded);
    assert.equal(Buffer.from(data, 'base64').length, 49 + (padded ? bucket : length));
    assert.equal(await a.context.decryptSecret(data, 'cafe\u0301', 5), text);
  });
}
for (const padded of [false, true]) test(`v5 ${padded ? 'padded' : 'compact'} interoperates with independent OpenSSL`, async () => {
  const text = '\ufeffFirst line\nסוד\t🔐\0';
  const capacity = padded ? 128 : Buffer.byteLength(text);
  assert.equal(await a.context.decryptSecret(seal(envelope(text, Number(padded), capacity)), 'cafe\u0301', 5), text);
  const decoded = open(await a.context.encryptSecret(text, password, 5, padded));
  assert.equal(decoded[0], Number(padded)); assert.equal(decoded.length, 5 + capacity);
  assert.equal(decoded.readUInt32BE(1), Buffer.byteLength(text));
  assert.equal(decoded.subarray(5, 5 + decoded.readUInt32BE(1)).toString(), text);
});
test('v5 buckets count UTF-8 bytes rather than characters or password length', async () => {
  const text = '字'.repeat(43);
  const data = await a.context.encryptSecret(text, 'x'.repeat(1024), 5, true);
  assert.equal(Buffer.from(data, 'base64').length, 49 + 256);
  assert.equal(await a.context.decryptSecret(data, 'x'.repeat(1024), 5), text);
});
for (const [label, make] of [
  ['unknown mode', () => envelope('x', 2, 128)],
  ['compact trailing padding', () => envelope('x', 0, 128)],
  ['compact truncated content', () => {const x = envelope('x', 0, 1); x.writeUInt32BE(2, 1); return x;}],
  ['padded non-bucket size', () => envelope('x', 1, 129)],
  ['padded non-minimal bucket', () => envelope('x', 1, 256)],
  ['oversized hidden length', () => {const x = envelope('x', 1, 1536); x.writeUInt32BE(1501, 1); return x;}],
  ['invalid UTF-8', () => {const x = envelope('x', 1, 128); x[5] = 0xff; return x;}],
]) test(`v5 rejects authenticated ${label}`, async () => {
  await assert.rejects(a.context.decryptSecret(seal(make()), password, 5));
});
test('v5 rejects oversized inputs and non-boolean padding before deriving a key', async () => {
  const local = app(); local.context.deriveKey = () => {throw new Error('key derivation must not run');};
  await assert.rejects(local.context.encryptSecret('字'.repeat(501), '', 5), /1500/);
  await assert.rejects(local.context.encryptSecret('x', '', 5, 'false'), /padding option/);
});
test('v5 parser enforces packet bounds before key derivation', async () => {
  const local = app(); local.context.deriveKey = () => {throw new Error('key derivation must not run');};
  for (const size of [44, 48, 1586, 3072]) {
    const data = Buffer.alloc(size).toString('base64');
    assert.equal(local.context.extractPayload('QRSEC5:' + data), null);
    await assert.rejects(local.context.decryptSecret(data, '', 5), /Invalid encrypted payload/);
  }
  for (const size of [49, 177, 305, 561, 1073, 1549, 1585]) {
    const data = Buffer.alloc(size).toString('base64');
    for (const prefix of ['QRSEC5:', 'QRSECW5:' + nonce + ':']) assert.equal(local.context.extractPayload(prefix + data).version, 5);
  }
});
test('v5 authenticates its version and detects altered ciphertext', async () => {
  const data = seal(envelope('x', 1, 128));
  for (const version of [1, 2, 3, 4]) await assert.rejects(a.context.decryptSecret(data, password, version));
  const changed = Buffer.from(data, 'base64'); changed[28] ^= 1;
  await assert.rejects(a.context.decryptSecret(changed.toString('base64'), password, 5));
});
for (const version of [1,2,3,4,5]) test(`leading U+FEFF survives v${version} decryption`, async () => {
  const text = '\ufeffDUMMY_SECRET';
  const data = await a.context.encryptSecret(text, password, version);
  assert.equal(await a.context.decryptSecret(data, password, version), text);
});
test('v4 wallet recovery still works in the receiver UI', async () => {
  const packet = await a.context.encryptSecret('LEGACY_V4', ':' + signature, 4);
  const receiver = app({hash: '#QRSECW4:' + nonce + ':' + packet});
  receiver.el('recv-recovery-key').value = a.context.walletRecoveryKey(nonce, signature, 4);
  await receiver.click('decrypt-btn'); assert.equal(receiver.el('recv-value').textContent, 'LEGACY_V4');
});
test('recovery keys cannot cross protocol versions', () => {
  for (const version of [4,5]) {
    const key = a.context.walletRecoveryKey(nonce, signature, version);
    assert.equal(a.context.signatureFromRecoveryKey(key, nonce, version), signature);
    assert.throws(() => a.context.signatureFromRecoveryKey(key, nonce, version === 4 ? 5 : 4));
  }
});
for (const [label, change] of [
  ['typed password', async x => {x.el('send-passphrase').value = 'new'; x.el('send-passphrase').handlers.input();}],
  ['random password', x => x.click('password-generate-btn')],
  ['new secret', async x => {x.el('secret').value = 'new'; x.el('secret').handlers.input();}],
  ['wallet toggle', async x => {x.el('send-wallet-toggle').checked = true; x.el('send-wallet-toggle').handlers.change({target:{checked:true}});}],
  ['padding toggle', async x => {x.el('conceal-length').checked = false; x.el('conceal-length').handlers.change();}],
]) test(`changing ${label} invalidates the published QR and recovery key`, async () => {
  const local = app(); local.el('secret').value = 'dummy'; await local.click('generate-btn');
  assert.ok(local.el('qr-url').textContent);
  local.el('wallet-recovery-key').textContent = 'dummy stale key';
  await change(local);
  assert.equal(local.el('qr-url').textContent, ''); assert.equal(local.el('qr-output').children.length, 0);
  assert.equal(local.el('qr-info').style.display, 'none'); assert.equal(local.el('wallet-recovery-key').textContent, '');
});
for (const field of ['secret', 'send-passphrase', 'send-wallet-toggle', 'conceal-length']) test(`silent change to ${field} while encrypting cannot publish stale output`, async () => {
  const local = app(); let finish;
  local.context.encryptSecret = () => new Promise(resolve => {finish = resolve;});
  local.el('secret').value = 'original'; const pending = local.click('generate-btn');
  assert.equal(local.el('secret').readOnly, true); assert.equal(local.el('send-passphrase').readOnly, true);
  assert.equal(local.el('send-wallet-toggle').disabled, true); assert.equal(local.el('conceal-length').disabled, true);
  if (field === 'secret' || field === 'send-passphrase') local.el(field).value = 'changed';
  else local.el(field).checked = !local.el(field).checked;
  finish('should never be published'); await pending;
  assert.equal(local.el('qr-url').textContent, ''); assert.match(local.el('send-error').textContent, /Inputs changed/);
  assert.equal(local.el('secret').readOnly, false); assert.equal(local.el('generate-btn').disabled, false);
});
test('padding is enabled on load and restored on reset', async () => {
  const local = app(); assert.equal(local.el('conceal-length').checked, true);
  local.el('conceal-length').checked = false; await local.click('clear-btn');
  assert.equal(local.el('conceal-length').checked, true);
});
