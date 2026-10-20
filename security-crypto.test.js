const { test } = require('node:test');
const assert = require('node:assert/strict');
const { pbkdf2Sync, createCipheriv, createDecipheriv, webcrypto } = require('node:crypto');
const { app } = require('./test-support/app');
const a = app();
// Test-only deterministic vectors built independently with Node/OpenSSL.
const pass = 'fixture password: independent oracle';
const plaintext = 'Independent authenticated fixture 🔐';
const salt = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
const iv = Buffer.from('101112131415161718191a1b', 'hex');
function fixture(version, text = plaintext) {
  const key = pbkdf2Sync(pass, salt, version === 1 ? 310000 : 600000, 32, 'sha256');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  if (version > 1) cipher.setAAD(Buffer.from('QR Secure Send v' + version));
  const ciphertext = Buffer.concat([cipher.update(text), cipher.final()]);
  return Buffer.concat([salt, iv, ciphertext, cipher.getAuthTag()]);
}
const vectors = new Map([1, 2, 3].map(version => [version, fixture(version)]));
for (const version of [1, 2, 3]) {
  test(`crypto v${version}: decrypts independent OpenSSL vector`, async () => {
    assert.equal(await a.context.decryptSecret(vectors.get(version).toString('base64'), pass, version), plaintext);
  });
  test(`crypto v${version}: generated output decrypts independently with exact parameters`, async () => {
    const packed = Buffer.from(await a.context.encryptSecret(plaintext, pass, version), 'base64');
    const key = pbkdf2Sync(pass, packed.subarray(0, 16), version === 1 ? 310000 : 600000, 32, 'sha256');
    const cipher = createDecipheriv('aes-256-gcm', key, packed.subarray(16, 28));
    if (version > 1) cipher.setAAD(Buffer.from('QR Secure Send v' + version));
    cipher.setAuthTag(packed.subarray(-16));
    assert.equal(Buffer.concat([cipher.update(packed.subarray(28, -16)), cipher.final()]).toString(), plaintext);
  });
  for (const [part, offset] of [['salt', 15], ['IV', 27], ['ciphertext', 28], ['authentication tag', -1]]) {
    test(`crypto v${version}: rejects altered ${part} in independent vector`, async () => {
      const packet = Buffer.from(vectors.get(version));
      packet[offset < 0 ? packet.length + offset : offset] ^= 0x80;
      await assert.rejects(a.context.decryptSecret(packet.toString('base64'), pass, version));
    });
  }
  test(`crypto v${version}: rejects truncated authentication tag`, async () => {
    await assert.rejects(a.context.decryptSecret(vectors.get(version).subarray(0, -1).toString('base64'), pass, version));
  });
  test(`crypto v${version}: rejects appended bytes`, async () => {
    const packet = Buffer.concat([vectors.get(version), Buffer.from([0])]);
    await assert.rejects(a.context.decryptSecret(packet.toString('base64'), pass, version));
  });
  test(`crypto v${version}: derived AES key cannot be exported`, async () => {
    const key = await a.context.deriveKey(pass, salt, version);
    assert.equal(key.extractable, false); assert.equal(key.algorithm.length, 256);
    assert.deepEqual([...key.usages].sort(), ['decrypt', 'encrypt']);
    await assert.rejects(webcrypto.subtle.exportKey('raw', key));
  });
  for (const other of [1, 2, 3].filter(x => x !== version)) test(`crypto rejects v${version} packet relabelled as v${other}`, async () => {
    await assert.rejects(a.context.decryptSecret(vectors.get(version).toString('base64'), pass, other));
  });
}
for (const [name, wrong] of [
  ['trailing space', pass + ' '], ['leading space', ' ' + pass], ['case change', pass.toUpperCase()],
  ['omitted password', ''], ['embedded NUL', pass.slice(0, 8) + '\0' + pass.slice(8)],
]) test(`crypto password identity: ${name} cannot unlock the independent vector`, async () => {
  await assert.rejects(a.context.decryptSecret(vectors.get(2).toString('base64'), wrong, 2));
});
for (const [name, secret, password] of [
  ['Hebrew and emoji', 'סוד 🔐', 'סיסמה 🔑'], ['line breaks and tabs', 'a\r\nb\tc\n', 'a\nb'],
  ['combining marks', 'e\u0301', 'e\u0301'], ['embedded NUL', 'a\0b', 'a\0b'],
]) test(`crypto preserves ${name} byte-for-byte`, async () => {
  const packet = await a.context.encryptSecret(secret, password, 3);
  assert.equal(await a.context.decryptSecret(packet, password, 3), secret);
});
test('legacy v2 preserves its original unnormalized password bytes', async () => {
  const packet = await a.context.encryptSecret('unicode identity', 'é', 2);
  await assert.rejects(a.context.decryptSecret(packet, 'e\u0301', 2));
});
test('cryptographic randomness supplies salt and IV separately', async () => {
  const lengths = [];
  const instrumented = app({ prepare(context) {
    context.crypto = { subtle: webcrypto.subtle, getRandomValues(bytes) {
      lengths.push(bytes.length); return webcrypto.getRandomValues(bytes);
    } };
  } });
  await instrumented.context.encryptSecret('randomness', pass);
  assert.deepEqual(lengths, [128 - Buffer.byteLength('randomness'), 16, 12]);
});
test('random password generation uses Web Crypto and includes all four character classes', () => {
  const lengths = [];
  const instrumented = app({ prepare(context) {
    context.crypto = { subtle: webcrypto.subtle, getRandomValues(bytes) {
      lengths.push(bytes.length); return webcrypto.getRandomValues(bytes);
    } };
  } });
  for (let i=0;i<100;i++) {
    const password = instrumented.context.generatePassword();
    assert.match(password, /^[!-~]{32}$/);
    for (const pattern of [/[a-z]/,/[A-Z]/,/[0-9]/,/[^A-Za-z0-9]/]) assert.match(password,pattern);
  }
  assert.ok(lengths.length >= 100); assert.ok(lengths.every(length=>length===64));
});
test('password sampling rejects out-of-range bytes and candidates missing a character class', () => {
  let draws=0;
  const a=app({prepare(context) {
    context.crypto={subtle:webcrypto.subtle,getRandomValues(bytes) {
      draws++;
      // First reject an entire buffer; then reject an all-symbol candidate.
      if(draws===1)return bytes.fill(255);
      if(draws===2)return bytes.fill(0);
      for(let i=0;i<bytes.length;i++)bytes[i]=[0,16,32,64][i%4];
      return bytes;
    }};
  }});
  assert.equal(a.context.generatePassword(),'!1Aa'.repeat(8));
  assert.equal(draws,3);
});
test('password generation fails rather than falling back when Web Crypto fails', () => {
  const a=app({prepare(context) {
    context.crypto={subtle:webcrypto.subtle,getRandomValues(){throw new Error('RNG unavailable');}};
  }});
  assert.throws(()=>a.context.generatePassword(),/RNG unavailable/);
});
test('random nonce generation requests exactly 16 bytes from Web Crypto', () => {
  const lengths = [];
  const instrumented = app({ prepare(context) {
    context.crypto = { subtle: webcrypto.subtle, getRandomValues(bytes) {
      lengths.push(bytes.length); return webcrypto.getRandomValues(bytes);
    } };
  } });
  assert.match(instrumented.context.generateNonce(), /^[0-9a-f]{32}$/);
  assert.deepEqual(lengths, [16]);
});
