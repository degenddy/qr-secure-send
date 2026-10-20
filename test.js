const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('crypto');
const vm = require('vm');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Setup: extract JS from index.html and evaluate in a sandboxed VM context
// ---------------------------------------------------------------------------

const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
let jsCode = scriptMatch[1];

// Expose QRGen.encode for testing
jsCode = jsCode.replace('return { toCanvas };', 'return { toCanvas, encode };');

// Make const/let top-level declarations accessible from the sandbox
jsCode = jsCode.replace('const QRGen =', 'var QRGen =');
jsCode = jsCode.replace('const QRScan =', 'var QRScan =');
jsCode = jsCode.replace(/^  const (BRUTE_FORCE_NOTE|GH_PAGES_URL|METAMASK_DEEP_URL|APP_VERSION|WALLET_SIGN_PREFIX) =/gm,
  '  var $1 =');

// Truncate at UI LOGIC to avoid DOM-dependent code
jsCode = jsCode.split('// UI LOGIC')[0];

const sandbox = {
  crypto: webcrypto,
  TextEncoder,
  TextDecoder,
  btoa,
  atob,
  URL,
  console,
  performance,
  window: { ethereum: undefined },
  document: {
    createElement: () => ({
      getContext: () => ({ fillStyle: '', fillRect: () => {} }),
      width: 0, height: 0, style: {},
    }),
  },
  navigator: {},
  location: { hash: '' },
  requestAnimationFrame: () => {},
  cancelAnimationFrame: () => {},
};

vm.createContext(sandbox);
vm.runInContext(jsCode, sandbox);

const {
  QRGen, encryptSecret, decryptSecret, deriveKey,
  evaluatePassphraseStrength, extractPayload, buildKeyInput,
  WALLET_SIGN_PREFIX, generateNonce,
} = sandbox;

// =========================================================================
// extractPayload
// =========================================================================

describe('extractPayload', () => {
  test('parses raw QRSEC: prefix', () => {
    const r = extractPayload('QRSEC:' + 'A'.repeat(60));
    assert.equal(r.data, 'A'.repeat(60));
    assert.equal(r.wallet, false);
    assert.equal(r.nonce, null);
  });

  test('parses raw QRSECW: with nonce', () => {
    const r = extractPayload('QRSECW:' + 'ab'.repeat(16) + ':' + 'A'.repeat(60));
    assert.equal(r.data, 'A'.repeat(60));
    assert.equal(r.wallet, true);
    assert.equal(r.nonce, 'ab'.repeat(16));
  });

  test('returns null for QRSECW: without nonce separator', () => {
    assert.equal(extractPayload('QRSECW:nodatahere'), null);
  });

  test('parses URL with QRSEC: in hash', () => {
    const r = extractPayload('https://example.com/page#QRSEC:' + 'B'.repeat(60));
    assert.equal(r.data, 'B'.repeat(60));
    assert.equal(r.wallet, false);
  });

  test('parses URL with QRSECW: in hash', () => {
    const r = extractPayload('https://example.com/page#QRSECW:' + 'cd'.repeat(16) + ':' + 'B'.repeat(60));
    assert.equal(r.data, 'B'.repeat(60));
    assert.equal(r.wallet, true);
    assert.equal(r.nonce, 'cd'.repeat(16));
  });

  test('returns null for unrelated text', () => {
    assert.equal(extractPayload('hello world'), null);
  });

  test('returns null for URL without valid hash', () => {
    assert.equal(extractPayload('https://example.com/page#other'), null);
  });

  test('returns null for empty string', () => {
    assert.equal(extractPayload(''), null);
  });

  test('handles URL with query params and hash', () => {
    const r = extractPayload('https://example.com?v=1#QRSEC:' + 'A'.repeat(60));
    assert.equal(r.data, 'A'.repeat(60));
    assert.equal(r.wallet, false);
  });

  test('generateNonce produces unique 32-char hex strings', () => {
    const n1 = generateNonce();
    const n2 = generateNonce();
    assert.equal((n1).length, 32);
    assert.match(n1, /^[0-9a-f]{32}$/);
    assert.notEqual(n1, n2);
  });
});

// =========================================================================
// buildKeyInput
// =========================================================================

describe('buildKeyInput', () => {
  test('returns passphrase alone when no wallet sig', () => {
    assert.equal(buildKeyInput('mypass', null), 'mypass');
    assert.equal(buildKeyInput('mypass', undefined), 'mypass');
  });

  test('returns passphrase alone when wallet sig is empty string', () => {
    assert.equal(buildKeyInput('mypass', ''), 'mypass');
  });

  test('concatenates passphrase and wallet sig with colon', () => {
    assert.equal(buildKeyInput('mypass', '0xabc'), 'mypass:0xabc');
  });

  test('works with empty passphrase and wallet sig', () => {
    assert.equal(buildKeyInput('', '0xabc'), ':0xabc');
  });

  test('works with empty passphrase and no wallet sig', () => {
    assert.equal(buildKeyInput('', null), '');
  });
});

// =========================================================================
// evaluatePassphraseStrength
// =========================================================================

describe('evaluatePassphraseStrength', () => {
  test('supports an omitted password', () => {
    for (const value of ['', null, undefined]) assert.equal(evaluatePassphraseStrength(value).level, 'none');
  });
  test('recognizes common passwords and repeated patterns', () => {
    for (const value of ['Password1!', '1234567890123456', 'aaaaaaaaaaaa1!', 'abcdabcdabcdabcd']) {
      assert.equal(evaluatePassphraseStrength(value).level, 'weak', value);
    }
  });
  test('does not claim entropy for human-chosen strings', () => {
    const result = evaluatePassphraseStrength('Mango orchard beside the violet river');
    assert.equal(result.level, 'strong');
    assert.equal(result.score, 4);
    assert.equal(result.bits, undefined);
    assert.match(result.message, /estimated/);
    assert.match(result.message, /4\/5/);
  });
  test('explains offline guessing', () => {
    assert.match(evaluatePassphraseStrength('abc').message, /no rate-limiting/);
  });
});

// =========================================================================
// Encryption round-trip
// =========================================================================

describe('Encryption round-trip', () => {
  test('encrypts and decrypts with passphrase', async () => {
    const encrypted = await encryptSecret('hello world', 'mypassphrase');
    const decrypted = await decryptSecret(encrypted, 'mypassphrase');
    assert.equal(decrypted, 'hello world');
  });

  test('recovers legacy empty-passphrase encryption', async () => {
    const encrypted = await encryptSecret('secret data', '', 1);
    const decrypted = await decryptSecret(encrypted, '', 1);
    assert.equal(decrypted, 'secret data');
  });

  test('recovers legacy simulated wallet-only encryption', async () => {
    const walletSig = '0x' + 'ab'.repeat(65);
    const keyInput = buildKeyInput('', walletSig);
    const encrypted = await encryptSecret('wallet-protected', keyInput, 1);
    const decrypted = await decryptSecret(encrypted, keyInput, 1);
    assert.equal(decrypted, 'wallet-protected');
  });

  test('encrypts and decrypts with passphrase + wallet signature', async () => {
    const walletSig = '0x' + 'cd'.repeat(65);
    const keyInput = buildKeyInput('mypass', walletSig);
    const encrypted = await encryptSecret('dual-protected', keyInput);
    const decrypted = await decryptSecret(encrypted, keyInput);
    assert.equal(decrypted, 'dual-protected');
  });

  test('handles unicode and emoji secrets', async () => {
    const secret = 'Hello \u4e16\u754c \ud83d\udd10\ud83d\udee1\ufe0f';
    const encrypted = await encryptSecret(secret, 'pass');
    const decrypted = await decryptSecret(encrypted, 'pass');
    assert.equal(decrypted, secret);
  });

  test('handles empty secret', async () => {
    const encrypted = await encryptSecret('', 'pass');
    const decrypted = await decryptSecret(encrypted, 'pass');
    assert.equal(decrypted, '');
  });

  test('handles special characters in passphrase', async () => {
    const pass = "p@$$w0rd!#%^&*()_+-=[]{}|;':\",./<>?";
    const encrypted = await encryptSecret('test', pass);
    const decrypted = await decryptSecret(encrypted, pass);
    assert.equal(decrypted, 'test');
  });

  test('handles very long secret (1500+ chars)', async () => {
    const secret = 'A'.repeat(1500);
    const encrypted = await encryptSecret(secret, 'pass');
    const decrypted = await decryptSecret(encrypted, 'pass');
    assert.equal(decrypted, secret);
  });

  test('handles binary-like content', async () => {
    const secret = Array.from({ length: 256 }, (_, i) => String.fromCharCode(i)).join('');
    const encrypted = await encryptSecret(secret, 'pass');
    const decrypted = await decryptSecret(encrypted, 'pass');
    assert.equal(decrypted, secret);
  });
});

// =========================================================================
// Security / attack resistance
// =========================================================================

describe('Security / attack resistance', () => {
  test('wrong passphrase fails decryption', async () => {
    const encrypted = await encryptSecret('secret', 'correct-pass');
    await assert.rejects(decryptSecret(encrypted, 'wrong-pass'));
  });

  test('wrong wallet signature fails decryption', async () => {
    const keyEnc = buildKeyInput('pass', '0xaaa');
    const keyDec = buildKeyInput('pass', '0xbbb');
    const encrypted = await encryptSecret('secret', keyEnc);
    await assert.rejects(decryptSecret(encrypted, keyDec));
  });

  test('tampered ciphertext fails GCM authentication', async () => {
    const encrypted = await encryptSecret('secret', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    raw[30] ^= 0xff;
    const tampered = btoa(String.fromCharCode(...raw));
    await assert.rejects(decryptSecret(tampered, 'pass'));
  });

  test('tampered salt fails', async () => {
    const encrypted = await encryptSecret('secret', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    raw[0] ^= 0xff;
    const tampered = btoa(String.fromCharCode(...raw));
    await assert.rejects(decryptSecret(tampered, 'pass'));
  });

  test('tampered IV fails', async () => {
    const encrypted = await encryptSecret('secret', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    raw[16] ^= 0xff;
    const tampered = btoa(String.fromCharCode(...raw));
    await assert.rejects(decryptSecret(tampered, 'pass'));
  });

  test('single bit-flip in middle of ciphertext fails', async () => {
    const encrypted = await encryptSecret('secret message here', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    const mid = Math.floor((28 + raw.length) / 2);
    raw[mid] ^= 0x01;
    const tampered = btoa(String.fromCharCode(...raw));
    await assert.rejects(decryptSecret(tampered, 'pass'));
  });

  test('truncated ciphertext (salt+iv only) fails', async () => {
    const encrypted = await encryptSecret('secret', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    const truncated = btoa(String.fromCharCode(...raw.slice(0, 28)));
    await assert.rejects(decryptSecret(truncated, 'pass'));
  });

  test('empty ciphertext string throws', async () => {
    await assert.rejects(decryptSecret('', 'pass'));
  });

  test('same secret + passphrase produces different ciphertext (random salt/IV)', async () => {
    const e1 = await encryptSecret('same', 'same');
    const e2 = await encryptSecret('same', 'same');
    assert.notEqual(e1, e2);
  });

  test('different secrets with same passphrase produce different ciphertext', async () => {
    const e1 = await encryptSecret('secret1', 'pass');
    const e2 = await encryptSecret('secret2', 'pass');
    assert.notEqual(e1, e2);
  });


  test('similar passphrases produce different keys / fail cross-decrypt', async () => {
    const e1 = await encryptSecret('test', 'password1');
    await assert.rejects(decryptSecret(e1, 'password2'));
  });

  test('no plaintext leakage in encrypted output', async () => {
    const secret = 'UNIQUE_PLAINTEXT_MARKER_12345';
    const encrypted = await encryptSecret(secret, 'pass');
    assert.ok(!(encrypted).includes('UNIQUE_PLAINTEXT_MARKER'));
    assert.ok(!(atob(encrypted)).includes('UNIQUE_PLAINTEXT_MARKER'));
  });

});

// =========================================================================
// QR encoding
// =========================================================================

describe('QR encoding', () => {
  test('encodes short text as version 1 (21x21)', () => {
    const { matrix, size } = QRGen.encode('Hi');
    assert.equal(size, 21);
    assert.equal((matrix).length, 21);
    assert.equal((matrix[0]).length, 21);
  });

  test('uses higher version for longer text', () => {
    const { size: s1 } = QRGen.encode('A');
    const { size: s2 } = QRGen.encode('A'.repeat(100));
    assert.ok((s2) > (s1));
  });

  test('matrix contains only 1 (black) and 2 (white)', () => {
    const { matrix, size } = QRGen.encode('test data');
    for (let r = 0; r < size; r++)
      for (let c = 0; c < size; c++)
        assert.ok(([1, 2]).includes(matrix[r][c]));
  });

  test('throws for data exceeding QR capacity', () => {
    assert.throws(() => QRGen.encode('A'.repeat(3000)), /too large/i);
  });

  test('handles version 2+ (alignment patterns)', () => {
    const { size } = QRGen.encode('A'.repeat(25));
    assert.ok((size) >= (25));
  });

  test('produces deterministic output for same input', () => {
    const r1 = QRGen.encode('deterministic');
    const r2 = QRGen.encode('deterministic');
    assert.equal(r1.size, r2.size);
    for (let r = 0; r < r1.size; r++)
      for (let c = 0; c < r1.size; c++)
        assert.equal(r1.matrix[r][c], r2.matrix[r][c]);
  });
});

// =========================================================================
// Payload format integration (full flow)
// =========================================================================

describe('Payload format integration', () => {
  test('full flow: encrypt -> QRSEC: -> extractPayload -> decrypt', async () => {
    const encrypted = await encryptSecret('my secret', 'mypass');
    const payload = 'QRSEC5:' + encrypted;
    const extracted = extractPayload(payload);
    assert.equal(extracted.wallet, false);
    const decrypted = await decryptSecret(extracted.data, 'mypass');
    assert.equal(decrypted, 'my secret');
  });

  test('full flow with QRSECW: prefix and nonce', async () => {
    const nonce = generateNonce();
    const keyInput = buildKeyInput('pass', '0xfakewalletsig');
    const encrypted = await encryptSecret('wallet secret', keyInput);
    const payload = 'QRSECW5:' + nonce + ':' + encrypted;
    const extracted = extractPayload(payload);
    assert.equal(extracted.wallet, true);
    assert.equal(extracted.nonce, nonce);
    const decrypted = await decryptSecret(extracted.data, keyInput);
    assert.equal(decrypted, 'wallet secret');
  });

  test('URL wrapping with GitHub Pages URL', async () => {
    const encrypted = await encryptSecret('via link', 'pass');
    const url = 'https://degenddy.github.io/qr-secure-send/?v=2.4.0#QRSEC5:' + encrypted;
    const extracted = extractPayload(url);
    assert.equal(extracted.wallet, false);
    const decrypted = await decryptSecret(extracted.data, 'pass');
    assert.equal(decrypted, 'via link');
  });

  test('encrypted output is valid base64', async () => {
    const encrypted = await encryptSecret('test', 'pass');
    assert.doesNotThrow(() => atob(encrypted));
    assert.match(encrypted, /^[A-Za-z0-9+/]+=*$/);
  });

  test('encrypted output has correct structure (salt + IV + ciphertext)', async () => {
    const encrypted = await encryptSecret('test', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    // salt(16) + iv(12) + v5 header(5) + padded capacity(128) + GCM-tag(16) = 177
    assert.ok((raw.length) >= (44));
    assert.equal(raw.length, 177);
  });
});
