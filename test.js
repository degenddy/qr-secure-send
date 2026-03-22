const { describe, it } = require('node:test');
const assert = require('node:assert');
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
  it('parses raw QRSEC: prefix', () => {
    const r = extractPayload('QRSEC:abc123');
    assert.strictEqual(r.data, 'abc123'); assert.strictEqual(r.wallet, false);
    assert.strictEqual(r.nonce, null);
  });

  it('parses raw QRSECW: with nonce', () => {
    const r = extractPayload('QRSECW:mynonce123:abc123');
    assert.strictEqual(r.data, 'abc123'); assert.strictEqual(r.wallet, true);
    assert.strictEqual(r.nonce, 'mynonce123');
  });

  it('returns null for QRSECW: without nonce separator', () => {
    assert.strictEqual(extractPayload('QRSECW:nodatahere'), null);
  });

  it('parses URL with QRSEC: in hash', () => {
    const r = extractPayload('https://example.com/page#QRSEC:xyz');
    assert.strictEqual(r.data, 'xyz'); assert.strictEqual(r.wallet, false);
  });

  it('parses URL with QRSECW: in hash', () => {
    const r = extractPayload('https://example.com/page#QRSECW:nonce42:xyz');
    assert.strictEqual(r.data, 'xyz'); assert.strictEqual(r.wallet, true);
    assert.strictEqual(r.nonce, 'nonce42');
  });

  it('returns null for unrelated text', () => {
    assert.strictEqual(extractPayload('hello world'), null);
  });

  it('returns null for URL without valid hash', () => {
    assert.strictEqual(extractPayload('https://example.com/page#other'), null);
  });

  it('returns null for empty string', () => {
    assert.strictEqual(extractPayload(''), null);
  });

  it('handles URL with query params and hash', () => {
    const r = extractPayload('https://example.com?v=1#QRSEC:data');
    assert.strictEqual(r.data, 'data'); assert.strictEqual(r.wallet, false);
  });

  it('generateNonce produces unique 32-char hex strings', () => {
    const n1 = generateNonce();
    const n2 = generateNonce();
    assert.strictEqual(n1.length, 32);
    assert.ok(/^[0-9a-f]{32}$/.test(n1));
    assert.notStrictEqual(n1, n2);
  });
});

// =========================================================================
// buildKeyInput
// =========================================================================

describe('buildKeyInput', () => {
  it('returns passphrase alone when no wallet sig', () => {
    assert.strictEqual(buildKeyInput('mypass', null), 'mypass');
    assert.strictEqual(buildKeyInput('mypass', undefined), 'mypass');
  });

  it('returns passphrase alone when wallet sig is empty string', () => {
    assert.strictEqual(buildKeyInput('mypass', ''), 'mypass');
  });

  it('concatenates passphrase and wallet sig with colon', () => {
    assert.strictEqual(buildKeyInput('mypass', '0xabc'), 'mypass:0xabc');
  });

  it('works with empty passphrase and wallet sig', () => {
    assert.strictEqual(buildKeyInput('', '0xabc'), ':0xabc');
  });

  it('works with empty passphrase and no wallet sig', () => {
    assert.strictEqual(buildKeyInput('', null), '');
  });
});

// =========================================================================
// evaluatePassphraseStrength
// =========================================================================

describe('evaluatePassphraseStrength', () => {
  it('returns none for empty/falsy', () => {
    assert.strictEqual(evaluatePassphraseStrength('').level, 'none');
    assert.strictEqual(evaluatePassphraseStrength(null).level, 'none');
    assert.strictEqual(evaluatePassphraseStrength(undefined).level, 'none');
  });

  it('returns weak for short lowercase', () => {
    const r = evaluatePassphraseStrength('abc');
    assert.strictEqual(r.level, 'weak');
    assert.ok(r.bits < 35);
  });

  it('returns weak for repeated character', () => {
    const r = evaluatePassphraseStrength('aaaaaaaaaaaa');
    assert.strictEqual(r.level, 'weak');
    assert.ok(r.bits <= 10, `Expected very low bits for repeated char, got ${r.bits}`);
  });

  it('returns weak for short numeric (< 6 chars)', () => {
    const r = evaluatePassphraseStrength('12345');
    assert.strictEqual(r.level, 'weak');
    assert.ok(r.bits <= 20);
  });

  it('returns moderate for medium mixed-case + digit', () => {
    const r = evaluatePassphraseStrength('Hello1ab');
    assert.strictEqual(r.level, 'moderate');
  });

  it('returns strong for long mixed with symbols', () => {
    const r = evaluatePassphraseStrength('C0mpl3x!P@ssw0rd#2024');
    assert.strictEqual(r.level, 'strong');
    assert.ok(r.bits >= 50);
  });

  it('weak message mentions rate-limiting', () => {
    const r = evaluatePassphraseStrength('abc');
    assert.ok(r.message.includes('rate-limiting'));
  });

  it('all-lowercase gets 0.7 factor applied', () => {
    const r = evaluatePassphraseStrength('abcdefghij');
    assert.ok(r.bits < 35);
  });
});

// =========================================================================
// Encryption round-trip
// =========================================================================

describe('Encryption round-trip', () => {
  it('encrypts and decrypts with passphrase', async () => {
    const encrypted = await encryptSecret('hello world', 'mypassphrase');
    const decrypted = await decryptSecret(encrypted, 'mypassphrase');
    assert.strictEqual(decrypted, 'hello world');
  });

  it('encrypts and decrypts with empty passphrase', async () => {
    const encrypted = await encryptSecret('secret data', '');
    const decrypted = await decryptSecret(encrypted, '');
    assert.strictEqual(decrypted, 'secret data');
  });

  it('encrypts and decrypts with simulated wallet signature only', async () => {
    const walletSig = '0x' + 'ab'.repeat(65);
    const keyInput = buildKeyInput('', walletSig);
    const encrypted = await encryptSecret('wallet-protected', keyInput);
    const decrypted = await decryptSecret(encrypted, keyInput);
    assert.strictEqual(decrypted, 'wallet-protected');
  });

  it('encrypts and decrypts with passphrase + wallet signature', async () => {
    const walletSig = '0x' + 'cd'.repeat(65);
    const keyInput = buildKeyInput('mypass', walletSig);
    const encrypted = await encryptSecret('dual-protected', keyInput);
    const decrypted = await decryptSecret(encrypted, keyInput);
    assert.strictEqual(decrypted, 'dual-protected');
  });

  it('handles unicode and emoji secrets', async () => {
    const secret = 'Hello \u4e16\u754c \ud83d\udd10\ud83d\udee1\ufe0f';
    const encrypted = await encryptSecret(secret, 'pass');
    const decrypted = await decryptSecret(encrypted, 'pass');
    assert.strictEqual(decrypted, secret);
  });

  it('handles empty secret', async () => {
    const encrypted = await encryptSecret('', 'pass');
    const decrypted = await decryptSecret(encrypted, 'pass');
    assert.strictEqual(decrypted, '');
  });

  it('handles special characters in passphrase', async () => {
    const pass = "p@$$w0rd!#%^&*()_+-=[]{}|;':\",./<>?";
    const encrypted = await encryptSecret('test', pass);
    const decrypted = await decryptSecret(encrypted, pass);
    assert.strictEqual(decrypted, 'test');
  });

  it('handles very long secret (1500+ chars)', async () => {
    const secret = 'A'.repeat(1500);
    const encrypted = await encryptSecret(secret, 'pass');
    const decrypted = await decryptSecret(encrypted, 'pass');
    assert.strictEqual(decrypted, secret);
  });

  it('handles binary-like content', async () => {
    const secret = Array.from({ length: 256 }, (_, i) => String.fromCharCode(i)).join('');
    const encrypted = await encryptSecret(secret, 'pass');
    const decrypted = await decryptSecret(encrypted, 'pass');
    assert.strictEqual(decrypted, secret);
  });
});

// =========================================================================
// Security / attack resistance
// =========================================================================

describe('Security / attack resistance', () => {
  it('wrong passphrase fails decryption', async () => {
    const encrypted = await encryptSecret('secret', 'correct-pass');
    await assert.rejects(() => decryptSecret(encrypted, 'wrong-pass'));
  });

  it('wrong wallet signature fails decryption', async () => {
    const keyEnc = buildKeyInput('pass', '0xaaa');
    const keyDec = buildKeyInput('pass', '0xbbb');
    const encrypted = await encryptSecret('secret', keyEnc);
    await assert.rejects(() => decryptSecret(encrypted, keyDec));
  });

  it('tampered ciphertext fails GCM authentication', async () => {
    const encrypted = await encryptSecret('secret', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    raw[30] ^= 0xff;
    const tampered = btoa(String.fromCharCode(...raw));
    await assert.rejects(() => decryptSecret(tampered, 'pass'));
  });

  it('tampered salt fails', async () => {
    const encrypted = await encryptSecret('secret', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    raw[0] ^= 0xff;
    const tampered = btoa(String.fromCharCode(...raw));
    await assert.rejects(() => decryptSecret(tampered, 'pass'));
  });

  it('tampered IV fails', async () => {
    const encrypted = await encryptSecret('secret', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    raw[16] ^= 0xff;
    const tampered = btoa(String.fromCharCode(...raw));
    await assert.rejects(() => decryptSecret(tampered, 'pass'));
  });

  it('single bit-flip in middle of ciphertext fails', async () => {
    const encrypted = await encryptSecret('secret message here', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    const mid = Math.floor((28 + raw.length) / 2);
    raw[mid] ^= 0x01;
    const tampered = btoa(String.fromCharCode(...raw));
    await assert.rejects(() => decryptSecret(tampered, 'pass'));
  });

  it('truncated ciphertext (salt+iv only) fails', async () => {
    const encrypted = await encryptSecret('secret', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    const truncated = btoa(String.fromCharCode(...raw.slice(0, 28)));
    await assert.rejects(() => decryptSecret(truncated, 'pass'));
  });

  it('empty ciphertext string throws', async () => {
    await assert.rejects(() => decryptSecret('', 'pass'));
  });

  it('same secret + passphrase produces different ciphertext (random salt/IV)', async () => {
    const e1 = await encryptSecret('same', 'same');
    const e2 = await encryptSecret('same', 'same');
    assert.notStrictEqual(e1, e2);
  });

  it('different secrets with same passphrase produce different ciphertext', async () => {
    const e1 = await encryptSecret('secret1', 'pass');
    const e2 = await encryptSecret('secret2', 'pass');
    assert.notStrictEqual(e1, e2);
  });

  it('PBKDF2 key derivation takes meaningful time (>10ms)', async () => {
    const salt = new Uint8Array(16);
    const start = performance.now();
    await deriveKey('test', salt);
    const elapsed = performance.now() - start;
    assert.ok(elapsed > 10, `Key derivation too fast (${elapsed.toFixed(1)}ms) — iterations may be too low`);
  });

  it('similar passphrases produce different keys / fail cross-decrypt', async () => {
    const e1 = await encryptSecret('test', 'password1');
    await assert.rejects(() => decryptSecret(e1, 'password2'));
  });

  it('no plaintext leakage in encrypted output', async () => {
    const secret = 'UNIQUE_PLAINTEXT_MARKER_12345';
    const encrypted = await encryptSecret(secret, 'pass');
    assert.ok(!encrypted.includes('UNIQUE_PLAINTEXT_MARKER'));
    const raw = atob(encrypted);
    assert.ok(!raw.includes('UNIQUE_PLAINTEXT_MARKER'));
  });

  it('timing consistency across encryptions', async () => {
    const times = [];
    for (let i = 0; i < 5; i++) {
      const start = performance.now();
      await encryptSecret('timing test', 'pass');
      times.push(performance.now() - start);
    }
    const min = Math.min(...times);
    const max = Math.max(...times);
    assert.ok(max < min * 5, `Timing variance too high: min=${min.toFixed(1)}ms, max=${max.toFixed(1)}ms`);
  });
});

// =========================================================================
// QR encoding
// =========================================================================

describe('QR encoding', () => {
  it('encodes short text as version 1 (21x21)', () => {
    const { matrix, size } = QRGen.encode('Hi');
    assert.strictEqual(size, 21);
    assert.strictEqual(matrix.length, 21);
    assert.strictEqual(matrix[0].length, 21);
  });

  it('uses higher version for longer text', () => {
    const { size: s1 } = QRGen.encode('A');
    const { size: s2 } = QRGen.encode('A'.repeat(100));
    assert.ok(s2 > s1, `Expected larger QR for longer text: got ${s1} vs ${s2}`);
  });

  it('matrix contains only 1 (black) and 2 (white)', () => {
    const { matrix, size } = QRGen.encode('test data');
    for (let r = 0; r < size; r++)
      for (let c = 0; c < size; c++)
        assert.ok(matrix[r][c] === 1 || matrix[r][c] === 2,
          `Invalid value ${matrix[r][c]} at [${r}][${c}]`);
  });

  it('throws for data exceeding QR capacity', () => {
    assert.throws(() => QRGen.encode('A'.repeat(3000)), /too large/i);
  });

  it('handles version 2+ (alignment patterns)', () => {
    const { size } = QRGen.encode('A'.repeat(25));
    assert.ok(size >= 25);
  });

  it('produces deterministic output for same input', () => {
    const r1 = QRGen.encode('deterministic');
    const r2 = QRGen.encode('deterministic');
    assert.strictEqual(r1.size, r2.size);
    for (let r = 0; r < r1.size; r++)
      for (let c = 0; c < r1.size; c++)
        assert.strictEqual(r1.matrix[r][c], r2.matrix[r][c],
          `Mismatch at [${r}][${c}]`);
  });
});

// =========================================================================
// Payload format integration (full flow)
// =========================================================================

describe('Payload format integration', () => {
  it('full flow: encrypt -> QRSEC: -> extractPayload -> decrypt', async () => {
    const encrypted = await encryptSecret('my secret', 'mypass');
    const payload = 'QRSEC:' + encrypted;
    const extracted = extractPayload(payload);
    assert.strictEqual(extracted.wallet, false);
    const decrypted = await decryptSecret(extracted.data, 'mypass');
    assert.strictEqual(decrypted, 'my secret');
  });

  it('full flow with QRSECW: prefix and nonce', async () => {
    const nonce = generateNonce();
    const keyInput = buildKeyInput('pass', '0xfakewalletsig');
    const encrypted = await encryptSecret('wallet secret', keyInput);
    const payload = 'QRSECW:' + nonce + ':' + encrypted;
    const extracted = extractPayload(payload);
    assert.strictEqual(extracted.wallet, true);
    assert.strictEqual(extracted.nonce, nonce);
    const decrypted = await decryptSecret(extracted.data, keyInput);
    assert.strictEqual(decrypted, 'wallet secret');
  });

  it('URL wrapping with GitHub Pages URL', async () => {
    const encrypted = await encryptSecret('via link', 'pass');
    const url = 'https://degenddy.github.io/qr-secure-send/?v=1.7.2#QRSEC:' + encrypted;
    const extracted = extractPayload(url);
    assert.strictEqual(extracted.wallet, false);
    const decrypted = await decryptSecret(extracted.data, 'pass');
    assert.strictEqual(decrypted, 'via link');
  });

  it('encrypted output is valid base64', async () => {
    const encrypted = await encryptSecret('test', 'pass');
    assert.doesNotThrow(() => atob(encrypted));
    assert.ok(/^[A-Za-z0-9+/]+=*$/.test(encrypted));
  });

  it('encrypted output has correct structure (salt + IV + ciphertext)', async () => {
    const encrypted = await encryptSecret('test', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    // salt(16) + iv(12) + plaintext(4) + GCM-tag(16) = 48
    assert.ok(raw.length >= 44, `Output too short: ${raw.length} bytes`);
    assert.strictEqual(raw.length, 48);
  });
});
