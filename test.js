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
    const r = extractPayload('QRSEC:abc123');
    expect(r.data).toBe('abc123');
    expect(r.wallet).toBe(false);
    expect(r.nonce).toBeNull();
  });

  test('parses raw QRSECW: with nonce', () => {
    const r = extractPayload('QRSECW:mynonce123:abc123');
    expect(r.data).toBe('abc123');
    expect(r.wallet).toBe(true);
    expect(r.nonce).toBe('mynonce123');
  });

  test('returns null for QRSECW: without nonce separator', () => {
    expect(extractPayload('QRSECW:nodatahere')).toBeNull();
  });

  test('parses URL with QRSEC: in hash', () => {
    const r = extractPayload('https://example.com/page#QRSEC:xyz');
    expect(r.data).toBe('xyz');
    expect(r.wallet).toBe(false);
  });

  test('parses URL with QRSECW: in hash', () => {
    const r = extractPayload('https://example.com/page#QRSECW:nonce42:xyz');
    expect(r.data).toBe('xyz');
    expect(r.wallet).toBe(true);
    expect(r.nonce).toBe('nonce42');
  });

  test('returns null for unrelated text', () => {
    expect(extractPayload('hello world')).toBeNull();
  });

  test('returns null for URL without valid hash', () => {
    expect(extractPayload('https://example.com/page#other')).toBeNull();
  });

  test('returns null for empty string', () => {
    expect(extractPayload('')).toBeNull();
  });

  test('handles URL with query params and hash', () => {
    const r = extractPayload('https://example.com?v=1#QRSEC:data');
    expect(r.data).toBe('data');
    expect(r.wallet).toBe(false);
  });

  test('generateNonce produces unique 32-char hex strings', () => {
    const n1 = generateNonce();
    const n2 = generateNonce();
    expect(n1).toHaveLength(32);
    expect(n1).toMatch(/^[0-9a-f]{32}$/);
    expect(n1).not.toBe(n2);
  });
});

// =========================================================================
// buildKeyInput
// =========================================================================

describe('buildKeyInput', () => {
  test('returns passphrase alone when no wallet sig', () => {
    expect(buildKeyInput('mypass', null)).toBe('mypass');
    expect(buildKeyInput('mypass', undefined)).toBe('mypass');
  });

  test('returns passphrase alone when wallet sig is empty string', () => {
    expect(buildKeyInput('mypass', '')).toBe('mypass');
  });

  test('concatenates passphrase and wallet sig with colon', () => {
    expect(buildKeyInput('mypass', '0xabc')).toBe('mypass:0xabc');
  });

  test('works with empty passphrase and wallet sig', () => {
    expect(buildKeyInput('', '0xabc')).toBe(':0xabc');
  });

  test('works with empty passphrase and no wallet sig', () => {
    expect(buildKeyInput('', null)).toBe('');
  });
});

// =========================================================================
// evaluatePassphraseStrength
// =========================================================================

describe('evaluatePassphraseStrength', () => {
  test('returns none for empty/falsy', () => {
    expect(evaluatePassphraseStrength('').level).toBe('none');
    expect(evaluatePassphraseStrength(null).level).toBe('none');
    expect(evaluatePassphraseStrength(undefined).level).toBe('none');
  });

  test('returns weak for short lowercase', () => {
    const r = evaluatePassphraseStrength('abc');
    expect(r.level).toBe('weak');
    expect(r.bits).toBeLessThan(35);
  });

  test('returns weak for repeated character', () => {
    const r = evaluatePassphraseStrength('aaaaaaaaaaaa');
    expect(r.level).toBe('weak');
    expect(r.bits).toBeLessThanOrEqual(10);
  });

  test('returns weak for short numeric (< 6 chars)', () => {
    const r = evaluatePassphraseStrength('12345');
    expect(r.level).toBe('weak');
    expect(r.bits).toBeLessThanOrEqual(20);
  });

  test('returns moderate for medium mixed-case + digit', () => {
    expect(evaluatePassphraseStrength('Hello1ab').level).toBe('moderate');
  });

  test('returns strong for long mixed with symbols', () => {
    const r = evaluatePassphraseStrength('C0mpl3x!P@ssw0rd#2024');
    expect(r.level).toBe('strong');
    expect(r.bits).toBeGreaterThanOrEqual(50);
  });

  test('weak message mentions rate-limiting', () => {
    expect(evaluatePassphraseStrength('abc').message).toContain('rate-limiting');
  });

  test('all-lowercase gets 0.7 factor applied', () => {
    expect(evaluatePassphraseStrength('abcdefghij').bits).toBeLessThan(35);
  });
});

// =========================================================================
// Encryption round-trip
// =========================================================================

describe('Encryption round-trip', () => {
  test('encrypts and decrypts with passphrase', async () => {
    const encrypted = await encryptSecret('hello world', 'mypassphrase');
    const decrypted = await decryptSecret(encrypted, 'mypassphrase');
    expect(decrypted).toBe('hello world');
  });

  test('encrypts and decrypts with empty passphrase', async () => {
    const encrypted = await encryptSecret('secret data', '');
    const decrypted = await decryptSecret(encrypted, '');
    expect(decrypted).toBe('secret data');
  });

  test('encrypts and decrypts with simulated wallet signature only', async () => {
    const walletSig = '0x' + 'ab'.repeat(65);
    const keyInput = buildKeyInput('', walletSig);
    const encrypted = await encryptSecret('wallet-protected', keyInput);
    const decrypted = await decryptSecret(encrypted, keyInput);
    expect(decrypted).toBe('wallet-protected');
  });

  test('encrypts and decrypts with passphrase + wallet signature', async () => {
    const walletSig = '0x' + 'cd'.repeat(65);
    const keyInput = buildKeyInput('mypass', walletSig);
    const encrypted = await encryptSecret('dual-protected', keyInput);
    const decrypted = await decryptSecret(encrypted, keyInput);
    expect(decrypted).toBe('dual-protected');
  });

  test('handles unicode and emoji secrets', async () => {
    const secret = 'Hello \u4e16\u754c \ud83d\udd10\ud83d\udee1\ufe0f';
    const encrypted = await encryptSecret(secret, 'pass');
    const decrypted = await decryptSecret(encrypted, 'pass');
    expect(decrypted).toBe(secret);
  });

  test('handles empty secret', async () => {
    const encrypted = await encryptSecret('', 'pass');
    const decrypted = await decryptSecret(encrypted, 'pass');
    expect(decrypted).toBe('');
  });

  test('handles special characters in passphrase', async () => {
    const pass = "p@$$w0rd!#%^&*()_+-=[]{}|;':\",./<>?";
    const encrypted = await encryptSecret('test', pass);
    const decrypted = await decryptSecret(encrypted, pass);
    expect(decrypted).toBe('test');
  });

  test('handles very long secret (1500+ chars)', async () => {
    const secret = 'A'.repeat(1500);
    const encrypted = await encryptSecret(secret, 'pass');
    const decrypted = await decryptSecret(encrypted, 'pass');
    expect(decrypted).toBe(secret);
  });

  test('handles binary-like content', async () => {
    const secret = Array.from({ length: 256 }, (_, i) => String.fromCharCode(i)).join('');
    const encrypted = await encryptSecret(secret, 'pass');
    const decrypted = await decryptSecret(encrypted, 'pass');
    expect(decrypted).toBe(secret);
  });
});

// =========================================================================
// Security / attack resistance
// =========================================================================

describe('Security / attack resistance', () => {
  test('wrong passphrase fails decryption', async () => {
    const encrypted = await encryptSecret('secret', 'correct-pass');
    await expect(decryptSecret(encrypted, 'wrong-pass')).rejects.toThrow();
  });

  test('wrong wallet signature fails decryption', async () => {
    const keyEnc = buildKeyInput('pass', '0xaaa');
    const keyDec = buildKeyInput('pass', '0xbbb');
    const encrypted = await encryptSecret('secret', keyEnc);
    await expect(decryptSecret(encrypted, keyDec)).rejects.toThrow();
  });

  test('tampered ciphertext fails GCM authentication', async () => {
    const encrypted = await encryptSecret('secret', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    raw[30] ^= 0xff;
    const tampered = btoa(String.fromCharCode(...raw));
    await expect(decryptSecret(tampered, 'pass')).rejects.toThrow();
  });

  test('tampered salt fails', async () => {
    const encrypted = await encryptSecret('secret', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    raw[0] ^= 0xff;
    const tampered = btoa(String.fromCharCode(...raw));
    await expect(decryptSecret(tampered, 'pass')).rejects.toThrow();
  });

  test('tampered IV fails', async () => {
    const encrypted = await encryptSecret('secret', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    raw[16] ^= 0xff;
    const tampered = btoa(String.fromCharCode(...raw));
    await expect(decryptSecret(tampered, 'pass')).rejects.toThrow();
  });

  test('single bit-flip in middle of ciphertext fails', async () => {
    const encrypted = await encryptSecret('secret message here', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    const mid = Math.floor((28 + raw.length) / 2);
    raw[mid] ^= 0x01;
    const tampered = btoa(String.fromCharCode(...raw));
    await expect(decryptSecret(tampered, 'pass')).rejects.toThrow();
  });

  test('truncated ciphertext (salt+iv only) fails', async () => {
    const encrypted = await encryptSecret('secret', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    const truncated = btoa(String.fromCharCode(...raw.slice(0, 28)));
    await expect(decryptSecret(truncated, 'pass')).rejects.toThrow();
  });

  test('empty ciphertext string throws', async () => {
    await expect(decryptSecret('', 'pass')).rejects.toThrow();
  });

  test('same secret + passphrase produces different ciphertext (random salt/IV)', async () => {
    const e1 = await encryptSecret('same', 'same');
    const e2 = await encryptSecret('same', 'same');
    expect(e1).not.toBe(e2);
  });

  test('different secrets with same passphrase produce different ciphertext', async () => {
    const e1 = await encryptSecret('secret1', 'pass');
    const e2 = await encryptSecret('secret2', 'pass');
    expect(e1).not.toBe(e2);
  });

  test('PBKDF2 key derivation takes meaningful time (>10ms)', async () => {
    const salt = new Uint8Array(16);
    const start = performance.now();
    await deriveKey('test', salt);
    const elapsed = performance.now() - start;
    expect(elapsed).toBeGreaterThan(10);
  });

  test('similar passphrases produce different keys / fail cross-decrypt', async () => {
    const e1 = await encryptSecret('test', 'password1');
    await expect(decryptSecret(e1, 'password2')).rejects.toThrow();
  });

  test('no plaintext leakage in encrypted output', async () => {
    const secret = 'UNIQUE_PLAINTEXT_MARKER_12345';
    const encrypted = await encryptSecret(secret, 'pass');
    expect(encrypted).not.toContain('UNIQUE_PLAINTEXT_MARKER');
    expect(atob(encrypted)).not.toContain('UNIQUE_PLAINTEXT_MARKER');
  });

  test('timing consistency across encryptions', async () => {
    const times = [];
    for (let i = 0; i < 5; i++) {
      const start = performance.now();
      await encryptSecret('timing test', 'pass');
      times.push(performance.now() - start);
    }
    const min = Math.min(...times);
    const max = Math.max(...times);
    expect(max).toBeLessThan(min * 5);
  });
});

// =========================================================================
// QR encoding
// =========================================================================

describe('QR encoding', () => {
  test('encodes short text as version 1 (21x21)', () => {
    const { matrix, size } = QRGen.encode('Hi');
    expect(size).toBe(21);
    expect(matrix).toHaveLength(21);
    expect(matrix[0]).toHaveLength(21);
  });

  test('uses higher version for longer text', () => {
    const { size: s1 } = QRGen.encode('A');
    const { size: s2 } = QRGen.encode('A'.repeat(100));
    expect(s2).toBeGreaterThan(s1);
  });

  test('matrix contains only 1 (black) and 2 (white)', () => {
    const { matrix, size } = QRGen.encode('test data');
    for (let r = 0; r < size; r++)
      for (let c = 0; c < size; c++)
        expect([1, 2]).toContain(matrix[r][c]);
  });

  test('throws for data exceeding QR capacity', () => {
    expect(() => QRGen.encode('A'.repeat(3000))).toThrow(/too large/i);
  });

  test('handles version 2+ (alignment patterns)', () => {
    const { size } = QRGen.encode('A'.repeat(25));
    expect(size).toBeGreaterThanOrEqual(25);
  });

  test('produces deterministic output for same input', () => {
    const r1 = QRGen.encode('deterministic');
    const r2 = QRGen.encode('deterministic');
    expect(r1.size).toBe(r2.size);
    for (let r = 0; r < r1.size; r++)
      for (let c = 0; c < r1.size; c++)
        expect(r1.matrix[r][c]).toBe(r2.matrix[r][c]);
  });
});

// =========================================================================
// Payload format integration (full flow)
// =========================================================================

describe('Payload format integration', () => {
  test('full flow: encrypt -> QRSEC: -> extractPayload -> decrypt', async () => {
    const encrypted = await encryptSecret('my secret', 'mypass');
    const payload = 'QRSEC:' + encrypted;
    const extracted = extractPayload(payload);
    expect(extracted.wallet).toBe(false);
    const decrypted = await decryptSecret(extracted.data, 'mypass');
    expect(decrypted).toBe('my secret');
  });

  test('full flow with QRSECW: prefix and nonce', async () => {
    const nonce = generateNonce();
    const keyInput = buildKeyInput('pass', '0xfakewalletsig');
    const encrypted = await encryptSecret('wallet secret', keyInput);
    const payload = 'QRSECW:' + nonce + ':' + encrypted;
    const extracted = extractPayload(payload);
    expect(extracted.wallet).toBe(true);
    expect(extracted.nonce).toBe(nonce);
    const decrypted = await decryptSecret(extracted.data, keyInput);
    expect(decrypted).toBe('wallet secret');
  });

  test('URL wrapping with GitHub Pages URL', async () => {
    const encrypted = await encryptSecret('via link', 'pass');
    const url = 'https://degenddy.github.io/qr-secure-send/?v=1.8.0#QRSEC:' + encrypted;
    const extracted = extractPayload(url);
    expect(extracted.wallet).toBe(false);
    const decrypted = await decryptSecret(extracted.data, 'pass');
    expect(decrypted).toBe('via link');
  });

  test('encrypted output is valid base64', async () => {
    const encrypted = await encryptSecret('test', 'pass');
    expect(() => atob(encrypted)).not.toThrow();
    expect(encrypted).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  test('encrypted output has correct structure (salt + IV + ciphertext)', async () => {
    const encrypted = await encryptSecret('test', 'pass');
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    // salt(16) + iv(12) + plaintext(4) + GCM-tag(16) = 48
    expect(raw.length).toBeGreaterThanOrEqual(44);
    expect(raw.length).toBe(48);
  });
});
