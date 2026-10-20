const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { createHash, pbkdf2Sync, createDecipheriv } = require('node:crypto');
const { app, legacyFixture, html, source } = require('./test-support/app');

test('legacy password and wallet-only transfers remain recoverable', async () => {
  const a = app();
  for (const password of ['old password', '', ':' + '0x' + 'ab'.repeat(65)]) {
    const data = legacyFixture(password, 'Legacy secret');
    const parsed = a.context.extractPayload('QRSEC:' + data);
    assert.equal(parsed.version, 1);
    assert.equal(await a.context.decryptSecret(data, password, parsed.version), 'Legacy secret');
  }
});

test('V2 uses 600000 iterations and authenticates its version', async () => {
  const a = app(), pass = 'random-like password';
  const data = await a.context.encryptSecret('test value', pass, 2);
  const packed = Buffer.from(data, 'base64');
  const key = pbkdf2Sync(pass, packed.subarray(0, 16), 600000, 32, 'sha256');
  const cipher = createDecipheriv('aes-256-gcm', key, packed.subarray(16, 28));
  cipher.setAAD(Buffer.from('QR Secure Send v2'));
  cipher.setAuthTag(packed.subarray(-16));
  assert.equal(Buffer.concat([cipher.update(packed.subarray(28, -16)), cipher.final()]).toString(), 'test value');
  await assert.rejects(a.context.decryptSecret(data, pass, 1));
  await assert.rejects(a.context.decryptSecret(data, pass, 999));
});

test('payload validation rejects malformed, oversized, future-version and invalid nonce inputs', () => {
  const a = app();
  for (const payload of ['QRSEC2:abc', 'QRSEC2:' + 'A'.repeat(4100), 'QRSEC3:' + 'A'.repeat(60),
    'QRSECW2:arbitrary signing text:' + 'A'.repeat(60), 'QRSECW2:' + 'ab'.repeat(16) + ':!!!!']) {
    assert.equal(a.context.extractPayload(payload), null);
  }
});

test('new UI permits passwordless transfers and warns about captured copies', async () => {
  const sender = app();
  assert.match(sender.el('protection-notice').textContent, /Anyone who captures/);
  sender.el('secret').value = 'immediate camera transfer';
  await sender.click('generate-btn');
  const link = sender.el('qr-url').textContent;
  assert.match(link, /#QRSEC5:/);
  const receiver = app({ hash: new URL(link).hash });
  await receiver.waitForIdle();
  assert.equal(receiver.el('recv-value').textContent, 'immediate camera transfer');
});

test('weak-password feedback is advisory, not a generation block', async () => {
  const a = app();
  a.el('secret').value = 'weak password chosen explicitly';
  a.el('send-passphrase').value = 'Password1!';
  await a.click('generate-btn');
  assert.match(a.el('send-passphrase-strength').textContent, /Weak/);
  assert.match(a.el('qr-url').textContent, /#QRSEC5:/);
  assert.equal(a.el('send-error').textContent, '');
});

test('wallet-only UI transfers use a versioned signing message and decrypt without a password', async () => {
  const requests = [];
  const ethereum = { request: async request => {
    requests.push(request);
    return request.method === 'eth_requestAccounts' ? ['0x' + '12'.repeat(20)] : '0x' + 'ab'.repeat(64) + '1b';
  } };
  const sender = app({ ethereum });
  sender.el('send-wallet-toggle').checked = true;
  sender.el('send-wallet-toggle').handlers.change({target:{checked:true}});
  assert.match(sender.el('protection-notice').textContent, /Wallet only/);
  sender.el('secret').value = 'wallet only test';
  await sender.click('send-wallet-connect-btn');
  await sender.click('generate-btn');
  const link = sender.el('qr-url').textContent;
  assert.match(link, /#QRSECW5:/);
  const receiver = app({ ethereum, hash: new URL(link).hash });
  await receiver.click('recv-wallet-connect-btn');
  await receiver.click('decrypt-btn');
  assert.equal(receiver.el('recv-value').textContent, 'wallet only test');
  const signed = requests.filter(x => x.method === 'personal_sign');
  assert.equal(signed[0].params[0], signed[1].params[0]);
  assert.match(Buffer.from(signed[0].params[0].slice(2), 'hex').toString(), /A password is recommended/);
});

test('generated passwords use secure randomness; typed strings do not get entropy claims', async () => {
  const a = app();
  const one = a.context.generatePassword(), two = a.context.generatePassword();
  assert.match(one, /^[A-Za-z0-9_-]{24}$/); assert.notEqual(one, two);
  await a.click('password-generate-btn');
  assert.match(a.el('send-passphrase-strength').textContent, /144 random bits/);
  a.el('send-passphrase').value = 'Password1!';
  a.el('send-passphrase').handlers.input();
  assert.match(a.el('send-passphrase-strength').textContent, /Weak/);
});

test('wallet transfer with a password still requires both factors', async () => {
  const a = app();
  const sig = '0x' + 'ab'.repeat(65), password = 'Mango orchard beside violet river';
  const data = await a.context.encryptSecret('wallet protected', a.context.buildKeyInput(password, sig));
  await assert.rejects(a.context.decryptSecret(data, a.context.buildKeyInput('', sig)));
  await assert.rejects(a.context.decryptSecret(data, password));
  assert.equal(await a.context.decryptSecret(data, a.context.buildKeyInput(password, sig)), 'wallet protected');
});

test('wallet messages preserve legacy bytes and make V2 key disclosure explicit', async () => {
  const requests = [];
  const a = app({ ethereum: { request: async request => { requests.push(request); return '0x' + 'ab'.repeat(65); } } });
  const nonce = 'cd'.repeat(16);
  await a.context.getWalletSignature('0x' + '12'.repeat(20), nonce, 1);
  assert.equal(Buffer.from(requests[0].params[0].slice(2), 'hex').toString(), 'QR Secure Send: ' + nonce);
  await a.context.getWalletSignature('0x' + '12'.repeat(20), nonce, 2);
  assert.match(Buffer.from(requests[1].params[0].slice(2), 'hex').toString(), /Signing exposes.*decryption key/);
  await assert.rejects(a.context.getWalletSignature('account', 'malicious message', 2));
  assert.equal(requests.length, 2);
});

test('reset cancels a pending encryption result and clears all sensitive DOM values', async () => {
  const a = app();
  a.el('secret').value = 'secret pending crypto';
  a.el('send-passphrase').value = 'Mango orchard beside violet river';
  const pending = a.click('generate-btn');
  await a.click('clear-btn');
  await pending;
  for (const id of ['secret', 'send-passphrase', 'recv-passphrase']) assert.equal(a.el(id).value, '');
  assert.equal(a.el('qr-url').textContent, '');
  assert.equal(a.el('recv-value').textContent, '');
});

test('reset cancels a pending decryption result', async () => {
  const data = legacyFixture('legacy', 'must not return');
  const a = app({ hash: '#QRSEC:' + data });
  await a.waitForIdle();
  a.el('recv-passphrase').value = 'legacy';
  const pending = a.click('decrypt-btn');
  await a.click('clear-btn');
  await pending;
  assert.equal(a.el('recv-value').textContent, '');
  assert.equal(a.el('recv-result').style.display, 'none');
});

test('incoming URL clears history; decrypted secret is hidden until reveal', async () => {
  const data = legacyFixture('legacy', '<img src=x onerror=alert(1)>');
  const a = app({ hash: '#QRSEC:' + data });
  await a.waitForIdle();
  assert.equal(a.context.location.hash, '');
  assert.equal(a.el('legacy-warning').style.display, 'block');
  a.el('recv-passphrase').value = 'legacy';
  await a.click('decrypt-btn');
  assert.equal(a.el('recv-value').textContent, '<img src=x onerror=alert(1)>');
  assert.equal(a.el('recv-value').hidden, true);
  assert.equal(a.el('recv-passphrase').value, '');
  await a.click('reveal-btn');
  assert.equal(a.el('recv-value').hidden, false);
  a.windowEvents.blur();
  assert.equal(a.el('recv-value').hidden, true);
});

test('idle and background expiry really clear secrets', () => {
  for (const background of [false, true]) {
    const a = app();
    a.el('send-passphrase').value = 'erase me';
    a.el('recv-value').textContent = 'erase me too';
    if (background) { a.context.document.hidden = true; a.documentEvents.visibilitychange(); }
    const timer = [...a.timers.values()].find(x => x.ms === (background ? 30000 : 120000));
    assert.ok(timer); a.advance(background ? 30000 : 120000); timer.fn();
    assert.equal(a.el('send-passphrase').value, '');
    assert.equal(a.el('recv-value').textContent, '');
  }
});

test('foreground return enforces background expiry even when no timer ran', () => {
  const a = app();
  a.el('secret').value = 'suspended secret';
  a.el('send-passphrase').value = 'suspended password';
  a.context.document.hidden = true;
  a.documentEvents.visibilitychange();
  a.advance(20000, { monotonic: false });
  a.documentEvents.visibilitychange(); // Duplicate notification cannot extend expiry.
  a.advance(10000, { monotonic: false });
  a.context.document.hidden = false;
  a.documentEvents.visibilitychange();
  assert.equal(a.el('secret').value, '');
  assert.equal(a.el('send-passphrase').value, '');
});

test('return before the background deadline preserves the session and cancels that deadline', () => {
  const a = app();
  a.el('secret').value = 'still current';
  a.context.document.hidden = true;
  a.documentEvents.visibilitychange();
  a.advance(29000);
  a.context.document.hidden = false;
  a.documentEvents.visibilitychange();
  a.advance(2000);
  a.windowEvents.focus();
  assert.equal(a.el('secret').value, 'still current');
});

test('first interaction cannot revive an idle session while its timer is suspended', () => {
  for (const type of ['pointerdown', 'keydown', 'beforeinput', 'input', 'click']) {
    const a = app();
    a.el('secret').value = 'expired';
    a.advance(120000, { monotonic: false });
    let prevented = false, stopped = false;
    a.documentEvents[type]({ preventDefault() { prevented = true; },
      stopImmediatePropagation() { stopped = true; } });
    assert.equal(a.el('secret').value, '', type);
    assert.ok(prevented && stopped, type);
  }
});

test('expiry tolerates a paused monotonic clock and detects wall-clock adjustments', () => {
  for (const [ms, clocks] of [[120000, { monotonic: false }],
    [120000, { wall: false }], [-1, { monotonic: false }]]) {
    const a = app();
    a.el('secret').value = 'expired';
    a.advance(ms, clocks);
    a.windowEvents.focus();
    assert.equal(a.el('secret').value, '');
  }
});

test('freeze, resume and history restoration clear expired or frozen sessions', () => {
  for (const event of ['freeze', 'resume', 'pageshow']) {
    const a = app();
    a.el('secret').value = 'suspended';
    if (event === 'resume') a.advance(120000);
    if (event === 'pageshow') a.windowEvents.pageshow({ persisted: true });
    else a.documentEvents[event]();
    assert.equal(a.el('secret').value, '', event);
  }
});

test('expired secrets cannot be revealed or copied before lifecycle events run', async () => {
  for (const action of ['copy-btn', 'reveal-btn']) {
    const a = app({ hash: '#QRSEC:' + legacyFixture('legacy', 'expired plaintext') });
    await a.waitForIdle();
    a.el('recv-passphrase').value = 'legacy';
    await a.click('decrypt-btn');
    let copies = 0;
    a.context.navigator.clipboard.writeText = async () => { copies++; };
    a.advance(120000);
    await a.click(action);
    assert.equal(a.el('recv-value').textContent, '');
    assert.equal(a.el('recv-value').hidden, true);
    assert.equal(copies, 0);
  }
});

test('late encryption and decryption results enforce elapsed deadlines without timers', async () => {
  for (const action of ['generate-btn', 'decrypt-btn']) {
    const a = app({ hash: '#QRSEC:' + legacyFixture('legacy', 'late plaintext') });
    await a.waitForIdle();
    a.el('secret').value = 'late secret';
    a.el('recv-passphrase').value = 'legacy';
    const pending = a.click(action);
    a.advance(120000);
    await pending;
    assert.equal(a.el('qr-url').textContent, '', action);
    assert.equal(a.el('recv-value').textContent, '', action);
    assert.equal(a.el('secret').value, '', action);
    assert.equal(a.el(action).disabled, false, action);
  }
});

test('late wallet responses cannot restore an expired session', async () => {
  let resolve;
  const a = app({ ethereum: { request: () => new Promise(done => { resolve = done; }) } });
  a.el('secret').value = 'wallet pending';
  const pending = a.click('send-wallet-connect-btn');
  a.advance(120000);
  resolve(['0x' + '12'.repeat(20)]);
  await pending;
  assert.equal(a.el('send-wallet-status').textContent, '');
  assert.equal(a.el('secret').value, '');
});

test('a clipboard write completing after expiry is followed by a clear', async () => {
  const a = app();
  let resolve;
  const writes = [];
  a.el('recv-value').textContent = 'late clipboard secret';
  a.context.navigator.clipboard.writeText = value => {
    writes.push(value);
    return writes.length === 1 ? new Promise(done => { resolve = done; }) : Promise.resolve();
  };
  const pending = a.click('copy-btn');
  a.advance(120000);
  resolve();
  await pending;
  assert.deepEqual(writes, ['late clipboard secret', '']);
  assert.equal(a.el('recv-value').textContent, '');
});

test('scanner matches only after hashing succeeds; failure rejects and permits a retry', async () => {
  const a = app(), crypto = a.context.crypto;
  a.context.crypto = {subtle: {digest: async () => {throw new Error('verification failed');}}};
  const pending = a.run('QRScan.loadJsQR()');
  assert.doesNotMatch(a.el('scanner-integrity-status').textContent, /^Matched/);
  await assert.rejects(pending, /verification failed/);
  assert.match(a.el('scanner-integrity-status').textContent, /^Blocked/);
  a.context.crypto = crypto;
  assert.equal(typeof await a.run('QRScan.loadJsQR()'), 'function');
  assert.match(a.el('scanner-integrity-status').textContent, /^Matched/);
  assert.equal(a.head.children.length, 0);
});

test('stopping while camera permission is pending closes the late stream', async () => {
  let acquire;
  let stopped = 0;
  const a = app();
  a.context.navigator.mediaDevices = { getUserMedia: () => new Promise(resolve => { acquire = resolve; }) };
  // Verify the real bundled scanner before reaching getUserMedia.
  await a.run('QRScan.loadJsQR()');
  const pending = a.run('QRScan.start(document.getElementById("scanner-region"), () => false, () => {})');
  await new Promise(resolve => setImmediate(resolve));
  a.run('QRScan.stop(document.getElementById("scanner-region"))');
  acquire({ getTracks: () => [{ stop() { stopped++; } }] });
  assert.equal(await pending, false);
  assert.equal(stopped, 1);
});

test('CSP matches the actual inline script and blocks connections and framing in CLI', () => {
  const digest = createHash('sha256').update(source).digest('base64');
  assert.ok(html.includes("'sha256-" + digest + "'"));
  assert.ok(html.includes("connect-src 'none'"));
  assert.ok(fs.readFileSync('cli.js', 'utf8').includes("frame-ancestors 'none'"));
});

test('passwordless V2 encryption round trips with the known empty key input', async () => {
  const a = app();
  const data = await a.context.encryptSecret('secret', '');
  assert.equal(await a.context.decryptSecret(data, ''), 'secret');
});

test('initial wallet disclosure preserves fields; switching an established account clears them', async () => {
  let change;
  const account = '0x' + 'ab'.repeat(20);
  const a = app({ ethereum: {
    on(event, fn) { if (event === 'accountsChanged') change = fn; },
    async request() { change([account]); return [account]; },
  } });
  a.el('send-passphrase').value = 'Mango orchard beside violet river';
  await a.click('send-wallet-connect-btn');
  assert.match(a.el('send-wallet-status').textContent, /Connected/);
  assert.notEqual(a.el('send-passphrase').value, '');
  change(['0x' + 'cd'.repeat(20)]);
  assert.equal(a.el('send-passphrase').value, '');
  assert.equal(a.el('send-wallet-status').textContent, '');
});

test('same-tab incoming links replace prior sensitive state', () => {
  let confirmations = 0;
  const a = app({ confirm: () => { confirmations++; return true; } });
  a.el('secret').value = 'prior secret';
  a.context.location.hash = '#QRSEC:' + legacyFixture('legacy', 'next transfer');
  a.windowEvents.hashchange();
  assert.equal(a.context.location.hash, '');
  assert.equal(a.el('secret').value, '');
  assert.equal(a.el('decrypt-btn').style.display, 'inline-block');
  assert.equal(confirmations, 1);
});

test('rejecting an incoming transfer preserves the active transfer and secret', async () => {
  let confirmations = 0;
  const a = app({ hash: '#QRSEC:' + legacyFixture('old', 'original secret'),
    confirm: () => { confirmations++; return false; } });
  await a.waitForIdle();
  a.el('recv-passphrase').value = 'old';
  a.context.location.hash = '#QRSEC:' + legacyFixture('new', 'replacement secret');
  a.windowEvents.hashchange();
  assert.equal(a.context.location.hash, '');
  assert.equal(a.el('recv-passphrase').value, 'old');
  assert.equal(confirmations, 1);
  await a.click('decrypt-btn');
  assert.equal(a.el('recv-value').textContent, 'original secret');
});

test('invalid incoming links cannot wipe or interrupt an active session', () => {
  const a = app({ confirm: () => { throw new Error('Must not prompt'); } });
  a.el('secret').value = 'keep this';
  a.context.location.hash = '#not-a-transfer';
  a.windowEvents.hashchange();
  assert.equal(a.el('secret').value, 'keep this');
  assert.match(a.el('session-status').textContent, /Incoming link ignored/);
});

test('incoming transfers open without confirmation when there is no active session', () => {
  const a = app({ confirm: () => { throw new Error('Must not prompt'); } });
  a.context.location.hash = '#QRSEC:' + legacyFixture('new', 'new transfer');
  a.windowEvents.hashchange();
  assert.equal(a.el('decrypt-btn').style.display, 'inline-block');
});

test('expiry is checked after a replacement confirmation pauses timers', () => {
  const a = app({ confirm: () => { a.advance(120000); return false; } });
  a.el('secret').value = 'expires during dialog';
  a.context.location.hash = '#QRSEC:' + legacyFixture('new', 'new transfer');
  a.windowEvents.hashchange();
  assert.equal(a.el('secret').value, '');
  assert.equal(a.el('decrypt-btn').style.display, 'none');
});

test('secret reveal and reset never turn it into a password-manager field', async () => {
  const a = app();
  a.el('secret').value = 'visually masked';
  const toggle = a.toggles.find(btn => btn.dataset.target === 'secret');
  toggle.handlers.click();
  assert.equal(a.el('secret').dataset.revealed, 'true');
  assert.equal(a.el('secret').type, 'textarea');
  a.windowEvents.blur();
  assert.equal(a.el('secret').dataset.revealed, 'false');
  assert.equal(a.el('secret').type, 'textarea');
  await a.click('clear-btn');
  assert.equal(a.el('secret').type, 'textarea');
  assert.equal(a.el('secret').value, '');
});

test('unsupported text masking leaves secret entry disabled instead of exposed', () => {
  const a = app({ masking: false });
  assert.equal(a.el('secret').disabled, true);
  assert.match(a.el('send-error').textContent, /cannot mask/);
});

test('framed documents remain hidden and abort before initializing the application', () => {
  let cleared = false;
  const context = { window: { top: {}, self: {} },
    document: { body: { hidden: true, replaceChildren() { cleared = true; } } } };
  vm.createContext(context);
  assert.throws(() => vm.runInContext(source, context), /own tab, not a frame/);
  assert.equal(cleared, true);
  assert.equal(context.document.body.hidden, true);
  assert.match(html, /<body hidden>/);
  assert.match(html, /body\[hidden\] \{ display: none !important; \}/);
});


test('estimator never silently truncates the encryption password', async () => {
  const a = app();
  const pass = 'A'.repeat(100) + 'tail';
  assert.match(a.context.evaluatePassphraseStrength(pass).message, /First 100 characters assessed/);
  const data = await a.context.encryptSecret('long-password secret', pass);
  await assert.rejects(a.context.decryptSecret(data, pass.slice(0, 100)));
  assert.equal(await a.context.decryptSecret(data, pass), 'long-password secret');
});

test('strength checking fails visibly rather than declaring success without its estimator', () => {
  const a = app();
  a.context.window.zxcvbn = undefined;
  const result = a.context.evaluatePassphraseStrength('example password');
  assert.equal(result.score, null);
  assert.match(result.message, /unavailable/);
});
