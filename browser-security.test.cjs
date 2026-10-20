// Optional real-browser checks; no production dependency is added.
// Install Playwright separately or point QR_TEST_PLAYWRIGHT at its module path.
const { test, before, after, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { chromium } = require(process.env.QR_TEST_PLAYWRIGHT || 'playwright');
const { createServer } = require('./cli');
const { html, legacyFixture } = require('./test-support/app');
let server, staticServer, browser, context, page, base, staticBase;
const incoming = '#QRSEC:' + legacyFixture('', 'DUMMY_INCOMING_SECRET');
const listen = server => new Promise((resolve, reject) => {
  server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
});
before(async () => {
  server = createServer(); await listen(server);
  base = 'http://127.0.0.1:' + server.address().port;
  // Model static hosting without framing headers. Different ports give the
  // parent and child different origins without contacting any external host.
  staticServer = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html');
    if (req.url.startsWith('/parent')) {
      const sandbox = req.url === '/parent-noscripts' ? ' sandbox=""' : req.url === '/parent-scripts' ? ' sandbox="allow-scripts"' : '';
      res.end(`<iframe${sandbox} src="${base}/"></iframe>`);
    } else res.end(html);
  });
  await listen(staticServer); staticBase = 'http://127.0.0.1:' + staticServer.address().port;
  browser = await chromium.launch({ channel: process.env.QR_TEST_BROWSER || 'chrome', headless: true });
});
after(async () => {
  if (browser) await browser.close();
  for (const item of [server, staticServer]) if (item?.listening) await new Promise(resolve => item.close(resolve));
});
beforeEach(async () => { context = await browser.newContext(); page = await context.newPage(); });
afterEach(async () => { if (context) await context.close(); });

test('browser: masked secret and revealed passphrases keep their input privacy settings', async () => {
  await page.goto(base); await page.locator('#secret').fill('DUMMY_SECRET');
  assert.equal(await page.locator('#secret').evaluate(el => el.tagName), 'TEXTAREA');
  assert.equal(await page.locator('#secret').evaluate(el => getComputedStyle(el).webkitTextSecurity), 'disc');
  for (const id of ['secret', 'send-passphrase', 'recv-passphrase']) {
    const el = page.locator('#' + id);
    for (const [attribute, expected] of [['spellcheck','false'],['autocorrect','off'],['autocapitalize','off']])
      assert.equal(await el.getAttribute(attribute), expected);
    assert.equal(await el.getAttribute('autocomplete'), id === 'secret' ? 'off' : 'one-time-code');
  }
  await page.locator('[data-target="secret"]').click();
  assert.equal(await page.locator('#secret').evaluate(el => getComputedStyle(el).webkitTextSecurity), 'none');
  await page.locator('[data-target="send-passphrase"]').click();
  assert.equal(await page.locator('#send-passphrase').evaluate(el => el.spellcheck), false);
  await page.evaluate(() => window.dispatchEvent(new Event('blur')));
  assert.equal(await page.locator('#secret').evaluate(el => getComputedStyle(el).webkitTextSecurity), 'disc');
  assert.equal(await page.locator('#send-passphrase').getAttribute('type'), 'password');
});

test('browser: declined replacement preserves input; accepted replacement decrypts', async () => {
  await page.goto(base); await page.locator('#secret').fill('DUMMY_CURRENT_SECRET');
  page.once('dialog', dialog => dialog.dismiss());
  await page.evaluate(hash => {location.hash = hash;}, incoming);
  await page.waitForFunction(() => location.hash === '');
  assert.equal(await page.locator('#secret').inputValue(), 'DUMMY_CURRENT_SECRET');
  page.once('dialog', dialog => dialog.accept());
  await page.evaluate(hash => {location.hash = hash;}, incoming);
  await page.locator('#recv-result').waitFor();
  assert.equal(await page.locator('#secret').inputValue(), '');
  assert.equal(await page.locator('#recv-value').textContent(), 'DUMMY_INCOMING_SECRET');
  assert.equal(await page.locator('#recv-value').isVisible(), false);
});

test('browser: HTML-looking plaintext stays inert after decryption and reveal', async () => {
  const secret = '<img src=x onerror="window.secretExecuted=true">';
  await page.goto(base + '#QRSEC:' + legacyFixture('', secret));
  await page.locator('#recv-result').waitFor();
  await page.locator('#reveal-btn').click();
  assert.equal(await page.locator('#recv-value').textContent(), secret);
  assert.equal(await page.locator('#recv-value img').count(), 0);
  assert.equal(await page.evaluate(() => window.secretExecuted), undefined);
});

for (const concealLength of [true, false]) {
  test(`browser: v5 passwordless transfer automatically unlocks hidden (padding ${concealLength})`, async () => {
    await page.addInitScript(() => {
      window.secretCopies=0;
      navigator.clipboard.writeText=async()=>{window.secretCopies++;};
    });
    await page.goto(base);
    const packet=await page.evaluate(padding=>encryptSecret('DUMMY_AUTO_SECRET','',5,padding),concealLength);
    await page.goto(base+'#QRSEC5:'+packet);
    await page.locator('#recv-result').waitFor();
    assert.equal(await page.locator('#recv-value').textContent(),'DUMMY_AUTO_SECRET');
    assert.equal(await page.locator('#recv-value').isVisible(),false);
    assert.equal(await page.locator('#decrypt-btn').isVisible(),false);
    assert.equal(await page.locator('#recv-passphrase').isVisible(),false);
    assert.equal(await page.evaluate(()=>window.secretCopies),0);
    await page.locator('#reveal-btn').click();
    assert.equal(await page.locator('#recv-value').isVisible(),true);
    await page.evaluate(()=>window.dispatchEvent(new Event('blur')));
    assert.equal(await page.locator('#recv-value').isVisible(),false);
    await page.locator('#clear-btn').click();
    assert.equal(await page.locator('#recv-value').textContent(),'');
  });
}

test('browser: automatic attempt asks for a password without reporting a false failure', async () => {
  await page.goto(base+'#QRSEC:'+legacyFixture('DUMMY_PASSWORD','DUMMY_PROTECTED_SECRET'));
  await page.waitForFunction(()=>document.getElementById('link-notice').textContent.startsWith('Enter the sender'));
  assert.equal(await page.locator('#recv-error').textContent(),'');
  assert.equal(await page.locator('#recv-result').isVisible(),false);
  assert.equal(await page.locator('#recv-value').textContent(),'');
  await page.locator('#recv-passphrase').fill('WRONG_PASSWORD');
  await page.locator('#decrypt-btn').click();
  await page.waitForFunction(()=>document.getElementById('recv-error').textContent.startsWith('Decryption failed'));
  await page.locator('#recv-passphrase').fill('DUMMY_PASSWORD');
  await page.locator('#decrypt-btn').click();await page.locator('#recv-result').waitFor();
  assert.equal(await page.locator('#recv-value').textContent(),'DUMMY_PROTECTED_SECRET');
  assert.equal(await page.locator('#recv-value').isVisible(),false);
});

test('browser: wallet transfer arrival never calls the wallet or decrypts automatically', async () => {
  await page.addInitScript(()=>{
    window.walletRequests=0;
    window.ethereum={request:async()=>{window.walletRequests++;throw new Error('Unexpected wallet request');}};
  });
  await page.goto(base+'#QRSECW3:'+'ab'.repeat(16)+':'+legacyFixture('', 'DUMMY_WALLET_PACKET'));
  assert.equal(await page.locator('#recv-wallet-section').isVisible(),true);
  assert.equal(await page.locator('#decrypt-btn').isEnabled(),true);
  assert.equal(await page.locator('#recv-result').isVisible(),false);
  assert.equal(await page.evaluate(()=>window.walletRequests),0);
});

test('browser: CSP blocks unapproved inline and remote code', async () => {
  let downloads=0;
  await page.route('https://cdn.jsdelivr.net/**', route => {downloads++;return route.fulfill({body:'window.unapprovedScanner=true;',contentType:'text/javascript'});});
  await page.goto(base);
  await page.evaluate(async () => {
    const script = document.createElement('script'); script.textContent = 'window.unapprovedInline=true'; document.head.appendChild(script);
    await new Promise(resolve => {
      const remote=document.createElement('script');remote.src='https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js';
      remote.onerror=remote.onload=resolve;document.head.appendChild(remote);
    });
  });
  assert.equal(await page.evaluate(() => window.unapprovedInline), undefined);
  assert.equal(await page.evaluate(() => window.unapprovedScanner), undefined);
  assert.equal(downloads,0);
});

test('browser: bundled scanner verifies and decodes a generated QR while offline', async () => {
  const external=[];page.on('request',request=>{if(!request.url().startsWith(base))external.push(request.url());});
  await page.goto(base);await context.setOffline(true);
  await page.locator('.integrity-details > summary').click();await page.locator('#verify-scanner-btn').click();
  await page.waitForFunction(()=>document.getElementById('scanner-integrity-status').textContent.startsWith('Matched'));
  const result=await page.evaluate(async()=>{
    const container=document.createElement('div');
    QRGen.toCanvas(container,'DUMMY_OFFLINE_QR_PAYLOAD');
    const canvas=container.querySelector('canvas');
    const pixels=canvas.getContext('2d').getImageData(0,0,canvas.width,canvas.height);
    const scanner=await QRScan.loadJsQR();
    return scanner(pixels.data,pixels.width,pixels.height)?.data;
  });
  assert.equal(result,'DUMMY_OFFLINE_QR_PAYLOAD');assert.deepEqual(external,[]);
});

test('browser: changing bundled scanner bytes invalidates the application CSP hash', async () => {
  const changed=html.replace('/* BEGIN BUNDLED JSQR */', '/* BEGIN BUNDLED JSQR */\nwindow.scannerTampered=true;');
  assert.notEqual(changed,html);
  await page.route(base+'/',route=>route.fulfill({body:changed,contentType:'text/html'}));
  await page.goto(base);
  assert.equal(await page.locator('#generate-btn').isVisible(),false);
  assert.equal(await page.evaluate(()=>window.scannerTampered),undefined);
});

test('browser: scanner fingerprint rejects changed library before its initializer runs', async () => {
  // Re-pin only the app CSP to isolate the library fingerprint check. An attacker
  // who also changes the library fingerprint can bypass both self-checks.
  const {createHash}=require('node:crypto');
  let changed=html.replace('/* BEGIN BUNDLED JSQR */', '/* BEGIN BUNDLED JSQR */\nwindow.scannerTampered=true;');
  const source=changed.match(/<script>([\s\S]*?)<\/script>/)[1];
  changed=changed.replace(/script-src 'sha256-[^']+'/, "script-src 'sha256-"+createHash('sha256').update(source).digest('base64')+"'");
  await page.route(base+'/',route=>route.fulfill({body:changed,contentType:'text/html'}));
  await page.goto(base);await page.locator('.integrity-details > summary').click();await page.locator('#verify-scanner-btn').click();
  await page.waitForFunction(()=>document.getElementById('scanner-integrity-status').textContent.startsWith('Blocked'));
  assert.match(await page.locator('#scanner-integrity-status').textContent(),/fingerprint mismatch/);
  assert.equal(await page.evaluate(()=>window.scannerTampered),undefined);
});

for (const route of ['/parent', '/parent-noscripts', '/parent-scripts']) {
  test(`browser: static-host frame refuses to render (${route})`, async () => {
    // Serve the child HTML without CLI framing headers to exercise the JS/CSS
    // fallback itself, including a sandbox where JavaScript cannot run.
    await page.route(base + '/', route => route.fulfill({ body: html, contentType: 'text/html' }));
    await page.goto(staticBase + route);
    const frame = page.frames().find(frame => frame.parentFrame()); assert.ok(frame);
    await frame.waitForLoadState();
    assert.equal(await frame.evaluate(() => getComputedStyle(document.body).display), 'none');
    assert.equal(await frame.locator('#generate-btn').isVisible(), false);
  });
}

test('browser: paused timeout callbacks cannot preserve an expired background session', async () => {
  const start = new Date('2026-10-19T12:00:00Z');
  await page.clock.install({time: start}); await page.clock.pauseAt(start); await page.goto(base);
  await page.locator('#secret').fill('DUMMY_EXPIRED_SECRET');
  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', {configurable: true, get: () => true});
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await page.clock.setSystemTime(new Date(start.getTime() + 61000));
  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', {configurable: true, get: () => false});
    document.dispatchEvent(new Event('visibilitychange'));
  });
  assert.equal(await page.locator('#secret').inputValue(), '');
});

test('browser: camera stream arriving after suspended expiry is stopped before preview', async () => {
  const start = new Date('2026-10-19T12:00:00Z');
  await page.clock.install({time:start}); await page.clock.pauseAt(start);
  await page.addInitScript(() => {
    window.BarcodeDetector = class { async detect() {return [];} };
    window.cameraStopped = 0; window.previewStarted = 0;
    navigator.mediaDevices.getUserMedia = () => new Promise(resolve => {window.grantTestCamera = resolve;});
    HTMLMediaElement.prototype.play = async function () {window.previewStarted++;};
  });
  await page.goto(base); await page.locator('[data-tab="receive"]').click(); await page.locator('#scan-btn').click();
  await page.waitForFunction(() => typeof window.grantTestCamera === 'function');
  await page.clock.setSystemTime(new Date(start.getTime() + 180000));
  await page.evaluate(() => window.grantTestCamera({getTracks: () => [{stop() {window.cameraStopped++;}}]}));
  assert.equal(await page.evaluate(() => window.cameraStopped), 1);
  assert.equal(await page.evaluate(() => window.previewStarted), 0);
  assert.equal(await page.locator('#scanner-region video').count(), 0);
});

test('browser: padded v5 QR codes decode at minimum and maximum lengths with smaller QR for short secrets', async () => {
  await page.goto(base);let dimensions;
  for(const secret of ['a','字'.repeat(500)]){
    await page.locator('#secret').fill(secret);await page.locator('#generate-btn').click();
    await page.locator('#qr-info').waitFor();
    const result=await page.evaluate(async()=>{
      const canvas=document.querySelector('#qr-output canvas'),ctx=canvas.getContext('2d');
      const pixels=ctx.getImageData(0,0,canvas.width,canvas.height),scan=await QRScan.loadJsQR();
      const text=scan(pixels.data,pixels.width,pixels.height)?.data;
      return {matches:text===document.getElementById('qr-url').textContent,width:canvas.width,height:canvas.height};
    });
    assert.equal(result.matches,true);if(dimensions)assert.ok(result.width > dimensions.width);dimensions=result;
  }
});

test('browser: v5 NFC password unlocks a transfer with decomposed keyboard input', async () => {
  await page.goto(base);await page.locator('#secret').fill('DUMMY_UNICODE_SECRET');
  await page.locator('#send-passphrase').fill('café');await page.locator('#generate-btn').click();await page.locator('#qr-info').waitFor();
  const link=await page.locator('#qr-url').textContent();
  await page.goto(base+'/?receiver=1'+new URL(link).hash);await page.locator('#recv-passphrase').fill('cafe\u0301');
  await page.locator('#decrypt-btn').click();await page.locator('#recv-result').waitFor();
  assert.equal(await page.locator('#recv-value').textContent(),'DUMMY_UNICODE_SECRET');
});

test('browser: wallet recovery remains private, decodes a padded wallet QR, and unlocks without a provider', async () => {
  await page.addInitScript(()=>{
    window.signRequests=0;
    window.ethereum={request:async({method})=>method==='eth_requestAccounts'?['0x'+'12'.repeat(20)]:('0x'+'11'.repeat(32)+'22'.repeat(32)+(++window.signRequests===1?'00':'1b'))};
  });
  await page.goto(base);await page.locator('#send-wallet-toggle').check();await page.locator('#send-wallet-connect-btn').click();
  await page.locator('#secret').fill('DUMMY_RECOVERY_SECRET');await page.locator('#generate-btn').click();await page.locator('#qr-info').waitFor();
  assert.equal(await page.evaluate(()=>window.signRequests),2);
  const key=await page.locator('#wallet-recovery-key').textContent();assert.equal(await page.locator('#wallet-recovery-key').isVisible(),false);
  const link=await page.locator('#qr-url').textContent();assert.ok(!link.includes(key));
  assert.equal(await page.evaluate(async()=>{
    const canvas=document.querySelector('#qr-output canvas'),pixels=canvas.getContext('2d').getImageData(0,0,canvas.width,canvas.height);
    return (await QRScan.loadJsQR())(pixels.data,pixels.width,pixels.height)?.data===document.getElementById('qr-url').textContent;
  }),true);
  await page.locator('#reveal-recovery-btn').click();assert.equal(await page.locator('#wallet-recovery-key').isVisible(),true);
  await page.evaluate(()=>window.dispatchEvent(new Event('blur')));assert.equal(await page.locator('#wallet-recovery-key').isVisible(),false);
  await page.goto(base+'/?receiver=1'+new URL(link).hash);await page.evaluate(()=>{delete window.ethereum;});
  await page.locator('#recv-recovery-key').fill(key);
  assert.equal(await page.locator('#recv-recovery-key').evaluate(el=>getComputedStyle(el).webkitTextSecurity),'disc');
  for(const [name,value]of [['spellcheck','false'],['autocorrect','off'],['autocapitalize','off'],['autocomplete','off']])assert.equal(await page.locator('#recv-recovery-key').getAttribute(name),value);
  await page.locator('#decrypt-btn').click();await page.locator('#recv-result').waitFor();
  assert.equal(await page.locator('#recv-value').textContent(),'DUMMY_RECOVERY_SECRET');
  assert.equal(await page.locator('#recv-recovery-key').inputValue(),'');
});

test('browser: multiline text and a leading U+FEFF survive the complete UI transfer', async () => {
  const secret = '\ufeffDUMMY_FIRST_LINE\nSECOND_LINE\t🔐';
  await page.goto(base); await page.locator('#secret').fill(secret);
  await page.locator('#send-passphrase').fill('DUMMY_PASSWORD');
  await page.locator('#generate-btn').click(); await page.locator('#qr-info').waitFor();
  const link = await page.locator('#qr-url').textContent();
  await page.goto(base + '/?receiver=1' + new URL(link).hash);
  await page.locator('#recv-passphrase').fill('DUMMY_PASSWORD'); await page.locator('#decrypt-btn').click();
  await page.locator('#recv-result').waitFor();
  assert.equal(await page.locator('#recv-value').textContent(), secret);
});

for (const change of ['random password', 'typed password', 'wallet', 'padding', 'secret']) {
  test(`browser: ${change} changes clear the old unprotected QR`, async () => {
    await page.goto(base); await page.locator('#secret').fill('DUMMY_STALE_QR');
    await page.locator('#generate-btn').click(); await page.locator('#qr-info').waitFor();
    if (change === 'random password') await page.locator('#password-generate-btn').click();
    if (change === 'typed password') await page.locator('#send-passphrase').fill('DUMMY_NEW_PASSWORD');
    if (change === 'wallet') await page.locator('#send-wallet-toggle').check();
    if (change === 'padding') await page.locator('#conceal-length').uncheck();
    if (change === 'secret') await page.locator('#secret').fill('DUMMY_NEW_SECRET');
    assert.equal(await page.locator('#qr-info').isVisible(), false);
    assert.equal(await page.locator('#qr-output canvas').count(), 0);
    assert.equal(await page.locator('#qr-url').textContent(), '');
    assert.equal(await page.locator('#copy-url-btn').isVisible(), false);
  });
}

test('browser: encryption locks inputs and rejects an unnoticed password change', async () => {
  await page.goto(base); await page.locator('#secret').fill('DUMMY_PENDING_SECRET');
  await page.evaluate(() => {
    const original = encryptSecret;
    encryptSecret = async (...args) => {await new Promise(resolve => {window.finishEncryption = resolve;}); return original(...args);};
  });
  await page.locator('#generate-btn').click(); await page.waitForFunction(() => typeof finishEncryption === 'function');
  for (const id of ['secret', 'send-passphrase']) assert.equal(await page.locator('#' + id).evaluate(el => el.readOnly), true);
  for (const id of ['conceal-length', 'send-wallet-toggle', 'password-generate-btn']) assert.equal(await page.locator('#' + id).isDisabled(), true);
  // Model an autofill/provider changing a value despite the read-only UI.
  await page.evaluate(() => {document.getElementById('send-passphrase').value = 'DUMMY_CHANGED'; finishEncryption();});
  await page.waitForFunction(() => !document.getElementById('generate-btn').disabled);
  assert.match(await page.locator('#send-error').textContent(), /Inputs changed/);
  assert.equal(await page.locator('#qr-info').isVisible(), false);
  assert.equal(await page.locator('#secret').inputValue(), 'DUMMY_PENDING_SECRET');
});

test('browser: padding defaults on, compact QR is smaller, and every bucket decodes', async () => {
  await page.goto(base); assert.equal(await page.locator('#conceal-length').isChecked(), true);
  const versions = [];
  for (const [length, padded] of [[1,false],[1,true],[128,true],[129,true],[257,true],[513,true],[1025,true],[1500,true],[1500,false]]) {
    await page.locator('#conceal-length').setChecked(padded);
    await page.locator('#secret').fill('x'.repeat(length));
    await page.locator('#generate-btn').click(); await page.locator('#qr-info').waitFor();
    const result = await page.evaluate(async () => {
      const canvas = document.querySelector('#qr-output canvas'), pixels = canvas.getContext('2d').getImageData(0,0,canvas.width,canvas.height);
      const link = document.getElementById('qr-url').textContent;
      const code = (await QRScan.loadJsQR())(pixels.data,pixels.width,pixels.height);
      const decoded = code?.data;
      const payload = extractPayload(decoded);
      return {matches: decoded === link, length: (await decryptSecret(payload.data,'',payload.version)).length, version: code.version};
    });
    assert.equal(result.matches, true); assert.equal(result.length, length); versions.push(result.version);
  }
  assert.ok(versions[0] < versions[1]); assert.equal(versions[1], versions[2]);
  await page.locator('#clear-btn').click(); assert.equal(await page.locator('#conceal-length').isChecked(), true);
  await page.locator('#secret').fill('DUMMY_PREVIEW'); await page.locator('#generate-btn').click();
  await page.locator('#qr-info').waitFor(); await page.screenshot({path:'/private/tmp/qr-v5-preview.png',fullPage:true});
});

test('browser: maximum padded wallet transfer fits and decodes in a single QR', async () => {
  await page.addInitScript(() => {
    window.ethereum = {request:async ({method}) => method === 'eth_requestAccounts' ? ['0x'+'12'.repeat(20)] : '0x'+'11'.repeat(32)+'22'.repeat(32)+'1b'};
  });
  await page.goto(base); await page.locator('#send-wallet-toggle').check(); await page.locator('#send-wallet-connect-btn').click();
  await page.locator('#secret').fill('字'.repeat(500)); await page.locator('#generate-btn').click(); await page.locator('#qr-info').waitFor();
  assert.equal(await page.evaluate(async () => {
    const canvas = document.querySelector('#qr-output canvas'), pixels = canvas.getContext('2d').getImageData(0,0,canvas.width,canvas.height);
    return (await QRScan.loadJsQR())(pixels.data,pixels.width,pixels.height)?.data === document.getElementById('qr-url').textContent;
  }), true);
});
