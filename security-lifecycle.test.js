const { test } = require('node:test');
const assert = require('node:assert/strict');
const { app, legacyFixture, html } = require('./test-support/app');
const packet = legacyFixture('old', 'ORIGINAL_PLAINTEXT');
const next = legacyFixture('next', 'NEXT_PLAINTEXT');
function deferred() { let resolve, reject; const promise = new Promise((a, b) => {resolve=a;reject=b;}); return {promise,resolve,reject}; }

for (const [name, cancel] of [
  ['page navigation', a => a.windowEvents.pagehide()],
  ['browser freeze', a => a.documentEvents.freeze()],
  ['tab switch', a => a.tabs[1].handlers.click()],
  ['idle expiry before foreground', a => {a.advance(120000);a.windowEvents.focus();}],
  ['background expiry before resume', a => {
    a.context.document.hidden=true;a.documentEvents.visibilitychange();a.advance(30000);
    a.context.document.hidden=false;a.documentEvents.visibilitychange();
  }],
  ['history restoration', a => a.windowEvents.pageshow({persisted:true})],
]) test(`pending encryption cannot restore a session after ${name}`, async () => {
  const a = app(), job = deferred();
  a.context.encryptSecret = () => job.promise;
  a.el('secret').value = 'late encryption';
  const pending = a.click('generate-btn'); cancel(a); job.resolve(packet); await pending;
  assert.equal(a.el('qr-url').textContent,''); assert.equal(a.el('secret').value,'');
  assert.equal(a.el('generate-btn').disabled,false);
});
test('accepted replacement discards an already pending decryption result', async () => {
  const a = app({hash:'#QRSEC:'+packet,confirm:()=>true}), job=deferred();
  a.context.decryptSecret=()=>job.promise;
  const pending=a.click('decrypt-btn');
  a.context.location.hash='#QRSEC:'+next;a.windowEvents.hashchange();
  job.resolve('OLD_LATE_PLAINTEXT');await pending;
  assert.equal(a.el('recv-value').textContent,'');
  assert.equal(a.run('incomingPayload.data'),next);
});
test('declined replacement lets the original pending decryption finish', async () => {
  const a = app({hash:'#QRSEC:'+packet,confirm:()=>false}), job=deferred();
  a.context.decryptSecret=()=>job.promise;
  const pending=a.click('decrypt-btn');
  a.context.location.hash='#QRSEC:'+next;a.windowEvents.hashchange();
  job.resolve('ORIGINAL_PLAINTEXT');await pending;
  assert.equal(a.el('recv-value').textContent,'ORIGINAL_PLAINTEXT');
  assert.equal(a.run('incomingPayload.data'),packet);
});
test('invalid replacement does not interrupt pending encryption', async () => {
  const a=app(),job=deferred();a.context.encryptSecret=()=>job.promise;
  a.el('secret').value='keep pending';const pending=a.click('generate-btn');
  a.context.location.hash='#invalid';a.windowEvents.hashchange();
  job.resolve(packet);await pending;
  assert.match(a.el('qr-url').textContent,/#QRSEC5:/);
});
test('a late rejected wallet connection cannot overwrite a newer session', async () => {
  const job=deferred(), a=app({ethereum:{request:()=>job.promise}});
  const pending=a.click('send-wallet-connect-btn');await a.click('clear-btn');
  a.el('send-error').textContent='new session status';job.reject(new Error('late rejection'));await pending;
  assert.equal(a.el('send-error').textContent,'new session status');
});
test('double activation cannot launch a second encryption while one is pending', async () => {
  const a=app(),job=deferred();let calls=0;
  a.context.encryptSecret=()=>{calls++;return job.promise;};a.el('secret').value='one operation';
  const first=a.click('generate-btn');await a.click('generate-btn');
  assert.equal(calls,1);job.resolve(packet);await first;
});
for(const [label,secret] of [['ASCII overflow','a'.repeat(1501)],['UTF-8 overflow','🔐'.repeat(376)]])
  test(`sender rejects ${label} before encryption`,async()=>{
    const a=app();let calls=0;a.context.encryptSecret=async()=>{calls++;return packet;};
    a.el('secret').value=secret;await a.click('generate-btn');
    assert.equal(calls,0);assert.match(a.el('send-error').textContent,/1500 UTF-8 bytes/);
  });
test('sender accepts exactly 1500 UTF-8 bytes without truncation',async()=>{
  const a=app();const secret='字'.repeat(500);let received;
  a.context.encryptSecret=async value=>{received=value;return packet;};
  a.el('secret').value=secret;await a.click('generate-btn');
  assert.equal(received,secret);assert.match(a.el('qr-url').textContent,/#QRSEC5:/);
});
test('sender rejects passwords exceeding the documented size limit',async()=>{
  const a=app();let calls=0;a.context.encryptSecret=async()=>{calls++;return packet;};
  a.el('secret').value='test';a.el('send-passphrase').value='x'.repeat(1025);await a.click('generate-btn');
  assert.equal(calls,0);assert.match(a.el('send-error').textContent,/maximum 1024/);
});
test('sender passes the entire maximum-length password to encryption',async()=>{
  const a=app();const pass='a'.repeat(1023)+'Z';let received;
  a.context.encryptSecret=async(_,value)=>{received=value;return packet;};
  a.el('secret').value='test';a.el('send-passphrase').value=pass;await a.click('generate-btn');
  assert.equal(received,pass);
});
test('sender preserves leading and trailing secret whitespace',async()=>{
  const a=app();let received;a.context.encryptSecret=async value=>{received=value;return packet;};
  a.el('secret').value=' \tsecret\n ';await a.click('generate-btn');assert.equal(received,' \tsecret\n ');
});
test('failed repeat decryption removes previously displayed plaintext',async()=>{
  const a=app({hash:'#QRSEC:'+packet});a.el('recv-passphrase').value='old';await a.click('decrypt-btn');
  await a.click('reveal-btn');a.el('recv-passphrase').value='incorrect';await a.click('decrypt-btn');
  assert.equal(a.el('recv-value').textContent,'');assert.equal(a.el('recv-result').style.display,'none');
  assert.match(a.el('recv-error').textContent,/Decryption failed/);
});
test('clipboard permission failure never reports a successful secret copy',async()=>{
  const a=app();a.el('recv-value').textContent='dummy';
  a.context.navigator.clipboard.writeText=async()=>{throw new Error('denied');};
  await a.click('copy-btn');assert.match(a.el('clipboard-status').textContent,/No copy was confirmed/);
});
test('clipboard clear failure never claims clipboard erasure',async()=>{
  const a=app();a.context.navigator.clipboard.writeText=async()=>{throw new Error('denied');};
  await a.click('clear-clipboard-btn');assert.match(a.el('clipboard-status').textContent,/could not clear/);
});
test('missing clipboard API fails visibly without leaking plaintext into the error',async()=>{
  const a=app();a.context.navigator.clipboard=undefined;a.el('recv-value').textContent='DO_NOT_LOG_ME';
  await a.click('copy-btn');assert.match(a.el('clipboard-status').textContent,/failed/);
  assert.doesNotMatch(a.el('clipboard-status').textContent,/DO_NOT_LOG_ME/);
});
test('new input after idle expiry starts a fresh expiring session',()=>{
  const a=app();a.el('secret').value='old';a.advance(120000);a.windowEvents.focus();
  a.documentEvents.input({});a.el('secret').value='new';a.advance(120000);a.windowEvents.focus();
  assert.equal(a.el('secret').value,'');
});
test('foreground activity does not extend an existing background deadline',()=>{
  const a=app();a.el('secret').value='background';a.context.document.hidden=true;a.documentEvents.visibilitychange();
  a.advance(20000);a.documentEvents.input({});a.advance(10000);a.documentEvents.resume();
  assert.equal(a.el('secret').value,'');
});
test('clearing an expired session also discards the pending incoming packet',async()=>{
  const a=app({hash:'#QRSEC:'+packet});a.advance(120000);a.windowEvents.focus();
  a.el('recv-passphrase').value='old';await a.click('decrypt-btn');
  assert.equal(a.el('recv-value').textContent,'');assert.equal(a.el('decrypt-btn').style.display,'none');
});
test('all sensitive fields opt out of spelling and text correction in actual markup',()=>{
  for(const id of ['secret','send-passphrase','recv-passphrase']) {
    const tag=html.match(new RegExp('<(?:input|textarea)[^>]*id="'+id+'"[^>]*>'))[0];
    for(const attr of ['spellcheck="false"','autocorrect="off"','autocapitalize="off"']) assert.ok(tag.includes(attr),id+': '+attr);
    assert.ok(tag.includes(id==='secret'?'autocomplete="off"':'autocomplete="one-time-code"'));
  }
});
test('revealing either passphrase is reversed by backgrounding',()=>{
  const a=app();for(const id of ['send-passphrase','recv-passphrase']) a.toggles.find(x=>x.dataset.target===id).handlers.click();
  a.context.document.hidden=true;a.documentEvents.visibilitychange();
  assert.equal(a.el('send-passphrase').type,'password');assert.equal(a.el('recv-passphrase').type,'password');
});
