const {test}=require('node:test');
const assert=require('node:assert/strict');
const {pbkdf2Sync,createCipheriv,createDecipheriv}=require('node:crypto');
const {app}=require('./test-support/app');
const a=app(),nonce='ab'.repeat(16),account='0x'+'12'.repeat(20);
const r='11'.repeat(32),s='22'.repeat(32),signature='0x'+r+s+'1b';
const order=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
function oracle(envelope,password='café') {
  const salt=Buffer.alloc(16,7),iv=Buffer.alloc(12,9);
  const key=pbkdf2Sync(password.normalize('NFC'),salt,600000,32,'sha256');
  const cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from('QR Secure Send v4'));
  return Buffer.concat([salt,iv,cipher.update(envelope),cipher.final(),cipher.getAuthTag()]).toString('base64');
}
function envelope(text) {const bytes=Buffer.from(text);const out=Buffer.alloc(1504,0xa5);out.writeUInt32BE(bytes.length);bytes.copy(out,4);return out;}
function wallet(response=signature) {return {request:async({method})=>method==='eth_requestAccounts'?[account]:response};}
async function send({ethereum=wallet(),password=''}={}) {
  const sender=app({ethereum});await sender.click('send-wallet-connect-btn');
  sender.el('secret').value='DUMMY WALLET SECRET';sender.el('send-passphrase').value=password;
  sender.el('send-wallet-toggle').checked=true;await sender.click('generate-btn');return sender;
}

test('v4 decrypts an independent padded NFC OpenSSL fixture',async()=>{
  assert.equal(await a.context.decryptSecret(oracle(envelope('secret é\0🔐')),'cafe\u0301',4),'secret é\0🔐');
});
test('v4 output independently decrypts with a hidden length and exact 1504-byte envelope',async()=>{
  const text='e\u0301\0🔐',data=Buffer.from(await a.context.encryptSecret(text,'cafe\u0301',4),'base64');
  assert.equal(data.length,1548);
  const key=pbkdf2Sync('café',data.subarray(0,16),600000,32,'sha256');
  const cipher=createDecipheriv('aes-256-gcm',key,data.subarray(16,28));
  cipher.setAAD(Buffer.from('QR Secure Send v4'));cipher.setAuthTag(data.subarray(-16));
  const plain=Buffer.concat([cipher.update(data.subarray(28,-16)),cipher.final()]);
  assert.equal(plain.length,1504);assert.equal(plain.readUInt32BE(0),Buffer.byteLength(text));
  assert.equal(plain.subarray(4,4+plain.readUInt32BE(0)).toString(),text);
});
for(const [label,text]of [['empty',''],['one byte','x'],['12 words',Array(12).fill('abandon').join(' ')],['24 words',Array(24).fill('abandon').join(' ')],['maximum ASCII','x'.repeat(1500)],['maximum UTF-8','字'.repeat(500)]])
  test(`v4 hides ${label} length in the same packet size`,async()=>{
    const data=await a.context.encryptSecret(text,'',4);assert.equal(data.length,2064);
    assert.equal(await a.context.decryptSecret(data,'',4),text);
  });
for(const [left,right]of [['é','e\u0301'],['Å','A\u030a'],['각','각']])
  test(`v4 canonical password equivalents round trip: ${JSON.stringify(left)}`,async()=>{
    const data=await a.context.encryptSecret('unchanged secret',left,4);
    assert.equal(await a.context.decryptSecret(data,right,4),'unchanged secret');
  });
for(const other of ['café ',' café','CAFÉ','cafe','ｃａｆé'])test(`v4 does not fold distinct password ${JSON.stringify(other)}`,async()=>{
  await assert.rejects(a.context.decryptSecret(oracle(envelope('secret')),other,4));
});
for(const version of [1,2,3])test(`v4 cannot be relabelled as legacy v${version}`,async()=>{
  await assert.rejects(a.context.decryptSecret(oracle(envelope('secret')),'café',version));
});
for(const [label,make]of [
  ['oversized encrypted length',()=>{const x=envelope('s');x.writeUInt32BE(1501);return x;}],
  ['invalid UTF-8',()=>{const x=envelope('s');x[4]=0xff;return x;}],
  ['short envelope',()=>Buffer.alloc(1503)],['long envelope',()=>Buffer.alloc(1505)],
])test(`v4 rejects authenticated ${label}`,async()=>{await assert.rejects(a.context.decryptSecret(oracle(make()),'café',4));});
test('v4 rejects oversized plaintext before requesting a key',async()=>{
  const local=app();local.context.deriveKey=()=>{throw new Error('must not derive');};
  await assert.rejects(local.context.encryptSecret('🔐'.repeat(376),'',4),/1500/);
});
test('v4 parser accepts fixed-size password and wallet packets only',()=>{
  const data=Buffer.alloc(1548).toString('base64');
  for(const prefix of ['QRSEC4:','QRSECW4:'+nonce+':']){
    assert.equal(a.context.extractPayload(prefix+data).version,4);
    for(const size of [44,1547,1549])assert.equal(a.context.extractPayload(prefix+Buffer.alloc(size).toString('base64')),null);
  }
});
for(const [v,expected]of [['00','1b'],['01','1c'],['1B','1b'],['1C','1c']])test(`v4 canonicalizes recovery byte ${v}`,async()=>{
  const local=app({ethereum:wallet('0x'+r.toUpperCase()+s.toUpperCase()+v)});
  assert.equal(await local.context.getWalletSignature(account,nonce,4),'0x'+r+s+expected);
});
test('v4 canonicalizes the equivalent high-s and flipped parity signature',()=>{
  const high=(order-BigInt('0x'+s)).toString(16).padStart(64,'0');
  assert.equal(a.context.normalizeWalletSignature('0x'+r+high+'1c'),signature);
});
for(const parity of [0,1])test(`v4 supports ERC-2098 compact parity ${parity}`,()=>{
  const packed=(BigInt('0x'+s)|(BigInt(parity)<<255n)).toString(16).padStart(64,'0');
  assert.equal(a.context.normalizeWalletSignature('0x'+r+packed),'0x'+r+s+(27+parity).toString(16));
});
for(const [label,value]of [['invalid v','0x'+r+s+'02'],['zero r','0x'+'00'.repeat(32)+s+'1b'],['zero s','0x'+r+'00'.repeat(32)+'1b'],['out-of-range r','0x'+order.toString(16)+s+'1b'],['out-of-range s','0x'+r+order.toString(16)+'1b'],['contract-sized signature','0x'+'11'.repeat(96)]])
  test(`v4 rejects ${label}`,()=>{assert.throws(()=>a.context.normalizeWalletSignature(value));});
test('sender rejects changing signatures without clearing the original or publishing a QR',async()=>{
  let count=0;const sender=await send({ethereum:{request:async({method})=>method==='eth_requestAccounts'?[account]:(++count===1?signature:'0x'+'33'.repeat(32)+s+'1b')}});
  assert.equal(count,2);assert.equal(sender.el('secret').value,'DUMMY WALLET SECRET');
  assert.equal(sender.el('qr-url').textContent,'');assert.equal(sender.el('wallet-recovery-key').textContent,'');
  assert.match(sender.el('send-error').textContent,/changing signatures/);
});
test('sender rejects unsupported contract signatures before encryption',async()=>{
  const sender=await send({ethereum:wallet('0x'+'11'.repeat(96))});
  assert.equal(sender.el('qr-url').textContent,'');assert.match(sender.el('send-error').textContent,/Unsupported wallet signature/);
  assert.equal(sender.el('secret').value,'DUMMY WALLET SECRET');
});
test('wallet transfers work across normalized recovery byte representations',async()=>{
  const sender=await send();const receiver=app({hash:new URL(sender.el('qr-url').textContent).hash,ethereum:wallet('0x'+r+s+'00')});
  await receiver.click('recv-wallet-connect-btn');await receiver.click('decrypt-btn');
  assert.equal(receiver.el('recv-value').textContent,'DUMMY WALLET SECRET');
});
test('recovery key bypasses unavailable wallet but still requires the normalized password',async()=>{
  const sender=await send({password:'café'}),link=sender.el('qr-url').textContent,key=sender.el('wallet-recovery-key').textContent;
  assert.ok(key.startsWith('QRKEY5:'));assert.ok(!link.includes(key));assert.ok(!link.includes(signature));
  assert.equal(sender.el('wallet-recovery-key').hidden,true);
  const receiver=app({hash:new URL(link).hash});receiver.el('recv-recovery-key').value=key;
  await receiver.click('decrypt-btn');assert.equal(receiver.el('recv-value').textContent,'');
  receiver.el('recv-passphrase').value='cafe\u0301';await receiver.click('decrypt-btn');
  assert.equal(receiver.el('recv-value').textContent,'DUMMY WALLET SECRET');assert.equal(receiver.el('recv-recovery-key').value,'');
});
test('wallet-only recovery works without any provider',async()=>{
  const sender=await send(),receiver=app({hash:new URL(sender.el('qr-url').textContent).hash});
  receiver.el('recv-recovery-key').value=sender.el('wallet-recovery-key').textContent;await receiver.click('decrypt-btn');
  assert.equal(receiver.el('recv-value').textContent,'DUMMY WALLET SECRET');
});
test('recovery key is bound to its transfer nonce',()=>{
  const key=a.context.walletRecoveryKey(nonce,signature);
  assert.throws(()=>a.context.signatureFromRecoveryKey(key,'cd'.repeat(16)),/does not match/);
  assert.throws(()=>a.context.signatureFromRecoveryKey(key+'\n',nonce));
});
for(const action of ['reset','expiry','blur','switch tabs'])test(`recovery data respects ${action}`,async()=>{
  const sender=await send();await sender.click('reveal-recovery-btn');assert.equal(sender.el('wallet-recovery-key').hidden,false);
  sender.el('recv-recovery-key').value='dummy recovery input';sender.el('recv-recovery-key').dataset.revealed='true';
  if(action==='reset')await sender.click('clear-btn');
  if(action==='expiry'){sender.advance(120000);sender.windowEvents.focus();}
  if(action==='blur')sender.windowEvents.blur();
  if(action==='switch tabs')sender.tabs[1].handlers.click();
  assert.equal(sender.el('wallet-recovery-key').hidden,true);assert.equal(sender.el('recv-recovery-key').dataset.revealed,'false');
  if(action!=='blur'){assert.equal(sender.el('wallet-recovery-key').textContent,'');assert.equal(sender.el('recv-recovery-key').value,'');}
});
test('reset during the second signature prevents encryption and recovery display',async()=>{
  let count=0,resolve;const sender=app({ethereum:{request:async({method})=>method==='eth_requestAccounts'?[account]:(++count===1?signature:new Promise(done=>{resolve=done;}))}});
  await sender.click('send-wallet-connect-btn');sender.el('secret').value='pending';sender.el('send-wallet-toggle').checked=true;
  const pending=sender.click('generate-btn');await new Promise(done=>setImmediate(done));await sender.click('clear-btn');resolve(signature);await pending;
  assert.equal(sender.el('qr-url').textContent,'');assert.equal(sender.el('wallet-recovery-key').textContent,'');
});
