const { test } = require('node:test');
const assert = require('node:assert/strict');
const { app, legacyFixture } = require('./test-support/app');
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() { let resolve; const promise=new Promise(done=>{resolve=done;});return {promise,resolve}; }
function camera() { const record={stops:0};record.stream={getTracks:()=>[{stop(){record.stops++;}}]};return record; }
function native({acquire,detect=async()=>[],play=async()=>{}}={}) {
  return app({prepare(context){
    context.BarcodeDetector=context.window.BarcodeDetector=class {detect(...args){return detect(...args);}};
    context.navigator.mediaDevices={getUserMedia:acquire};
    const create=context.document.createElement;
    context.document.createElement=tag=>{const el=create(tag);if(tag==='video') el.play=play;return el;};
  }});
}
test('scanner coalesces concurrent integrity checks without creating scripts',async()=>{
  const a=app();const first=a.run('QRScan.loadJsQR()'),second=a.run('QRScan.loadJsQR()');
  assert.equal(first,second);assert.equal(a.head.children.length,0);
  const [scanner,other]=await Promise.all([first,second]);
  assert.equal(typeof scanner,'function');assert.equal(scanner,other);
  assert.equal(a.context.window.jsQR,undefined);
});
test('scanner refuses to initialize without Web Crypto verification',async()=>{
  const a=app();a.context.crypto={};
  await assert.rejects(a.run('QRScan.loadJsQR()'),/cannot verify/);
  assert.equal(a.head.children.length,0);assert.match(a.el('scanner-integrity-status').textContent,/Blocked/);
});
test('scanner fingerprint mismatch fails closed',async()=>{
  const a=app();a.context.crypto={subtle:{digest:async()=>new Uint8Array(48).buffer}};
  await assert.rejects(a.run('QRScan.loadJsQR()'),/fingerprint mismatch/);
  assert.doesNotMatch(a.el('scanner-integrity-status').textContent,/^Matched/);
});
test('failed scanner verification never asks for camera permission',async()=>{
  const a=app();let requests=0;a.context.navigator.mediaDevices={getUserMedia:async()=>{requests++;throw new Error('must not run');}};
  a.context.crypto={subtle:{digest:async()=>{throw new Error('verification failed');}}};
  await a.click('scan-btn');
  assert.equal(requests,0);assert.equal(a.el('scan-btn').disabled,false);
});
test('canceling pending scanner verification prevents later camera acquisition',async()=>{
  const a=app(),check=deferred(),crypto=a.context.crypto;let requests=0;
  a.context.crypto={subtle:{digest:async(...args)=>{await check.promise;return crypto.subtle.digest(...args);}}};
  a.context.navigator.mediaDevices={getUserMedia:async()=>{requests++;return camera().stream;}};
  const pending=a.click('scan-btn');await a.click('stop-btn');
  check.resolve();await pending;assert.equal(requests,0);
});
test('native scanner avoids fallback initialization',async()=>{
  const c=camera(),a=native({acquire:async()=>c.stream});
  a.context.crypto={subtle:{digest:async()=>{throw new Error('must not run');}}};
  await a.click('scan-btn');
  assert.equal(a.el('scan-btn').disabled,true);
  assert.equal(a.head.children.length,0);await a.click('stop-btn');assert.equal(c.stops,1);
});
test('camera permission rejection restores usable controls',async()=>{
  const a=native({acquire:async()=>{throw new Error('denied');}});await a.click('scan-btn');
  assert.match(a.el('recv-error').textContent,/Camera access denied/);
  assert.equal(a.el('scan-btn').disabled,false);assert.equal(a.el('stop-btn').style.display,'none');
});
test('camera preview failure stops acquired tracks',async()=>{
  const c=camera(),a=native({acquire:async()=>c.stream,play:async()=>{throw new Error('cannot play');}});
  await a.click('scan-btn');assert.equal(c.stops,1);assert.match(a.el('recv-error').textContent,/preview/);
});
test('reset while preview is pending closes camera and prevents scan scheduling',async()=>{
  const c=camera(),play=deferred(),a=native({acquire:async()=>c.stream,play:()=>play.promise});
  const pending=a.click('scan-btn');await tick();await a.click('clear-btn');play.resolve();await pending;
  assert.equal(c.stops,1);assert.equal(a.frames.size,0);
});
test('late camera permission after suspended expiry never starts preview',async()=>{
  const c=camera(),permission=deferred();let previews=0;
  const a=native({acquire:()=>permission.promise,play:async()=>{previews++;}});
  const pending=a.click('scan-btn');a.advance(120000);permission.resolve(c.stream);await pending;
  assert.equal(previews,0);assert.equal(c.stops,1);assert.equal(a.frames.size,0);
});
test('camera preview completing after suspended expiry stops tracks',async()=>{
  const c=camera(),play=deferred(),a=native({acquire:async()=>c.stream,play:()=>play.promise});
  const pending=a.click('scan-btn');await tick();a.advance(120000);play.resolve();await pending;
  assert.equal(c.stops,1);assert.equal(a.frames.size,0);
});
test('resumed scan loop enforces expiry even when no QR code is detected',async()=>{
  const c=camera(),a=native({acquire:async()=>c.stream});await a.click('scan-btn');a.advance(120000);
  const [id,frame]=a.frames.entries().next().value;a.frames.delete(id);await frame();
  assert.equal(c.stops,1);assert.equal(a.frames.size,0);
});
test('detector result after reset cannot install an incoming transfer',async()=>{
  const c=camera(),detection=deferred(),a=native({acquire:async()=>c.stream,detect:()=>detection.promise});
  await a.click('scan-btn');const [id,frame]=a.frames.entries().next().value;a.frames.delete(id);
  const pending=frame();await a.click('clear-btn');detection.resolve([{rawValue:'QRSEC2:'+Buffer.alloc(45).toString('base64')}]);
  await pending;assert.equal(a.run('incomingPayload'),null);assert.equal(c.stops,1);
});
test('scanning a wallet transfer never automatically requests a wallet signature',async()=>{
  const c=camera(),a=native({acquire:async()=>c.stream,detect:async()=>[{rawValue:'QRSECW3:'+'ab'.repeat(16)+':'+Buffer.alloc(45).toString('base64')}]});
  let calls=0;a.context.window.ethereum={request:async()=>{calls++;}};
  await a.click('scan-btn');const [id,frame]=a.frames.entries().next().value;a.frames.delete(id);await frame();
  assert.equal(calls,0);assert.equal(a.el('decrypt-btn').style.display,'inline-block');assert.equal(c.stops,1);
});
test('scanning a passwordless transfer automatically decrypts but does not reveal or copy',async()=>{
  const packet=legacyFixture('', 'DUMMY_SCANNED_SECRET'),c=camera();
  const a=native({acquire:async()=>c.stream,detect:async()=>[{rawValue:'QRSEC:'+packet}]});
  let copies=0;a.context.navigator.clipboard.writeText=async()=>{copies++;};
  await a.click('scan-btn');
  const [id,frame]=a.frames.entries().next().value;a.frames.delete(id);await frame();
  assert.equal(a.el('recv-value').textContent,'DUMMY_SCANNED_SECRET');
  assert.equal(a.el('recv-value').hidden,true);
  assert.equal(a.el('decrypt-btn').style.display,'none');
  assert.equal(copies,0);assert.equal(c.stops,1);
});
