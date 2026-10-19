const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createServer } = require('./cli');
const { html } = require('./test-support/app');
let server,port;
before(async()=>{server=createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});port=server.address().port;});
after(async()=>{if(server?.listening) await new Promise(resolve=>server.close(resolve));});
function request({path='/',method='GET',host=`127.0.0.1:${port}`,headers={}}={}) {
  return new Promise((resolve,reject)=>{
    const req=http.request({hostname:'127.0.0.1',port,path,method,setHost:false,headers:{host,...headers}},res=>{
      const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks).toString()}));
    });req.on('error',reject);req.end();
  });
}
test('HTTP serves exact reviewed HTML on loopback',async()=>{
  const r=await request();assert.equal(r.status,200);assert.equal(r.body,html);assert.equal(server.address().address,'127.0.0.1');
});
test('HTTP HEAD returns protection headers without an application body',async()=>{
  const r=await request({method:'HEAD'});assert.equal(r.status,200);assert.equal(r.body,'');assert.equal(r.headers['cache-control'],'no-store');
});
for(const path of ['/index.html','/?v=2.1.0']) test(`HTTP supports intended entry point ${path}`,async()=>{
  const r=await request({path});assert.equal(r.status,200);assert.equal(r.body,html);
});
for(const [name,host] of [
  ['external origin','attacker.example'],['localhost suffix','localhost.attacker.example'],
  ['loopback suffix','127.0.0.1.attacker.example'],['userinfo disguise','attacker@127.0.0.1'],
  ['wildcard address','0.0.0.0'],['empty Host',''],
]) test(`HTTP refuses ${name} Host`,async()=>{
  const r=await request({host});assert.equal(r.status,403);assert.ok(!r.body.includes('<script>'));
});
for(const method of ['POST','PUT','DELETE','OPTIONS','TRACE']) test(`HTTP rejects ${method} without executing actions`,async()=>{
  const r=await request({method});assert.equal(r.status,405);assert.equal(r.headers.allow,'GET, HEAD');assert.equal(r.body,'');
});
for(const [name,path] of [
  ['Git metadata','/.git/config'],['parent traversal','/../package.json'],
  ['encoded traversal','/%2e%2e/package.json'],['source disclosure','/cli.js'],['dependency metadata','/package-lock.json'],
]) test(`HTTP rejects ${name}`,async()=>{
  const r=await request({path});assert.equal(r.status,404);assert.equal(r.body,'');
});
test('HTTP security policy blocks framing, network exfiltration, forms and MIME sniffing',async()=>{
  const r=await request();assert.equal(r.headers['x-frame-options'],'DENY');assert.equal(r.headers['x-content-type-options'],'nosniff');
  for(const directive of ["frame-ancestors 'none'","connect-src 'none'","form-action 'none'","base-uri 'none'","object-src 'none'"])
    assert.ok(r.headers['content-security-policy'].includes(directive),directive);
  assert.equal(r.headers['referrer-policy'],'no-referrer');assert.match(r.headers['permissions-policy'],/microphone=\(\)/);
});
test('HTTP denial responses remain uncached and protected from framing',async()=>{
  for(const options of [{host:'attacker.example'},{path:'/unknown'},{method:'POST'}]){
    const r=await request(options);assert.equal(r.headers['cache-control'],'no-store');assert.equal(r.headers['x-frame-options'],'DENY');
  }
});
test('HTTP does not trust forwarded Host headers over the actual Host',async()=>{
  const r=await request({host:'attacker.example',headers:{'x-forwarded-host':'localhost'}});assert.equal(r.status,403);
});
