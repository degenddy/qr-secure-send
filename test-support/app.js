// Minimal deterministic DOM/lifecycle harness. Real browser checks are separate.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto, pbkdf2Sync, createCipheriv } = require('node:crypto');
const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const source = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const script = new vm.Script(source);

function app({ hash = '', ethereum, confirm = () => false, masking = true, prepare = () => {} } = {}) {
  const elements = new Map();
  const timers = new Map();
  const frames = new Map();
  const documentEvents = {};
  const windowEvents = {};
  let timerId = 0;
  let wallTime = 1000000;
  let monotonicTime = 0;
  class TestDate extends Date { static now() { return wallTime; } }
  function element(id = '') {
    const classes = new Set();
    return { id, value: '', textContent: '', style: {}, type: 'password', hidden: false,
      disabled: false, checked: false, integrity: '', dataset: {}, handlers: {}, children: [],
      classList: { add: x => classes.add(x), remove: x => classes.delete(x),
        contains: x => classes.has(x), toggle: (x, on) => on ? classes.add(x) : classes.delete(x) },
      addEventListener(name, fn) { this.handlers[name] = fn; },
      appendChild(child) { this.children.push(child); }, replaceChildren() { this.children = []; },
      removeAttribute(name) { delete this[name]; }, setAttribute(name, val) { this[name] = val; },
      remove() { this.removed = true; },
      play: async () => {}, videoWidth: 0, videoHeight: 0,
      getContext: () => ({ fillRect() {}, drawImage() {}, getImageData: () => ({data: [], width: 1, height: 1}) }),
    };
  }
  for (const match of html.matchAll(/id="([^"]+)"/g)) elements.set(match[1], element(match[1]));
  elements.get('secret').type = 'textarea';
  elements.get('conceal-length').checked = true;
  elements.get('secret').disabled = true;
  elements.get('secret').dataset.revealed = 'false';
  const tabs = ['send', 'receive'].map(name => Object.assign(element(), { dataset: { tab: name } }));
  const toggles = ['secret', 'send-passphrase', 'recv-passphrase', 'recv-recovery-key'].map(target =>
    Object.assign(element(), { dataset: { target } }));
  const panels = [elements.get('send'), elements.get('receive')];
  const head = element();
  const location = { hash, pathname: '/', search: '', origin: 'http://127.0.0.1:3037', protocol: 'http:' };
  const context = {
    crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, btoa, atob, URL, console,
    Date: TestDate, performance: { now: () => monotonicTime },
    setTimeout(fn, ms) { const id = ++timerId; timers.set(id, { fn, ms }); return id; },
    clearTimeout(id) { timers.delete(id); },
    requestAnimationFrame(fn) { const id = ++timerId; frames.set(id, fn); return id; },
    cancelAnimationFrame(id) { frames.delete(id); },
    location, history: { replaceState() { location.hash = ''; } },
    document: { head, body: Object.assign(element(), { hidden: true }), hidden: false,
      createElement: () => element(), getElementById: id => elements.get(id),
      querySelectorAll: selector => selector === '.tab-btn' ? tabs : selector === '.panel' ? panels : selector === '.toggle-vis' ? toggles : [],
      addEventListener: (name, fn) => { documentEvents[name] = fn; } },
    window: { ethereum, confirm, CSS: { supports: () => masking },
      addEventListener: (name, fn) => { windowEvents[name] = fn; } },
    navigator: { clipboard: { async writeText() {} } },
  };
  context.window.self = context.window;
  context.window.top = context.window;
  prepare(context);
  vm.createContext(context);
  script.runInContext(context);
  return { context, elements, timers, documentEvents, windowEvents, head, toggles, tabs, frames,
    advance(ms, { wall = true, monotonic = true } = {}) {
      if (wall) wallTime += ms;
      if (monotonic) monotonicTime += ms;
    },
    run: code => vm.runInContext(code, context),
    click: id => elements.get(id).handlers.click(),
    el: id => elements.get(id),
  };
}

function legacyFixture(password, text) {
  const salt = Buffer.alloc(16, 7), iv = Buffer.alloc(12, 9);
  const key = pbkdf2Sync(password, salt, 310000, 32, 'sha256');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return Buffer.concat([salt, iv, encrypted, cipher.getAuthTag()]).toString('base64');
}


module.exports = { app, legacyFixture, html, source };
