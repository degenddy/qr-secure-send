'use strict';
// Re-pin the exact inline application script after editing index.html.
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const file = path.join(__dirname, '..', 'index.html');
const html = fs.readFileSync(file, 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
if (scripts.length !== 1) throw new Error('Expected exactly one inline application script.');
const digest = createHash('sha256').update(scripts[0][1]).digest('base64');
const next = html.replace(/script-src 'sha256-[^']+'/, "script-src 'sha256-" + digest + "'");
if (next === html) console.log('CSP fingerprint already matches.');
else { fs.writeFileSync(file, next); console.log('Updated inline application CSP fingerprint.'); }
