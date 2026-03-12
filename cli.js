#!/usr/bin/env node

const { execSync } = require("child_process");
const path = require("path");

const dir = path.resolve(__dirname);
const port = process.argv[2] || 3000;

console.log(`QR Secure Send running at http://localhost:${port}`);

try {
  execSync(`npx serve -l ${port} "${dir}"`, { stdio: "inherit" });
} catch (_) {
  // user pressed Ctrl+C
}
