#!/usr/bin/env node

const http = require("http");
const fs = require("fs");
const path = require("path");

const port = process.argv[2] || 3000;
const file = path.join(__dirname, "index.html");
const html = fs.readFileSync(file);

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
});

server.listen(port, () => {
  console.log(`QR Secure Send running at http://localhost:${port}`);
});
