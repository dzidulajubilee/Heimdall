// Node test for frontend/skin-loader.js skin resolution (no browser needed).
// Usage: node tests/skin_loader.test.js   — exits non-zero on failure.
'use strict';
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');
const SRC = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'skin-loader.js'), 'utf8');

function el() {
  return { style: {}, children: [], dataset: {},
    appendChild(c) { this.children.push(c); if (c.onload) setTimeout(c.onload, 0); return c; },
    setAttribute() {}, addEventListener() {}, remove() {}, contains() { return false; } };
}
async function run({ stored, fetchImpl }) {
  const head = el(), body = el(), fetched = [];
  const document = {
    readyState: 'complete', head, body,
    getElementById: () => null,
    createElement: () => el(), createElementNS: () => el(), createTextNode: () => el(),
    addEventListener() {},
  };
  const localStorage = { getItem: () => stored, setItem() {} };
  const fetch = (u, o) => { fetched.push(u); return fetchImpl(u, o); };
  vm.runInNewContext(SRC, { document, localStorage, fetch, location: {}, console, setTimeout, Promise });
  await new Promise(r => setTimeout(r, 30));
  const css = head.children.find(c => c.rel === 'stylesheet');
  return { skin: css && css.href.split('/')[3], fetched };
}
const ok = (skin) => () => Promise.resolve({ ok: true, json: () => Promise.resolve({ skin }) });

(async () => {
  let r = await run({ stored: 'mosaic', fetchImpl: ok('seal') });
  assert.deepStrictEqual([r.skin, r.fetched], ['mosaic', []], 'browser choice wins, no request');

  r = await run({ stored: null, fetchImpl: ok('seal') });
  assert.deepStrictEqual([r.skin, r.fetched], ['seal', ['/skin']], 'server default used');

  r = await run({ stored: 'bogus', fetchImpl: ok('chronicles') });
  assert.strictEqual(r.skin, 'chronicles', 'invalid stored value ignored');

  r = await run({ stored: null, fetchImpl: ok('not-a-skin') });
  assert.strictEqual(r.skin, 'original', 'unknown server value -> built-in default');

  r = await run({ stored: null, fetchImpl: () => Promise.reject(new Error('down')) });
  assert.strictEqual(r.skin, 'original', 'network failure -> built-in default');

  r = await run({ stored: null, fetchImpl: () => Promise.resolve({ ok: false }) });
  assert.strictEqual(r.skin, 'original', 'HTTP error -> built-in default');
  console.log('skin-loader: 6 checks passed');
})().catch(e => { console.error(e.message); process.exit(1); });
