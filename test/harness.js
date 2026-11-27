// Loads src/*.js into one VM context, the way the pages inline them.
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const EXPORTS = ['ED', 'P256', 'KEY_TYPES', 'prepareKey', 'parsePrivateKey', 'inspectPrivateKey', 'signRing',
  'verifyRing', 'armor', 'dearmor', 'parseLogins', 'fetchRingUser', 'fetchUserById', 'ZsError', 'b64enc', 'b64dec',
  'toHex', 'fromHex', 'bcryptPbkdf', 'md5', 'bytesToBig', 'bigToBytes', 'modpow', 'ed25519ScalarFromSeed', 'sha256'];

function load(extraGlobals = {}) {
  const dir = path.join(__dirname, '..', 'src');
  const src = fs.readdirSync(dir).filter((f) => f.endsWith('.js')).sort()
    .map((f) => fs.readFileSync(path.join(dir, f), 'utf8')).join('\n');
  const ctx = vm.createContext(Object.assign({
    crypto: globalThis.crypto, TextEncoder, TextDecoder, console, Uint8Array, fetch: globalThis.fetch,
  }, extraGlobals));
  const names = EXPORTS.map((n) => `${n}: typeof ${n} === 'undefined' ? undefined : ${n}`).join(',');
  vm.runInContext(src + `\n;globalThis.__z = {${names}};`, ctx, { filename: 'core.js' });
  return ctx.__z;
}

let failures = 0, passes = 0;
async function test(name, fn) {
  try { await fn(); passes++; console.log('  ok  ' + name); } catch (e) { failures++; console.log('  FAIL ' + name + '\n       ' + (e && e.stack || e)); }
}
function assert(c, m) { if (!c) throw new Error('assertion failed: ' + (m || '')); }
async function rejects(p, re) {
  try { await p; } catch (e) { if (re && !re.test(e.message)) throw new Error('wrong error: ' + e.message); return e; }
  throw new Error('expected rejection');
}
function summary() { console.log(`\n${passes} passed, ${failures} failed`); process.exitCode = failures ? 1 : 0; }

// Test-only npm modules: from node_modules, or a global install.
function need(name) {
  try { return require(name); } catch (e) { return require('/opt/npm-tools/node_modules/' + name); }
}

module.exports = { need, load, test, assert, rejects, summary };
