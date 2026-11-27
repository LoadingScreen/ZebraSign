// ZebraSign core: byte helpers, encodings, hashing, bigint math.
'use strict';

const te = new TextEncoder();
const tdStrict = new TextDecoder('utf-8', { fatal: true });

function concatBytes(...arrs) {
  let n = 0;
  for (const a of arrs) n += a.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

function toHex(u8) {
  let s = '';
  for (const b of u8) s += b.toString(16).padStart(2, '0');
  return s;
}

function fromHex(s) {
  if (s.length % 2 || /[^0-9a-fA-F]/.test(s)) throw new Error('bad hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function b64enc(u8) {
  let s = '';
  let i = 0;
  for (; i + 2 < u8.length; i += 3) {
    const n = (u8[i] << 16) | (u8[i + 1] << 8) | u8[i + 2];
    s += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  if (i < u8.length) {
    const n = (u8[i] << 16) | ((i + 1 < u8.length ? u8[i + 1] : 0) << 8);
    s += B64[n >> 18] + B64[(n >> 12) & 63];
    s += i + 1 < u8.length ? B64[(n >> 6) & 63] + '=' : '==';
  }
  return s;
}

function b64dec(str) {
  const s = str.replace(/\s+/g, '');
  if (s.length % 4 === 1 || /[^A-Za-z0-9+/=]/.test(s) || /=[^=]/.test(s)) throw new Error('bad base64');
  const clean = s.replace(/=+$/, '');
  const out = new Uint8Array(Math.floor(clean.length * 3 / 4));
  let o = 0, acc = 0, bits = 0;
  for (const ch of clean) {
    acc = (acc << 6) | B64.indexOf(ch);
    bits += 6;
    if (bits >= 8) { bits -= 8; out[o++] = (acc >> bits) & 255; }
  }
  return out;
}

// Big-endian and little-endian bigint conversions.
function bytesToBig(u8) {
  let n = 0n;
  for (const b of u8) n = (n << 8n) | BigInt(b);
  return n;
}
function bigToBytes(n, len) {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) { out[i] = Number(n & 255n); n >>= 8n; }
  if (n !== 0n) throw new Error('number too large for field');
  return out;
}
function bytesToBigLE(u8) { return bytesToBig(Uint8Array.from(u8).reverse()); }
function bigToBytesLE(n, len) { return bigToBytes(n, len).reverse(); }

function bitLength(n) { return n === 0n ? 0 : n.toString(2).length; }
function byteLength(n) { return Math.ceil(bitLength(n) / 8); }

function mod(a, m) { const r = a % m; return r < 0n ? r + m : r; }

function modpow(b, e, m) {
  if (m === 1n) return 0n;
  let r = 1n;
  b = mod(b, m);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    e >>= 1n;
    if (e > 0n) b = (b * b) % m;
  }
  return r;
}

function egcd(a, b) {
  let [r0, r1] = [a, b], [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  return [r0, s0]; // gcd, x with a*x = gcd (mod b)
}

function modinv(a, m) {
  const [g, x] = egcd(mod(a, m), m);
  if (g !== 1n) throw new Error('not invertible');
  return mod(x, m);
}

function randBytes(n) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)));
  return out;
}

// Uniform-enough integer in [0, q): 128 extra bits make the bias negligible.
function randBelow(q) { return mod(bytesToBig(randBytes(byteLength(q) + 16)), q); }

async function sha256(u8) { return new Uint8Array(await crypto.subtle.digest('SHA-256', u8)); }
async function sha512(u8) { return new Uint8Array(await crypto.subtle.digest('SHA-512', u8)); }

// SSH wire format (RFC 4251).
class SshReader {
  constructor(u8) { this.b = u8; this.o = 0; }
  need(n) { if (this.o + n > this.b.length) throw new Error('truncated data'); }
  u32() { this.need(4); const b = this.b, o = this.o; this.o += 4; return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0; }
  bytes(n) { this.need(n); const r = this.b.subarray(this.o, this.o + n); this.o += n; return r; }
  string() { return this.bytes(this.u32()); }
  text() { return tdStrict.decode(this.string()); }
  mpint() {
    const s = this.string();
    if (s.length && s[0] & 0x80) throw new Error('negative mpint');
    return bytesToBig(s);
  }
  rest() { return this.b.subarray(this.o); }
  done() { return this.o === this.b.length; }
}

function u32be(n) { return Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255); }
function sshString(u8) { if (typeof u8 === 'string') u8 = te.encode(u8); return concatBytes(u32be(u8.length), u8); }
function sshMpint(n) {
  if (n === 0n) return sshString(new Uint8Array(0));
  let b = bigToBytes(n, byteLength(n));
  if (b[0] & 0x80) b = concatBytes(Uint8Array.of(0), b);
  return sshString(b);
}

// Plain-language error. The UI shows .message as is.
class ZsError extends Error {}
function fail(msg) { throw new ZsError(msg); }
