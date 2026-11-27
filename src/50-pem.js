// RSA in openssh-key-v1, and the older PEM formats: PKCS#1 RSA, SEC1 EC,
// unencrypted PKCS#8, and legacy "Proc-Type: 4,ENCRYPTED" PEM.

PRIVATE_TYPES['ssh-rsa'] = async (r) => {
  const n = r.mpint(), e = r.mpint(), d = r.mpint();
  r.mpint(); // iqmp, recomputed
  const p = r.mpint(), q = r.mpint();
  return rsaPrivate(n, e, d, p, q);
};

// Minimal DER reader.
function derRead(u8, o = 0) {
  if (o + 2 > u8.length) fail('The key is damaged.');
  const tag = u8[o];
  let len = u8[o + 1], hdr = 2;
  if (len & 0x80) {
    const nb = len & 0x7f;
    if (nb < 1 || nb > 3 || o + 2 + nb > u8.length) fail('The key is damaged.');
    len = 0;
    for (let i = 0; i < nb; i++) len = (len << 8) | u8[o + 2 + i];
    hdr += nb;
  }
  if (o + hdr + len > u8.length) fail('The key is damaged.');
  return { tag, value: u8.subarray(o + hdr, o + hdr + len), end: o + hdr + len };
}
function derSeq(u8) {
  const out = [];
  for (let o = 0; o < u8.length;) { const t = derRead(u8, o); out.push(t); o = t.end; }
  return out;
}
const derInt = (t) => { if (t.tag !== 2) fail('The key is damaged.'); return bytesToBig(t.value); };
const OID_RSA = '2a864886f70d010101', OID_EC = '2a8648ce3d0201', OID_P256 = '2a8648ce3d030107', OID_ED25519 = '2b6570';

async function rsaFromPkcs1(der) {
  const s = derSeq(derRead(der).value);
  if (s.length < 9) fail('The RSA key is damaged.');
  const [, n, e, d, p, q] = s.map((t) => derInt(t));
  return Object.assign(await rsaPrivate(n, e, d, p, q), { type: 'ssh-rsa' });
}

function ecFromSec1(der, outerCurveOid) {
  const s = derSeq(derRead(der).value);
  if (s.length < 2 || s[1].tag !== 4) fail('The EC key is damaged.');
  let curve = outerCurveOid;
  for (const t of s.slice(2)) if (t.tag === 0xa0) curve = toHex(derRead(t.value).value);
  if (curve && curve !== OID_P256) fail('Only P-256 EC keys are supported.');
  let pubBytes = null;
  for (const t of s.slice(2)) if (t.tag === 0xa1) pubBytes = derRead(t.value).value.subarray(1); // BIT STRING
  return Object.assign(p256Private(bytesToBig(s[1].value), pubBytes), { type: 'ecdsa-sha2-nistp256' });
}

async function fromPkcs8(der) {
  const s = derSeq(derRead(der).value);
  if (s.length < 3 || s[1].tag !== 0x30 || s[2].tag !== 4) fail('The key is damaged.');
  const alg = derSeq(s[1].value);
  const oid = toHex(alg[0].value);
  if (oid === OID_RSA) return rsaFromPkcs1(s[2].value);
  if (oid === OID_EC) return ecFromSec1(s[2].value, alg[1] ? toHex(alg[1].value) : null);
  if (oid === OID_ED25519) {
    const seed = derRead(s[2].value).value;
    if (seed.length !== 32) fail('The Ed25519 key is damaged.');
    const x = await ed25519ScalarFromSeed(seed);
    const pub = ED.encode(ED.mul(ED.G, x));
    return { id: 'ed25519:' + toHex(pub), sec: { x }, blob: concatBytes(sshString('ssh-ed25519'), sshString(pub)), type: 'ssh-ed25519' };
  }
  fail('Unsupported key type in PKCS#8 file.');
}

PEM_FORMATS['RSA PRIVATE KEY'] = rsaFromPkcs1;
PEM_FORMATS['EC PRIVATE KEY'] = (der) => ecFromSec1(der, null);
PEM_FORMATS['PRIVATE KEY'] = fromPkcs8;

const LEGACY_CIPHERS = { 'AES-128-CBC': 16, 'AES-256-CBC': 32 };

async function parsePemPrivateKey(pem, passphrase) {
  let der = pem.bytes;
  if (pem.headers['Proc-Type'] === '4,ENCRYPTED') {
    const [name, ivHex] = (pem.headers['DEK-Info'] || '').split(',');
    const keyLen = LEGACY_CIPHERS[name];
    if (!keyLen) fail('This key is encrypted with ' + (name || 'an unknown cipher') + ', which isn\'t supported. Convert it with: ssh-keygen -p -f yourkey');
    const iv = fromHex(ivHex.trim());
    // EVP_BytesToKey with MD5, one iteration, salt = first 8 bytes of the IV.
    const pass = te.encode(passphrase);
    let k = new Uint8Array(0), prev = new Uint8Array(0);
    while (k.length < keyLen) { prev = md5(concatBytes(prev, pass, iv.subarray(0, 8))); k = concatBytes(k, prev); }
    const key = await crypto.subtle.importKey('raw', k.subarray(0, keyLen), { name: 'AES-CBC' }, false, ['decrypt']);
    try {
      der = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, der));
    } catch (e) { fail('Wrong passphrase.'); }
    try { derRead(der); } catch (e) { fail('Wrong passphrase.'); }
  }
  try {
    return await PEM_FORMATS[pem.label](der);
  } catch (e) {
    if (e instanceof ZsError && pem.headers['Proc-Type']) fail('Wrong passphrase.');
    throw e;
  }
}

// MD5 (RFC 1321), only for legacy PEM key derivation.
function md5(msg) {
  const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32);
  const len = msg.length, padLen = ((len + 8) >> 6 << 6) + 64;
  const buf = new Uint8Array(padLen);
  buf.set(msg); buf[len] = 0x80;
  const bits = len * 8;
  for (let i = 0; i < 8; i++) buf[padLen - 8 + i] = Math.floor(bits / 2 ** (8 * i)) & 255;
  const dv = new DataView(buf.buffer);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let off = 0; off < padLen; off += 64) {
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + dv.getUint32(off + g * 4, true)) | 0;
      A = D; D = C; C = B;
      const s = S[(i >> 4) * 4 + (i & 3)];
      B = (B + ((F << s) | (F >>> (32 - s)))) | 0;
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
  }
  const out = new Uint8Array(16), ov = new DataView(out.buffer);
  [a0, b0, c0, d0].forEach((w, i) => ov.setUint32(i * 4, w >>> 0, true));
  return out;
}
