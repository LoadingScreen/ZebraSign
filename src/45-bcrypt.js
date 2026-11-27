// bcrypt_pbkdf as used by OpenSSH (port of OpenBSD bcrypt_pbkdf.c), and
// decryption of passphrase-protected openssh-key-v1 keys.

// Blowfish's initial P-array and S-boxes are the first 1042 32-bit words of
// pi's fractional hex digits. Computed once with Machin's formula.
let BF_INIT = null;
function blowfishInit() {
  if (BF_INIT) return BF_INIT;
  const words = 18 + 4 * 256, bits = BigInt(words * 32 + 64);
  const one = 1n << bits;
  const atanInv = (x) => { // arctan(1/x) * 2^bits
    const x2 = x * x;
    let term = one / x, sum = term, k = 1n, sign = -1n;
    while (term > 0n) {
      term /= x2; k += 2n;
      sum += sign * (term / k); sign = -sign;
    }
    return sum;
  };
  const pi = 16n * atanInv(5n) - 4n * atanInv(239n);
  const frac = (pi % one) >> 64n; // drop guard bits
  const out = new Uint32Array(words);
  for (let i = 0; i < words; i++) out[i] = Number((frac >> BigInt((words - 1 - i) * 32)) & 0xffffffffn);
  if (out[0] !== 0x243f6a88 || out[18] !== 0xd1310ba6 || out[words - 1] !== 0x3ac372e6) throw new Error('Blowfish init failed');
  BF_INIT = out;
  return out;
}

function bfState() {
  const init = blowfishInit();
  return { P: init.slice(0, 18), S: init.slice(18) }; // S: four boxes, 256 each
}

function bfEncipher(st, d, i) {
  const P = st.P, S = st.S;
  let l = d[i], r = d[i + 1];
  l ^= P[0];
  for (let n = 1; n <= 16; n += 2) {
    r ^= (((S[l >>> 24] + S[256 | ((l >>> 16) & 255)]) ^ S[512 | ((l >>> 8) & 255)]) + S[768 | (l & 255)]) ^ P[n];
    l ^= (((S[r >>> 24] + S[256 | ((r >>> 16) & 255)]) ^ S[512 | ((r >>> 8) & 255)]) + S[768 | (r & 255)]) ^ P[n + 1];
  }
  d[i] = r ^ P[17];
  d[i + 1] = l;
}

function streamWord(data, pos) {
  let w = 0;
  for (let i = 0; i < 4; i++) { w = (w << 8) | data[pos.j]; pos.j = (pos.j + 1) % data.length; }
  return w >>> 0;
}

// Blowfish_expandstate when data is given, Blowfish_expand0state otherwise.
function bfExpand(st, key, data) {
  const kp = { j: 0 }, dp = { j: 0 };
  for (let i = 0; i < 18; i++) st.P[i] ^= streamWord(key, kp);
  const d = new Uint32Array(2);
  for (let i = 0; i < 18; i += 2) {
    if (data) { d[0] ^= streamWord(data, dp); d[1] ^= streamWord(data, dp); }
    bfEncipher(st, d, 0);
    st.P[i] = d[0]; st.P[i + 1] = d[1];
  }
  for (let i = 0; i < 1024; i += 2) {
    if (data) { d[0] ^= streamWord(data, dp); d[1] ^= streamWord(data, dp); }
    bfEncipher(st, d, 0);
    st.S[i] = d[0]; st.S[i + 1] = d[1];
  }
}

const BCRYPT_MAGIC = te.encode('OxychromaticBlowfishSwatDynamite');

function bcryptHash(sha2pass, sha2salt) {
  const st = bfState();
  bfExpand(st, sha2pass, sha2salt);
  for (let i = 0; i < 64; i++) { bfExpand(st, sha2salt, null); bfExpand(st, sha2pass, null); }
  const cdata = new Uint32Array(8);
  const pos = { j: 0 };
  for (let i = 0; i < 8; i++) cdata[i] = streamWord(BCRYPT_MAGIC, pos);
  for (let i = 0; i < 64; i++) for (let b = 0; b < 8; b += 2) bfEncipher(st, cdata, b);
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[4 * i] = cdata[i] & 255; out[4 * i + 1] = (cdata[i] >>> 8) & 255;
    out[4 * i + 2] = (cdata[i] >>> 16) & 255; out[4 * i + 3] = cdata[i] >>> 24;
  }
  return out;
}

async function bcryptPbkdf(pass, salt, keylen, rounds) {
  if (rounds < 1 || keylen < 1 || keylen > 1024) throw new Error('bad bcrypt_pbkdf parameters');
  const stride = Math.ceil(keylen / 32);
  let amt = Math.ceil(keylen / stride);
  const key = new Uint8Array(keylen);
  const sha2pass = await sha512(pass);
  let remaining = keylen;
  for (let count = 1; remaining > 0; count++) {
    let sha2salt = await sha512(concatBytes(salt, u32be(count)));
    let tmp = bcryptHash(sha2pass, sha2salt);
    const out = Uint8Array.from(tmp);
    for (let i = 1; i < rounds; i++) {
      sha2salt = await sha512(tmp);
      tmp = bcryptHash(sha2pass, sha2salt);
      for (let j = 0; j < 32; j++) out[j] ^= tmp[j];
    }
    amt = Math.min(amt, remaining);
    let i = 0;
    for (; i < amt; i++) {
      const dest = i * stride + (count - 1);
      if (dest >= keylen) break;
      key[dest] = out[i];
    }
    remaining -= i;
  }
  return key;
}

// OpenSSH cipher name -> WebCrypto parameters.
const SSH_CIPHERS = {
  'aes256-ctr': { alg: 'AES-CTR', keyLen: 32, ivLen: 16 },
  'aes128-ctr': { alg: 'AES-CTR', keyLen: 16, ivLen: 16 },
  'aes256-gcm@openssh.com': { alg: 'AES-GCM', keyLen: 32, ivLen: 12, tagLen: 16 },
  'aes128-gcm@openssh.com': { alg: 'AES-GCM', keyLen: 16, ivLen: 12, tagLen: 16 },
  'aes256-cbc': { alg: 'AES-CBC', keyLen: 32, ivLen: 16 },
  'aes128-cbc': { alg: 'AES-CBC', keyLen: 16, ivLen: 16 },
};

// AES with no padding handling: OpenSSH pads the plaintext itself.
async function aesDecrypt(ci, keyBytes, iv, data) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: ci.alg }, false, ['decrypt', 'encrypt']);
  if (ci.alg === 'AES-CTR') {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CTR', counter: iv, length: 128 }, key, data));
  }
  if (ci.alg === 'AES-GCM') {
    try {
      return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, data));
    } catch (e) { return null; } // tag mismatch: wrong passphrase
  }
  // AES-CBC: WebCrypto insists on PKCS#7 padding. Encrypt a full padding block
  // under the last ciphertext block and append it, so decrypt strips exactly that.
  if (data.length % 16) return null;
  const last = data.length ? data.subarray(data.length - 16) : iv;
  const pad = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: last }, key, new Uint8Array(0)));
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, concatBytes(data, pad)));
}

async function opensshDecrypt(h, passphrase) {
  const ci = SSH_CIPHERS[h.cipher];
  if (!ci) fail('This key uses the ' + h.cipher + ' cipher, which isn\'t supported. Re-encrypt it with: ssh-keygen -p -Z aes256-ctr -f yourkey');
  if (h.kdf !== 'bcrypt') fail('Unsupported key derivation: ' + h.kdf + '.');
  const r = new SshReader(h.kdfopts);
  const salt = r.string(), rounds = r.u32();
  if (rounds > 1000) fail('This key uses ' + rounds + ' bcrypt rounds; more than 1000 isn\'t supported.');
  const k = await bcryptPbkdf(te.encode(passphrase), salt, ci.keyLen + ci.ivLen, rounds);
  let data = h.priv;
  if (ci.tagLen) {
    if (h.rest.length < ci.tagLen) fail('The key is damaged.');
    data = concatBytes(h.priv, h.rest.subarray(0, ci.tagLen));
  }
  const plain = await aesDecrypt(ci, k.subarray(0, ci.keyLen), k.subarray(ci.keyLen), data);
  if (!plain) fail('Wrong passphrase.');
  return plain;
}
