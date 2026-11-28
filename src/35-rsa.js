// RSA keys: Guillou-Quisquater proof of knowledge of an e-th root.
//
// Each key gets a fixed y = FDH(key) in Z_n. The proof is a single GQ round
// with exponent E = e^m, the smallest power of e that is at least 2^128, so the
// whole 128-bit challenge fits (m = 8 for e = 65537). The key's owner can
// compute the E-th root x = y^(d^m). Two accepting answers to one commitment
// still give an e-th root of y, so this is as hard to fake as the RSA key is to
// break. See PROTOCOL.md.

const SMALL_PRIMES = (() => {
  const lim = 4096, sieve = new Uint8Array(lim), out = [];
  for (let i = 2; i < lim; i++) if (!sieve[i]) { out.push(i); for (let j = i * i; j < lim; j += i) sieve[j] = 1; }
  return out;
})();

function isSmallPrime(e) { // e < 2^32, as a Number
  if (e < 2) return false;
  for (let i = 2; i * i <= e; i++) if (e % i === 0) return false;
  return true;
}

// Integer k-th root (floor) by Newton's method.
function iroot(n, k) {
  if (n < 2n) return n;
  const K = BigInt(k);
  let x = 1n << BigInt(Math.ceil(bitLength(n) / k));
  for (;;) {
    const y = ((K - 1n) * x + n / (x ** (K - 1n))) / K;
    if (y >= x) return x;
    x = y;
  }
}

// Rejects moduli that would let anyone compute e-th roots: primes, prime
// powers, and numbers with small factors. A real RSA modulus passes.
function checkModulus(n) {
  if (!(n & 1n)) return false;
  for (const p of SMALL_PRIMES) if (n % BigInt(p) === 0n) return false;
  // Fermat test base 2: a real modulus fails it, a prime passes.
  if (modpow(2n, n - 1n, n) === 1n) return false;
  const maxK = Math.floor(bitLength(n) / 12);
  for (const k of SMALL_PRIMES) {
    if (k > maxK) break;
    const r = iroot(n, k);
    if (r ** BigInt(k) === n) return false;
  }
  return true;
}

async function rsaFdh(blob, n) {
  const len = byteLength(n) + 16, parts = [];
  const tag = sshString(DOMAIN + '/rsa-fdh');
  for (let i = 0, got = 0; got < len; i++, got += 32) parts.push(await sha256(concatBytes(u32be(i), tag, sshString(blob))));
  return mod(bytesToBig(concatBytes(...parts).subarray(0, len)), n);
}

const randUnit = (n) => randBelow(n - 1n) + 1n;

const GQ = {
  simulate(pub, c) {
    const z = randUnit(pub.n);
    const t = (modpow(z, pub.E, pub.n) * modpow(pub.yinv, bytesToBig(c), pub.n)) % pub.n;
    return { t: bigToBytes(t, pub.k), z: bigToBytes(z, pub.k) };
  },
  commit(pub) {
    const r = randUnit(pub.n);
    return { t: bigToBytes(modpow(r, pub.E, pub.n), pub.k), st: r };
  },
  respond(pub, sec, r, c) {
    return bigToBytes((r * modpow(sec.x, bytesToBig(c), pub.n)) % pub.n, pub.k);
  },
  recompute(pub, c, z) {
    if (z.length !== pub.k) return null;
    const zz = bytesToBig(z);
    if (zz <= 0n || zz >= pub.n) return null;
    return bigToBytes((modpow(zz, pub.E, pub.n) * modpow(pub.yinv, bytesToBig(c), pub.n)) % pub.n, pub.k);
  },
  zLen(pub) { return pub.k; },
};

// Smallest m with e^m >= 2^128.
function gqPower(e) {
  let m = 1, E = e;
  while (E < (1n << BigInt(CHAL_BYTES * 8))) { E *= e; m++; }
  return { m, E };
}

function rsaId(n, e) { return 'rsa:' + e.toString(16) + ':' + n.toString(16); }

KEY_TYPES['ssh-rsa'] = {
  kind: 'rsa',
  proto: GQ,
  async parse(r) {
    const e = r.mpint(), n = r.mpint();
    const bits = bitLength(n);
    if (bits < 2048) fail('RSA key is ' + bits + ' bits; at least 2048 are needed.');
    if (bits > 16384) fail('RSA key is too large.');
    if (e >= 2n ** 32n || !isSmallPrime(Number(e)) || e < 3n) fail('RSA key has an unusual public exponent.');
    if (!checkModulus(n)) fail('RSA key has an invalid modulus.');
    const blob = concatBytes(sshString('ssh-rsa'), sshMpint(e), sshMpint(n));
    const y = await rsaFdh(blob, n);
    let yinv;
    try { yinv = modinv(y, n); } catch (err) { fail('RSA key has an invalid modulus.'); }
    const { m, E } = gqPower(e);
    return { n, e, E, m, y, yinv, k: byteLength(n), id: rsaId(n, e) };
  },
};

// x = y^(d^m) mod n via CRT, checked against x^E = y.
async function rsaPrivate(n, e, d, p, q) {
  if (p * q !== n || d <= 0n) fail('The RSA key is damaged.');
  const blob = concatBytes(sshString('ssh-rsa'), sshMpint(e), sshMpint(n));
  const y = await rsaFdh(blob, n);
  const { m, E } = gqPower(e);
  const xp = modpow(y, modpow(d % (p - 1n), BigInt(m), p - 1n), p);
  const xq = modpow(y, modpow(d % (q - 1n), BigInt(m), q - 1n), q);
  const x = xq + q * mod((xp - xq) * modinv(q, p), p);
  if (modpow(x, E, n) !== y) fail('The RSA key is damaged.');
  return { id: rsaId(n, e), sec: { x }, blob };
}
