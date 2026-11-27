// RSA keys: Guillou-Quisquater proof of knowledge of an e-th root.
//
// Each key gets a fixed y = FDH(key) in Z_n. Only the key's owner can compute
// x = y^d. One GQ round has a challenge below e, so the 128-bit challenge is
// split into chunks of floor(log2 e) bits (16 for e = 65537, giving 8 rounds).

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

function gqChunks(pub, c) {
  const cb = bytesToBig(c), total = CHAL_BYTES * 8, out = [];
  for (let j = 0; j < pub.rounds; j++) {
    const start = j * pub.bits, end = Math.min(total, start + pub.bits);
    out.push((cb >> BigInt(total - end)) & ((1n << BigInt(end - start)) - 1n));
  }
  return out;
}

const randUnit = (n) => randBelow(n - 1n) + 1n;

const GQ = {
  simulate(pub, c) {
    const ts = [], zs = [];
    gqChunks(pub, c).forEach((cj) => {
      const z = randUnit(pub.n);
      ts.push(bigToBytes((modpow(z, pub.e, pub.n) * modpow(pub.yinv, cj, pub.n)) % pub.n, pub.k));
      zs.push(bigToBytes(z, pub.k));
    });
    return { t: concatBytes(...ts), z: concatBytes(...zs) };
  },
  commit(pub) {
    const rs = [], ts = [];
    for (let j = 0; j < pub.rounds; j++) {
      const r = randUnit(pub.n);
      rs.push(r);
      ts.push(bigToBytes(modpow(r, pub.e, pub.n), pub.k));
    }
    return { t: concatBytes(...ts), st: rs };
  },
  respond(pub, sec, rs, c) {
    return concatBytes(...gqChunks(pub, c).map((cj, j) => bigToBytes((rs[j] * modpow(sec.x, cj, pub.n)) % pub.n, pub.k)));
  },
  recompute(pub, c, z) {
    if (z.length !== pub.k * pub.rounds) return null;
    const ts = [];
    const cs = gqChunks(pub, c);
    for (let j = 0; j < pub.rounds; j++) {
      const zj = bytesToBig(z.subarray(j * pub.k, (j + 1) * pub.k));
      if (zj <= 0n || zj >= pub.n) return null;
      ts.push(bigToBytes((modpow(zj, pub.e, pub.n) * modpow(pub.yinv, cs[j], pub.n)) % pub.n, pub.k));
    }
    return concatBytes(...ts);
  },
};

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
    const eb = bitLength(e) - 1;
    return { n, e, y, yinv, k: byteLength(n), bits: eb, rounds: Math.ceil(CHAL_BYTES * 8 / eb), id: rsaId(n, e) };
  },
};

// x = y^d mod n via CRT, checked against x^e = y.
async function rsaPrivate(n, e, d, p, q) {
  if (p * q !== n || d <= 0n) fail('The RSA key is damaged.');
  const blob = concatBytes(sshString('ssh-rsa'), sshMpint(e), sshMpint(n));
  const y = await rsaFdh(blob, n);
  const xp = modpow(y, d % (p - 1n), p), xq = modpow(y, d % (q - 1n), q);
  const x = xq + q * mod((xp - xq) * modinv(q, p), p);
  if (modpow(x, e, n) !== y) fail('The RSA key is damaged.');
  return { id: rsaId(n, e), sec: { x }, blob };
}
