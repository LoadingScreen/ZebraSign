// Edwards25519 group arithmetic (RFC 8032), extended coordinates.
// Not constant time: BigInt arithmetic in JS can't be.

const ED = (() => {
  const p = 2n ** 255n - 19n;
  const q = 2n ** 252n + 27742317777372353535851937790883648493n;
  const f = (a) => { const r = a % p; return r < 0n ? r + p : r; };
  const inv = (a) => modpow(a, p - 2n, p);
  const d = f(-121665n * inv(121666n));
  const sqrtm1 = modpow(2n, (p - 1n) / 4n, p);
  const ZERO = [0n, 1n, 1n, 0n];

  function add(P, Q) {
    const [X1, Y1, Z1, T1] = P, [X2, Y2, Z2, T2] = Q;
    const A = f((Y1 - X1) * (Y2 - X2)), B = f((Y1 + X1) * (Y2 + X2));
    const C = f(T1 * 2n * d * T2), D = f(Z1 * 2n * Z2);
    const E = B - A, F = D - C, G = D + C, H = B + A;
    return [f(E * F), f(G * H), f(F * G), f(E * H)];
  }
  function dbl(P) {
    const [X1, Y1, Z1] = P;
    const A = f(X1 * X1), B = f(Y1 * Y1), C = f(2n * Z1 * Z1);
    const D = p - A, E = f((X1 + Y1) * (X1 + Y1) - A - B);
    const G = D + B, F = G - C, H = D - B;
    return [f(E * F), f(G * H), f(F * G), f(E * H)];
  }
  function neg(P) { return [f(-P[0]), P[1], P[2], f(-P[3])]; }
  function mul(P, k) {
    let R = ZERO;
    for (let i = bitLength(k) - 1; i >= 0; i--) {
      R = dbl(R);
      if ((k >> BigInt(i)) & 1n) R = add(R, P);
    }
    return R;
  }
  function isZero(P) { return f(P[0]) === 0n && f(P[1] - P[2]) === 0n; }
  function encode(P) {
    const zi = inv(P[2]);
    const x = f(P[0] * zi), y = f(P[1] * zi);
    const out = bigToBytesLE(y, 32);
    if (x & 1n) out[31] |= 0x80;
    return out;
  }
  function decode(b) {
    if (b.length !== 32) return null;
    const yb = Uint8Array.from(b);
    const sign = (yb[31] >> 7) & 1;
    yb[31] &= 0x7f;
    const y = bytesToBigLE(yb);
    if (y >= p) return null;
    const u = f(y * y - 1n), v = f(d * y * y + 1n);
    const v3 = f(v * v * v);
    let x = f(u * v3 * modpow(f(u * v3 * v3 * v), (p - 5n) / 8n, p));
    const vx2 = f(v * x * x);
    if (vx2 === u) { /* ok */ } else if (vx2 === f(-u)) x = f(x * sqrtm1);
    else return null;
    if (x === 0n && sign) return null;
    if (Number(x & 1n) !== sign) x = p - x;
    return [x, y, 1n, f(x * y)];
  }
  const Gy = f(4n * inv(5n));
  const G = decode(bigToBytesLE(Gy, 32));

  return { name: 'ed25519', p, q, G, ZERO, add, dbl, neg, mul, isZero, encode, decode };
})();

// Secret scalar from a 32-byte Ed25519 seed (RFC 8032 5.1.5).
async function ed25519ScalarFromSeed(seed) {
  const h = await sha512(seed);
  const a = Uint8Array.from(h.subarray(0, 32));
  a[0] &= 248; a[31] &= 127; a[31] |= 64;
  return mod(bytesToBigLE(a), ED.q);
}
