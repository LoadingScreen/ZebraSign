// NIST P-256 group arithmetic, Jacobian coordinates (a = -3).

const P256 = (() => {
  const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  const q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
  const Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
  const Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;
  const f = (a) => { const r = a % p; return r < 0n ? r + p : r; };
  const ZERO = [1n, 1n, 0n];
  const G = [Gx, Gy, 1n];

  const isZero = (P) => P[2] === 0n;
  function dbl(P) {
    if (isZero(P) || P[1] === 0n) return ZERO;
    const [X, Y, Z] = P;
    const delta = f(Z * Z), gamma = f(Y * Y), beta = f(X * gamma);
    const alpha = f(3n * (X - delta) * (X + delta));
    const X3 = f(alpha * alpha - 8n * beta);
    const Z3 = f((Y + Z) * (Y + Z) - gamma - delta);
    const Y3 = f(alpha * (4n * beta - X3) - 8n * gamma * gamma);
    return [X3, Y3, Z3];
  }
  function add(P, Q) {
    if (isZero(P)) return Q;
    if (isZero(Q)) return P;
    const [X1, Y1, Z1] = P, [X2, Y2, Z2] = Q;
    const Z1Z1 = f(Z1 * Z1), Z2Z2 = f(Z2 * Z2);
    const U1 = f(X1 * Z2Z2), U2 = f(X2 * Z1Z1);
    const S1 = f(Y1 * Z2 * Z2Z2), S2 = f(Y2 * Z1 * Z1Z1);
    const H = f(U2 - U1), r = f(2n * (S2 - S1));
    if (H === 0n) return r === 0n ? dbl(P) : ZERO;
    const I = f(4n * H * H), J = f(H * I), V = f(U1 * I);
    const X3 = f(r * r - J - 2n * V);
    const Y3 = f(r * (V - X3) - 2n * S1 * J);
    const Z3 = f(((Z1 + Z2) * (Z1 + Z2) - Z1Z1 - Z2Z2) * H);
    return [X3, Y3, Z3];
  }
  const neg = (P) => [P[0], f(-P[1]), P[2]];
  function mul(P, k) {
    let R = ZERO;
    for (let i = bitLength(k) - 1; i >= 0; i--) {
      R = dbl(R);
      if ((k >> BigInt(i)) & 1n) R = add(R, P);
    }
    return R;
  }
  function affine(P) {
    const zi = modpow(P[2], p - 2n, p), zi2 = f(zi * zi);
    return [f(P[0] * zi2), f(P[1] * zi2 * zi)];
  }
  // SEC1 compressed; the point at infinity is a single zero byte.
  function encode(P) {
    if (isZero(P)) return Uint8Array.of(0);
    const [x, y] = affine(P);
    return concatBytes(Uint8Array.of(2 | Number(y & 1n)), bigToBytes(x, 32));
  }
  function encodeUncompressed(P) {
    const [x, y] = affine(P);
    return concatBytes(Uint8Array.of(4), bigToBytes(x, 32), bigToBytes(y, 32));
  }
  // Uncompressed SEC1 only (that's what OpenSSH uses). Cofactor is 1, so
  // on-curve is enough.
  function decode(u8) {
    if (u8.length !== 65 || u8[0] !== 4) return null;
    const x = bytesToBig(u8.subarray(1, 33)), y = bytesToBig(u8.subarray(33));
    if (x >= p || y >= p) return null;
    if (f(y * y) !== f(x * x * x - 3n * x + b)) return null;
    return [x, y, 1n];
  }
  return { name: 'p256', p, q, G, ZERO, add, dbl, neg, mul, isZero, encode, encodeUncompressed, decode };
})();
