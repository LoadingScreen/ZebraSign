# ZebraSign construction (format 2)

This is what the code does, written down for review. In the hash transcript,
strings and integers are encoded as in SSH (RFC 4251): `string` is a u32
length then the bytes.

## Ring

Ring entries are `(login, user ID, public key)`, one per usable key. They are
sorted by user ID, then by SHA-256 of the SSH key blob, compared bytewise. The
verifier rejects a ring that isn't in this order, or that has a duplicate key.

## Challenge

```
T = string("zebrasign-github-v2") || string(signed_at) || string(msg) || u32(n)
    || for each entry i: string(login_i) || string(decimal user ID_i) || string(blob_i)
    || for each entry i: string(commitment_i)
c = SHA-256(T)[0..16]          (128 bits)
```

`signed_at` is the date as `YYYY-MM-DD`. The proof is `(c_i, z_i)` for every
entry, and is valid when every `commitment_i` recomputed from `(c_i, z_i)`
gives `XOR of all c_i = c`. Logins, user IDs and the date are hashed too, so
none of them can be changed without breaking the proof.

The signer picks random `c_i` for every other entry and simulates those
proofs, makes an honest commitment for its own key, computes `c`, sets its own
`c_j = c XOR (all other c_i)`, and answers it.

## Per key type

**Ed25519 and P-256.** Schnorr proof of knowledge of `x` with `X = xG`.
Commitment `R = rG`, response `s = r + c_i x mod q` (32 bytes), check
`R = sG - c_i X`. `c_i` is read as a 128-bit big-endian integer. For Ed25519,
`x` is the clamped scalar from SHA-512 of the seed, reduced mod q. Commitments
are the 32-byte Ed25519 encoding or the 33-byte compressed SEC1 point. Ed25519
keys that are the identity or not in the prime-order subgroup are rejected;
P-256 keys must be on the curve.

**RSA.** Single-round Guillou–Quisquater with exponent `E = e^m`, where `m` is
the smallest integer with `e^m >= 2^128` (`m = 8` for e = 65537, `m = 81` for
e = 3). Each key gets a fixed
`y = OS2IP(SHA-256(u32(0) || string("zebrasign-github-v2/rsa-fdh") || string(blob)) || ...) mod n`,
truncated to `len(n) + 16` bytes before reduction. The blob here is rebuilt
from `(e, n)` with minimal mpints. The key's owner computes the secret
`x = y^(d^m) mod n`, so `x^E = y`. Commitment `t = r^E`, response
`z = r · x^c_i mod n` (`len(n)` bytes), check `t = z^E · y^(-c_i) mod n`, with
`c_i` as a 128-bit integer.

Keys are rejected if `n` is under 2048 bits, even, has a factor below 4096,
passes a base-2 Fermat test (i.e. looks prime), or is a perfect power, or if
`e` isn't a prime in `[3, 2^32)`.

*Soundness argument.* Take two accepting answers `z, z'` to one commitment `t`,
with challenges `c ≠ c'`. Then `a^E = y^Δ` for `a = z/z'` and `Δ = c − c'`,
with `0 < |Δ| < 2^128 <= E`, so `Δ = e^j · Δ'` with `j < m` and `e ∤ Δ'`.

- For a genuine RSA key, `gcd(e, φ(n)) = 1`, so raising to the power `e` is a
  bijection on `Z_n*` and can be cancelled `j` times: `a^(e^(m−j)) = y^Δ'`.
  Now `gcd(e^(m−j), Δ') = 1`, and Bezout `u·e^(m−j) + v·Δ' = 1` gives
  `w = a^v y^u` with `w^(e^(m−j)) = y`, so `w^(e^(m−j−1))` is an e-th root of
  `y`. This is plain special soundness, with no exceptions.
- For a key where `e` divides `φ(n)` (not a working RSA key), that cancellation
  isn't available when `j > 0`. Challenges are uniform, so a rewinding
  extractor gets `j = 0` except with probability about `1/e`, and can retry.

The test suite (`test/test-rsa.js`) does the `j = 0` extraction on real keys.

This replaced format 1's eight parallel rounds with 16-bit challenges, which
had plain special soundness but made each RSA key's proof eight times larger.

## Signature encoding

The armored block is base64 of:

```
byte 2                                  format
u16  days since 1970-01-01              signed_at
varint len, UTF-8                       message
varint number of users
  per user, by increasing user ID:
  varint user ID
  varint len, ASCII                     login
  varint number of keys
    per key: varint len, SSH key blob
proof: per key, in ring order: c_i (16 bytes) || z_i
```

Varints are unsigned LEB128 with no redundant trailing zero bytes. Key order
within a user follows the ring order above. The decoder rejects users out of
order, and the verifier rejects anything left over or missing in the proof.
Format 1 (base64 of JSON) is recognized and refused with a message.

## For the reviewer

- Is a 128-bit XOR challenge sound across the mixed group orders and the
  RSA challenge space?
- RSA: is the argument above right, and is the retry case for keys with
  `e | φ(n)` acceptable within the CDS OR-composition, which is usually stated
  for protocols with plain special soundness?
- Is the FDH for `y` adequate, and are the modulus checks enough to stop a
  key that anyone could prove knowledge for?
- Challenges from SHA-256 truncated to 128 bits; scalars sampled with 128
  extra bits and reduced.
- No constant-time arithmetic: JavaScript BigInt can't provide it.
- A ring is only as hard to forge as its weakest key: whoever breaks or holds
  any one ring key can sign as the ring. RSA-2048 (about 112-bit security) is
  the weakest accepted, and the modulus checks can't prove a modulus is hard
  to factor.
- The signer's anonymity doesn't depend on the keys staying secure: the faked
  answers have the same distribution as the real one (up to negligible
  sampling bias), so even someone who later learns every private key in the
  ring can't tell who signed.
