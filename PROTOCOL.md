# ZebraSign construction (format v1)

This is what the code does, written down for review. Strings and integers are
encoded as in SSH (RFC 4251): `string` is a u32 length then the bytes.

## Ring

Ring entries are `(login, user ID, public key)`, one per usable key. They are
sorted by user ID, then by SHA-256 of the SSH key blob, compared bytewise. The
verifier rejects a ring that isn't in this order, or that has a duplicate key.

## Challenge

```
T = string("zebrasign-github-v1") || string(signed_at) || string(msg) || u32(n)
    || for each entry i: string(login_i) || string(decimal user ID_i) || string(blob_i)
    || for each entry i: string(commitment_i)
c = SHA-256(T)[0..16]          (128 bits)
```

The proof is `(c_i, z_i)` for every entry, and is valid when every
`commitment_i` recomputed from `(c_i, z_i)` gives `XOR of all c_i = c`.
Logins, user IDs and the date are hashed too, so none of them can be changed
without breaking the proof.

The signer picks random `c_i` for every other entry and simulates those
proofs, makes an honest commitment for its own key, computes `c`, sets its own
`c_j = c XOR (all other c_i)`, and answers it.

## Per key type

**Ed25519 and P-256.** Schnorr proof of knowledge of `x` with `X = xG`.
Commitment `R = rG`, response `s = r + c_i x mod q`, check `R = sG - c_i X`.
`c_i` is read as a 128-bit big-endian integer. For Ed25519, `x` is the clamped
scalar from SHA-512 of the seed, reduced mod q. Commitments are the 32-byte
Ed25519 encoding or the 33-byte compressed SEC1 point. Ed25519 keys that are
the identity or not in the prime-order subgroup are rejected; P-256 keys must
be on the curve.

**RSA.** Guillou–Quisquater. Each key gets a fixed
`y = OS2IP(SHA-256(u32(0) || string("zebrasign-github-v1/rsa-fdh") || string(blob)) || ...) mod n`,
truncated to `len(n) + 16` bytes before reduction. The blob here is rebuilt
from `(e, n)` with minimal mpints. The secret is `x = y^d mod n`. Let
`b = floor(log2 e)` (16 for e = 65537). The 128-bit `c_i` is cut into
`ceil(128 / b)` chunks of `b` bits, each below `e`. For each chunk `c_ij`:
commitment `t_j = r_j^e`, response `z_j = r_j x^c_ij`, check
`t_j = z_j^e · y^(-c_ij) mod n`. Keys are rejected if `n` is under 2048 bits,
even, has a factor below 4096, passes a base-2 Fermat test (i.e. looks prime),
or is a perfect power, or if `e` isn't a prime in `[3, 2^32)`.

## For the reviewer

- Is a 128-bit XOR challenge sound across the mixed group orders and the
  chunked GQ challenge space?
- Is the FDH for `y` adequate, and are the modulus checks enough to stop a
  key that anyone could prove knowledge for?
- Challenges from SHA-256 truncated to 128 bits; scalars sampled with 128
  extra bits and reduced.
- No constant-time arithmetic: JavaScript BigInt can't provide it.
