// Public keys: parse OpenSSH key lines, decide what's usable, and the
// per-type sigma protocols that the OR-proof is built from.

const CHAL_BYTES = 16; // 128-bit challenges

// Schnorr proof of knowledge of a discrete log, over a prime-order group.
function makeSchnorr(group, scalarLen) {
  const c2n = (c) => bytesToBig(c); // c < 2^128 < q
  return {
    simulate(pub, c) {
      const s = randBelow(group.q);
      const R = group.add(group.mul(group.G, s), group.neg(group.mul(pub.point, c2n(c))));
      return { t: group.encode(R), z: bigToBytes(s, scalarLen) };
    },
    commit() {
      const r = randBelow(group.q);
      return { t: group.encode(group.mul(group.G, r)), st: r };
    },
    respond(pub, sec, r, c) {
      return bigToBytes(mod(r + c2n(c) * sec.x, group.q), scalarLen);
    },
    recompute(pub, c, z) {
      if (z.length !== scalarLen) return null;
      const s = bytesToBig(z);
      if (s >= group.q) return null;
      const R = group.add(group.mul(group.G, s), group.neg(group.mul(pub.point, c2n(c))));
      return group.encode(R);
    },
  };
}

const KEY_TYPES = {};

KEY_TYPES['ssh-ed25519'] = {
  kind: 'ed25519',
  proto: makeSchnorr(ED, 32),
  async parse(r) {
    const a = r.string();
    if (a.length !== 32) fail('Ed25519 key has the wrong length.');
    const point = ED.decode(a);
    if (!point) fail('Ed25519 key is not a valid curve point.');
    // The identity has secret 0: anyone could sign for it.
    if (ED.isZero(point)) fail('Ed25519 key is the identity point.');
    // Reject keys with a small-order component; nobody could prove knowledge for them.
    if (!ED.isZero(ED.mul(point, ED.q))) fail('Ed25519 key is not in the prime-order group.');
    return { point, id: 'ed25519:' + toHex(a) };
  },
};

KEY_TYPES['ecdsa-sha2-nistp256'] = {
  kind: 'p256',
  proto: makeSchnorr(P256, 32),
  async parse(r) {
    if (r.text() !== 'nistp256') fail('P-256 key names the wrong curve.');
    const q = r.string();
    const point = P256.decode(q);
    if (!point) fail('P-256 key is not a valid curve point.');
    return { point, id: 'p256:' + toHex(q) };
  },
};

const UNUSABLE_TYPES = {
  'sk-ssh-ed25519@openssh.com': 'Hardware security key; it can\'t be used in a ring.',
  'sk-ecdsa-sha2-nistp256@openssh.com': 'Hardware security key; it can\'t be used in a ring.',
  'ecdsa-sha2-nistp384': 'P-384 keys aren\'t supported.',
  'ecdsa-sha2-nistp521': 'P-521 keys aren\'t supported.',
  'ssh-dss': 'DSA keys aren\'t supported.',
};

// "ssh-ed25519 AAAA... comment" -> { type, blob }
function parseKeyLine(line) {
  const parts = line.trim().split(/\s+/);
  if (parts.length < 2) fail('Not an OpenSSH public key.');
  let blob;
  try { blob = b64dec(parts[1]); } catch (e) { fail('Not an OpenSSH public key.'); }
  return { type: parts[0], blob };
}

function fingerprint(hash) { return 'SHA256:' + b64enc(hash).replace(/=+$/, ''); }

// Returns { usable: true, key } or { usable: false, type, reason }.
async function prepareKey(line) {
  let type = '?';
  try {
    const kl = parseKeyLine(line);
    type = kl.type;
    if (UNUSABLE_TYPES[type]) return { usable: false, type, reason: UNUSABLE_TYPES[type] };
    const kt = KEY_TYPES[type];
    if (!kt) return { usable: false, type, reason: 'Unknown key type.' };
    const r = new SshReader(kl.blob);
    if (r.text() !== type) fail('Key type doesn\'t match key data.');
    const pub = await kt.parse(r, kl.blob);
    if (!r.done()) fail('Key has trailing data.');
    const hash = await sha256(kl.blob);
    return {
      usable: true,
      key: Object.assign(pub, {
        type, kind: kt.kind, proto: kt.proto, blob: kl.blob,
        line: type + ' ' + b64enc(kl.blob), fpHash: hash, fp: fingerprint(hash),
      }),
    };
  } catch (e) {
    if (e instanceof ZsError) return { usable: false, type, reason: e.message };
    throw e;
  }
}
