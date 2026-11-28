// The ring signature: a CDS OR-proof made non-interactive with Fiat-Shamir.
//
// Each ring key i gets a 128-bit challenge c_i. The XOR of all c_i must equal
// H(transcript)[0..16]. The signer simulates every other key's proof with a
// random c_i, then answers its own share honestly. See PROTOCOL.md.

const DOMAIN = 'zebrasign-github-v2';
const FORMAT = 2;
const ARMOR_BEGIN = '-----BEGIN ZEBRASIGN SIGNATURE-----';
const ARMOR_END = '-----END ZEBRASIGN SIGNATURE-----';

function xorInto(acc, c) { for (let i = 0; i < acc.length; i++) acc[i] ^= c[i]; }

// Ring order: GitHub user ID, then SHA-256 of the key blob.
function ringCompare(a, b) { return (a.userId - b.userId) || compareBytes(a.key.fpHash, b.key.fpHash); }

function transcript(body, commitments) {
  const parts = [sshString(DOMAIN), sshString(body.signed_at), sshString(body.msg), u32be(body.ring.length)];
  for (const e of body.ring) parts.push(sshString(e.login), sshString(String(e.id)), sshString(e.blob));
  for (const t of commitments) parts.push(sshString(t));
  return concatBytes(...parts);
}

async function challenge(body, commitments) {
  return (await sha256(transcript(body, commitments))).subarray(0, CHAL_BYTES);
}

// entries: [{ login, userId, key }] where key comes from prepareKey().
// priv: from parsePrivateKey(). Returns the body: { v, msg, signed_at,
// ring: [{ login, id, key }], proof } where proof is c_i || z_i for each key.
async function signRing(msg, signedAt, entries, priv) {
  if (!entries.length) fail('The ring is empty.');
  const ring = entries.slice().sort(ringCompare);
  for (let i = 1; i < ring.length; i++) {
    if (ring[i].key.id === ring[i - 1].key.id) fail('The same key appears twice in the ring.');
  }
  const me = ring.findIndex((e) => e.key.id === priv.id);
  if (me < 0) fail('This private key doesn\'t match any key in the ring.');

  const body = {
    v: FORMAT, msg, signed_at: signedAt,
    ring: ring.map((e) => ({ login: e.login, id: e.userId, key: e.key.line, blob: e.key.blob })),
  };
  const cs = [], ts = [], zs = [];
  let mine;
  for (let i = 0; i < ring.length; i++) {
    const k = ring[i].key;
    if (i === me) {
      mine = await k.proto.commit(k);
      ts[i] = mine.t;
    } else {
      cs[i] = randBytes(CHAL_BYTES);
      const sim = await k.proto.simulate(k, cs[i]);
      ts[i] = sim.t; zs[i] = sim.z;
    }
  }
  const c = Uint8Array.from(await challenge(body, ts));
  for (let i = 0; i < ring.length; i++) if (i !== me) xorInto(c, cs[i]);
  cs[me] = c;
  zs[me] = await ring[me].key.proto.respond(ring[me].key, priv.sec, mine.st, c);

  body.proof = concatBytes(...cs.flatMap((ci, i) => [ci, zs[i]]));
  for (const e of body.ring) delete e.blob;
  return body;
}

// Binary format, version 2. Integers are unsigned LEB128 varints.
//   byte 2 | u16 days since 1970-01-01 (signed_at) | varint len, message UTF-8
//   varint users | per user, in ring order:
//     varint user ID | varint len, login | varint keys | per key: varint len, SSH key blob
//   proof: per key, in ring order: 16-byte c, then z (32 bytes for Ed25519 and
//   P-256; the modulus length for RSA)
const DAY_MS = 86400000;

function varint(n) {
  const out = [];
  do { let b = n % 128; n = Math.floor(n / 128); if (n) b |= 128; out.push(b); } while (n);
  return Uint8Array.from(out);
}
const lenBytes = (u8) => concatBytes(varint(u8.length), u8);

function encodeBody(body) {
  const days = Date.parse(body.signed_at + 'T00:00:00Z') / DAY_MS;
  const parts = [Uint8Array.of(FORMAT, days >> 8, days & 255), lenBytes(te.encode(body.msg))];
  const groups = [];
  for (const e of body.ring) {
    const g = groups[groups.length - 1];
    if (g && g.id === e.id) g.keys.push(e.key); else groups.push({ id: e.id, login: e.login, keys: [e.key] });
  }
  parts.push(varint(groups.length));
  for (const g of groups) {
    parts.push(varint(g.id), lenBytes(te.encode(g.login)), varint(g.keys.length));
    for (const k of g.keys) parts.push(lenBytes(parseKeyLine(k).blob));
  }
  parts.push(body.proof);
  return concatBytes(...parts);
}

class BinReader {
  constructor(u8) { this.b = u8; this.o = 0; }
  bytes(n) {
    if (this.o + n > this.b.length) fail('The signature is damaged (it ends too early). Copy all of it.');
    const r = this.b.subarray(this.o, this.o + n); this.o += n; return r;
  }
  varint(max) {
    let n = 0, mul = 1;
    for (let i = 0; i < 8; i++) {
      const b = this.bytes(1)[0];
      n += (b & 127) * mul;
      if (!(b & 128)) {
        if (i > 0 && b === 0) fail('The signature is damaged.');
        if (n > max) fail('The signature is damaged.');
        return n;
      }
      mul *= 128;
    }
    fail('The signature is damaged.');
  }
  lenBytes(max) { return this.bytes(this.varint(max)); }
}

function decodeBody(bytes) {
  const r = new BinReader(bytes);
  const [v, d1, d2] = r.bytes(3);
  if (v !== FORMAT) fail('This signature uses a format this page doesn\'t know (version ' + v + ').');
  const signed_at = new Date(((d1 << 8) | d2) * DAY_MS).toISOString().slice(0, 10);
  let msg;
  try { msg = tdStrict.decode(r.lenBytes(1 << 20)); } catch (e) {
    if (e instanceof ZsError) throw e;
    fail('The signature is damaged (the message isn\'t valid text).');
  }
  const ring = [];
  const nUsers = r.varint(1000);
  let lastId = 0;
  for (let u = 0; u < nUsers; u++) {
    const id = r.varint(Number.MAX_SAFE_INTEGER);
    if (id <= lastId) fail('The ring isn\'t in the standard order.');
    lastId = id;
    const login = String.fromCharCode(...r.lenBytes(39));
    const nKeys = r.varint(100);
    if (!nKeys) fail('The signature is damaged.');
    for (let k = 0; k < nKeys; k++) {
      const blob = r.lenBytes(4096);
      let type;
      try { type = new SshReader(blob).text(); } catch (e) { fail('The signature is damaged.'); }
      ring.push({ login, id, key: type + ' ' + b64enc(blob) });
    }
  }
  return { v, msg, signed_at, ring, proof: bytes.subarray(r.o) };
}

function armor(body) {
  const lines = b64enc(encodeBody(body)).match(/.{1,64}/g);
  return [ARMOR_BEGIN, ...lines, ARMOR_END].join('\n');
}

function dearmor(text) {
  const i = text.indexOf(ARMOR_BEGIN), j = text.indexOf(ARMOR_END);
  if (i < 0 && /<ZebraSign \d[^>]*>/.test(text)) {
    fail('This signature was made with the original ZebraSign desktop app, which used its own keys instead of GitHub\'s. This page can\'t check it. That app is no longer maintained: github.com/kurt-brown/zebra');
  }
  if (i < 0) fail('No ZebraSign signature found. It starts with ' + ARMOR_BEGIN);
  if (j < i) fail('The signature is cut off. Copy all of it, down to the END line.');
  let bytes;
  try { bytes = b64dec(text.slice(i + ARMOR_BEGIN.length, j)); } catch (e) {
    fail('The signature is damaged (bad base64). Copy it again.');
  }
  if (bytes[0] === 0x7b) fail('This signature uses an older test format that this page no longer reads. Ask the signer to sign the message again.');
  return decodeBody(bytes);
}

const isWellFormed = (s) => typeof s === 'string' && tdStrict.decode(te.encode(s)) === s;
const LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;

// Checks the proof against the keys carried in the signature. Doesn't touch
// the network. Returns { body, ring: [{ login, id, key }] } or throws ZsError.
async function verifyRing(body) {
  if (!body || typeof body !== 'object' || body.v !== FORMAT) fail('Unknown signature version.');
  if (!isWellFormed(body.msg)) fail('The signature has no valid message.');
  if (typeof body.signed_at !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(body.signed_at)) fail('The signature has no valid date.');
  if (!Array.isArray(body.ring) || !body.ring.length) fail('The signature has no ring.');
  if (!(body.proof instanceof Uint8Array)) fail('The signature has no proof.');

  const ring = [];
  for (let i = 0; i < body.ring.length; i++) {
    const e = body.ring[i];
    if (!e || typeof e.login !== 'string' || !LOGIN_RE.test(e.login)) fail('Ring entry ' + (i + 1) + ' has an invalid login.');
    if (!Number.isSafeInteger(e.id) || e.id <= 0) fail('Ring entry ' + (i + 1) + ' has an invalid user ID.');
    if (typeof e.key !== 'string') fail('Ring entry ' + (i + 1) + ' has no key.');
    const pk = await prepareKey(e.key);
    if (!pk.usable) fail('Ring key ' + (i + 1) + ' (' + e.login + ') can\'t be used: ' + pk.reason);
    ring.push({ login: e.login, userId: e.id, key: pk.key });
  }
  for (let i = 1; i < ring.length; i++) {
    if (ring[i].key.id === ring[i - 1].key.id) fail('The same key appears twice in the ring.');
    if (ringCompare(ring[i - 1], ring[i]) >= 0) fail('The ring isn\'t in the standard order.');
  }
  for (let i = 0; i < ring.length; i++) {
    for (let j = 0; j < i; j++) {
      if (ring[i].key.id === ring[j].key.id) fail('The same key appears twice in the ring.');
      if (ring[i].userId === ring[j].userId && ring[i].login !== ring[j].login) fail('One user ID has two different logins.');
    }
  }

  const acc = new Uint8Array(CHAL_BYTES), ts = [];
  const want = ring.reduce((n, e) => n + CHAL_BYTES + e.key.proto.zLen(e.key), 0);
  if (body.proof.length !== want) fail('The proof doesn\'t match the ring. The signature may be cut off or changed.');
  for (let i = 0, o = 0; i < ring.length; i++) {
    const c = body.proof.subarray(o, o + CHAL_BYTES); o += CHAL_BYTES;
    const z = body.proof.subarray(o, o + ring[i].key.proto.zLen(ring[i].key)); o += z.length;
    const t = await ring[i].key.proto.recompute(ring[i].key, c, z);
    if (!t) fail('The proof is damaged.');
    ts.push(t);
    xorInto(acc, c);
  }
  const hb = { msg: body.msg, signed_at: body.signed_at, ring: ring.map((e) => ({ login: e.login, id: e.userId, blob: e.key.blob })) };
  const h = await challenge(hb, ts);
  if (!bytesEqual(h, acc)) fail('The signature doesn\'t check out. The message, the ring, or the proof was changed, or it was never valid.');
  return { body, ring };
}
