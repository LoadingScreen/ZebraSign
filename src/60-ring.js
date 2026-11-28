// The ring signature: a CDS OR-proof made non-interactive with Fiat-Shamir.
//
// Each ring key i gets a 128-bit challenge c_i. The XOR of all c_i must equal
// H(transcript)[0..16]. The signer simulates every other key's proof with a
// random c_i, then answers its own share honestly. See PROTOCOL.md.

const DOMAIN = 'zebrasign-github-v1';
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
// priv: from parsePrivateKey(). Returns the JSON body.
async function signRing(msg, signedAt, entries, priv) {
  if (!entries.length) fail('The ring is empty.');
  const ring = entries.slice().sort(ringCompare);
  for (let i = 1; i < ring.length; i++) {
    if (ring[i].key.id === ring[i - 1].key.id) fail('The same key appears twice in the ring.');
  }
  const me = ring.findIndex((e) => e.key.id === priv.id);
  if (me < 0) fail('This private key doesn\'t match any key in the ring.');

  const body = {
    v: 1, msg, signed_at: signedAt,
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

  body.proof = cs.map((ci, i) => ({ c: b64enc(ci), z: b64enc(zs[i]) }));
  for (const e of body.ring) delete e.blob;
  return body;
}

function armor(body) {
  const b64 = b64enc(te.encode(JSON.stringify(body)));
  const lines = b64.match(/.{1,64}/g);
  return [ARMOR_BEGIN, ...lines, ARMOR_END].join('\n');
}

function dearmor(text) {
  const i = text.indexOf(ARMOR_BEGIN), j = text.indexOf(ARMOR_END);
  if (i < 0 && /<ZebraSign \d[^>]*>/.test(text)) {
    fail('This signature was made with the original ZebraSign desktop app, which used its own keys instead of GitHub\'s. This page can\'t check it. That app is no longer maintained: github.com/kurt-brown/zebra');
  }
  if (i < 0) fail('No ZebraSign signature found. It starts with ' + ARMOR_BEGIN);
  if (j < i) fail('The signature is cut off. Copy all of it, down to the END line.');
  let json;
  try { json = tdStrict.decode(b64dec(text.slice(i + ARMOR_BEGIN.length, j))); } catch (e) {
    fail('The signature is damaged (bad base64). Copy it again.');
  }
  try { return JSON.parse(json); } catch (e) { fail('The signature is damaged (bad JSON).'); }
}

const isWellFormed = (s) => typeof s === 'string' && tdStrict.decode(te.encode(s)) === s;
const LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;

// Checks the proof against the keys carried in the signature. Doesn't touch
// the network. Returns { body, ring: [{ login, id, key }] } or throws ZsError.
async function verifyRing(body) {
  if (!body || typeof body !== 'object' || body.v !== 1) fail('Unknown signature version.');
  if (!isWellFormed(body.msg)) fail('The signature has no valid message.');
  if (typeof body.signed_at !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(body.signed_at)) fail('The signature has no valid date.');
  if (!Array.isArray(body.ring) || !body.ring.length) fail('The signature has no ring.');
  if (!Array.isArray(body.proof) || body.proof.length !== body.ring.length) fail('The proof doesn\'t match the ring.');

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
  for (let i = 0; i < ring.length; i++) {
    const p = body.proof[i];
    let c, z;
    try { c = b64dec(p.c); z = b64dec(p.z); } catch (e) { fail('The proof is damaged.'); }
    if (c.length !== CHAL_BYTES) fail('The proof is damaged.');
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
