// Private key parsing: OpenSSH (openssh-key-v1) and older PEM formats.

// "-----BEGIN X-----" blocks, with optional RFC 1421 headers.
function parsePemBlock(text) {
  const m = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(text);
  if (!m) return null;
  const headers = {};
  let body = m[2].replace(/\r/g, '');
  const hm = /^\s*((?:[A-Za-z-]+:[^\n]*\n)+)\n/.exec(body);
  if (hm) {
    for (const ln of hm[1].trim().split('\n')) {
      const i = ln.indexOf(':');
      headers[ln.slice(0, i).trim()] = ln.slice(i + 1).trim();
    }
    body = body.slice(hm[0].length);
  }
  let bytes;
  try { bytes = b64dec(body); } catch (e) { fail('The key text is damaged (bad base64). Copy it again.'); }
  return { label: m[1], headers, bytes };
}

const PRIVATE_TYPES = {};

PRIVATE_TYPES['ssh-ed25519'] = async (r) => {
  const pub = r.string(), priv = r.string();
  if (pub.length !== 32 || priv.length !== 64 || !bytesEqual(priv.subarray(32), pub)) fail('The Ed25519 key is damaged.');
  const x = await ed25519ScalarFromSeed(priv.subarray(0, 32));
  if (!bytesEqual(ED.encode(ED.mul(ED.G, x)), pub)) fail('The Ed25519 key is damaged.');
  return { id: 'ed25519:' + toHex(pub), sec: { x }, blob: concatBytes(sshString('ssh-ed25519'), sshString(pub)) };
};

// From a P-256 secret scalar, with the public point if the file has one.
function p256Private(d, qBytes) {
  if (d <= 0n || d >= P256.q) fail('The P-256 key is damaged.');
  const Q = P256.encodeUncompressed(P256.mul(P256.G, d));
  if (qBytes && !bytesEqual(Q, qBytes)) fail('The P-256 key is damaged.');
  return { id: 'p256:' + toHex(Q), sec: { x: d }, blob: concatBytes(sshString('ecdsa-sha2-nistp256'), sshString('nistp256'), sshString(Q)) };
}

PRIVATE_TYPES['ecdsa-sha2-nistp256'] = async (r) => {
  if (r.text() !== 'nistp256') fail('The P-256 key is damaged.');
  const qBytes = r.string();
  return p256Private(r.mpint(), qBytes);
};

const OPENSSH_MAGIC = te.encode('openssh-key-v1\0');

function opensshHeader(bytes) {
  if (!bytesEqual(bytes.subarray(0, OPENSSH_MAGIC.length), OPENSSH_MAGIC)) fail('Not an OpenSSH private key.');
  const r = new SshReader(bytes.subarray(OPENSSH_MAGIC.length));
  const cipher = r.text(), kdf = r.text(), kdfopts = r.string();
  if (r.u32() !== 1) fail('Key files with more than one key aren\'t supported.');
  const pubBlob = r.string();
  const priv = r.string();
  return { cipher, kdf, kdfopts, pubBlob, priv, rest: r.rest() };
}

// What the UI needs before asking for a passphrase.
function inspectPrivateKey(text) {
  const t = text.trim();
  if (!t) return { empty: true };
  if (/^(ssh-|ecdsa-|sk-)\S+\s+AAAA/.test(t)) fail('That\'s a public key. Paste the private key: the file without .pub at the end.');
  const pem = parsePemBlock(t);
  if (!pem) fail('Not a private key. It should start with -----BEGIN.');
  if (pem.label === 'OPENSSH PRIVATE KEY') {
    const h = opensshHeader(pem.bytes);
    return { format: 'openssh', encrypted: h.cipher !== 'none', pem };
  }
  if (PEM_FORMATS[pem.label]) {
    return { format: 'pem', encrypted: pem.headers['Proc-Type'] === '4,ENCRYPTED', pem };
  }
  if (pem.label === 'ENCRYPTED PRIVATE KEY') fail('Encrypted PKCS#8 keys aren\'t supported. Convert it with: ssh-keygen -p -f yourkey');
  fail('Unsupported key format (' + pem.label.toLowerCase() + ').');
}

// Returns { id, type, sec, blob }: id matches the ring key's id.
async function parsePrivateKey(text, passphrase) {
  const info = inspectPrivateKey(text);
  if (info.empty) fail('Paste a private key.');
  if (info.encrypted && !passphrase) fail('This key has a passphrase. Enter it.');
  if (info.format === 'pem') return parsePemPrivateKey(info.pem, passphrase);

  const h = opensshHeader(info.pem.bytes);
  let plain = h.priv;
  if (h.cipher !== 'none') plain = await opensshDecrypt(h, passphrase);
  const r = new SshReader(plain);
  const c1 = r.u32(), c2 = r.u32();
  if (c1 !== c2) fail(h.cipher === 'none' ? 'The key is damaged.' : 'Wrong passphrase.');
  const type = r.text();
  const parse = PRIVATE_TYPES[type];
  if (!parse) {
    fail(UNUSABLE_TYPES[type] || ('Unsupported key type: ' + type + '.'));
  }
  const k = await parse(r);
  if (!bytesEqual(k.blob, h.pubBlob)) {
    const pk = await prepareKey(type + ' ' + b64enc(h.pubBlob));
    if (!pk.usable || pk.key.id !== k.id) fail('The key is damaged: its public and private parts don\'t match.');
  }
  return Object.assign(k, { type });
}

// Filled in by 50-pem.js.
const PEM_FORMATS = {};
