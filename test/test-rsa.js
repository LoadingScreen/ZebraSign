const { load, test, assert, rejects, summary } = require('./harness');
const { makeKey, sshpk } = require('./fixtures');
const crypto = require('crypto');
const Z = load();

const pubOf = (nodeKey) => sshpk.parseKey(crypto.createPublicKey(nodeKey).export({ type: 'spki', format: 'pem' }), 'pem').toString('ssh');

async function roundTrip(privText, pubLine, pass) {
  const priv = await Z.parsePrivateKey(privText, pass);
  const pk = await Z.prepareKey(pubLine);
  assert(pk.usable, pk.reason);
  assert(priv.id === pk.key.id, 'id mismatch');
  const body = await Z.signRing('rsa test', '2026-11-27', [{ login: 'a', userId: 1, key: pk.key }], priv);
  await Z.verifyRing(body);
  return body;
}

(async () => {
  console.log('RSA and PEM');

  await test('MD5 matches Node', async () => {
    for (const n of [0, 1, 55, 56, 63, 64, 65, 200]) {
      const m = crypto.randomBytes(n);
      assert(Z.toHex(Z.md5(new Uint8Array(m))) === crypto.createHash('md5').update(m).digest('hex'), 'len ' + n);
    }
  });

  await test('OpenSSH RSA 2048 and 4096, plain and with passphrase', async () => {
    for (const bits of [2048, 4096]) {
      const k = makeKey('rsa', { bits });
      const body = await roundTrip(k.priv, k.pub);
      assert(Z.b64dec(body.proof[0].z).length === 8 * bits / 8, 'expected 8 rounds');
    }
    const k = makeKey('rsa', { passphrase: 'pw', cipher: 'aes256-ctr' });
    await roundTrip(k.priv, k.pub, 'pw');
  });

  const { privateKey: rsaNode } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const rsaPub = pubOf(rsaNode);

  await test('PEM PKCS#1, unencrypted', async () => {
    await roundTrip(rsaNode.export({ type: 'pkcs1', format: 'pem' }), rsaPub);
  });

  for (const cipher of ['aes-128-cbc', 'aes-256-cbc']) {
    await test('legacy encrypted PEM, ' + cipher, async () => {
      const pem = rsaNode.export({ type: 'pkcs1', format: 'pem', cipher, passphrase: 'old secret' });
      assert(/Proc-Type: 4,ENCRYPTED/.test(pem) && pem.includes(cipher.toUpperCase()));
      assert(Z.inspectPrivateKey(pem).encrypted);
      await rejects(Z.parsePrivateKey(pem, 'nope'), /Wrong passphrase/);
      await roundTrip(pem, rsaPub, 'old secret');
    });
  }

  await test('legacy DES-EDE3 PEM gives a conversion hint', async () => {
    const pem = rsaNode.export({ type: 'pkcs1', format: 'pem', cipher: 'des-ede3-cbc', passphrase: 'x' });
    await rejects(Z.parsePrivateKey(pem, 'x'), /ssh-keygen -p/);
  });

  await test('PKCS#8 for all three types; encrypted PKCS#8 refused plainly', async () => {
    await roundTrip(rsaNode.export({ type: 'pkcs8', format: 'pem' }), rsaPub);
    for (const kind of ['ed25519', 'p256']) {
      const k = makeKey(kind);
      await roundTrip(k.nodeKey.export({ type: 'pkcs8', format: 'pem' }), k.pub);
    }
    const enc = rsaNode.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'x' });
    await rejects(Z.parsePrivateKey(enc, 'x'), /Encrypted PKCS#8/);
  });

  await test('SEC1 EC PEM, plain and legacy-encrypted', async () => {
    const k = makeKey('p256');
    await roundTrip(k.nodeKey.export({ type: 'sec1', format: 'pem' }), k.pub);
    await roundTrip(k.nodeKey.export({ type: 'sec1', format: 'pem', cipher: 'aes-128-cbc', passphrase: 'ec' }), k.pub, 'ec');
  });

  await test('e = 3 works (128 one-bit rounds)', async () => {
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 3 });
    const body = await roundTrip(privateKey.export({ type: 'pkcs1', format: 'pem' }), pubOf(privateKey));
    assert(Z.b64dec(body.proof[0].z).length === 128 * 256);
  });

  const rsaLine = (e, n) => {
    const str = (b) => Buffer.concat([Buffer.from([0, 0, 0, b.length].map((x, i) => i < 3 ? (b.length >> (8 * (3 - i))) & 255 : b.length & 255)), b]);
    const mp = (v) => { let h = v.toString(16); if (h.length % 2) h = '0' + h; let b = Buffer.from(h, 'hex'); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return str(b); };
    return 'ssh-rsa ' + Buffer.concat([str(Buffer.from('ssh-rsa')), mp(e), mp(n)]).toString('base64');
  };

  await test('weak RSA keys are skipped', async () => {
    const { privateKey: small } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
    let r = await Z.prepareKey(pubOf(small));
    assert(!r.usable && /2048/.test(r.reason), r.reason);
    // A prime modulus: anyone could take e-th roots.
    const prime = crypto.generatePrimeSync(2048, { bigint: true });
    r = await Z.prepareKey(rsaLine(65537n, prime));
    assert(!r.usable && /invalid modulus/.test(r.reason), 'prime accepted');
    // A perfect square of a prime.
    const p = crypto.generatePrimeSync(1100, { bigint: true });
    r = await Z.prepareKey(rsaLine(65537n, p * p));
    assert(!r.usable && /invalid modulus/.test(r.reason), 'square accepted');
    // Even exponent.
    const n = BigInt('0x' + Buffer.from(crypto.createPublicKey(rsaNode).export({ format: 'jwk' }).n, 'base64url').toString('hex'));
    r = await Z.prepareKey(rsaLine(65536n, n));
    assert(!r.usable && /exponent/.test(r.reason), 'even e accepted');
    r = await Z.prepareKey(rsaLine(65537n, n));
    assert(r.usable, 'real modulus rejected: ' + r.reason);
  });

  summary();
})();
