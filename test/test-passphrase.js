const { need } = require('./harness');
// Passphrase-protected keys. sshpk + the npm bcrypt-pbkdf module make the
// fixtures, independently of our implementation.
const { load, test, assert, rejects, summary } = require('./harness');
const { makeKey } = require('./fixtures');
const crypto = require('crypto');
const refBcrypt = need('bcrypt-pbkdf');
const Z = load();

// OpenSSH's GCM layout (sshkey.c): key||iv from bcrypt_pbkdf with a 12-byte IV,
// the u32 length covers the ciphertext only, and the 16-byte tag follows it.
function opensshGcm(unencryptedPem, pass, keyLen) {
  const raw = Buffer.from(unencryptedPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  let o = 15; // magic
  const rd = () => { const n = raw.readUInt32BE(o); const v = raw.subarray(o + 4, o + 4 + n); o += 4 + n; return v; };
  rd(); rd(); rd(); o += 4; const pub = rd(); const priv = rd();
  const salt = crypto.randomBytes(16), rounds = 16;
  const kiv = new Uint8Array(keyLen + 12);
  refBcrypt.pbkdf(Buffer.from(pass), pass.length, salt, 16, kiv, kiv.length, rounds);
  const c = crypto.createCipheriv(`aes-${keyLen * 8}-gcm`, kiv.subarray(0, keyLen), kiv.subarray(keyLen));
  const ct = Buffer.concat([c.update(priv), c.final()]);
  const str = (b) => { const l = Buffer.alloc(4); l.writeUInt32BE(b.length); return Buffer.concat([l, Buffer.from(b)]); };
  const kdfopts = Buffer.concat([str(salt), Buffer.from([0, 0, 0, rounds])]);
  const body = Buffer.concat([Buffer.from('openssh-key-v1\0'), str(`aes${keyLen * 8}-gcm@openssh.com`), str('bcrypt'),
    str(kdfopts), Buffer.from([0, 0, 0, 1]), str(pub), str(ct), c.getAuthTag()]);
  return '-----BEGIN OPENSSH PRIVATE KEY-----\n' + body.toString('base64').match(/.{1,70}/g).join('\n') + '\n-----END OPENSSH PRIVATE KEY-----\n';
}
function makeEncrypted(kind, pass, cipher) {
  if (!cipher.includes('gcm')) return makeKey(kind, { passphrase: pass, cipher });
  const k = makeKey(kind);
  return { kind, pub: k.pub, priv: opensshGcm(k.priv, pass, cipher.startsWith('aes256') ? 32 : 16) };
}

(async () => {
  console.log('Passphrases');

  await test('bcrypt_pbkdf matches the reference module', async () => {
    for (const [plen, slen, klen, rounds] of [[8, 16, 48, 16], [1, 1, 32, 1], [30, 16, 44, 4], [5, 24, 64, 2], [12, 16, 7, 3]]) {
      const pass = crypto.randomBytes(plen), salt = crypto.randomBytes(slen);
      const ref = new Uint8Array(klen);
      refBcrypt.pbkdf(pass, plen, salt, slen, ref, klen, rounds);
      const ours = await Z.bcryptPbkdf(new Uint8Array(pass), new Uint8Array(salt), klen, rounds);
      assert(Buffer.from(ours).equals(Buffer.from(ref)), `p${plen} s${slen} k${klen} r${rounds}`);
    }
  });

  for (const kind of ['ed25519', 'p256']) {
    for (const cipher of ['aes256-ctr', 'aes128-ctr', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-cbc']) {
      await test(`${kind} with ${cipher}`, async () => {
        const pass = 'correct horse ' + kind;
        const k = makeEncrypted(kind, pass, cipher);
        assert(k.priv.includes('OPENSSH PRIVATE KEY'));
        const info = Z.inspectPrivateKey(k.priv);
        assert(info.encrypted, 'not detected as encrypted');
        await rejects(Z.parsePrivateKey(k.priv, ''), /has a passphrase/);
        await rejects(Z.parsePrivateKey(k.priv, 'wrong'), /Wrong passphrase/);
        const t0 = Date.now();
        const priv = await Z.parsePrivateKey(k.priv, pass);
        const ms = Date.now() - t0;
        const pk = await Z.prepareKey(k.pub);
        assert(priv.id === pk.key.id);
        const body = await Z.signRing('m', '2026-11-27', [{ login: 'a', userId: 1, key: pk.key }], priv);
        await Z.verifyRing(body);
        if (cipher === 'aes256-ctr') console.log(`       decrypt took ${ms} ms`);
      });
    }
  }

  await test('unencrypted key is not flagged as encrypted', async () => {
    assert(!Z.inspectPrivateKey(makeKey('ed25519').priv).encrypted);
  });

  summary();
})();
