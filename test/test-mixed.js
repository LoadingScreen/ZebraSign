// Round trips over rings that mix key types. Usage: node test-mixed.js ed25519 p256 [rsa]
const { load, test, assert, rejects, summary } = require('./harness');
const { makeKey } = require('./fixtures');
const Z = load();
const kinds = process.argv.slice(2);

(async () => {
  console.log('Mixed ring: ' + kinds.join(', '));

  await test('private keys match their public keys', async () => {
    for (const kind of kinds) {
      for (let i = 0; i < (kind === 'rsa' ? 2 : 5); i++) {
        const k = makeKey(kind);
        const priv = await Z.parsePrivateKey(k.priv);
        const pk = await Z.prepareKey(k.pub);
        assert(pk.usable, pk.reason);
        assert(priv.id === pk.key.id, kind);
      }
    }
  });

  const keys = [];
  for (const kind of kinds) keys.push(makeKey(kind), makeKey(kind));
  const entries = [];
  for (let i = 0; i < keys.length; i++) {
    const pk = await Z.prepareKey(keys[i].pub);
    entries.push({ login: 'user' + (i % 3), userId: 1000 + (i % 3), key: pk.key });
  }

  await test('sign with every member, verify', async () => {
    for (const k of keys) {
      const t0 = Date.now();
      const body = await Z.signRing('mixed ring message', '2026-11-27', entries, await Z.parsePrivateKey(k.priv));
      const t1 = Date.now();
      const armored = Z.armor(body);
      await Z.verifyRing(Z.dearmor(armored));
      console.log(`       ${k.kind}: sign ${t1 - t0} ms, verify ${Date.now() - t1} ms, ${armored.length} chars`);
    }
  });

  await test('tampering with any one response is detected', async () => {
    const body = await Z.signRing('m', '2026-11-27', entries, await Z.parsePrivateKey(keys[0].priv));
    // Flip one bit at many positions across every key's c and z.
    const step = Math.max(1, Math.floor(body.proof.length / 60));
    for (let i = 0; i < body.proof.length; i += step) {
      const b = Z.dearmor(Z.armor(body));
      const p = Uint8Array.from(b.proof); p[i] ^= 0x10; b.proof = p;
      await rejects(Z.verifyRing(b)).catch((e) => { throw new Error('byte ' + i + ': ' + e.message); });
    }
  });

  await test('proof entries look alike whoever signed (lengths)', async () => {
    const a = await Z.signRing('m', '2026-11-27', entries, await Z.parsePrivateKey(keys[0].priv));
    const b = await Z.signRing('m', '2026-11-27', entries, await Z.parsePrivateKey(keys[keys.length - 1].priv));
    assert(a.proof.length === b.proof.length, 'proof lengths differ');
    assert(Z.armor(a).length === Z.armor(b).length, 'armored lengths differ');
  });

  if (kinds.includes('p256')) {
    await test('off-curve P-256 key is skipped', async () => {
      const k = await Z.prepareKey(keys.find((x) => x.kind === 'p256').pub);
      const blob = Uint8Array.from(k.key.blob);
      blob[blob.length - 1] ^= 1;
      const r = await Z.prepareKey('ecdsa-sha2-nistp256 ' + Z.b64enc(blob));
      assert(!r.usable && /curve point/.test(r.reason), r.reason);
    });
  }

  summary();
})();
