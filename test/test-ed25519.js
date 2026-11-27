const { load, test, assert, rejects, summary } = require('./harness');
const { makeKey } = require('./fixtures');
const Z = load();

async function entry(login, userId, line) {
  const pk = await Z.prepareKey(line);
  assert(pk.usable, pk.reason);
  return { login, userId, key: pk.key };
}

(async () => {
  console.log('Ed25519');

  await test('RFC 8032 test 1: seed -> public key', async () => {
    const seed = Z.fromHex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
    const x = await Z.ed25519ScalarFromSeed(seed);
    const pub = Z.ED.encode(Z.ED.mul(Z.ED.G, x));
    assert(Z.toHex(pub) === 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', Z.toHex(pub));
  });

  await test('decode/encode round trip on random points', async () => {
    for (let i = 0; i < 5; i++) {
      const k = makeKey('ed25519');
      const pk = await Z.prepareKey(k.pub);
      assert(pk.usable, pk.reason);
      const raw = pk.key.blob.subarray(pk.key.blob.length - 32);
      assert(Z.toHex(Z.ED.encode(pk.key.point)) === Z.toHex(raw));
    }
  });

  await test('rejects small-order and invalid points', async () => {
    const blob = (pt) => Z.b64enc(Uint8Array.from([0, 0, 0, 11, ...Buffer.from('ssh-ed25519'), 0, 0, 0, 32, ...pt]));
    const identity = new Uint8Array(32); identity[0] = 1;
    let r = await Z.prepareKey('ssh-ed25519 ' + blob(identity));
    assert(!r.usable, 'identity accepted');
    const bad = new Uint8Array(32).fill(0xff); bad[31] = 0x7f; // y >= p
    r = await Z.prepareKey('ssh-ed25519 ' + blob(bad));
    assert(!r.usable, 'y >= p accepted');
    for (const h of ['ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // order 2
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05']) { // order 8
      r = await Z.prepareKey('ssh-ed25519 ' + blob(Z.fromHex(h)));
      assert(!r.usable, 'small-order accepted: ' + h);
    }
  });

  await test('private key from sshpk matches its public key', async () => {
    for (let i = 0; i < 5; i++) {
      const k = makeKey('ed25519');
      const priv = await Z.parsePrivateKey(k.priv);
      const pk = await Z.prepareKey(k.pub);
      assert(priv.id === pk.key.id);
    }
  });

  await test('hardware keys are skipped', async () => {
    const r = await Z.prepareKey('sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIEX/dQ0v4127bEo8eeG1EV0ApO2lWbSnN6RWusn/NjqIAAAABHNzaDo=');
    assert(!r.usable && /Hardware/.test(r.reason));
  });

  const keys = [makeKey('ed25519'), makeKey('ed25519'), makeKey('ed25519'), makeKey('ed25519'), makeKey('ed25519')];
  const owners = [['alice', 101], ['alice', 101], ['bob', 7], ['carol-x', 55555], ['dave', 3]];
  const entries = await Promise.all(keys.map((k, i) => entry(owners[i][0], owners[i][1], k.pub)));

  await test('sign and verify with each ring member', async () => {
    for (const k of keys) {
      const priv = await Z.parsePrivateKey(k.priv);
      const body = await Z.signRing('hello ring\nline two', '2026-11-27', entries, priv);
      const armored = Z.armor(body);
      assert(armored.startsWith('-----BEGIN ZEBRASIGN SIGNATURE-----\n'));
      const res = await Z.verifyRing(Z.dearmor('some chat text\n' + armored + '\nmore'));
      assert(res.ring.length === 5);
    }
  });

  await test('ring is in (user ID, fingerprint) order', async () => {
    const body = await Z.signRing('m', '2026-11-27', entries, await Z.parsePrivateKey(keys[0].priv));
    const ids = body.ring.map((e) => e.id);
    assert(JSON.stringify(ids) === JSON.stringify([3, 7, 101, 101, 55555]), ids);
  });

  await test('single-key ring works', async () => {
    const body = await Z.signRing('solo', '2026-11-27', [entries[2]], await Z.parsePrivateKey(keys[2].priv));
    await Z.verifyRing(body);
  });

  await test('tampering is detected', async () => {
    const body = await Z.signRing('original', '2026-11-27', entries, await Z.parsePrivateKey(keys[3].priv));
    const clone = () => JSON.parse(JSON.stringify(body));
    const cases = {
      message: (b) => { b.msg = 'changed'; },
      date: (b) => { b.signed_at = '2026-11-28'; },
      login: (b) => { b.ring[0].login = 'mallory'; },
      'user id': (b) => { b.ring[4].id = 55556; },
      'key swap': (b) => { b.ring[0].key = makeKey('ed25519').pub; },
      'order swap': (b) => { [b.ring[2], b.ring[3]] = [b.ring[3], b.ring[2]]; [b.proof[2], b.proof[3]] = [b.proof[3], b.proof[2]]; },
      'challenge': (b) => { const c = Z.b64dec(b.proof[0].c); c[0] ^= 1; b.proof[0].c = Z.b64enc(c); },
      'response': (b) => { const z = Z.b64dec(b.proof[2].z); z[31] ^= 1; b.proof[2].z = Z.b64enc(z); },
      'drop member': (b) => { b.ring.pop(); b.proof.pop(); },
      version: (b) => { b.v = 2; },
    };
    for (const [name, mutate] of Object.entries(cases)) {
      const b = clone(); mutate(b);
      await rejects(Z.verifyRing(b)).catch((e) => { throw new Error(name + ': ' + e.message); });
    }
    await Z.verifyRing(clone());
  });

  await test('key not in ring is refused', async () => {
    const outsider = await Z.parsePrivateKey(makeKey('ed25519').priv);
    await rejects(Z.signRing('x', '2026-11-27', entries, outsider), /doesn't match any key/);
  });

  await test('pasting a public key gives a plain message', async () => {
    await rejects(Z.parsePrivateKey(keys[0].pub), /That's a public key/);
  });

  await test('damaged armor gives a plain message', async () => {
    const a = Z.armor(await Z.signRing('x', '2026-11-27', entries, await Z.parsePrivateKey(keys[0].priv)));
    let threw = false;
    try { Z.dearmor(a.replace(/\n(.)/, '\n!')); } catch (e) { threw = /damaged/.test(e.message); }
    assert(threw);
  });

  await test('signature from the old desktop app is recognized', async () => {
    const old = '[Jane Doe <jane@example.com> <ZebraSign 1.0 Beta> ' + 'A'.repeat(64) + ' ' + 'B'.repeat(200) + ']';
    let msg = '';
    try { Z.dearmor('Here it is:\n' + old); } catch (e) { msg = e.message; }
    assert(/original ZebraSign desktop app/.test(msg), msg);
  });

  summary();
})();
