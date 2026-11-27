// GitHub fetching against a fake API.
const { load, test, assert, rejects, summary } = require('./harness');
const { makeKey } = require('./fixtures');

const k1 = makeKey('ed25519'), k2 = makeKey('ed25519');
const USERS = {
  alice: { id: 101, keys: [k1.pub], signing: [k1.pub, k2.pub] },
  nokeys: { id: 9, keys: [], signing: ['sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIEX/dQ0v4127bEo8eeG1EV0ApO2lWbSnN6RWusn/NjqIAAAABHNzaDo='] },
};
let limited = false, calls = [];
function fakeFetch(url) {
  calls.push(url);
  const json = (status, body, headers = {}) => Promise.resolve({
    status, ok: status < 300, json: async () => body,
    headers: { get: (h) => headers[h.toLowerCase()] ?? null },
  });
  if (limited) return json(403, { message: 'rate limit' }, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1800000000' });
  let m;
  if ((m = /\/users\/([^/]+)$/.exec(url))) {
    const u = USERS[m[1].toLowerCase()];
    return u ? json(200, { login: m[1].toLowerCase(), id: u.id }) : json(404, {});
  }
  if ((m = /\/user\/(\d+)$/.exec(url))) {
    const e = Object.entries(USERS).find(([, u]) => u.id === Number(m[1]));
    return e ? json(200, { login: e[0], id: e[1].id }) : json(404, {});
  }
  if ((m = /\/users\/([^/]+)\/(keys|ssh_signing_keys)$/.exec(url))) {
    const u = USERS[m[1].toLowerCase()];
    if (!u) return json(404, {});
    return json(200, (m[2] === 'keys' ? u.keys : u.signing).map((key, i) => ({ id: i, key })));
  }
  return json(404, {});
}

const Z = load({ fetch: fakeFetch });

(async () => {
  console.log('GitHub');

  await test('parseLogins accepts common spellings and flags junk', async () => {
    const r = Z.parseLogins('alice\n@Bob, https://github.com/carol-x/\nalice\nbad--name -x');
    assert(JSON.stringify(r.logins) === '["alice","Bob","carol-x"]', JSON.stringify(r.logins));
    assert(r.bad.length === 2);
  });

  await test('keys from both endpoints, deduplicated', async () => {
    const u = await Z.fetchRingUser('alice');
    assert(u.userId === 101 && u.keys.length === 2, JSON.stringify(u.keys.length));
    assert(calls.some((c) => c.endsWith('/users/alice/ssh_signing_keys')));
  });

  await test('user with only hardware keys has nothing usable', async () => {
    const u = await Z.fetchRingUser('nokeys');
    assert(u.keys.length === 0 && u.skipped.length === 1);
  });

  await test('unknown user is reported missing', async () => {
    const u = await Z.fetchRingUser('ghost');
    assert(u.missing);
  });

  await test('lookup by ID returns current login and key IDs', async () => {
    const u = await Z.fetchUserById(101);
    assert(u.login === 'alice' && u.keyIds.size === 2);
    assert((await Z.fetchUserById(4242)).missing);
  });

  await test('rate limit gives a plain message', async () => {
    limited = true;
    await rejects(Z.fetchRingUser('alice'), /limit of 60 requests/);
    limited = false;
  });

  summary();
})();
