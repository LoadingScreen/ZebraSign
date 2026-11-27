// GitHub API: users and their published SSH keys. Unauthenticated, so
// GitHub allows 60 requests per hour per IP. Each user costs 3 requests.

const GH_API = 'https://api.github.com';

async function ghGet(path) {
  let res;
  try {
    res = await fetch(GH_API + path, {
      headers: { Accept: 'application/vnd.github+json' },
      credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer',
    });
  } catch (e) {
    fail('Couldn\'t reach GitHub. Check your connection.');
  }
  if (res.status === 404) return null;
  if (res.status === 403 || res.status === 429) {
    const left = res.headers.get('x-ratelimit-remaining');
    const reset = Number(res.headers.get('x-ratelimit-reset'));
    if (left === '0' || res.status === 429) {
      const when = reset ? ' Try again after ' + new Date(reset * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + '.' : '';
      fail('GitHub\'s limit of 60 requests an hour from your IP address is used up.' + when);
    }
  }
  if (!res.ok) fail('GitHub returned an error (' + res.status + ').');
  return res.json();
}

// Parse the username box: one per line; also accepts commas, spaces, @name,
// and github.com/name.
function parseLogins(text) {
  const out = [], bad = [], seen = new Set();
  for (let t of text.split(/[\s,]+/)) {
    t = t.trim().replace(/^https?:\/\//, '').replace(/^(www\.)?github\.com\//, '').replace(/^@/, '').replace(/\/+$/, '');
    if (!t) continue;
    if (!LOGIN_RE.test(t)) { bad.push(t); continue; }
    const k = t.toLowerCase();
    if (!seen.has(k)) { seen.add(k); out.push(t); }
  }
  return { logins: out, bad };
}

// Both key lists for a login, deduplicated, each run through prepareKey().
async function fetchKeys(login) {
  const enc = encodeURIComponent(login);
  const [auth, signing] = await Promise.all([ghGet('/users/' + enc + '/keys'), ghGet('/users/' + enc + '/ssh_signing_keys')]);
  const lines = [];
  for (const k of [...(auth || []), ...(signing || [])]) if (k && typeof k.key === 'string') lines.push(k.key);
  const seen = new Set(), keys = [], skipped = [];
  for (const line of lines) {
    const pk = await prepareKey(line);
    if (pk.usable) {
      if (seen.has(pk.key.id)) continue;
      seen.add(pk.key.id);
      keys.push(pk.key);
    } else {
      skipped.push(pk);
    }
  }
  return { keys, skipped };
}

// For the signer: { login, userId, avatar, keys, skipped } or { login, missing: true }.
async function fetchRingUser(login) {
  const [user, ks] = await Promise.all([ghGet('/users/' + encodeURIComponent(login)), fetchKeys(login)]);
  if (!user) return { login, missing: true };
  return { login: user.login, userId: user.id, avatar: avatarUrl(user.id), keys: ks.keys, skipped: ks.skipped };
}

// For the verifier: look the account up by ID, since logins can change.
async function fetchUserById(id) {
  const user = await ghGet('/user/' + id);
  if (!user) return { id, missing: true };
  const ks = await fetchKeys(user.login);
  return { id, login: user.login, keyIds: new Set(ks.keys.map((k) => k.id)) };
}

function avatarUrl(id) { return 'https://avatars.githubusercontent.com/u/' + id + '?s=64&v=4'; }
