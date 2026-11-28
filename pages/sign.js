// Signer page.

let ring = null;       // { entries, users, signedAt, loginsText }
let fetching = false;

function ringStale() { return ring && ring.loginsText !== $('logins').value; }

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) { const i = next++; out[i] = await fn(items[i], i); }
  }));
  return out;
}

async function fetchRing() {
  const status = $('ringStatus'), list = $('ringList'), sum = $('ringSummary');
  const text = $('logins').value;
  const { logins, bad } = parseLogins(text);
  list.replaceChildren(); sum.textContent = '';
  ring = null;
  if (bad.length) return setStatus(status, 'Not valid GitHub usernames: ' + bad.join(', '), 'err');
  if (!logins.length) return setStatus(status, 'Enter at least one username.', 'err');
  if (logins.length > 20) setStatus(status, 'That\'s ' + logins.length + ' users. GitHub only allows about 20 per hour without signing in, so some may fail.');

  fetching = true; update();
  let done = 0;
  setStatus(status, 'Fetching keys: 0 of ' + logins.length);
  let users;
  try {
    users = await mapLimit(logins, 4, async (login) => {
      const u = await fetchRingUser(login);
      setStatus(status, 'Fetching keys: ' + (++done) + ' of ' + logins.length);
      return u;
    });
  } catch (e) {
    fetching = false; update();
    return setStatus(status, errText(e), 'err');
  }
  fetching = false;

  const seen = new Set(), found = [], missing = [];
  for (const u of users) {
    if (u.missing) { missing.push(u.login); continue; }
    if (seen.has(u.userId)) continue;
    seen.add(u.userId);
    found.push(u);
  }
  for (const u of found) list.append(userRow(u));

  const usable = found.filter((u) => u.keys.length);
  const entries = usable.flatMap((u) => u.keys.map((key) => ({ login: u.login, userId: u.userId, key })));
  setStatus(status, missing.length ? 'No GitHub user named ' + missing.join(', ') + '.' : '', missing.length ? 'err' : '');
  if (entries.length) {
    sum.textContent = 'Ring: ' + plural(usable.length, 'user') + ', ' + plural(entries.length, 'key') + '.' +
      (usable.length === 1 ? ' With one user, the signature shows who signed it. Add others to hide among them.' : '');
    ring = { entries, users: usable, signedAt: new Date().toISOString().slice(0, 10), loginsText: text };
  } else {
    sum.textContent = 'No usable keys, so there is no ring yet.';
  }
  update();
  checkKey();
}

function userRow(u) {
  const skipped = !u.keys.length;
  const keys = el('ul', { class: 'keys' },
    u.keys.map((k) => el('li', null, el('span', { class: 'kt' }, keyLabel(k)), el('span', { class: 'fp' }, k.fp))),
    u.skipped.map((s) => el('li', { class: 'dead' }, el('span', { class: 'kt' }, s.type), el('span', { class: 'fp' }, 'skipped: ' + s.reason))));
  if (!u.keys.length && !u.skipped.length) keys.append(el('li', { class: 'dead' }, 'No SSH keys on GitHub.'));
  const help = skipped ? el('div', { class: 'idhelp' }, 'If this is your account, make a key for testing by running ',
    el('code', null, 'ssh-keygen -t ed25519 -f ~/.ssh/zebrasign_test'), ' in a terminal. Then copy the contents of ',
    el('code', null, '~/.ssh/zebrasign_test.pub'), ' into ',
    el('a', { href: 'https://github.com/settings/ssh/new', target: '_blank', rel: 'noopener noreferrer' }, 'github.com/settings/ssh/new'),
    ', set Key type to Signing Key, and fetch the keys again.') : null;
  return el('div', { class: 'idrow' + (skipped ? ' skip' : '') }, avatarImg(u.userId),
    el('div', { class: 'idmeta' },
      el('div', { class: 'idname' }, profileLink(u.login), skipped ? el('span', { class: 'idnote' }, 'skipped, no usable key') : null),
      keys, help));
}

// Private key box: detect a passphrase and, once the ring is known, which key it is.
let keyCheckSeq = 0;
async function checkKey() {
  const seq = ++keyCheckSeq;
  const status = $('keyStatus');
  let info;
  try { info = inspectPrivateKey($('key').value); } catch (e) {
    $('passRow').hidden = true;
    setStatus(status, errText(e), 'err');
    return update();
  }
  $('passRow').hidden = !info.encrypted;
  if (info.empty) { setStatus(status, ''); return update(); }
  if (info.encrypted && !$('pass').value) { setStatus(status, 'This key has a passphrase.'); return update(); }
  if (info.encrypted) setStatus(status, 'Checking passphrase...');
  try {
    const priv = await parsePrivateKey($('key').value, $('pass').value);
    if (seq !== keyCheckSeq) return;
    const label = { 'ssh-ed25519': 'Ed25519', 'ecdsa-sha2-nistp256': 'P-256', 'ssh-rsa': 'RSA' }[priv.type] || priv.type;
    const fp = fingerprint(await sha256(priv.blob));
    if (!ring) setStatus(status, label + ' key ' + fp + '. Fetch the ring to check it\'s in it.');
    else {
      const m = ring.entries.find((e) => e.key.id === priv.id);
      if (m) setStatus(status, label + ' key ' + fp + ', listed on ' + m.login + '\'s GitHub account.', 'ok');
      else setStatus(status, 'This ' + label + ' key (' + fp + ') isn\'t in the ring. Add the GitHub user it belongs to, or use a different key. If it\'s yours, it may not be on GitHub yet: add its .pub file at github.com/settings/ssh/new as a Signing Key, then fetch the keys again.', 'err');
    }
  } catch (e) {
    if (seq !== keyCheckSeq) return;
    setStatus(status, errText(e), 'err');
  }
  update();
}

function update() {
  $('fetchBtn').disabled = fetching;
  $('fetchBtn').textContent = ring && !ringStale() ? 'Fetch again' : 'Fetch keys';
  const ready = ring && !ringStale() && $('msg').value.trim() && $('keyStatus').classList.contains('ok');
  $('signBtn').disabled = !ready;
  if (ringStale()) $('ringSummary').textContent = 'The list changed. Fetch keys again before signing.';
}

async function sign() {
  const status = $('signStatus'), out = $('signOut');
  out.replaceChildren();
  $('signBtn').disabled = true;
  setStatus(status, 'Signing...');
  try {
    const priv = await parsePrivateKey($('key').value, $('pass').value);
    const body = await signRing($('msg').value, ring.signedAt, ring.entries, priv);
    const text = armor(body);
    await verifyRing(dearmor(text)); // check the exact text before showing it
    setStatus(status, '');
    const copy = el('button', { class: 'small', onclick: async () => {
      try { await navigator.clipboard.writeText(text); toast('Copied'); } catch (e) { toast('Copy failed. Select the text and copy it.'); }
    } }, 'Copy');
    out.append(el('div', { class: 'out' },
      el('pre', { class: 'sigtext' }, text),
      el('div', { class: 'outfoot' },
        el('span', null, ring.users.length === 1 ? 'Signed as ' + ring.users[0].login + '. ' : 'Signed as one of ' + ring.users.length + ' GitHub users. ',
          'Anyone can check it on the ', el('a', { href: 'verify.html' }, 'verify page'), '.'),
        copy)));
  } catch (e) {
    setStatus(status, errText(e), 'err');
  }
  update();
}

// Show the copy command for this system; the others stay under "other systems".
(function copyHelp() {
  const ua = navigator.userAgent;
  const touchMac = /Mac/.test(ua) && navigator.maxTouchPoints > 1; // iPads report as Mac
  const cmd = /iPhone|iPad|Android/.test(ua) || touchMac ? null
    : /Mac/.test(ua) ? ['To copy it on a Mac, run ', 'pbcopy < ~/.ssh/zebrasign_test', ' in Terminal, then paste it here.']
    : /Win/.test(ua) ? ['To copy it on Windows, run ', 'Get-Content $env:USERPROFILE\\.ssh\\zebrasign_test | Set-Clipboard', ' in PowerShell, then paste it here.']
    : /Linux|X11/.test(ua) ? ['To see it on Linux, run ', 'cat ~/.ssh/zebrasign_test', ', then copy everything it prints and paste it here.']
    : null;
  if (!cmd) { $('copyMore').open = true; return; }
  $('copyHow').append(cmd[0], el('code', null, cmd[1]), cmd[2]);
})();

$('fetchBtn').addEventListener('click', fetchRing);
$('logins').addEventListener('input', update);
$('msg').addEventListener('input', update);
$('key').addEventListener('input', checkKey);
let passTimer;
$('pass').addEventListener('input', () => { clearTimeout(passTimer); passTimer = setTimeout(checkKey, 400); });
$('signBtn').addEventListener('click', sign);
$('keyFile').addEventListener('change', async (ev) => {
  const f = ev.target.files[0];
  if (!f) return;
  if (f.size > 64 * 1024) { setStatus($('keyStatus'), 'That file is too large to be a private key.', 'err'); return; }
  $('key').value = await f.text();
  ev.target.value = '';
  checkKey();
});
update();
