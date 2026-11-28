// Verifier page.

let verifySeq = 0;

async function verify() {
  const seq = ++verifySeq;
  const out = $('result');
  out.replaceChildren();
  let res;
  try {
    res = await verifyRing(dearmor($('sig').value));
  } catch (e) {
    out.append(el('div', { class: 'verdict v-invalid' }, el('span', { class: 'vbadge' }, 'Not valid'), el('span', { class: 'vtext' }, errText(e))));
    return;
  }
  const { body, ring } = res;

  // Group keys by user, keeping ring order.
  const users = [];
  for (const e of ring) {
    let u = users.find((x) => x.id === e.userId);
    if (!u) users.push(u = { id: e.userId, login: e.login, keys: [] });
    u.keys.push({ key: e.key, st: el('span', { class: 'st wait' }, 'checking') });
  }

  // The proof only shows that one of the keys in the signature signed. The
  // headline says "these GitHub users" only after GitHub confirms the keys.
  const badge = el('span', { class: 'vbadge' }, 'Checking');
  const vtext = el('span', { class: 'vtext' }, 'The proof checks out. Checking that the keys are on these GitHub accounts...');
  const verdict = el('div', { class: 'verdict v-pending' }, badge, vtext);
  const setVerdict = (cls, label, ...text) => { verdict.className = 'verdict ' + cls; badge.textContent = label; vtext.replaceChildren(...text); };

  const noteBox = el('div');
  const ghStatus = el('div', { class: 'status' }, 'Checking the keys on GitHub...');
  out.append(
    verdict,
    el('div', { class: 'msgbox' }, body.msg),
    el('div', { class: 'meta' }, 'Keys fetched by the signer on ' + body.signed_at + '.'),
    el('div', { class: 'idlist' }, users.map((u) => {
      u.nameNote = el('span', { class: 'idnote' });
      return el('div', { class: 'idrow' }, avatarImg(u.id),
        el('div', { class: 'idmeta' },
          el('div', { class: 'idname' }, profileLink(u.login), u.nameNote),
          el('ul', { class: 'keys' }, u.keys.map((k) => el('li', null,
            el('span', { class: 'kt' }, keyLabel(k.key)), el('span', { class: 'fp' }, k.key.fp), k.st)))));
    })),
    ghStatus, noteBox);

  // Compare with what GitHub lists now. Accounts are looked up by ID, since logins can change.
  let missingKeys = 0, renamed = 0;
  try {
    for (const u of users) {
      const now = await fetchUserById(u.id);
      if (seq !== verifySeq) return;
      if (now.missing) {
        u.nameNote.textContent = 'account no longer exists';
        for (const k of u.keys) { k.st.className = 'st warn'; k.st.textContent = 'no longer listed'; missingKeys++; }
        continue;
      }
      if (now.login.toLowerCase() !== u.login.toLowerCase()) { renamed++; u.nameNote.textContent = 'now ' + now.login; }
      for (const k of u.keys) {
        const listed = now.keyIds.has(k.key.id);
        k.st.className = 'st ' + (listed ? 'ok' : 'warn');
        k.st.textContent = listed ? 'still listed' : 'no longer listed';
        if (!listed) missingKeys++;
      }
    }
  } catch (e) {
    if (seq !== verifySeq) return;
    for (const u of users) for (const k of u.keys) if (k.st.textContent === 'checking') { k.st.className = 'st wait'; k.st.textContent = 'not checked'; }
    setVerdict('v-warn', 'Not confirmed', 'The proof checks out for the keys in the signature, but this page couldn\'t reach GitHub, so it can\'t confirm the keys belong to these accounts.');
    setStatus(ghStatus, 'Couldn\'t check the keys on GitHub. ' + errText(e), 'err');
    return;
  }
  const total = ring.length;
  if (!missingKeys) {
    setStatus(ghStatus, (total === 1 ? 'The key is' : 'All ' + total + ' keys are') + ' still listed on ' + (users.length === 1 ? 'this GitHub account.' : 'these GitHub accounts.'), 'ok');
    if (users.length === 1) {
      setVerdict('v-valid', 'Valid', el('b', null, users[0].login + ' signed this.'), ' With only one user in the ring, the signer isn\'t hidden.');
    } else {
      setVerdict('v-valid', 'Valid', el('b', null, 'One of these ' + users.length + ' GitHub users signed this;'), ' which one stays hidden.');
    }
  } else {
    setVerdict('v-warn', 'Not confirmed', 'The proof checks out, but ' + missingKeys + ' of ' + total + (total === 1 ? ' key isn\'t' : ' keys aren\'t') +
      ' on these GitHub accounts now. That shows someone holding one of the keys in the signature signed this, not that one of these users did.');
    setStatus(ghStatus, plural(missingKeys, 'key') + ' of ' + total + (missingKeys === 1 ? ' is' : ' are') + ' no longer listed on GitHub.');
    noteBox.append(el('p', { class: 'note' }, 'A key that\'s no longer listed may have been removed or replaced by its owner since ' + body.signed_at +
      '. Or the signer used keys that never belonged to that account. This page can\'t tell which.'));
  }
  if (renamed) noteBox.append(el('p', { class: 'note' }, 'Some accounts have changed their username since the signature was made. They\'re matched by account ID, so this doesn\'t affect the result.'));
}

$('verifyBtn').addEventListener('click', verify);
$('sig').addEventListener('paste', () => setTimeout(verify, 0));
