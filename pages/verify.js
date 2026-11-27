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
    out.append(el('div', { class: 'verdict v-invalid' }, el('span', { class: 'vbadge' }, 'INVALID'), el('span', { class: 'vtext' }, errText(e))));
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

  const noteBox = el('div');
  const ghStatus = el('div', { class: 'status' }, 'Checking the keys on GitHub...');
  out.append(
    el('div', { class: 'verdict v-valid' }, el('span', { class: 'vbadge' }, 'VALID'),
      el('span', { class: 'vtext' }, el('b', null, 'One of these ' + plural(users.length, 'GitHub user') + ' signed this;'), ' which one stays hidden.')),
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
    setStatus(ghStatus, 'Couldn\'t check the keys on GitHub. ' + errText(e) + ' The signature is still valid for the keys it carries.', 'err');
    return;
  }
  const total = ring.length;
  if (!missingKeys) setStatus(ghStatus, (total === 1 ? 'The key is' : 'All ' + total + ' keys are') + ' still listed on these GitHub accounts.', 'ok');
  else {
    setStatus(ghStatus, plural(missingKeys, 'key') + ' of ' + total + (missingKeys === 1 ? ' is' : ' are') + ' no longer listed on GitHub.');
    noteBox.append(el('p', { class: 'note' }, 'A key that\'s no longer listed may have been removed or replaced by its owner since ' + body.signed_at +
      '. Or the signer used keys that never belonged to that account. This page can\'t tell which.'));
  }
  if (renamed) noteBox.append(el('p', { class: 'note' }, 'Some accounts have changed their username since the signature was made. They\'re matched by account ID, so this doesn\'t affect the result.'));
}

$('verifyBtn').addEventListener('click', verify);
$('sig').addEventListener('paste', () => setTimeout(verify, 0));
