// Shared page helpers. Untrusted text only ever goes in through textContent.

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) e.append(typeof k === 'string' ? document.createTextNode(k) : k);
  return e;
}
const $ = (id) => document.getElementById(id);

function setStatus(node, text, kind) {
  node.textContent = text || '';
  node.className = 'status' + (kind ? ' ' + kind : '');
}

let toastTimer;
function toast(text) {
  const t = $('toast');
  t.textContent = text;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 1800);
}

// Theme follows the system. The toggle lasts until the page is closed;
// nothing is stored.
document.documentElement.setAttribute('data-theme', matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
function toggleTheme() {
  const h = document.documentElement;
  h.setAttribute('data-theme', h.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
}

const KIND_LABEL = { ed25519: 'Ed25519', p256: 'P-256', rsa: 'RSA' };
function keyLabel(k) { return k.kind === 'rsa' ? 'RSA ' + bitLength(k.n) : KIND_LABEL[k.kind]; }

function avatarImg(id) { return el('img', { class: 'avatar', src: avatarUrl(id), alt: '', loading: 'lazy', referrerpolicy: 'no-referrer' }); }
function profileLink(login) { return el('a', { href: 'https://github.com/' + login, target: '_blank', rel: 'noopener noreferrer' }, login); }

function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many || one + 's'); }

function errText(e) {
  if (e instanceof ZsError) return e.message;
  console.error(e);
  return 'Something went wrong: ' + (e && e.message || e);
}
