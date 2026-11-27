const { need } = require('./harness');
// End-to-end in Chrome with a fake GitHub API. Usage: node test/e2e.js
const path = require('path');
const { chromium } = need('playwright');
const { makeKey } = require('./fixtures');

const alice = makeKey('ed25519', { passphrase: 'zebra crossing', cipher: 'aes256-ctr' });
const alice2 = makeKey('ed25519');
const bob = makeKey('p256');
const carol = makeKey('rsa');
const USERS = {
  alice: { id: 583231, auth: [alice2.pub], signing: [alice.pub] },
  bob: { id: 1024025, auth: [bob.pub], signing: [] },
  carol: { id: 66, auth: [carol.pub], signing: [] },
  dave: { id: 912, auth: [], signing: ['sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIEX/dQ0v4127bEo8eeG1EV0ApO2lWbSnN6RWusn/NjqIAAAABHNzaDo='] },
};
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64');
let requests = 0;

async function route(r) {
  const url = new URL(r.request().url());
  if (url.host === 'avatars.githubusercontent.com') return r.fulfill({ status: 200, contentType: 'image/png', body: PNG });
  requests++;
  const json = (status, body) => r.fulfill({ status, contentType: 'application/json', headers: { 'access-control-allow-origin': '*' }, body: JSON.stringify(body) });
  let m;
  if ((m = /^\/users\/([^/]+)$/.exec(url.pathname))) {
    const u = USERS[m[1].toLowerCase()];
    return u ? json(200, { login: m[1].toLowerCase(), id: u.id }) : json(404, { message: 'Not Found' });
  }
  if ((m = /^\/user\/(\d+)$/.exec(url.pathname))) {
    const e = Object.entries(USERS).find(([, u]) => u.id === Number(m[1]));
    return e ? json(200, { login: e[0], id: e[1].id }) : json(404, {});
  }
  if ((m = /^\/users\/([^/]+)\/(keys|ssh_signing_keys)$/.exec(url.pathname))) {
    const u = USERS[m[1].toLowerCase()];
    if (!u) return json(404, {});
    return json(200, (m[2] === 'keys' ? u.auth : u.signing).map((key, i) => ({ id: i + 1, key })));
  }
  return json(404, {});
}

const fail = (m) => { console.log('  FAIL ' + m); process.exitCode = 1; };
const ok = (m) => console.log('  ok  ' + m);

(async () => {
  const browser = await chromium.launch({ ...(process.env.CHROME ? { executablePath: process.env.CHROME } : {}), args: ['--no-sandbox'] });
  const ctx = await browser.newContext({ viewport: { width: 900, height: 1200 }, permissions: ['clipboard-read', 'clipboard-write'] });
  await ctx.route('https://api.github.com/**', route);
  await ctx.route('https://avatars.githubusercontent.com/**', route);
  const page = await ctx.newPage();
  const problems = [];
  page.on('console', (m) => { if (m.type() === 'error' || m.type() === 'warning') problems.push(m.text()); });
  page.on('pageerror', (e) => problems.push(String(e)));
  const shots = path.join(__dirname, '..', 'shots');

  console.log('Browser');
  await page.goto('file://' + path.join(__dirname, '..', 'docs', 'sign.html'));
  await page.fill('#logins', 'alice\n@Bob\ncarol\ndave\nghost');
  await page.click('#fetchBtn');
  await page.waitForFunction(() => document.getElementById('ringSummary').textContent.startsWith('Ring'));
  const summary = await page.textContent('#ringSummary');
  summary === 'Ring: 3 users, 4 keys.' ? ok('fetch: ' + summary) : fail('summary: ' + summary);
  const status = await page.textContent('#ringStatus');
  /ghost/.test(status) ? ok('missing user reported') : fail('ghost not reported: ' + status);
  (await page.textContent('#ringList')).includes('skipped, no usable key') ? ok('hardware-key user skipped') : fail('dave not skipped');
  requests === 15 ? ok('15 API requests for 5 users') : fail('requests: ' + requests);

  await page.fill('#msg', 'The meeting moved to Thursday.\nBring the draft.');
  await page.fill('#key', alice.priv);
  await page.waitForSelector('#passRow:not([hidden])');
  ok('passphrase field shown for encrypted key');
  await page.fill('#pass', 'wrong one');
  await page.waitForFunction(() => /Wrong passphrase/.test(document.getElementById('keyStatus').textContent));
  ok('wrong passphrase reported');
  await page.fill('#pass', 'zebra crossing');
  await page.waitForFunction(() => document.getElementById('keyStatus').classList.contains('ok'));
  ok('key matched: ' + await page.textContent('#keyStatus'));
  await page.click('#signBtn');
  await page.waitForSelector('.sigtext');
  const sig = await page.textContent('.sigtext');
  sig.startsWith('-----BEGIN ZEBRASIGN SIGNATURE-----') ? ok('signature produced, ' + sig.length + ' chars') : fail('no signature');
  await page.click('.outfoot button');
  const clip = await page.evaluate(() => navigator.clipboard.readText());
  clip === sig ? ok('copy button copies the block') : fail('clipboard mismatch');
  await page.screenshot({ path: shots + '/sign.png', fullPage: true });

  // Key not in ring.
  await page.fill('#key', makeKey('ed25519').priv);
  await page.waitForFunction(() => /isn't in the ring/.test(document.getElementById('keyStatus').textContent));
  (await page.isDisabled('#signBtn')) ? ok('outside key refused, sign disabled') : fail('sign enabled for outside key');
  await page.fill('#key', carol.pub);
  await page.waitForFunction(() => /public key/.test(document.getElementById('keyStatus').textContent));
  ok('public key pasted: plain message');
  await page.fill('#logins', 'alice\nbob');
  (await page.textContent('#ringSummary')).includes('changed') ? ok('editing the list marks the ring stale') : fail('stale not shown');

  // Verify.
  await page.goto('file://' + path.join(__dirname, '..', 'docs', 'verify.html'));
  await page.fill('#sig', 'From the group chat:\n\n' + sig + '\n');
  await page.click('#verifyBtn');
  await page.waitForFunction(() => /still listed on these/.test(document.getElementById('result').textContent));
  const vt = await page.textContent('.verdict');
  vt.includes('VALID') && vt.includes('One of these 3 GitHub users signed this') ? ok('verdict: ' + vt) : fail('verdict: ' + vt);
  (await page.textContent('.msgbox')) === 'The meeting moved to Thursday.\nBring the draft.' ? ok('message shown exactly') : fail('message');
  await page.screenshot({ path: shots + '/verify.png', fullPage: true });

  // Bob rotates his key; carol renames.
  const bobOld = USERS.bob.auth; USERS.bob.auth = [makeKey('p256').pub];
  USERS.caroline = USERS.carol; delete USERS.carol;
  await page.click('#verifyBtn');
  await page.waitForFunction(() => /no longer listed on GitHub/.test(document.getElementById('result').textContent));
  const rt = await page.textContent('#result');
  rt.includes('1 key of 4 is no longer listed') && rt.includes('now caroline') ? ok('rotated key and rename shown') : fail('rotation: ' + rt);
  await page.screenshot({ path: shots + '/verify-rotated.png', fullPage: true });
  USERS.bob.auth = bobOld; USERS.carol = USERS.caroline; delete USERS.caroline;

  // Tampered.
  const body = JSON.parse(Buffer.from(sig.split('\n').slice(1, -1).join(''), 'base64').toString());
  body.msg = 'The meeting moved to Friday.\nBring the draft.';
  const forged = '-----BEGIN ZEBRASIGN SIGNATURE-----\n' + Buffer.from(JSON.stringify(body)).toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END ZEBRASIGN SIGNATURE-----';
  await page.fill('#sig', forged);
  await page.click('#verifyBtn');
  await page.waitForSelector('.v-invalid');
  ok('changed message: ' + await page.textContent('.verdict'));
  await page.fill('#sig', sig.slice(0, 200));
  await page.click('#verifyBtn');
  await page.waitForSelector('.v-invalid');
  (await page.textContent('.verdict')).includes('cut off') ? ok('truncated: cut-off message') : fail('truncated message');

  // GitHub down during the key check.
  await ctx.unroute('https://api.github.com/**');
  await ctx.route('https://api.github.com/**', (r) => r.abort());
  await page.fill('#sig', sig);
  await page.click('#verifyBtn');
  await page.waitForFunction(() => /Couldn't check/.test(document.getElementById('result').textContent));
  (await page.textContent('.verdict')).includes('VALID') ? ok('offline: still VALID, GitHub check reported failed') : fail('offline');

  await page.emulateMedia({ colorScheme: 'dark' });
  await page.goto('file://' + path.join(__dirname, '..', 'docs', 'verify.html'));
  await ctx.unroute('https://api.github.com/**');
  await ctx.route('https://api.github.com/**', route);
  await page.fill('#sig', sig);
  await page.click('#verifyBtn');
  await page.waitForFunction(() => /still listed on these/.test(document.getElementById('result').textContent));
  await page.screenshot({ path: shots + '/verify-dark.png', fullPage: true });

  const real = problems.filter((p) => !/net::ERR_FAILED|Failed to load resource/.test(p));
  real.length ? fail('console: ' + real.join(' | ')) : ok('no console errors or CSP violations');
  await browser.close();
})();
