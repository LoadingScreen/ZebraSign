// Test keys made by Node's crypto and converted to OpenSSH format by sshpk,
// so the parser is checked against an implementation that isn't ours.
const crypto = require('crypto');
const { need } = require('./harness');
const sshpk = need('sshpk');

function genNode(kind, bits) {
  if (kind === 'ed25519') return crypto.generateKeyPairSync('ed25519');
  if (kind === 'p256') return crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  if (kind === 'rsa') return crypto.generateKeyPairSync('rsa', { modulusLength: bits || 2048 });
  throw new Error(kind);
}

// opts: { passphrase, cipher }
function makeKey(kind, opts = {}) {
  const { privateKey } = genNode(kind, opts.bits);
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const k = sshpk.parsePrivateKey(pem, 'pkcs8');
  const wopts = {};
  if (opts.passphrase) { wopts.passphrase = opts.passphrase; if (opts.cipher) wopts.cipher = opts.cipher; }
  return {
    kind,
    priv: k.toString('ssh-private', wopts),
    pub: k.toPublic().toString('ssh'),
    nodeKey: privateKey,
  };
}

module.exports = { makeKey, sshpk };
