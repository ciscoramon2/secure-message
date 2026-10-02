'use strict';
// Reference implementation of the hybrid scheme (mirrors mobile_app/lib/services/crypto_service.dart)
// X25519 (ECC) + HKDF-SHA256 key wrapping, AES-256-GCM payload encryption.
const c = require('crypto');
const SPKI = Buffer.from('302a300506032b656e032100', 'hex');
const PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const INFO = Buffer.from('e2ee-key-wrap-v1');
const b64 = (b) => Buffer.from(b).toString('base64');
const unb64 = (s) => Buffer.from(s, 'base64');

function generateIdentity() {
  const { publicKey, privateKey } = c.generateKeyPairSync('x25519');
  return { pub: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32),
           priv: privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32) };
}
const pubObj = (raw) => c.createPublicKey({ key: Buffer.concat([SPKI, raw]), format: 'der', type: 'spki' });
const privObj = (raw) => c.createPrivateKey({ key: Buffer.concat([PKCS8, raw]), format: 'der', type: 'pkcs8' });
const kek = (priv, pub) => Buffer.from(c.hkdfSync('sha256', c.diffieHellman({ privateKey: priv, publicKey: pub }), Buffer.alloc(0), INFO, 32));
const aad = (from, to, id, exp) => Buffer.from(`${from}|${to}|${id}|${exp}`);

function gcm(key, plain, ad) {
  const nonce = c.randomBytes(12);
  const ci = c.createCipheriv('aes-256-gcm', key, nonce);
  ci.setAAD(ad);
  const ct = Buffer.concat([ci.update(plain), ci.final()]);
  return { ct, nonce, tag: ci.getAuthTag() };
}
function ungcm(key, ct, nonce, tag, ad) {
  const d = c.createDecipheriv('aes-256-gcm', key, nonce);
  d.setAAD(ad); d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]); // throws if tampered
}

function encryptMessage({ from, to, id, text, expiresAt, recipientPub }) {
  const ks = c.randomBytes(32);                                   // session key Ks (CSPRNG)
  const p = gcm(ks, Buffer.from(text, 'utf8'), aad(from, to, id, expiresAt)); // Cp, Ta
  const eph = generateIdentity();                                  // ephemeral ECC key
  const w = gcm(kek(privObj(eph.priv), pubObj(recipientPub)), ks, Buffer.from('wrap'));  // Ck
  ks.fill(0);                                                      // wipe Ks
  return { id, from, to, cp: b64(p.ct), ta: b64(p.tag), nonce: b64(p.nonce), expiresAt,
           ck: { epk: b64(eph.pub), nonce: b64(w.nonce), ct: b64(w.ct), tag: b64(w.tag) } };
}
function decryptMessage(env, myPriv) {
  const ks = ungcm(kek(privObj(myPriv), pubObj(unb64(env.ck.epk))), unb64(env.ck.ct), unb64(env.ck.nonce), unb64(env.ck.tag), Buffer.from('wrap'));
  const plain = ungcm(ks, unb64(env.cp), unb64(env.nonce), unb64(env.ta), aad(env.from, env.to, env.id, env.expiresAt));
  ks.fill(0);
  return plain.toString('utf8');
}
module.exports = { generateIdentity, encryptMessage, decryptMessage, b64, unb64 };
