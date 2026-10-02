'use strict';
process.env.DB_FILE = require('path').join(require('os').tmpdir(), `users-${Date.now()}.json`);
process.env.JWT_SECRET = 'test';
const assert = require('assert');
const { io: Client } = require('socket.io-client');
const { server } = require('../server');
const E = require('./e2ee');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let BASE;
const post = async (p, body, token) => (await fetch(BASE + p, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(token && { Authorization: 'Bearer ' + token }) }, body: JSON.stringify(body) })).json();
const get = async (p, token) => (await fetch(BASE + p, { headers: { Authorization: 'Bearer ' + token } })).json();
const connect = (token) => new Promise((res, rej) => { const s = Client(BASE, { auth: { token }, transports: ['websocket'] }); s.on('connect', () => res(s)); s.on('connect_error', rej); });
const emitAck = (s, ev, d) => new Promise((r) => s.emit(ev, d, r));
const once = (s, ev) => new Promise((r) => s.once(ev, r));

(async () => {
  await new Promise((r) => server.listen(0, r));
  BASE = `http://localhost:${server.address().port}`;
  const results = [];
  const ok = (name) => { results.push(name); console.log('  PASS', name); };

  const A = E.generateIdentity(), B = E.generateIdentity();
  const ra = await post('/api/register', { username: 'alice', password: 'secret1', publicKey: E.b64(A.pub) });
  const rb = await post('/api/register', { username: 'bob', password: 'secret2', publicKey: E.b64(B.pub) });
  assert(ra.token && rb.token); ok('registration stores public key only');
  assert.strictEqual((await post('/api/login', { username: 'alice', password: 'wrong' })).error, 'Invalid username or password'); ok('bad password rejected');
  assert.strictEqual((await post('/api/register', { username: 'alice', password: 'secret1', publicKey: E.b64(A.pub) })).error, 'Username already taken'); ok('duplicate username rejected');
  await assert.rejects(connect('bad-token')); ok('socket without valid JWT rejected');

  const sa = await connect(ra.token), sb = await connect(rb.token);
  const bobKey = await get('/api/users/bob/key', ra.token);
  assert.strictEqual(bobKey.publicKey, E.b64(B.pub)); ok('public key directory lookup');

  // 1) live E2EE delivery
  const secret = 'Meet at KWASU library 5pm — TOP SECRET 🔐';
  const env = E.encryptMessage({ from: 'alice', to: 'bob', id: 'm1', text: secret, expiresAt: 0, recipientPub: E.unb64(bobKey.publicKey) });
  const wire = JSON.stringify(env);
  assert(!wire.includes('TOP SECRET') && !wire.includes('library')); ok('wire packet contains no plaintext');
  const got = once(sb, 'message');
  const ack = await emitAck(sa, 'send', env);
  const recv = await got;
  assert(ack.ok && ack.delivered);
  assert.strictEqual(E.decryptMessage(recv, B.priv), secret); ok('bob decrypts message relayed by server');

  // 2) wrong key cannot decrypt
  const eve = E.generateIdentity();
  assert.throws(() => E.decryptMessage(recv, eve.priv)); ok('third party (wrong private key) cannot decrypt');

  // 3) tamper detection (GCM auth tag)
  const bad = JSON.parse(JSON.stringify(recv)); const buf = E.unb64(bad.cp); buf[0] ^= 1; bad.cp = E.b64(buf);
  assert.throws(() => E.decryptMessage(bad, B.priv)); ok('1-bit ciphertext tamper detected');
  const bad2 = { ...recv, from: 'mallory' };
  assert.throws(() => E.decryptMessage(bad2, B.priv)); ok('sender spoofing detected (AAD binding)');

  // 4) spoofed "from" rejected by server
  const spoof = await emitAck(sa, 'send', { ...env, from: 'bob', to: 'alice' });
  assert(!spoof.ok); ok('server rejects spoofed sender');

  // 5) offline queue + delivery on reconnect
  sb.disconnect(); await sleep(100);
  const env2 = E.encryptMessage({ from: 'alice', to: 'bob', id: 'm2', text: 'offline hello', expiresAt: 0, recipientPub: B.pub });
  const ack2 = await emitAck(sa, 'send', env2);
  assert(ack2.ok && ack2.delivered === false);
  const sb2 = Client(BASE, { auth: { token: rb.token }, transports: ['websocket'] });
  const q = await once(sb2, 'message');
  assert.strictEqual(E.decryptMessage(q, B.priv), 'offline hello'); ok('offline message queued and delivered on reconnect');
  sb2.disconnect(); await sleep(100);

  // 6) expired message never delivered from queue
  const env3 = E.encryptMessage({ from: 'alice', to: 'bob', id: 'm3', text: 'burn me', expiresAt: Date.now() + 300, recipientPub: B.pub });
  await emitAck(sa, 'send', env3); await sleep(600);
  let leaked = false;
  const sb3 = Client(BASE, { auth: { token: rb.token }, transports: ['websocket'] });
  sb3.on('message', () => { leaked = true; });
  await once(sb3, 'connect'); await sleep(400);
  assert(!leaked); ok('expired queued message is purged, not delivered');

  // 7) server data at rest contains no message text
  const dbText = require('fs').readFileSync(process.env.DB_FILE, 'utf8');
  assert(!dbText.includes('TOP SECRET') && !dbText.includes('hello') && !/privateKey/i.test(dbText)); ok('server storage holds no plaintext / private keys');

  // 8) quick latency benchmark (objective 5 in the report)
  const times = [];
  for (let i = 0; i < 50; i++) {
    const t0 = process.hrtime.bigint();
    const e = E.encryptMessage({ from: 'alice', to: 'bob', id: 'b' + i, text: 'ping ' + i, expiresAt: 0, recipientPub: B.pub });
    const r = once(sb3, 'message'); sa.emit('send', e); const m = await r; E.decryptMessage(m, B.priv);
    times.push(Number(process.hrtime.bigint() - t0) / 1e6);
  }
  times.sort((a, b) => a - b);
  console.log(`  Round-trip (encrypt+relay+decrypt) over 50 msgs: median ${times[25].toFixed(2)} ms, p95 ${times[47].toFixed(2)} ms`);
  assert(times[25] < 200); ok('median latency < 200ms target');

  console.log(`\nAll ${results.length} checks passed.`);
  process.exit(0);
})().catch((e) => { console.error('FAILED:', e); process.exit(1); });
