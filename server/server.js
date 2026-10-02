'use strict';
/**
 * Zero-knowledge relay server.
 * - Stores only: usernames, bcrypt password hashes, PUBLIC keys.
 * - Relays opaque encrypted envelopes; never sees plaintext or private keys.
 * - Offline queue is in-memory (volatile, like the Redis queue in the report)
 *   and expired envelopes are purged automatically.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'users.json');
const MAX_ENVELOPE_BYTES = 16 * 1024;

// ---------- tiny user directory (JSON file) ----------
let users = {}; // username -> { passwordHash, publicKey, createdAt }
try { users = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (_) { users = {}; }
const saveUsers = () => fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));

// ---------- volatile state ----------
const sockets = new Map();       // username -> Set<socket.id>
const offlineQueue = new Map();  // username -> [envelope]

const app = express();
app.use(cors());
app.use(express.json({ limit: '32kb' }));

const USERNAME_RE = /^[a-z0-9_]{3,20}$/;
const isB64 = (s, n) => typeof s === 'string' && Buffer.from(s, 'base64').length === n;

const sign = (username) => jwt.sign({ sub: username }, JWT_SECRET, { expiresIn: '7d' });
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  try {
    req.user = jwt.verify(h.replace('Bearer ', ''), JWT_SECRET).sub;
    next();
  } catch (_) { res.status(401).json({ error: 'Unauthorized' }); }
}

app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/api/register', async (req, res) => {
  const { username, password, publicKey } = req.body || {};
  const u = String(username || '').toLowerCase();
  if (!USERNAME_RE.test(u)) return res.status(400).json({ error: 'Username: 3-20 chars, a-z, 0-9, _' });
  if (typeof password !== 'string' || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (!isB64(publicKey, 32)) return res.status(400).json({ error: 'publicKey must be a base64 X25519 key (32 bytes)' });
  if (users[u]) return res.status(409).json({ error: 'Username already taken' });
  users[u] = { passwordHash: await bcrypt.hash(password, 10), publicKey, createdAt: Date.now() };
  saveUsers();
  res.json({ token: sign(u), username: u });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const u = String(username || '').toLowerCase();
  const rec = users[u];
  if (!rec || !(await bcrypt.compare(String(password || ''), rec.passwordHash)))
    return res.status(401).json({ error: 'Invalid username or password' });
  res.json({ token: sign(u), username: u, publicKey: rec.publicKey });
});

// Public-key directory
app.get('/api/users/:username/key', auth, (req, res) => {
  const rec = users[String(req.params.username).toLowerCase()];
  if (!rec) return res.status(404).json({ error: 'User not found' });
  res.json({ username: req.params.username.toLowerCase(), publicKey: rec.publicKey, online: sockets.has(req.params.username.toLowerCase()) });
});

app.get('/api/users', auth, (req, res) => {
  const q = String(req.query.q || '').toLowerCase();
  const list = Object.keys(users)
    .filter((n) => n !== req.user && n.includes(q))
    .slice(0, 30)
    .map((n) => ({ username: n, online: sockets.has(n) }));
  res.json(list);
});

// ---------- Socket.io relay ----------
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' }, maxHttpBufferSize: 64 * 1024 });

io.use((socket, next) => {
  try {
    socket.user = jwt.verify(socket.handshake.auth.token, JWT_SECRET).sub;
    if (!users[socket.user]) throw new Error('no user');
    next();
  } catch (_) { next(new Error('unauthorized')); }
});

const emitToUser = (username, event, payload) => {
  const set = sockets.get(username);
  if (!set) return false;
  set.forEach((id) => io.to(id).emit(event, payload));
  return set.size > 0;
};
const broadcastPresence = (username, online) => io.emit('presence', { username, online });

io.on('connection', (socket) => {
  const me = socket.user;
  if (!sockets.has(me)) sockets.set(me, new Set());
  sockets.get(me).add(socket.id);
  broadcastPresence(me, true);

  // flush offline queue (drop anything already expired)
  const queued = (offlineQueue.get(me) || []).filter((e) => e.expiresAt === 0 || e.expiresAt > Date.now());
  offlineQueue.delete(me);
  queued.forEach((env) => socket.emit('message', env));

  socket.on('send', (env, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    try {
      if (!env || env.from !== me || !users[env.to]) return reply({ ok: false, error: 'bad envelope' });
      if (JSON.stringify(env).length > MAX_ENVELOPE_BYTES) return reply({ ok: false, error: 'too large' });
      // server only checks the SHAPE of the packet, never its contents
      const ok = ['id', 'cp', 'ta', 'nonce'].every((k) => typeof env[k] === 'string') && env.ck && typeof env.ck.epk === 'string';
      if (!ok) return reply({ ok: false, error: 'malformed envelope' });
      const packet = { id: env.id, from: me, to: env.to, cp: env.cp, ta: env.ta, nonce: env.nonce, ck: env.ck,
        sentAt: Date.now(), expiresAt: Number(env.expiresAt) || 0 };
      if (emitToUser(env.to, 'message', packet)) return reply({ ok: true, delivered: true });
      if (!offlineQueue.has(env.to)) offlineQueue.set(env.to, []);
      offlineQueue.get(env.to).push(packet);
      reply({ ok: true, delivered: false });
    } catch (_) { reply({ ok: false, error: 'server error' }); }
  });

  // delivery/read receipts and remote "burn" (carry only message ids)
  socket.on('receipt', ({ to, id, type } = {}) => {
    if (users[to] && ['delivered', 'read'].includes(type)) emitToUser(to, 'receipt', { from: me, id, type });
  });
  socket.on('burn', ({ to, id } = {}) => { if (users[to]) emitToUser(to, 'burn', { from: me, id }); });
  socket.on('typing', ({ to } = {}) => { if (users[to]) emitToUser(to, 'typing', { from: me }); });

  socket.on('disconnect', () => {
    const set = sockets.get(me);
    if (set) { set.delete(socket.id); if (!set.size) { sockets.delete(me); broadcastPresence(me, false); } }
  });
});

// purge expired queued envelopes every 10s
setInterval(() => {
  const now = Date.now();
  for (const [user, list] of offlineQueue) {
    const keep = list.filter((e) => e.expiresAt === 0 || e.expiresAt > now);
    keep.length ? offlineQueue.set(user, keep) : offlineQueue.delete(user);
  }
}, 10000).unref();

if (require.main === module) {
  server.listen(PORT, '0.0.0.0', () => console.log(`Relay server listening on :${PORT}`));
}
module.exports = { server, io, app };
