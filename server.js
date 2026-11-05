'use strict';
/*
 * Dalsız — kurum içi, uçtan uca şifreli mesajlaşma sunucusu.
 *
 * Sunucu hiçbir zaman mesaj içeriğini, dosyaları veya kullanıcı parolalarını
 * düz metin olarak görmez. Sadece şifreli veriyi saklar ve iletir.
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const { WebSocketServer } = require('ws');

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const FILES_DIR = path.join(DATA_DIR, 'files');
const PUBLIC_DIR = path.join(__dirname, 'public');
// Kayıt için gereken davet kodu. Boş bırakılırsa herkes kayıt olabilir.
const INVITE_CODE = process.env.INVITE_CODE || '';
const MAX_UPLOAD = Number(process.env.MAX_UPLOAD_MB || 100) * 1024 * 1024;
const MAX_JSON = 2 * 1024 * 1024;

fs.mkdirSync(FILES_DIR, { recursive: true });

// ---------------------------------------------------------------- veritabanı
const db = new DatabaseSync(path.join(DATA_DIR, 'dalsiz.db'));
db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  auth_hash TEXT NOT NULL,
  auth_salt TEXT NOT NULL,
  public_key TEXT NOT NULL,
  key_backup TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS conversations (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL CHECK (type IN ('direct','group')),
  name TEXT,
  created_by INTEGER NOT NULL,
  disappear_seconds INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS members (
  conv_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member',
  last_delivered INTEGER NOT NULL DEFAULT 0,
  last_read INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (conv_id, user_id)
);
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  conv_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  sender_id INTEGER NOT NULL,
  envelope TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conv_id, created_at);
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  owner_id INTEGER NOT NULL,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
`);

const q = {
  userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
  userById: db.prepare('SELECT id, username, display_name, public_key FROM users WHERE id = ?'),
  insertUser: db.prepare(`INSERT INTO users (username, display_name, auth_hash, auth_salt, public_key, key_backup, created_at)
                          VALUES (?, ?, ?, ?, ?, ?, ?)`),
  searchUsers: db.prepare(`SELECT id, username, display_name, public_key FROM users
                           WHERE (username LIKE ? OR display_name LIKE ?) AND id != ? ORDER BY display_name LIMIT 30`),
  updateDisplayName: db.prepare('UPDATE users SET display_name = ? WHERE id = ?'),
  insertSession: db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)'),
  sessionUser: db.prepare('SELECT user_id FROM sessions WHERE token = ?'),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token = ?'),
  convById: db.prepare('SELECT * FROM conversations WHERE id = ?'),
  insertConv: db.prepare('INSERT INTO conversations (id, type, name, created_by, created_at) VALUES (?, ?, ?, ?, ?)'),
  updateConvName: db.prepare('UPDATE conversations SET name = ? WHERE id = ?'),
  updateConvDisappear: db.prepare('UPDATE conversations SET disappear_seconds = ? WHERE id = ?'),
  insertMember: db.prepare('INSERT OR IGNORE INTO members (conv_id, user_id, role) VALUES (?, ?, ?)'),
  deleteMember: db.prepare('DELETE FROM members WHERE conv_id = ? AND user_id = ?'),
  membership: db.prepare('SELECT * FROM members WHERE conv_id = ? AND user_id = ?'),
  convMembers: db.prepare(`SELECT u.id, u.username, u.display_name, u.public_key, m.role, m.last_delivered, m.last_read
                           FROM members m JOIN users u ON u.id = m.user_id WHERE m.conv_id = ?`),
  memberIds: db.prepare('SELECT user_id FROM members WHERE conv_id = ?'),
  userConvs: db.prepare(`SELECT c.* FROM conversations c JOIN members m ON m.conv_id = c.id WHERE m.user_id = ?`),
  lastMessage: db.prepare('SELECT * FROM messages WHERE conv_id = ? ORDER BY created_at DESC LIMIT 1'),
  unreadCount: db.prepare('SELECT COUNT(*) AS n FROM messages WHERE conv_id = ? AND sender_id != ? AND created_at > ?'),
  insertMessage: db.prepare('INSERT INTO messages (id, conv_id, sender_id, envelope, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)'),
  messagesBefore: db.prepare(`SELECT * FROM messages WHERE conv_id = ? AND created_at < ? ORDER BY created_at DESC LIMIT ?`),
  messageById: db.prepare('SELECT * FROM messages WHERE id = ?'),
  deleteMessage: db.prepare('DELETE FROM messages WHERE id = ?'),
  expired: db.prepare('SELECT id, conv_id FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?'),
  setDelivered: db.prepare('UPDATE members SET last_delivered = MAX(last_delivered, ?) WHERE conv_id = ? AND user_id = ?'),
  setRead: db.prepare(`UPDATE members SET last_read = MAX(last_read, ?), last_delivered = MAX(last_delivered, ?)
                       WHERE conv_id = ? AND user_id = ?`),
  insertFile: db.prepare('INSERT INTO files (id, owner_id, size, created_at) VALUES (?, ?, ?, ?)'),
  fileById: db.prepare('SELECT * FROM files WHERE id = ?'),
};

const now = () => Date.now();
const newId = (bytes = 16) => crypto.randomBytes(bytes).toString('hex');

function publicUser(u) {
  return { id: u.id, username: u.username, displayName: u.display_name, publicKey: JSON.parse(u.public_key) };
}

function messageOut(m) {
  return {
    id: m.id,
    convId: m.conv_id,
    senderId: m.sender_id,
    envelope: JSON.parse(m.envelope),
    createdAt: m.created_at,
    expiresAt: m.expires_at,
  };
}

function conversationOut(c, forUserId) {
  const members = q.convMembers.all(c.id).map((m) => ({
    ...publicUser(m),
    role: m.role,
    lastDelivered: m.last_delivered,
    lastRead: m.last_read,
  }));
  const me = members.find((m) => m.id === forUserId);
  const last = q.lastMessage.get(c.id);
  return {
    id: c.id,
    type: c.type,
    name: c.name,
    createdBy: c.created_by,
    disappearSeconds: c.disappear_seconds,
    createdAt: c.created_at,
    members,
    lastMessage: last ? messageOut(last) : null,
    unread: me ? q.unreadCount.get(c.id, forUserId, me.lastRead).n : 0,
  };
}

// ------------------------------------------------------------------ parolalar
// İstemci gerçek parolayı asla göndermez; PBKDF2 ile türetilmiş bir "auth key"
// gönderir. Sunucu bunu ayrıca scrypt ile tuzlayıp saklar.
function hashAuth(authKey, salt) {
  return crypto.scryptSync(authKey, Buffer.from(salt, 'hex'), 64).toString('hex');
}

// ------------------------------------------------------------------- yardımcı
function send(res, status, body, headers = {}) {
  const data = body === undefined ? '' : JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(data);
}

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new HttpError(413, 'İstek çok büyük')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readJson(req) {
  const buf = await readBody(req, MAX_JSON);
  try { return JSON.parse(buf.toString('utf8') || '{}'); } catch { throw new HttpError(400, 'Geçersiz JSON'); }
}

function authUser(req) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) throw new HttpError(401, 'Oturum gerekli');
  const s = q.sessionUser.get(token);
  if (!s) throw new HttpError(401, 'Oturum geçersiz');
  return { userId: s.user_id, token };
}

function requireMember(convId, userId) {
  const c = q.convById.get(convId);
  if (!c || !q.membership.get(convId, userId)) throw new HttpError(404, 'Sohbet bulunamadı');
  return c;
}

const str = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max;
const USERNAME_RE = /^[a-zA-Z0-9._-]{3,32}$/;

// Basit hız sınırı (giriş/kayıt denemeleri için)
const attempts = new Map();
function rateLimit(key, max = 20, windowMs = 10 * 60 * 1000) {
  const t = now();
  const a = (attempts.get(key) || []).filter((x) => t - x < windowMs);
  if (a.length >= max) throw new HttpError(429, 'Çok fazla deneme, biraz sonra tekrar deneyin');
  a.push(t);
  attempts.set(key, a);
}

// --------------------------------------------------------------------- API
const routes = [];
const route = (method, pattern, handler) => {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
  routes.push({ method, re, keys, handler });
};

route('GET', '/api/config', () => ({ inviteRequired: Boolean(INVITE_CODE) }));

route('POST', '/api/register', async ({ req }) => {
  rateLimit('reg:' + req.socket.remoteAddress, 10);
  const b = await readJson(req);
  if (INVITE_CODE && b.inviteCode !== INVITE_CODE) throw new HttpError(403, 'Davet kodu hatalı');
  if (!USERNAME_RE.test(b.username || '')) throw new HttpError(400, 'Kullanıcı adı 3-32 karakter olmalı (harf, rakam, . _ -)');
  if (!str(b.displayName, 64)) throw new HttpError(400, 'Görünen ad gerekli');
  if (!str(b.authKey, 256)) throw new HttpError(400, 'Eksik kimlik bilgisi');
  if (!b.publicKey || typeof b.publicKey !== 'object' || !b.keyBackup || typeof b.keyBackup !== 'object') {
    throw new HttpError(400, 'Eksik anahtar bilgisi');
  }
  if (q.userByName.get(b.username)) throw new HttpError(409, 'Bu kullanıcı adı alınmış');
  const salt = newId(16);
  const info = q.insertUser.run(
    b.username, b.displayName.trim(), hashAuth(b.authKey, salt), salt,
    JSON.stringify(b.publicKey), JSON.stringify(b.keyBackup), now(),
  );
  const token = newId(32);
  q.insertSession.run(token, Number(info.lastInsertRowid), now());
  return { token, user: publicUser(q.userById.get(Number(info.lastInsertRowid))) };
});

route('POST', '/api/login', async ({ req }) => {
  rateLimit('login:' + req.socket.remoteAddress, 30);
  const b = await readJson(req);
  const u = q.userByName.get(String(b.username || ''));
  const ok = u && str(b.authKey, 256) &&
    crypto.timingSafeEqual(Buffer.from(hashAuth(b.authKey, u.auth_salt), 'hex'), Buffer.from(u.auth_hash, 'hex'));
  if (!ok) throw new HttpError(401, 'Kullanıcı adı veya parola hatalı');
  const token = newId(32);
  q.insertSession.run(token, u.id, now());
  return { token, user: publicUser(u), keyBackup: JSON.parse(u.key_backup) };
});

route('POST', '/api/logout', ({ auth }) => { q.deleteSession.run(auth.token); return { ok: true }; });

route('GET', '/api/me', ({ auth }) => ({ user: publicUser(q.userById.get(auth.userId)) }));

route('PATCH', '/api/me', async ({ req, auth }) => {
  const b = await readJson(req);
  if (!str(b.displayName, 64)) throw new HttpError(400, 'Görünen ad gerekli');
  q.updateDisplayName.run(b.displayName.trim(), auth.userId);
  const user = publicUser(q.userById.get(auth.userId));
  // Ortak sohbetlerdeki herkese bildir
  const peers = new Set();
  for (const c of q.userConvs.all(auth.userId)) for (const m of q.memberIds.all(c.id)) peers.add(m.user_id);
  for (const p of peers) pushTo(p, { t: 'user', user });
  return { user };
});

route('GET', '/api/users', ({ url, auth }) => {
  const term = '%' + (url.searchParams.get('q') || '').replace(/[%_]/g, '') + '%';
  return { users: q.searchUsers.all(term, term, auth.userId).map(publicUser) };
});

route('GET', '/api/conversations', ({ auth }) => ({
  conversations: q.userConvs.all(auth.userId).map((c) => conversationOut(c, auth.userId)),
}));

route('POST', '/api/conversations', async ({ req, auth }) => {
  const b = await readJson(req);
  const ids = [...new Set((Array.isArray(b.memberIds) ? b.memberIds : []).map(Number))].filter((x) => x && x !== auth.userId);
  for (const id of ids) if (!q.userById.get(id)) throw new HttpError(400, 'Kullanıcı bulunamadı');
  let conv;
  if (b.type === 'direct') {
    if (ids.length !== 1) throw new HttpError(400, 'Birebir sohbet için tek kişi seçin');
    const [a, c] = [auth.userId, ids[0]].sort((x, y) => x - y);
    const id = `d-${a}-${c}`;
    conv = q.convById.get(id);
    if (!conv) {
      q.insertConv.run(id, 'direct', null, auth.userId, now());
      q.insertMember.run(id, a, 'member');
      q.insertMember.run(id, c, 'member');
      conv = q.convById.get(id);
    }
  } else if (b.type === 'group') {
    if (!str(b.name, 64)) throw new HttpError(400, 'Grup adı gerekli');
    if (ids.length < 1) throw new HttpError(400, 'En az bir üye seçin');
    const id = 'g-' + newId(12);
    q.insertConv.run(id, 'group', b.name.trim(), auth.userId, now());
    q.insertMember.run(id, auth.userId, 'admin');
    for (const uid of ids) q.insertMember.run(id, uid, 'member');
    conv = q.convById.get(id);
  } else {
    throw new HttpError(400, 'Geçersiz sohbet türü');
  }
  broadcastConversation(conv.id);
  return { conversation: conversationOut(conv, auth.userId) };
});

route('PATCH', '/api/conversations/:id', async ({ req, auth, params }) => {
  const c = requireMember(params.id, auth.userId);
  const b = await readJson(req);
  if (b.name !== undefined) {
    if (c.type !== 'group' || !str(b.name, 64)) throw new HttpError(400, 'Geçersiz grup adı');
    q.updateConvName.run(b.name.trim(), c.id);
  }
  if (b.disappearSeconds !== undefined) {
    const s = Number(b.disappearSeconds);
    if (!Number.isInteger(s) || s < 0 || s > 60 * 60 * 24 * 28) throw new HttpError(400, 'Geçersiz süre');
    q.updateConvDisappear.run(s, c.id);
  }
  broadcastConversation(c.id);
  return { conversation: conversationOut(q.convById.get(c.id), auth.userId) };
});

route('POST', '/api/conversations/:id/members', async ({ req, auth, params }) => {
  const c = requireMember(params.id, auth.userId);
  if (c.type !== 'group') throw new HttpError(400, 'Sadece gruplara üye eklenebilir');
  const b = await readJson(req);
  for (const id of (b.memberIds || []).map(Number)) {
    if (q.userById.get(id)) q.insertMember.run(c.id, id, 'member');
  }
  broadcastConversation(c.id);
  return { conversation: conversationOut(c, auth.userId) };
});

route('DELETE', '/api/conversations/:id/members/:userId', ({ auth, params }) => {
  const c = requireMember(params.id, auth.userId);
  const target = Number(params.userId);
  const me = q.membership.get(c.id, auth.userId);
  if (c.type !== 'group') throw new HttpError(400, 'Birebir sohbetten ayrılınamaz');
  if (target !== auth.userId && me.role !== 'admin') throw new HttpError(403, 'Sadece yöneticiler üye çıkarabilir');
  const before = q.memberIds.all(c.id).map((m) => m.user_id);
  q.deleteMember.run(c.id, target);
  for (const uid of before) pushTo(uid, { t: 'conversation', conversation: q.membership.get(c.id, uid) ? conversationOut(c, uid) : null, removedId: c.id });
  return { ok: true };
});

route('GET', '/api/conversations/:id/messages', ({ url, auth, params }) => {
  requireMember(params.id, auth.userId);
  const before = Number(url.searchParams.get('before')) || Number.MAX_SAFE_INTEGER;
  const limit = Math.min(Number(url.searchParams.get('limit')) || 50, 200);
  const rows = q.messagesBefore.all(params.id, before, limit).reverse();
  return { messages: rows.map(messageOut) };
});

route('POST', '/api/files', async ({ req, auth }) => {
  const buf = await readBody(req, MAX_UPLOAD);
  if (!buf.length) throw new HttpError(400, 'Boş dosya');
  const id = newId(16);
  fs.writeFileSync(path.join(FILES_DIR, id), buf);
  q.insertFile.run(id, auth.userId, buf.length, now());
  return { id, size: buf.length };
});

route('GET', '/api/files/:id', ({ res, params }) => {
  // Dosyalar istemcide şifrelenir; kimliği tahmin edilemez (128 bit) ve
  // anahtar olmadan içerik okunamaz.
  if (!/^[a-f0-9]{32}$/.test(params.id) || !q.fileById.get(params.id)) throw new HttpError(404, 'Dosya yok');
  res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'private, max-age=31536000, immutable' });
  fs.createReadStream(path.join(FILES_DIR, params.id)).pipe(res);
  return undefined;
});

// -------------------------------------------------------------- statik dosya
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.svg': 'image/svg+xml', '.png': 'image/png',
};

function serveStatic(req, res, pathname) {
  let p = path.normalize(decodeURIComponent(pathname)).replace(/^([/\\])+/, '');
  if (!p || p === '.') p = 'index.html';
  const file = path.join(PUBLIC_DIR, p);
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return send(res, 403, { error: 'Yasak' });
  fs.stat(file, (err, st) => {
    const target = !err && st.isFile() ? file : path.join(PUBLIC_DIR, 'index.html');
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(target)] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self' ws: wss:; style-src 'self'; script-src 'self'; frame-ancestors 'none'",
    });
    fs.createReadStream(target).pipe(res);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url.pathname);
  const r = routes.find((x) => x.method === req.method && x.re.test(url.pathname));
  if (!r) return send(res, 404, { error: 'Bulunamadı' });
  try {
    const m = url.pathname.match(r.re);
    const params = Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])]));
    const open = ['/api/config', '/api/register', '/api/login'].includes(url.pathname);
    const auth = open ? null : authUser(req);
    const out = await r.handler({ req, res, url, params, auth });
    if (out !== undefined) send(res, 200, out);
  } catch (e) {
    if (!(e instanceof HttpError)) console.error(e);
    if (!res.headersSent) send(res, e.status || 500, { error: e instanceof HttpError ? e.message : 'Sunucu hatası' });
  }
});

// ---------------------------------------------------------------- WebSocket
const sockets = new Map(); // userId -> Set<ws>

function pushTo(userId, payload) {
  const set = sockets.get(userId);
  if (!set) return;
  const data = JSON.stringify(payload);
  for (const ws of set) if (ws.readyState === ws.OPEN) ws.send(data);
}

function pushToConv(convId, payload, exceptUserId) {
  for (const { user_id } of q.memberIds.all(convId)) if (user_id !== exceptUserId) pushTo(user_id, payload);
}

function broadcastConversation(convId) {
  const c = q.convById.get(convId);
  for (const { user_id } of q.memberIds.all(convId)) pushTo(user_id, { t: 'conversation', conversation: conversationOut(c, user_id) });
}

function peersOf(userId) {
  const peers = new Set();
  for (const c of q.userConvs.all(userId)) for (const m of q.memberIds.all(c.id)) if (m.user_id !== userId) peers.add(m.user_id);
  return peers;
}

function setPresence(userId, online) {
  for (const p of peersOf(userId)) pushTo(p, { t: 'presence', userId, online });
}

function validEnvelope(env, memberIds) {
  if (!env || typeof env !== 'object') return false;
  if (!str(env.iv, 64) || typeof env.ct !== 'string' || env.ct.length > 1024 * 1024) return false;
  if (!env.keys || typeof env.keys !== 'object') return false;
  // Her alıcı için şifreli mesaj anahtarı bulunmalı
  return memberIds.every((id) => env.keys[id] && str(env.keys[id].iv, 64) && str(env.keys[id].ct, 256));
}

function handleWs(ws, userId, msg) {
  switch (msg.t) {
    case 'send': {
      const c = q.convById.get(msg.convId);
      if (!c || !q.membership.get(c.id, userId)) return ws.send(JSON.stringify({ t: 'error', ref: msg.ref, error: 'Sohbet yok' }));
      const memberIds = q.memberIds.all(c.id).map((m) => m.user_id);
      if (!validEnvelope(msg.envelope, memberIds)) {
        return ws.send(JSON.stringify({ t: 'error', ref: msg.ref, error: 'Geçersiz şifreli mesaj (üyelik değişmiş olabilir)' }));
      }
      const id = /^[a-f0-9]{32}$/.test(msg.id || '') && !q.messageById.get(msg.id) ? msg.id : newId(16);
      const createdAt = now();
      const expiresAt = c.disappear_seconds ? createdAt + c.disappear_seconds * 1000 : null;
      const env = { iv: msg.envelope.iv, ct: msg.envelope.ct, keys: msg.envelope.keys };
      q.insertMessage.run(id, c.id, userId, JSON.stringify(env), createdAt, expiresAt);
      q.setRead.run(createdAt, createdAt, c.id, userId);
      const out = messageOut(q.messageById.get(id));
      ws.send(JSON.stringify({ t: 'ack', ref: msg.ref, message: out }));
      for (const uid of memberIds) pushTo(uid, { t: 'message', message: out });
      return;
    }
    case 'delete': {
      const m = q.messageById.get(msg.id || '');
      if (!m || m.sender_id !== userId) return;
      q.deleteMessage.run(m.id);
      pushToConv(m.conv_id, { t: 'deleted', convId: m.conv_id, id: m.id });
      return;
    }
    case 'typing': {
      if (!q.membership.get(msg.convId, userId)) return;
      pushToConv(msg.convId, { t: 'typing', convId: msg.convId, userId, on: Boolean(msg.on) }, userId);
      return;
    }
    case 'delivered':
    case 'read': {
      if (!q.membership.get(msg.convId, userId)) return;
      const ts = Math.min(Number(msg.ts) || 0, now());
      if (msg.t === 'read') q.setRead.run(ts, ts, msg.convId, userId);
      else q.setDelivered.run(ts, msg.convId, userId);
      const m = q.membership.get(msg.convId, userId);
      pushToConv(msg.convId, { t: 'receipt', convId: msg.convId, userId, lastDelivered: m.last_delivered, lastRead: m.last_read });
      return;
    }
    case 'ping':
      return ws.send(JSON.stringify({ t: 'pong' }));
    default:
  }
}

const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 2 * 1024 * 1024 });
wss.on('connection', (ws) => {
  let userId = null;
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  const authTimer = setTimeout(() => { if (!userId) ws.close(4001, 'auth'); }, 10000);
  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }
    if (!userId) {
      const s = msg.t === 'auth' && q.sessionUser.get(String(msg.token || ''));
      if (!s) { ws.close(4001, 'auth'); return; }
      userId = s.user_id;
      clearTimeout(authTimer);
      if (!sockets.has(userId)) sockets.set(userId, new Set());
      const firstSocket = sockets.get(userId).size === 0;
      sockets.get(userId).add(ws);
      const online = [...peersOf(userId)].filter((p) => sockets.get(p)?.size);
      ws.send(JSON.stringify({ t: 'ready', online }));
      if (firstSocket) setPresence(userId, true);
      return;
    }
    try { handleWs(ws, userId, msg); } catch (e) { console.error(e); }
  });
  ws.on('close', () => {
    clearTimeout(authTimer);
    if (!userId) return;
    const set = sockets.get(userId);
    set?.delete(ws);
    if (set && set.size === 0) { sockets.delete(userId); setPresence(userId, false); }
  });
});

// Ölü bağlantıları temizle
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) { ws.terminate(); continue; }
    ws.isAlive = false;
    ws.ping();
  }
}, 30000).unref();

// Süresi dolan (kaybolan) mesajları sil
setInterval(() => {
  for (const m of q.expired.all(now())) {
    q.deleteMessage.run(m.id);
    pushToConv(m.conv_id, { t: 'deleted', convId: m.conv_id, id: m.id });
  }
}, 5000).unref();

server.listen(PORT, () => {
  console.log(`Dalsız çalışıyor: http://localhost:${PORT}`);
  console.log(INVITE_CODE ? 'Kayıt için davet kodu gerekli.' : 'UYARI: INVITE_CODE ayarlanmamış, herkes kayıt olabilir.');
});

module.exports = { server };
