import * as C from './crypto.js';

// ================================================================ durum
const S = {
  token: null,
  me: null,
  keyring: null,
  convs: new Map(),        // id -> conversation
  users: new Map(),        // id -> {id, username, displayName, publicKey}
  messages: new Map(),     // convId -> [msg] (yüklenmiş olanlar)
  decrypted: new Map(),    // messageId -> msg
  activeId: null,
  online: new Set(),
  typing: new Map(),       // convId -> Map(userId -> timer)
  ws: null,
  wsReady: false,
  pendingRefs: new Map(),  // ref -> {resolve, reject}
  attachments: [],         // [{file, url}]
  blobs: new Map(),        // fileId -> Promise<objectURL>
};

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};
const svg = (path) => {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  s.setAttribute('viewBox', '0 0 24 24');
  s.innerHTML = path;
  return s;
};
const ICONS = {
  clock: '<circle cx="12" cy="12" r="8"/><path d="M12 8v4l2.5 2"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
  checks: '<path d="M2 12.5l4.5 4.5L16 7.5M10 16l1 1 9.5-9.5"/>',
  file: '<path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8z"/><path d="M14 3v5h5"/>',
  timer: '<circle cx="12" cy="13" r="7"/><path d="M12 9v4M10 3h4"/>',
};

const SESSION_KEY = 'dalsiz.session';

// ================================================================ yardımcılar
function toast(text, ms = 3000) {
  const t = el('div', 'toast', text);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), ms);
}

async function api(path, { method = 'GET', body, raw } = {}) {
  const headers = {};
  if (S.token) headers.Authorization = 'Bearer ' + S.token;
  let payload;
  if (raw) { payload = raw; headers['Content-Type'] = 'application/octet-stream'; }
  else if (body !== undefined) { payload = JSON.stringify(body); headers['Content-Type'] = 'application/json'; }
  const res = await fetch(path, { method, headers, body: payload });
  if (res.status === 401 && S.token) { logout(true); throw new Error('Oturum sona erdi'); }
  const isJson = (res.headers.get('content-type') || '').includes('json');
  const data = isJson ? await res.json() : await res.arrayBuffer();
  if (!res.ok) throw new Error((data && data.error) || 'İstek başarısız');
  return data;
}

const COLORS = ['#2c6bed', '#c13c8f', '#3a8f5c', '#c2620f', '#6a4fc9', '#0f8a94', '#b5322f', '#7a6b00', '#4e6a8a', '#a14ac2'];
function avatar(name, seed, cls = '') {
  const a = el('div', 'avatar ' + cls);
  const words = String(name || '?').trim().split(/\s+/);
  a.textContent = ((words[0]?.[0] || '?') + (words[1]?.[0] || '')).toLocaleUpperCase('tr');
  let h = 0;
  for (const ch of String(seed)) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  a.style.background = COLORS[h % COLORS.length];
  return a;
}

const fmtTime = (ts) => new Date(ts).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });
function fmtListTime(ts) {
  const d = new Date(ts);
  const today = new Date();
  if (d.toDateString() === today.toDateString()) return fmtTime(ts);
  const diff = (today - d) / 86400000;
  if (diff < 6) return d.toLocaleDateString('tr-TR', { weekday: 'short' });
  return d.toLocaleDateString('tr-TR', { day: 'numeric', month: 'short' });
}
function fmtDay(ts) {
  const d = new Date(ts);
  const today = new Date();
  const y = new Date(); y.setDate(y.getDate() - 1);
  if (d.toDateString() === today.toDateString()) return 'Bugün';
  if (d.toDateString() === y.toDateString()) return 'Dün';
  return d.toLocaleDateString('tr-TR', { day: 'numeric', month: 'long', year: 'numeric' });
}
function fmtSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 ** 2) return (n / 1024).toFixed(0) + ' KB';
  return (n / 1024 ** 2).toFixed(1) + ' MB';
}
const DISAPPEAR = [
  [0, 'Kapalı'], [30, '30 saniye'], [300, '5 dakika'], [3600, '1 saat'], [28800, '8 saat'],
  [86400, '1 gün'], [604800, '1 hafta'], [2419200, '4 hafta'],
];
const disappearLabel = (s) => (DISAPPEAR.find((d) => d[0] === s) || [0, s + ' sn'])[1];

function rememberUsers(list) {
  for (const u of list) S.users.set(u.id, { id: u.id, username: u.username, displayName: u.displayName, publicKey: u.publicKey });
}

function convTitle(c) {
  if (c.type === 'group') return c.name;
  const other = c.members.find((m) => m.id !== S.me.id);
  return other ? other.displayName : 'Not defteri';
}
function convPeer(c) {
  return c.type === 'direct' ? c.members.find((m) => m.id !== S.me.id) : null;
}

// ================================================================ oturum
function saveSession() {
  localStorage.setItem(SESSION_KEY, JSON.stringify({ token: S.token, user: S.me, privateJwk: S.privateJwk }));
}

async function logout(expired) {
  try { if (!expired && S.token) await api('/api/logout', { method: 'POST' }); } catch { /* yoksay */ }
  localStorage.removeItem(SESSION_KEY);
  location.reload();
}

function setupAuth(inviteRequired) {
  const auth = $('auth');
  const form = $('auth-form');
  let mode = 'login';
  const setMode = (m) => {
    mode = m;
    auth.classList.toggle('login', m === 'login');
    document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.mode === m));
    $('auth-submit').textContent = m === 'login' ? 'Giriş yap' : 'Hesap oluştur';
    form.password.autocomplete = m === 'login' ? 'current-password' : 'new-password';
    form.displayName.required = m === 'register';
    form.inviteCode.required = m === 'register' && inviteRequired;
    $('auth-error').textContent = '';
  };
  if (!inviteRequired) document.querySelector('.invite-field').classList.add('hidden');
  document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => setMode(t.dataset.mode)));
  setMode('login');
  auth.classList.remove('hidden');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('auth-submit');
    const username = form.username.value.trim();
    const password = form.password.value;
    btn.disabled = true;
    $('auth-error').textContent = '';
    btn.textContent = mode === 'login' ? 'Giriş yapılıyor…' : 'Anahtarlar oluşturuluyor…';
    try {
      const authKey = await C.deriveAuthKey(username, password);
      if (mode === 'register') {
        const id = await C.generateIdentity(password);
        const r = await api('/api/register', {
          method: 'POST',
          body: {
            username, displayName: form.displayName.value.trim(), authKey,
            publicKey: id.publicKey, keyBackup: id.keyBackup, inviteCode: form.inviteCode.value.trim(),
          },
        });
        Object.assign(S, { token: r.token, me: r.user, privateJwk: id.privateJwk });
      } else {
        const r = await api('/api/login', { method: 'POST', body: { username, authKey } });
        S.token = r.token;
        let jwk;
        try { jwk = await C.decryptBackup(r.keyBackup, password); } catch { throw new Error('Anahtar yedeği açılamadı'); }
        Object.assign(S, { me: r.user, privateJwk: jwk });
      }
      saveSession();
      auth.classList.add('hidden');
      askNotifications();
      await start();
    } catch (err) {
      S.token = null;
      $('auth-error').textContent = err.message;
    } finally {
      btn.disabled = false;
      setMode(mode);
    }
  });
}

function askNotifications() {
  if ('Notification' in window && Notification.permission === 'default') Notification.requestPermission().catch(() => {});
}

// ================================================================ başlangıç
async function boot() {
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
  let saved = null;
  try { saved = JSON.parse(localStorage.getItem(SESSION_KEY) || 'null'); } catch { /* yoksay */ }
  if (saved?.token && saved.privateJwk) {
    Object.assign(S, { token: saved.token, me: saved.user, privateJwk: saved.privateJwk });
    try { await start(); return; } catch (e) { console.error(e); }
  }
  const cfg = await api('/api/config');
  setupAuth(cfg.inviteRequired);
}

async function start() {
  const pk = await C.importPrivate(S.privateJwk);
  S.keyring = new C.KeyRing(pk, S.me.id);
  const { user } = await api('/api/me');
  S.me = user;
  rememberUsers([user]);
  saveSession();
  $('app').classList.remove('hidden');
  renderMe();
  bindUi();
  await loadConversations();
  connect();
  setInterval(expireLocal, 1000);
  window.addEventListener('popstate', () => { if (S.activeId && !location.hash) closeChat(true); });
}

function renderMe() {
  const b = $('me-btn');
  b.replaceChildren(avatar(S.me.displayName, S.me.id, 'sm'));
}

async function loadConversations() {
  const { conversations } = await api('/api/conversations');
  S.convs.clear();
  for (const c of conversations) { S.convs.set(c.id, c); rememberUsers(c.members); }
  await Promise.all(conversations.map((c) => c.lastMessage && decryptMessage(c.lastMessage)));
  renderConvList();
}

// ================================================================ WebSocket
let reconnectDelay = 1000;
function connect() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  S.ws = ws;
  ws.onopen = () => ws.send(JSON.stringify({ t: 'auth', token: S.token }));
  ws.onmessage = (e) => { let m; try { m = JSON.parse(e.data); } catch { return; } onWs(m); };
  ws.onclose = (e) => {
    S.wsReady = false;
    $('conn-status').classList.remove('hidden');
    for (const p of S.pendingRefs.values()) p.reject(new Error('Bağlantı koptu'));
    S.pendingRefs.clear();
    if (e.code === 4001) { logout(true); return; }
    setTimeout(connect, reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 2, 15000);
  };
}

function wsSend(obj) {
  if (S.ws && S.wsReady) S.ws.send(JSON.stringify(obj));
}

function wsRequest(obj) {
  return new Promise((resolve, reject) => {
    if (!S.wsReady) { reject(new Error('Sunucuya bağlı değil')); return; }
    const ref = C.randomHex(8);
    S.pendingRefs.set(ref, { resolve, reject });
    S.ws.send(JSON.stringify({ ...obj, ref }));
    setTimeout(() => { if (S.pendingRefs.delete(ref)) reject(new Error('Zaman aşımı')); }, 30000);
  });
}

async function onWs(m) {
  switch (m.t) {
    case 'ready': {
      const wasReconnect = S.everConnected;
      S.wsReady = true;
      S.everConnected = true;
      reconnectDelay = 1000;
      $('conn-status').classList.add('hidden');
      S.online = new Set(m.online);
      if (wasReconnect) {
        await loadConversations();
        if (S.activeId) {
          if (S.convs.has(S.activeId)) await openChat(S.activeId, { keepHistory: true });
          else closeChat();
        }
      }
      renderConvList();
      renderChatHeader();
      markRead();
      return;
    }
    case 'ack':
    case 'error': {
      const p = S.pendingRefs.get(m.ref);
      if (!p) return;
      S.pendingRefs.delete(m.ref);
      if (m.t === 'ack') p.resolve(m.message); else p.reject(new Error(m.error));
      return;
    }
    case 'message': return onIncoming(m.message);
    case 'deleted': return removeMessage(m.convId, m.id);
    case 'conversation': {
      if (!m.conversation) {
        S.convs.delete(m.removedId);
        if (S.activeId === m.removedId) closeChat();
        renderConvList();
        return;
      }
      const prev = S.convs.get(m.conversation.id);
      S.convs.set(m.conversation.id, m.conversation);
      rememberUsers(m.conversation.members);
      if (m.conversation.lastMessage) await decryptMessage(m.conversation.lastMessage);
      if (prev && S.activeId === m.conversation.id) { renderChatHeader(); refreshTicks(); }
      renderConvList();
      return;
    }
    case 'receipt': {
      const c = S.convs.get(m.convId);
      const mem = c?.members.find((x) => x.id === m.userId);
      if (!mem) return;
      mem.lastDelivered = m.lastDelivered;
      mem.lastRead = m.lastRead;
      if (m.userId === S.me.id) {
        // Başka bir cihazımda okundu
        if (!c.lastMessage || m.lastRead >= c.lastMessage.createdAt) c.unread = 0;
        renderConvList();
      }
      if (S.activeId === m.convId) refreshTicks();
      return;
    }
    case 'typing': return onTyping(m);
    case 'presence':
      if (m.online) S.online.add(m.userId); else S.online.delete(m.userId);
      renderConvList();
      renderChatHeader();
      return;
    case 'user': {
      rememberUsers([m.user]);
      for (const c of S.convs.values()) {
        const mem = c.members.find((x) => x.id === m.user.id);
        if (mem) mem.displayName = m.user.displayName;
      }
      if (m.user.id === S.me.id) { S.me.displayName = m.user.displayName; saveSession(); renderMe(); }
      renderConvList();
      renderChatHeader();
      return;
    }
    default:
  }
}

// ================================================================ şifreleme
async function decryptMessage(raw) {
  if (S.decrypted.has(raw.id)) return S.decrypted.get(raw.id);
  const msg = { id: raw.id, convId: raw.convId, senderId: raw.senderId, createdAt: raw.createdAt, expiresAt: raw.expiresAt, body: null, error: null };
  const sender = S.users.get(raw.senderId);
  try {
    if (!sender) throw new Error('Gönderen bilinmiyor');
    msg.body = await S.keyring.open(raw.envelope, sender);
  } catch (e) {
    msg.error = 'Bu mesajın şifresi çözülemedi';
  }
  S.decrypted.set(raw.id, msg);
  return msg;
}

async function onIncoming(raw) {
  const c = S.convs.get(raw.convId);
  if (!c) { await loadConversations(); return; }
  if (S.decrypted.has(raw.id) && S.messages.get(raw.convId)?.some((x) => x.id === raw.id)) return;
  const msg = await decryptMessage(raw);
  c.lastMessage = raw;
  const list = S.messages.get(raw.convId);
  if (list && !list.some((x) => x.id === msg.id)) {
    list.push(msg);
    if (S.activeId === raw.convId) appendMessage(msg);
  }
  if (raw.senderId !== S.me.id) {
    clearTyping(raw.convId, raw.senderId);
    wsSend({ t: 'delivered', convId: raw.convId, ts: raw.createdAt });
    const visible = S.activeId === raw.convId && document.visibilityState === 'visible';
    if (visible) markRead();
    else {
      c.unread = (c.unread || 0) + 1;
      notify(c, msg);
    }
  }
  renderConvList();
}

function notify(c, msg) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  const sender = S.users.get(msg.senderId);
  const title = c.type === 'group' ? `${sender?.displayName || ''} · ${c.name}` : (sender?.displayName || 'Yeni mesaj');
  try {
    const n = new Notification(title, { body: previewText(msg), tag: c.id, icon: '/icon.svg' });
    n.onclick = () => { window.focus(); openChat(c.id); n.close(); };
  } catch { /* bazı mobil tarayıcılarda desteklenmez */ }
}

function previewText(msg) {
  if (!msg) return '';
  if (msg.error) return '🔒 ' + msg.error;
  const att = msg.body?.attachments || [];
  const text = msg.body?.text || '';
  if (att.length) {
    const t = att[0].type || '';
    const icon = t.startsWith('image/') ? '📷 Fotoğraf' : t.startsWith('video/') ? '🎥 Video' : t.startsWith('audio/') ? '🎵 Ses' : '📎 ' + att[0].name;
    return text ? `${icon} · ${text}` : icon;
  }
  return text;
}

// ================================================================ sohbet listesi
function renderConvList() {
  const ul = $('conv-list');
  const term = $('conv-search').value.trim().toLocaleLowerCase('tr');
  const convs = [...S.convs.values()]
    .filter((c) => !term || convTitle(c).toLocaleLowerCase('tr').includes(term))
    .sort((a, b) => (b.lastMessage?.createdAt || b.createdAt) - (a.lastMessage?.createdAt || a.createdAt));
  const tpl = $('tpl-conv');
  const items = convs.map((c) => {
    const li = tpl.content.firstElementChild.cloneNode(true);
    const peer = convPeer(c);
    const av = avatar(convTitle(c), c.id);
    if (peer && S.online.has(peer.id)) av.classList.add('online');
    li.querySelector('.avatar').replaceWith(av);
    li.querySelector('.conv-name').textContent = convTitle(c);
    const last = c.lastMessage && S.decrypted.get(c.lastMessage.id);
    li.querySelector('.conv-time').textContent = fmtListTime(c.lastMessage?.createdAt || c.createdAt);
    let prev = last ? previewText(last) : (c.type === 'group' ? 'Grup oluşturuldu' : 'Yeni sohbet');
    if (last && c.type === 'group' && last.senderId !== S.me.id && !last.error) prev = `${S.users.get(last.senderId)?.displayName || ''}: ${prev}`;
    if (last && last.senderId === S.me.id) prev = 'Sen: ' + prev;
    if (S.typing.get(c.id)?.size) prev = 'yazıyor…';
    li.querySelector('.conv-preview').textContent = prev;
    const badge = li.querySelector('.badge');
    if (c.unread > 0 && c.id !== S.activeId) { badge.textContent = c.unread > 99 ? '99+' : c.unread; badge.classList.remove('hidden'); }
    li.classList.toggle('active', c.id === S.activeId);
    li.addEventListener('click', () => openChat(c.id));
    return li;
  });
  if (!items.length) {
    const empty = el('li', 'conv-empty', term ? 'Sonuç yok' : 'Henüz sohbet yok. Sağ üstteki + ile başlayın.');
    ul.replaceChildren(empty);
  } else ul.replaceChildren(...items);
  const total = [...S.convs.values()].reduce((n, c) => n + (c.unread || 0), 0);
  document.title = total ? `(${total}) Dalsız` : 'Dalsız';
}

// ================================================================ sohbet ekranı
async function openChat(id, { keepHistory } = {}) {
  const c = S.convs.get(id);
  if (!c) return;
  const switching = S.activeId !== id;
  S.activeId = id;
  if (switching) {
    clearAttachments();
    $('msg-input').value = '';
    autoGrow();
    if (!location.hash) history.pushState({ chat: id }, '', '#c');
  }
  $('app').classList.add('in-chat');
  $('empty-chat').classList.add('hidden');
  $('chat-inner').classList.remove('hidden');
  renderChatHeader();
  renderTyping();
  if (!S.messages.has(id) || keepHistory) {
    const { messages } = await api(`/api/conversations/${id}/messages?limit=100`);
    const list = await Promise.all(messages.map(decryptMessage));
    S.messages.set(id, list);
  }
  if (S.activeId !== id) return;
  renderMessages();
  markRead();
  renderConvList();
  if (matchMedia('(min-width: 761px)').matches) $('msg-input').focus();
}

function closeChat(fromPop) {
  S.activeId = null;
  $('app').classList.remove('in-chat');
  $('chat-inner').classList.add('hidden');
  $('empty-chat').classList.remove('hidden');
  if (!fromPop && location.hash) history.back();
  renderConvList();
}

function renderChatHeader() {
  const c = S.convs.get(S.activeId);
  if (!c) return;
  const peer = convPeer(c);
  const av = avatar(convTitle(c), c.id);
  av.id = 'chat-avatar';
  if (peer && S.online.has(peer.id)) av.classList.add('online');
  $('chat-avatar').replaceWith(av);
  $('chat-name').textContent = convTitle(c);
  let sub;
  if (c.type === 'group') sub = `${c.members.length} üye`;
  else sub = peer && S.online.has(peer.id) ? 'çevrimiçi' : '@' + (peer?.username || '');
  if (c.disappearSeconds) sub += ` · ⏱ ${disappearLabel(c.disappearSeconds)}`;
  $('chat-sub').textContent = sub;
}

function markRead() {
  const c = S.convs.get(S.activeId);
  if (!c || document.visibilityState !== 'visible') return;
  const list = S.messages.get(c.id) || [];
  const last = list[list.length - 1];
  if (c.unread || (last && last.senderId !== S.me.id)) {
    c.unread = 0;
    if (last) wsSend({ t: 'read', convId: c.id, ts: last.createdAt });
    renderConvList();
  }
}

function linkify(parent, text) {
  const re = /\bhttps?:\/\/[^\s<>"']+/gi;
  let i = 0;
  for (const m of text.matchAll(re)) {
    parent.append(text.slice(i, m.index));
    const a = el('a', '', m[0]);
    a.href = m[0];
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    parent.append(a);
    i = m.index + m[0].length;
  }
  parent.append(text.slice(i));
}

function getBlobUrl(att) {
  if (!S.blobs.has(att.fileId)) {
    S.blobs.set(att.fileId, (async () => {
      const data = await api('/api/files/' + att.fileId);
      const plain = await C.decryptFile(data, att.key, att.iv);
      return URL.createObjectURL(new Blob([plain], { type: att.type || 'application/octet-stream' }));
    })().catch((e) => { S.blobs.delete(att.fileId); throw e; }));
  }
  return S.blobs.get(att.fileId);
}

function renderAttachment(att) {
  const t = att.type || '';
  if (t.startsWith('image/') || t.startsWith('video/')) {
    const box = el('div', 'media-loading', 'Şifre çözülüyor…');
    getBlobUrl(att).then((url) => {
      let m;
      if (t.startsWith('image/')) {
        m = el('img');
        m.alt = att.name || 'Fotoğraf';
        m.addEventListener('click', () => openLightbox(url, 'image'));
      } else {
        m = el('video');
        m.controls = true;
        m.playsInline = true;
        m.preload = 'metadata';
      }
      m.src = url;
      const wasBottom = nearBottom();
      m.addEventListener(t.startsWith('image/') ? 'load' : 'loadedmetadata', () => { if (wasBottom) scrollBottom(); }, { once: true });
      box.replaceWith(m);
    }).catch(() => { box.textContent = 'Medya yüklenemedi'; });
    return box;
  }
  if (t.startsWith('audio/')) {
    const box = el('div', 'media-loading', 'Şifre çözülüyor…');
    getBlobUrl(att).then((url) => { const a = el('audio'); a.controls = true; a.src = url; box.replaceWith(a); })
      .catch(() => { box.textContent = 'Ses yüklenemedi'; });
    return box;
  }
  const a = el('a', 'file');
  a.href = '#';
  a.append(svg(ICONS.file));
  const info = el('div');
  info.append(el('div', '', att.name || 'Dosya'), el('small', '', fmtSize(att.size || 0)));
  a.append(info);
  a.addEventListener('click', async (e) => {
    e.preventDefault();
    try {
      const url = await getBlobUrl(att);
      const dl = el('a');
      dl.href = url;
      dl.download = att.name || 'dosya';
      dl.click();
    } catch { toast('Dosya indirilemedi'); }
  });
  return a;
}

function messageStatus(msg) {
  if (msg.pending) return 'pending';
  const c = S.convs.get(msg.convId);
  const others = c ? c.members.filter((m) => m.id !== S.me.id) : [];
  if (!others.length) return 'read';
  if (others.every((m) => m.lastRead >= msg.createdAt)) return 'read';
  if (others.every((m) => m.lastDelivered >= msg.createdAt)) return 'delivered';
  return 'sent';
}

function statusIcon(st) {
  if (st === 'pending') return svg(ICONS.clock);
  if (st === 'sent') return svg(ICONS.check);
  const s = svg(ICONS.checks);
  if (st === 'read') s.classList.add('read');
  return s;
}

function buildMessage(msg, prev) {
  const c = S.convs.get(msg.convId);
  const out = msg.senderId === S.me.id;
  const wrap = el('div', 'msg ' + (out ? 'out' : 'in'));
  wrap.dataset.id = msg.id;
  const grouped = prev && prev.senderId === msg.senderId && msg.createdAt - prev.createdAt < 5 * 60 * 1000 &&
    new Date(prev.createdAt).toDateString() === new Date(msg.createdAt).toDateString();
  if (grouped) wrap.classList.add('grouped');
  if (!out && c?.type === 'group' && !grouped) {
    const u = S.users.get(msg.senderId);
    const s = el('div', 'sender', u?.displayName || 'Bilinmeyen');
    s.style.color = avatar('', msg.senderId).style.background;
    wrap.append(s);
  }
  const bubble = el('div', 'bubble');
  if (msg.error) {
    bubble.classList.add('failed');
    bubble.textContent = '🔒 ' + msg.error;
  } else {
    const atts = msg.body?.attachments || [];
    if (atts.length) bubble.classList.add('media');
    for (const a of atts) bubble.append(renderAttachment(a));
    if (msg.body?.text) {
      const t = atts.length ? el('div', 'caption') : bubble;
      linkify(t, msg.body.text);
      if (t !== bubble) bubble.append(t);
    }
  }
  wrap.append(bubble);
  const meta = el('div', 'meta');
  if (msg.expiresAt) meta.append(svg(ICONS.timer));
  meta.append(el('span', '', fmtTime(msg.createdAt)));
  if (out) {
    const st = el('span', 'status');
    st.append(statusIcon(messageStatus(msg)));
    meta.append(st);
    if (!msg.pending) {
      const del = el('button', 'del-btn', 'Sil');
      del.type = 'button';
      del.addEventListener('click', () => {
        if (confirm('Bu mesaj herkes için silinsin mi?')) wsSend({ t: 'delete', id: msg.id });
      });
      meta.append(del);
    }
  }
  wrap.append(meta);
  return wrap;
}

const nearBottom = () => { const b = $('messages'); return b.scrollHeight - b.scrollTop - b.clientHeight < 120; };
const scrollBottom = () => { const b = $('messages'); b.scrollTop = b.scrollHeight; };

function renderMessages() {
  const box = $('messages');
  const list = S.messages.get(S.activeId) || [];
  const c = S.convs.get(S.activeId);
  const nodes = [];
  const sys = el('div', 'sys-msg', '🔒 Bu sohbetteki mesajlar ve dosyalar uçtan uca şifrelidir.');
  nodes.push(sys);
  if (c?.disappearSeconds) nodes.push(el('div', 'sys-msg', `⏱ Kaybolan mesajlar açık: ${disappearLabel(c.disappearSeconds)}`));
  let prev = null;
  for (const m of list) {
    if (!prev || new Date(prev.createdAt).toDateString() !== new Date(m.createdAt).toDateString()) nodes.push(el('div', 'day-sep', fmtDay(m.createdAt)));
    nodes.push(buildMessage(m, prev));
    prev = m;
  }
  box.replaceChildren(...nodes);
  scrollBottom();
}

function appendMessage(msg) {
  const box = $('messages');
  const list = S.messages.get(msg.convId);
  const idx = list.indexOf(msg);
  const prev = idx > 0 ? list[idx - 1] : null;
  const stick = nearBottom() || msg.senderId === S.me.id;
  if (!prev || new Date(prev.createdAt).toDateString() !== new Date(msg.createdAt).toDateString()) box.append(el('div', 'day-sep', fmtDay(msg.createdAt)));
  box.append(buildMessage(msg, prev));
  if (stick) scrollBottom();
}

function refreshTicks() {
  for (const m of S.messages.get(S.activeId) || []) {
    if (m.senderId !== S.me.id) continue;
    const st = document.querySelector(`.msg[data-id="${m.id}"] .status`);
    if (st) st.replaceChildren(statusIcon(messageStatus(m)));
  }
}

function removeMessage(convId, id) {
  const list = S.messages.get(convId);
  if (list) {
    const i = list.findIndex((m) => m.id === id);
    if (i >= 0) list.splice(i, 1);
  }
  S.decrypted.delete(id);
  const c = S.convs.get(convId);
  if (c && c.lastMessage?.id === id) {
    const l = list?.[list.length - 1];
    c.lastMessage = l ? { id: l.id, createdAt: l.createdAt, senderId: l.senderId } : null;
  }
  if (S.activeId === convId) document.querySelector(`.msg[data-id="${id}"]`)?.remove();
  renderConvList();
}

function expireLocal() {
  const t = Date.now();
  for (const [convId, list] of S.messages) {
    for (const m of [...list]) if (m.expiresAt && m.expiresAt <= t) removeMessage(convId, m.id);
  }
}

// ================================================================ yazıyor…
function onTyping(m) {
  if (!S.typing.has(m.convId)) S.typing.set(m.convId, new Map());
  const map = S.typing.get(m.convId);
  clearTimeout(map.get(m.userId));
  if (m.on) map.set(m.userId, setTimeout(() => clearTyping(m.convId, m.userId), 6000));
  else map.delete(m.userId);
  renderTyping();
  renderConvList();
}
function clearTyping(convId, userId) {
  const map = S.typing.get(convId);
  if (!map?.has(userId)) return;
  clearTimeout(map.get(userId));
  map.delete(userId);
  renderTyping();
  renderConvList();
}
function renderTyping() {
  const map = S.typing.get(S.activeId);
  const box = $('typing');
  if (!map?.size) { box.classList.add('hidden'); return; }
  const names = [...map.keys()].map((id) => S.users.get(id)?.displayName || '').filter(Boolean);
  box.textContent = names.join(', ') + ' yazıyor…';
  box.classList.remove('hidden');
}

let typingSent = 0;
function onInputTyping() {
  if (!S.activeId) return;
  const t = Date.now();
  if (t - typingSent > 3000) { typingSent = t; wsSend({ t: 'typing', convId: S.activeId, on: true }); }
}
function stopTyping() {
  if (typingSent && S.activeId) wsSend({ t: 'typing', convId: S.activeId, on: false });
  typingSent = 0;
}

// ================================================================ gönderme
function autoGrow() {
  const ta = $('msg-input');
  ta.style.height = '';
  if (!ta.value || !ta.offsetParent) return;
  ta.style.height = 'auto';
  ta.style.height = Math.min(ta.scrollHeight, 140) + 'px';
}

function clearAttachments() {
  for (const a of S.attachments) URL.revokeObjectURL(a.url);
  S.attachments = [];
  renderAttachPreview();
}

function renderAttachPreview() {
  const box = $('attach-preview');
  box.classList.toggle('hidden', !S.attachments.length);
  box.replaceChildren(...S.attachments.map((a, i) => {
    const it = el('div', 'item');
    if (a.file.type.startsWith('image/')) { const img = el('img'); img.src = a.url; it.append(img); }
    else if (a.file.type.startsWith('video/')) { const v = el('video'); v.src = a.url; v.muted = true; it.append(v); }
    else it.append(el('span', '', a.file.name));
    const x = el('button', '', '✕');
    x.type = 'button';
    x.addEventListener('click', () => { URL.revokeObjectURL(a.url); S.attachments.splice(i, 1); renderAttachPreview(); });
    it.append(x);
    return it;
  }));
}

function addFiles(files) {
  const MAX = 100 * 1024 * 1024;
  for (const f of files) {
    if (f.size > MAX) { toast(`${f.name} çok büyük (en fazla 100 MB)`); continue; }
    S.attachments.push({ file: f, url: URL.createObjectURL(f) });
  }
  renderAttachPreview();
}

let sending = false;
async function sendCurrent() {
  const c = S.convs.get(S.activeId);
  const input = $('msg-input');
  const text = input.value.trim();
  if (!c || sending || (!text && !S.attachments.length)) return;
  if (!S.wsReady) { toast('Sunucuya bağlı değil, tekrar deneyin'); return; }
  sending = true;
  $('send-btn').disabled = true;
  const files = S.attachments.slice();
  const local = {
    id: C.randomHex(16), convId: c.id, senderId: S.me.id, createdAt: Date.now(), pending: true,
    body: { text, attachments: [] }, error: null,
  };
  input.value = '';
  autoGrow();
  stopTyping();
  S.attachments = [];
  renderAttachPreview();
  let placeholder = null;
  if (files.length) {
    placeholder = el('div', 'sys-msg', `Şifreleniyor ve yükleniyor (${files.length} dosya)…`);
    $('messages').append(placeholder);
    scrollBottom();
  }
  try {
    for (const a of files) {
      const buf = await a.file.arrayBuffer();
      const encd = await C.encryptFile(buf);
      const up = await api('/api/files', { method: 'POST', raw: encd.data });
      local.body.attachments.push({ fileId: up.id, key: encd.key, iv: encd.iv, name: a.file.name, type: a.file.type, size: a.file.size });
      // Kendi dosyamızı tekrar indirmeyelim
      S.blobs.set(up.id, Promise.resolve(a.url));
    }
    placeholder?.remove();
    const list = S.messages.get(c.id);
    list.push(local);
    appendMessage(local);
    const send = async () => {
      const conv = S.convs.get(c.id);
      const envelope = await S.keyring.seal(local.body, conv.members.map((m) => ({ id: m.id, publicKey: m.publicKey })));
      return wsRequest({ t: 'send', convId: c.id, id: local.id, envelope });
    };
    let saved;
    try { saved = await send(); } catch (e) {
      if (!/üyelik/.test(e.message)) throw e;
      await loadConversations(); // üye listesi değişmiş, yeniden dene
      saved = await send();
    }
    // Yerel kopyayı sunucudakiyle değiştir
    const final = { ...local, id: saved.id, createdAt: saved.createdAt, expiresAt: saved.expiresAt, pending: false };
    S.decrypted.set(saved.id, final);
    const i = list.indexOf(local);
    if (i >= 0 && !list.some((m) => m.id === saved.id && m !== local)) list[i] = final;
    else if (i >= 0) list.splice(i, 1);
    if (S.activeId === c.id) {
      const node = document.querySelector(`.msg[data-id="${local.id}"]`);
      if (node) node.replaceWith(buildMessage(final, list[list.indexOf(final) - 1]));
    }
    c.lastMessage = { id: saved.id, createdAt: saved.createdAt, senderId: S.me.id };
    renderConvList();
  } catch (e) {
    placeholder?.remove();
    toast('Gönderilemedi: ' + e.message);
    const list = S.messages.get(c.id);
    const i = list.indexOf(local);
    if (i >= 0) list.splice(i, 1);
    document.querySelector(`.msg[data-id="${local.id}"]`)?.remove();
    if (!input.value) { input.value = text; autoGrow(); }
  } finally {
    sending = false;
    $('send-btn').disabled = false;
  }
}

// ================================================================ modallar
function openModal(title, content) {
  $('modal-title').textContent = title;
  $('modal-body').replaceChildren(...[].concat(content));
  $('modal-back').classList.remove('hidden');
}
function closeModal() { $('modal-back').classList.add('hidden'); $('modal-body').replaceChildren(); }

function openLightbox(url, kind) {
  const lb = $('lightbox');
  const m = el(kind === 'image' ? 'img' : 'video');
  m.src = url;
  if (kind !== 'image') m.controls = true;
  lb.replaceChildren(m);
  lb.classList.remove('hidden');
}

function userRow(u, selected) {
  const li = el('li');
  li.append(avatar(u.displayName, u.id, 'sm'));
  const g = el('div', 'grow');
  g.append(el('div', '', u.displayName), el('small', '', '@' + u.username));
  li.append(g);
  if (selected !== undefined) { li.append(el('span', 'check')); li.classList.toggle('selected', selected); }
  return li;
}

// Kullanıcı seçici (tekli veya çoklu)
function userPicker({ multi, exclude = [], onPick }) {
  const wrap = el('div');
  const search = el('input');
  search.type = 'search';
  search.placeholder = 'İsim veya kullanıcı adı ara';
  const field = el('label', 'field');
  field.append(search);
  const ul = el('ul', 'user-list');
  const selected = new Map();
  let timer;
  const load = async () => {
    const { users } = await api('/api/users?q=' + encodeURIComponent(search.value.trim()));
    rememberUsers(users);
    const rows = users.filter((u) => !exclude.includes(u.id)).map((u) => {
      const li = userRow(u, multi ? selected.has(u.id) : undefined);
      li.addEventListener('click', () => {
        if (!multi) { onPick([u]); return; }
        if (selected.has(u.id)) selected.delete(u.id); else selected.set(u.id, u);
        li.classList.toggle('selected', selected.has(u.id));
        wrap.dispatchEvent(new Event('change'));
      });
      return li;
    });
    ul.replaceChildren(...(rows.length ? rows : [el('li', 'muted', 'Kullanıcı bulunamadı')]));
  };
  search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(load, 200); });
  load().catch((e) => toast(e.message));
  wrap.append(field, ul);
  wrap.selected = selected;
  setTimeout(() => search.focus(), 50);
  return wrap;
}

function newChatModal() {
  const groupBtn = el('button', 'secondary wide', '👥 Yeni grup oluştur');
  groupBtn.type = 'button';
  groupBtn.addEventListener('click', newGroupModal);
  const picker = userPicker({
    multi: false,
    exclude: [S.me.id],
    onPick: async ([u]) => {
      try {
        const { conversation } = await api('/api/conversations', { method: 'POST', body: { type: 'direct', memberIds: [u.id] } });
        S.convs.set(conversation.id, conversation);
        rememberUsers(conversation.members);
        closeModal();
        renderConvList();
        openChat(conversation.id);
      } catch (e) { toast(e.message); }
    },
  });
  openModal('Yeni sohbet', [groupBtn, el('div', 'section-title', 'Kişiler'), picker]);
}

function newGroupModal() {
  const name = el('input');
  name.maxLength = 64;
  name.placeholder = 'Grup adı';
  const f = el('label', 'field', 'Grup adı');
  f.append(name);
  const picker = userPicker({ multi: true, exclude: [S.me.id] });
  const create = el('button', 'primary', 'Oluştur');
  create.type = 'button';
  create.addEventListener('click', async () => {
    if (!name.value.trim()) { toast('Grup adı girin'); return; }
    if (!picker.selected.size) { toast('En az bir üye seçin'); return; }
    try {
      create.disabled = true;
      const { conversation } = await api('/api/conversations', {
        method: 'POST', body: { type: 'group', name: name.value.trim(), memberIds: [...picker.selected.keys()] },
      });
      S.convs.set(conversation.id, conversation);
      rememberUsers(conversation.members);
      closeModal();
      renderConvList();
      openChat(conversation.id);
    } catch (e) { toast(e.message); create.disabled = false; }
  });
  const actions = el('div', 'row-actions');
  actions.append(create);
  openModal('Yeni grup', [f, el('div', 'section-title', 'Üyeler'), picker, actions]);
}

function disappearSelect(c) {
  const f = el('label', 'field', 'Kaybolan mesajlar');
  const sel = el('select');
  for (const [v, label] of DISAPPEAR) {
    const o = el('option', '', label);
    o.value = v;
    if (v === c.disappearSeconds) o.selected = true;
    sel.append(o);
  }
  sel.addEventListener('change', async () => {
    try { await api(`/api/conversations/${c.id}`, { method: 'PATCH', body: { disappearSeconds: Number(sel.value) } }); toast('Kaybolan mesaj süresi güncellendi'); }
    catch (e) { toast(e.message); }
  });
  f.append(sel);
  return f;
}

async function chatInfoModal() {
  const c = S.convs.get(S.activeId);
  if (!c) return;
  const head = el('div', 'info-head');
  head.append(avatar(convTitle(c), c.id, 'lg'), el('h4', '', convTitle(c)));
  const nodes = [head];
  if (c.type === 'direct') {
    const peer = convPeer(c);
    if (peer) {
      head.append(el('div', 'muted', '@' + peer.username));
      nodes.push(el('div', 'section-title', 'Güvenlik numarası'));
      const box = el('div', 'safety');
      const num = await C.safetyNumber(S.me, peer);
      for (const g of num.split(' ')) box.append(el('span', '', g));
      nodes.push(box, el('p', 'hint', `${peer.displayName} ile uçtan uca şifrelemeyi doğrulamak için bu numarayı onun cihazındakiyle karşılaştırın. Aynıysa aranızda kimse yoktur.`));
    }
    nodes.push(el('div', 'section-title', 'Ayarlar'), disappearSelect(c));
  } else {
    const me = c.members.find((m) => m.id === S.me.id);
    head.append(el('div', 'muted', `${c.members.length} üye`));
    const nameIn = el('input');
    nameIn.value = c.name;
    nameIn.maxLength = 64;
    nameIn.addEventListener('change', async () => {
      try { await api(`/api/conversations/${c.id}`, { method: 'PATCH', body: { name: nameIn.value.trim() } }); toast('Grup adı güncellendi'); }
      catch (e) { toast(e.message); }
    });
    const nf = el('label', 'field', 'Grup adı');
    nf.append(nameIn);
    nodes.push(el('div', 'section-title', 'Ayarlar'), nf, disappearSelect(c));
    nodes.push(el('div', 'section-title', 'Üyeler'));
    const ul = el('ul', 'user-list');
    for (const m of c.members) {
      const li = userRow(m);
      if (m.role === 'admin') li.append(el('span', 'chip', 'Yönetici'));
      if (me?.role === 'admin' && m.id !== S.me.id) {
        const rm = el('button', 'danger-btn', 'Çıkar');
        rm.type = 'button';
        rm.addEventListener('click', async (e) => {
          e.stopPropagation();
          if (!confirm(`${m.displayName} gruptan çıkarılsın mı?`)) return;
          try { await api(`/api/conversations/${c.id}/members/${m.id}`, { method: 'DELETE' }); li.remove(); }
          catch (err) { toast(err.message); }
        });
        li.append(rm);
      }
      ul.append(li);
    }
    nodes.push(ul);
    const add = el('button', 'secondary', '+ Üye ekle');
    add.type = 'button';
    add.addEventListener('click', () => {
      const picker = userPicker({ multi: true, exclude: c.members.map((m) => m.id) });
      const ok = el('button', 'primary', 'Ekle');
      ok.type = 'button';
      ok.addEventListener('click', async () => {
        if (!picker.selected.size) return;
        try {
          await api(`/api/conversations/${c.id}/members`, { method: 'POST', body: { memberIds: [...picker.selected.keys()] } });
          closeModal();
          toast('Üyeler eklendi');
        } catch (e) { toast(e.message); }
      });
      const ra = el('div', 'row-actions');
      ra.append(ok);
      openModal('Üye ekle', [picker, ra]);
    });
    const leave = el('button', 'danger-btn', 'Gruptan ayrıl');
    leave.type = 'button';
    leave.addEventListener('click', async () => {
      if (!confirm('Gruptan ayrılmak istediğinize emin misiniz?')) return;
      try { await api(`/api/conversations/${c.id}/members/${S.me.id}`, { method: 'DELETE' }); closeModal(); }
      catch (e) { toast(e.message); }
    });
    const ra = el('div', 'row-actions');
    ra.append(add, leave);
    nodes.push(ra);
  }
  openModal(c.type === 'group' ? 'Grup bilgisi' : 'Sohbet bilgisi', nodes);
}

function settingsModal() {
  const head = el('div', 'info-head');
  head.append(avatar(S.me.displayName, S.me.id, 'lg'), el('h4', '', S.me.displayName), el('div', 'muted', '@' + S.me.username));
  const nameIn = el('input');
  nameIn.value = S.me.displayName;
  nameIn.maxLength = 64;
  const nf = el('label', 'field', 'Görünen ad');
  nf.append(nameIn);
  const save = el('button', 'primary', 'Kaydet');
  save.type = 'button';
  save.addEventListener('click', async () => {
    try { await api('/api/me', { method: 'PATCH', body: { displayName: nameIn.value.trim() } }); toast('Kaydedildi'); closeModal(); }
    catch (e) { toast(e.message); }
  });
  const nodes = [head, nf];
  if ('Notification' in window && Notification.permission !== 'granted') {
    const nb = el('button', 'secondary', '🔔 Bildirimleri aç');
    nb.type = 'button';
    nb.addEventListener('click', async () => { await Notification.requestPermission(); nb.remove(); });
    nodes.push(nb);
  }
  const out = el('button', 'danger-btn', 'Çıkış yap');
  out.type = 'button';
  out.addEventListener('click', () => { if (confirm('Bu cihazdan çıkış yapılsın mı?')) logout(); });
  const ra = el('div', 'row-actions');
  ra.append(out, save);
  nodes.push(ra, el('p', 'hint', 'Şifreleme anahtarınız bu cihazda saklanır. Çıkış yapınca cihazdan silinir; tekrar giriş yaptığınızda parolanızla geri açılır.'));
  openModal('Ayarlar', nodes);
}

// ================================================================ arayüz bağlama
function bindUi() {
  $('new-chat-btn').addEventListener('click', newChatModal);
  $('me-btn').addEventListener('click', settingsModal);
  $('conv-search').addEventListener('input', renderConvList);
  $('back-btn').addEventListener('click', () => closeChat());
  $('chat-info-btn').addEventListener('click', chatInfoModal);
  $('chat-title-btn').addEventListener('click', chatInfoModal);
  $('modal-close').addEventListener('click', closeModal);
  $('modal-back').addEventListener('click', (e) => { if (e.target === $('modal-back')) closeModal(); });
  $('lightbox').addEventListener('click', () => { $('lightbox').classList.add('hidden'); $('lightbox').replaceChildren(); });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (!$('lightbox').classList.contains('hidden')) $('lightbox').click();
    else if (!$('modal-back').classList.contains('hidden')) closeModal();
  });

  const input = $('msg-input');
  input.addEventListener('input', () => { autoGrow(); onInputTyping(); });
  input.addEventListener('blur', stopTyping);
  input.addEventListener('keydown', (e) => {
    const mobile = matchMedia('(pointer: coarse)').matches;
    if (e.key === 'Enter' && !e.shiftKey && !mobile && !e.isComposing) { e.preventDefault(); sendCurrent(); }
  });
  input.addEventListener('paste', (e) => {
    const files = [...(e.clipboardData?.files || [])];
    if (files.length) { e.preventDefault(); addFiles(files); }
  });
  $('composer').addEventListener('submit', (e) => { e.preventDefault(); sendCurrent(); });
  $('attach-btn').addEventListener('click', () => $('file-input').click());
  $('file-input').addEventListener('change', (e) => { addFiles([...e.target.files]); e.target.value = ''; });

  const chat = $('chat');
  chat.addEventListener('dragover', (e) => { if (S.activeId) e.preventDefault(); });
  chat.addEventListener('drop', (e) => {
    if (!S.activeId) return;
    e.preventDefault();
    addFiles([...e.dataTransfer.files]);
  });

  // Eski mesajları yükle (yukarı kaydırınca)
  const box = $('messages');
  let loadingOlder = false;
  box.addEventListener('scroll', async () => {
    if (box.scrollTop > 60 || loadingOlder || !S.activeId) return;
    const id = S.activeId;
    const list = S.messages.get(id);
    if (!list?.length || list.noMore) return;
    loadingOlder = true;
    try {
      const { messages } = await api(`/api/conversations/${id}/messages?limit=100&before=${list[0].createdAt}`);
      if (!messages.length) { list.noMore = true; return; }
      const older = await Promise.all(messages.map(decryptMessage));
      list.unshift(...older.filter((m) => !list.some((x) => x.id === m.id)));
      if (S.activeId === id) {
        const h = box.scrollHeight;
        renderMessages();
        box.scrollTop = box.scrollHeight - h;
      }
    } finally { loadingOlder = false; }
  });

  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') markRead(); });
  setInterval(() => wsSend({ t: 'ping' }), 25000);
}

boot().catch((e) => { console.error(e); document.body.textContent = 'Uygulama başlatılamadı: ' + e.message; });
