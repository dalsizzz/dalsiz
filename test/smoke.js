'use strict';
// Uçtan uca duman testi: sunucuyu başlatır, iki kullanıcı kaydeder, şifreli mesaj
// ve dosya gönderip alıcı tarafında çözer. Çalıştırma: npm test
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const WebSocket = require('ws');

const PORT = 3900 + Math.floor(Math.random() * 90);
const BASE = `http://127.0.0.1:${PORT}`;
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dalsiz-test-'));

async function api(p, { token, method = 'GET', body, raw } = {}) {
  const headers = {};
  if (token) headers.Authorization = 'Bearer ' + token;
  if (body) headers['Content-Type'] = 'application/json';
  const r = await fetch(BASE + p, { method, headers, body: raw || (body && JSON.stringify(body)) });
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.arrayBuffer();
  if (!r.ok) throw new Error(`${r.status} ${data.error}`);
  return data;
}

function connectWs(token) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}/ws`);
    const inbox = [];
    const waiters = [];
    ws.on('message', (d) => {
      const m = JSON.parse(d);
      const w = waiters.findIndex((x) => x.pred(m));
      if (w >= 0) waiters.splice(w, 1)[0].resolve(m); else inbox.push(m);
    });
    ws.wait = (pred) => {
      const i = inbox.findIndex(pred);
      if (i >= 0) return Promise.resolve(inbox.splice(i, 1)[0]);
      return new Promise((res, rej) => { waiters.push({ pred, resolve: res }); setTimeout(() => rej(new Error('ws timeout')), 5000); });
    };
    ws.on('open', () => ws.send(JSON.stringify({ t: 'auth', token })));
    ws.on('error', reject);
    ws.wait((m) => m.t === 'ready').then(() => resolve(ws), reject);
  });
}

(async () => {
  const C = await import('../public/js/crypto.js');
  const srv = spawn(process.execPath, ['--no-warnings=ExperimentalWarning', 'server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PORT: String(PORT), DATA_DIR: dataDir, INVITE_CODE: 'sirket123' },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  await new Promise((res) => srv.stdout.on('data', (d) => { if (String(d).includes('çalışıyor')) res(); }));
  try {
    assert.deepEqual(await api('/api/config'), { inviteRequired: true });

    async function register(username, displayName, password) {
      const id = await C.generateIdentity(password);
      const authKey = await C.deriveAuthKey(username, password);
      const r = await api('/api/register', { method: 'POST', body: { username, displayName, authKey, publicKey: id.publicKey, keyBackup: id.keyBackup, inviteCode: 'sirket123' } });
      return { ...r, privateJwk: id.privateJwk };
    }

    await assert.rejects(api('/api/register', { method: 'POST', body: { username: 'x', inviteCode: 'yanlis' } }), /403/);
    const ali = await register('ali', 'Ali Yılmaz', 'parola-ali-123');
    const ayse = await register('ayse', 'Ayşe Kaya', 'parola-ayse-123');
    await assert.rejects(register('ALI', 'Kopya', 'xxxxxxxxx'), /409/);

    // Giriş: yanlış parola reddedilir, doğru parola anahtar yedeğini açar
    await assert.rejects(api('/api/login', { method: 'POST', body: { username: 'ayse', authKey: await C.deriveAuthKey('ayse', 'yanlis') } }), /401/);
    const login = await api('/api/login', { method: 'POST', body: { username: 'ayse', authKey: await C.deriveAuthKey('ayse', 'parola-ayse-123') } });
    const restored = await C.decryptBackup(login.keyBackup, 'parola-ayse-123');
    assert.equal(restored.d, ayse.privateJwk.d);

    const aliRing = new C.KeyRing(await C.importPrivate(ali.privateJwk), ali.user.id);
    const ayseRing = new C.KeyRing(await C.importPrivate(restored), ayse.user.id);

    const found = await api('/api/users?q=ay', { token: ali.token });
    assert.equal(found.users[0].username, 'ayse');

    const { conversation } = await api('/api/conversations', { token: ali.token, method: 'POST', body: { type: 'direct', memberIds: [ayse.user.id] } });
    const again = await api('/api/conversations', { token: ayse.token, method: 'POST', body: { type: 'direct', memberIds: [ali.user.id] } });
    assert.equal(again.conversation.id, conversation.id, 'birebir sohbet tekil olmalı');

    const wsAli = await connectWs(ali.token);
    const wsAyse = await connectWs(login.token);

    // Şifreli dosya yükle
    const photo = Buffer.from('sahte-jpeg-verisi-'.repeat(1000));
    const encFile = await C.encryptFile(photo);
    const up = await api('/api/files', { token: ali.token, method: 'POST', raw: Buffer.from(encFile.data) });
    const stored = fs.readFileSync(path.join(dataDir, 'files', up.id));
    assert.ok(!stored.includes(Buffer.from('sahte-jpeg')), 'sunucudaki dosya şifreli olmalı');

    const body = { text: 'Merhaba Ayşe! 🔒', attachments: [{ fileId: up.id, key: encFile.key, iv: encFile.iv, name: 'foto.jpg', type: 'image/jpeg', size: photo.length }] };
    const envelope = await aliRing.seal(body, conversation.members);
    wsAli.send(JSON.stringify({ t: 'send', convId: conversation.id, envelope, ref: 'r1', id: C.randomHex(16) }));
    const ack = await wsAli.wait((m) => m.t === 'ack' && m.ref === 'r1');
    assert.ok(ack.message.id);

    const incoming = await wsAyse.wait((m) => m.t === 'message');
    assert.ok(!JSON.stringify(incoming).includes('Merhaba'), 'sunucu düz metin görmemeli');
    const opened = await ayseRing.open(incoming.message.envelope, { id: ali.user.id, publicKey: ali.user.publicKey });
    assert.equal(opened.text, 'Merhaba Ayşe! 🔒');
    const fileData = await api('/api/files/' + opened.attachments[0].fileId, { token: ayse.token });
    const plain = Buffer.from(await C.decryptFile(fileData, opened.attachments[0].key, opened.attachments[0].iv));
    assert.ok(plain.equals(photo));

    // Gönderen kendi mesajını da çözebilmeli (çoklu cihaz)
    const self = await aliRing.open(incoming.message.envelope, { id: ali.user.id, publicKey: ali.user.publicKey });
    assert.equal(self.text, body.text);

    // Okundu bilgisi
    wsAyse.send(JSON.stringify({ t: 'read', convId: conversation.id, ts: incoming.message.createdAt }));
    const rc = await wsAli.wait((m) => m.t === 'receipt' && m.userId === ayse.user.id);
    assert.equal(rc.lastRead, incoming.message.createdAt);

    // Eksik alıcı anahtarı olan zarf reddedilir
    const bad = await aliRing.seal({ text: 'x' }, [conversation.members.find((m) => m.id === ali.user.id)]);
    wsAli.send(JSON.stringify({ t: 'send', convId: conversation.id, envelope: bad, ref: 'r2' }));
    await wsAli.wait((m) => m.t === 'error' && m.ref === 'r2');

    // Grup + kaybolan mesaj
    const veli = await register('veli', 'Veli Demir', 'parola-veli-123');
    const g = await api('/api/conversations', { token: ali.token, method: 'POST', body: { type: 'group', name: 'Proje Ekibi', memberIds: [ayse.user.id, veli.user.id] } });
    assert.equal(g.conversation.members.length, 3);
    await api(`/api/conversations/${g.conversation.id}`, { token: ali.token, method: 'PATCH', body: { disappearSeconds: 30 } });
    const genv = await aliRing.seal({ text: 'Toplantı 15:00' }, g.conversation.members);
    wsAli.send(JSON.stringify({ t: 'send', convId: g.conversation.id, envelope: genv, ref: 'r3' }));
    const gack = await wsAli.wait((m) => m.t === 'ack' && m.ref === 'r3');
    assert.ok(gack.message.expiresAt > gack.message.createdAt);
    const veliRing = new C.KeyRing(await C.importPrivate(veli.privateJwk), veli.user.id);
    assert.equal((await veliRing.open(gack.message.envelope, ali.user)).text, 'Toplantı 15:00');

    // Üye olmayan sohbet okuyamaz
    const outsider = await register('mehmet', 'Mehmet', 'parola-mehmet-1');
    await assert.rejects(api(`/api/conversations/${conversation.id}/messages`, { token: outsider.token }), /404/);

    const hist = await api(`/api/conversations/${conversation.id}/messages`, { token: ayse.token });
    assert.equal(hist.messages.length, 1);

    wsAli.close();
    wsAyse.close();
    console.log('✓ Tüm testler geçti');
  } finally {
    srv.kill();
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
})().catch((e) => { console.error('✗', e); process.exit(1); });
