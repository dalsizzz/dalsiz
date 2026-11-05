// Uçtan uca şifreleme katmanı (Web Crypto API).
//
// - Her kullanıcının bir ECDH P-256 anahtar çifti vardır. Gizli anahtar yalnızca
//   cihazda açılır; sunucuda parolayla şifrelenmiş yedeği durur.
// - Her mesaj rastgele bir AES-256-GCM anahtarıyla şifrelenir. Bu anahtar,
//   gönderen ile her alıcı arasındaki ECDH ortak sırrından HKDF ile türetilen
//   anahtarla ayrı ayrı sarılır.
// - Dosyalar (fotoğraf, video) kendi rastgele anahtarıyla şifrelenir; anahtar
//   şifreli mesajın içinde taşınır.

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const b64 = {
  from(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(s);
  },
  to(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  },
};

export const randomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
export const randomHex = (n = 16) => [...randomBytes(n)].map((b) => b.toString(16).padStart(2, '0')).join('');

const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
const PBKDF2_ITER = 310000;

async function pbkdf2(password, salt, usage) {
  const base = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']);
  if (usage === 'bits') {
    return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' }, base, 256));
  }
  return subtle.deriveKey({ name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// Sunucuya gönderilen kimlik doğrulama anahtarı. Parolanın kendisi sunucuya gitmez,
// ve bu değerden gizli anahtar yedeğini açan anahtar türetilemez (farklı tuz).
export async function deriveAuthKey(username, password) {
  const salt = enc.encode('dalsiz-auth:' + username.toLowerCase());
  return b64.from(await pbkdf2(password, salt, 'bits'));
}

export async function generateIdentity(password) {
  const pair = await subtle.generateKey(ECDH, true, ['deriveBits']);
  const publicKey = await subtle.exportKey('jwk', pair.publicKey);
  const privateJwk = await subtle.exportKey('jwk', pair.privateKey);
  const keyBackup = await encryptBackup(privateJwk, password);
  return { publicKey, privateJwk, keyBackup };
}

export async function encryptBackup(privateJwk, password) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await pbkdf2(password, salt, 'key');
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(privateJwk)));
  return { v: 1, salt: b64.from(salt), iv: b64.from(iv), ct: b64.from(ct) };
}

export async function decryptBackup(backup, password) {
  const key = await pbkdf2(password, b64.to(backup.salt), 'key');
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: b64.to(backup.iv) }, key, b64.to(backup.ct));
  return JSON.parse(dec.decode(pt));
}

export const importPrivate = (jwk) => subtle.importKey('jwk', jwk, ECDH, false, ['deriveBits']);
export const importPublic = (jwk) => subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, ECDH, false, []);

// Bir kişiyle aramızdaki anahtar sarma anahtarı (önbellekli)
export class KeyRing {
  constructor(privateKey, myId) {
    this.privateKey = privateKey;
    this.myId = myId;
    this.cache = new Map();
  }

  async wrapKeyFor(userId, publicJwk) {
    const id = `${userId}:${publicJwk.x}:${publicJwk.y}`;
    if (!this.cache.has(id)) {
      this.cache.set(id, (async () => {
        const pub = await importPublic(publicJwk);
        const shared = await subtle.deriveBits({ name: 'ECDH', public: pub }, this.privateKey, 256);
        const hk = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
        const ids = [Number(this.myId), Number(userId)].sort((a, b) => a - b).join(':');
        return subtle.deriveKey(
          { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('dalsiz-v1'), info: enc.encode('wrap:' + ids) },
          hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
        );
      })());
    }
    return this.cache.get(id);
  }

  // members: [{id, publicKey}] — gönderen dahil tüm üyeler
  async seal(payload, members) {
    const raw = randomBytes(32);
    const msgKey = await subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
    const iv = randomBytes(12);
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, msgKey, enc.encode(JSON.stringify(payload)));
    const keys = {};
    await Promise.all(members.map(async (m) => {
      const wk = await this.wrapKeyFor(m.id, m.publicKey);
      const kiv = randomBytes(12);
      keys[m.id] = { iv: b64.from(kiv), ct: b64.from(await subtle.encrypt({ name: 'AES-GCM', iv: kiv }, wk, raw)) };
    }));
    return { iv: b64.from(iv), ct: b64.from(ct), keys };
  }

  async open(envelope, sender) {
    const mine = envelope.keys[this.myId];
    if (!mine) throw new Error('Bu mesaj için anahtar yok');
    const wk = await this.wrapKeyFor(sender.id, sender.publicKey);
    const raw = await subtle.decrypt({ name: 'AES-GCM', iv: b64.to(mine.iv) }, wk, b64.to(mine.ct));
    const msgKey = await subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: b64.to(envelope.iv) }, msgKey, b64.to(envelope.ct));
    return JSON.parse(dec.decode(pt));
  }
}

export async function encryptFile(buffer) {
  const raw = randomBytes(32);
  const key = await subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, buffer);
  return { data: ct, key: b64.from(raw), iv: b64.from(iv) };
}

export async function decryptFile(buffer, keyB64, ivB64) {
  const key = await subtle.importKey('raw', b64.to(keyB64), 'AES-GCM', false, ['decrypt']);
  return subtle.decrypt({ name: 'AES-GCM', iv: b64.to(ivB64) }, key, buffer);
}

// Güvenlik numarası: iki tarafın açık anahtarlarından türetilir. Yüz yüze
// karşılaştırıldığında araya giren biri (MITM) olmadığı doğrulanır.
export async function safetyNumber(a, b) {
  const part = async (u) => {
    const h = new Uint8Array(await subtle.digest('SHA-256', enc.encode(`${u.id}|${u.publicKey.x}|${u.publicKey.y}`)));
    let digits = '';
    for (let i = 0; i < 30; i += 5) {
      const n = ((h[i] * 2 ** 32) + (h[i + 1] << 24 >>> 0) + (h[i + 2] << 16) + (h[i + 3] << 8) + h[i + 4]) % 100000;
      digits += String(n).padStart(5, '0');
    }
    return digits;
  };
  const [pa, pb] = await Promise.all([part(a), part(b)]);
  const all = Number(a.id) < Number(b.id) ? pa + pb : pb + pa;
  return all.match(/.{5}/g).join(' ');
}
