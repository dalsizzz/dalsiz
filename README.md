# Dalsız — Kurum İçi Şifreli Mesajlaşma

Signal benzeri, **uçtan uca şifreli** (E2EE), kendi sunucunuzda çalışan bir ekip içi mesajlaşma uygulaması.
Tarayıcıdan ve telefondan (PWA olarak "Ana ekrana ekle") kullanılır.

## Özellikler

- 🔒 **Uçtan uca şifreleme** — mesajlar, fotoğraflar, videolar ve dosyalar cihazda şifrelenir; sunucu yalnızca şifreli veriyi görür
- 💬 Birebir ve **grup** sohbetleri (yönetici, üye ekleme/çıkarma, gruptan ayrılma)
- 📷 **Fotoğraf, video, ses ve dosya** gönderme (sürükle-bırak, yapıştır; 100 MB'a kadar)
- ✓✓ İletildi / okundu bilgisi, **yazıyor…** göstergesi, çevrimiçi durumu
- ⏱ **Kaybolan mesajlar** (30 sn – 4 hafta)
- 🔢 **Güvenlik numarası** ile karşı tarafın kimliğini doğrulama
- 🗑 Gönderilen mesajı herkes için silme
- 🔔 Masaüstü bildirimleri, karanlık mod, mobil uyumlu arayüz
- 🎟 **Davet kodu** ile kayıt — sadece ekibiniz katılabilir

## Kurulum

Gereksinim: **Node.js 22.13+** (yerleşik SQLite kullanılır, ayrıca veritabanı kurmaya gerek yok).

```bash
npm install
INVITE_CODE=sirketkodu npm start
```

Ardından `http://localhost:3000` adresini açın. Ekip arkadaşlarınıza adresi ve davet kodunu verin.

| Ortam değişkeni | Varsayılan | Açıklama |
|---|---|---|
| `PORT` | `3000` | Dinlenecek port |
| `INVITE_CODE` | _(boş)_ | Kayıt için gereken kod. **Boşsa herkes kayıt olabilir** |
| `DATA_DIR` | `./data` | Veritabanı ve şifreli dosyaların saklandığı klasör |
| `MAX_UPLOAD_MB` | `100` | En büyük dosya boyutu |

### Canlıya alma

Tarayıcılar Web Crypto ve bildirimleri yalnızca **HTTPS** (veya `localhost`) üzerinde çalıştırır. Sunucuyu
Nginx/Caddy gibi bir ters vekilin arkasına koyup HTTPS açın. Caddy örneği:

```
mesaj.sirketiniz.com {
    reverse_proxy localhost:3000
}
```

`data/` klasörünü düzenli yedekleyin.

## Güvenlik nasıl çalışıyor?

- Kayıt olurken cihazda bir **ECDH P-256** anahtar çifti üretilir. Açık anahtar sunucuya gönderilir.
- Gizli anahtar, parolanızdan (PBKDF2, 310.000 tur) türetilen anahtarla şifrelenip sunucuda yedeklenir;
  böylece başka bir cihazdan girdiğinizde parolanızla açılır. **Sunucu parolanızı hiç görmez** — kimlik
  doğrulama için farklı bir tuzla türetilmiş ayrı bir değer gönderilir ve sunucuda ayrıca scrypt ile saklanır.
- Her mesaj rastgele bir **AES-256-GCM** anahtarıyla şifrelenir. Bu anahtar, her alıcı için ECDH + HKDF ile
  türetilen ortak anahtarla ayrı ayrı sarılır.
- Dosyalar kendi rastgele anahtarıyla şifrelenip yüklenir; anahtar şifreli mesajın içinde taşınır.
- Güvenlik numarası iki tarafın açık anahtarlarından hesaplanır; yüz yüze karşılaştırarak araya kimsenin
  girmediğini doğrulayabilirsiniz.

**Bilinmesi gerekenler:** Bu uygulama Signal Protokolü'nün tamamını (Double Ratchet / ileri gizlilik) uygulamaz;
kimlik anahtarı ele geçirilirse geçmiş mesajlar çözülebilir. Parolanızı unutursanız mesaj geçmişi kurtarılamaz.
Sunucu kimin kiminle ne zaman konuştuğunu (üst veri) bilir.

## Geliştirme

```bash
npm test   # sunucuyu başlatıp kayıt, giriş, şifreli mesaj/dosya, grup ve yetki testlerini çalıştırır
```

Yapı:

```
server.js            HTTP API + WebSocket + SQLite
public/index.html    Arayüz
public/js/app.js     İstemci uygulaması
public/js/crypto.js  Uçtan uca şifreleme (Web Crypto)
public/css/style.css Stil
public/sw.js         PWA servis çalışanı
test/smoke.js        Uçtan uca test
```
