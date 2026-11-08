# Gün 161: Mini Proje 22 - Kurumsal Güvenli Form Arayüzü Mimarisi

## Usta-Çırak Başlangıç Hasbihali
**Usta:** Evlat, bu hafta boyunca web güvenliğinin temel yapı taşlarını tek tek döşedik: HTTP çerez bayrakları, oturum yaşam döngüsü, girdi doğrulama, bağlamsal çıktı kodlama ve XSS savunması. Bugün Aşama 7'nin (Hafta 23) taçlandırma günü: **Mini Proje 22: Güvenli Form Arayüzü**. Bir web formunu sadece `<form>` ve `<input>` etiketlerinden ibaret sanan bir geliştirici, bankanın kasasını açık unutan bir veznedara benzer.

**Çırak:** Ustam, bir form arayüzünde sadece "Kaydet" veya "Gönder" butonuna basıldığında arka planda tam olarak ne tür fırtınalar kopuyor?

**Usta:** İşte gerçek bir güvenlik mimarı bu fırtınayı yöneten kişidir evlat. İstek daha sunucu kapısına geldiğinde şunlar yaşanır:
1. **İstemci Hızı:** Saldırgan dakikada yüzlerce form gönderip sistemi kilitliyor mu? (Rate Limiting).
2. **Köken Güvenliği:** Bu istek gerçekten bizim uygulamamızın alan adından mı geldi, yoksa saldırganın kötü niyetli sitesinden arka planda mı tetiklendi? (Origin / Referer Denetimi).
3. **CSRF Koruması:** Kullanıcı bu formu bizzat kendi isteğiyle mi doldurdu, yoksa tarayıcı oturumu istismar mı edildi? (HMAC-SHA256 Token Doğrulaması).
4. **Veri Bütünlüğü ve Enjeksiyon:** Kullanıcı adı veya e-posta alanlarına SQLi ya da XSS yükleri sıkıştırılmış mı? (Katı Doğrulama ve Arındırma).
5. **İstemci Güvenliği:** Tarayıcıya dönen yanıtta form verisi ekrana basılırken XSS oluşabilir mi, yetkisiz betikler çalıştırılabilir mi? (CSP Seviye 3 ve HTML Kaçışı).

Bugün bu 5 katmanı birleştiren, endüstri standardı bir kurumsal form arayüzü inşa edeceğiz.

---

## 1. Güvenli Form Arayüzünün 5 Savunma Katmanı

```
[İstemci Tarayıcısı] 
       |
       |  POST /api/v1/transfer
       v
+-----------------------------------------------------------------------------+
| Katman 1: İstek Hız Sınırlaması (Rate Limiting - Sliding Window)            |
|   -> IP ve Oturum bazında dakikada azami 5 istek (HTTP 429 Too Many Req)    |
+-----------------------------------------------------------------------------+
       v
+-----------------------------------------------------------------------------+
| Katman 2: Köken (Origin) ve Çapraz İstek Denetimi                           |
|   -> Origin == 'https://banka.kurum.internal' (HTTP 403 Forbidden)          |
+-----------------------------------------------------------------------------+
       v
+-----------------------------------------------------------------------------+
| Katman 3: Kriptografik CSRF Token Doğrulaması (HMAC-SHA256 + TTL + Nonce)   |
|   -> session_id : timestamp : nonce : signature (HTTP 403 Forbidden)       |
+-----------------------------------------------------------------------------+
       v
+-----------------------------------------------------------------------------+
| Katman 4: Katı Şema Doğrulama, Entropi ve Enjeksiyon Taraması               |
|   -> Regex + RFC 5322 + Shannon Entropi (>=3.0 bit) + SQLi/XSS Engeli      |
+-----------------------------------------------------------------------------+
       v
+-----------------------------------------------------------------------------+
| Katman 5: Güvenli Çerez ve CSP Seviye 3 Başlık Mimarisi                     |
|   -> __Host- prefix, SameSite=Strict, HttpOnly, CSP script-src 'nonce-...'  |
+-----------------------------------------------------------------------------+
       v
[Güvenli ve Arındırılmış İşlem Onayı - HTTP 200 OK]
```

---

## 2. Derinlemesine Teknik Bileşenler

### 2.1 Kriptografik CSRF Savunması (Synchronizer Token Pattern & HMAC)
Klasik zayıf uygulamalar CSRF tokenını oturum tablosunda düz metin olarak saklar veya tahmin edilebilir bir MD5 özetine güvenir. Modern kurumsal yaklaşımda:
- **Token Yapısı:** `session_id:timestamp:nonce:signature`
- **İmzalama:** `HMAC-SHA256(server_secret, session_id:timestamp:nonce)`
- **Zaman Damgası (TTL):** Token 30 dakika (1800 saniye) sonra kendiliğinden geçersiz hale gelir.
- **Tek Kullanımlık Nonce (Single-Use Nonce):** Kullanılan her token sunucu tarafındaki bellekte işaretlenir; aynı token ile ikinci kez istek gönderilirse (Replay Attack) istek derhal reddedilir.
- **Sabit Zamanlı Karşılaştırma:** İmza doğrulaması `hmac.compare_digest()` ile yapılarak zamanlama saldırıları (Timing Attacks) engellenir.

### 2.2 Katı Alan Doğrulama ve Shannon Entropi Kontrolü
- **Kullanıcı Adı:** `^[a-zA-Z0-9_]{3,32}$`. Ek olarak `SELECT`, `UNION`, `<script>`, `onerror` gibi SQLi ve XSS kalıpları regex öncesinde öncelikli taranarak doğrudan engellenir.
- **E-posta:** RFC 5322 uyumlu format denetimi, azami 254 karakter sınırı.
- **Parola Gücü ve Entropi:** Yalnızca büyük/küçük harf kontrolü yetmez; `P@ssword1` gibi kalıplar kolayca kırılır. Form motorumuz parolanın Shannon Bilgi Entropisini hesaplar:
  \[
  H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)
  \]
  Entropisi 3.0 bit/karakter eşiğinin altında kalan tahmin edilebilir parolalar reddedilir.
- **Finansal Tutar:** 0.01 ile 100.000,00 TL arasındaki sınırlar, sayısal tip kontrolü, negatif değer engellemesi.
- **Açıklama (Comment):** Serbest metin alanı `html.escape(quote=True)` ile HTML gövde kaçışına tabi tutulur.

### 2.3 İstek Sınırlandırma (Rate Limiting)
Kaba kuvvet (brute-force) ve hizmet engelleme (DoS) saldırılarına karşı her istemci IP adresi için kayan zaman penceresi (sliding window) mekanizması işletilir. 60 saniyelik pencerede 5'ten fazla gönderim yapan istemciye `HTTP 429 Too Many Requests` yanıtı dönülür.

### 2.4 İstemci Güvenlik Başlıkları
Form sayfasını render ederken sunucu şu HTTP başlıklarını basar:
- `Content-Security-Policy: default-src 'self'; script-src 'nonce-{RANDOM}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; require-trusted-types-for 'script';`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Set-Cookie: __Host-SessionID=...; Secure; HttpOnly; SameSite=Strict; Path=/`

---

## Usta Öğüdü ve Altın Kurallar
1. **"Formu Çizen ile Formu İşleyen Aynı Güvenlik Sözleşmesini Paylaşmalıdır":** İstemci tarafında HTML5 `required` veya JavaScript `validateForm()` olması sadece kullanıcı deneyimi (UX) içindir, güvenlik değildir. Saldırgan cURL veya Python ile doğrudan POST isteği atar. Güvenlik daima sunucu tarafında uygulanır.
2. **"Çapraz Kökenleri (Origin) Daima Sorgula":** `SameSite=Strict` çerezleri CSRF'i büyük ölçüde önler; ancak intranet ağlarında veya eski tarayıcılarda `Origin` ve `Referer` başlık kontrolü zorunlu bir ek güvencedir.
3. **"Replay Saldırılarına Karşı Nonce Tüketimi Şarttır":** Bir CSRF tokenı bir kez başarılı bir işlem için kullanıldığında (ör. 10.000 TL transfer), o token derhal emekliye ayrılmalıdır.
