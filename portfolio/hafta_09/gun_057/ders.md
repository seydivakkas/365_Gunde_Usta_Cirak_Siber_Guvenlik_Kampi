# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

# Gün 057: HTTP İstek ve Yanıt Yapısı — Protokol Sözdizimi, Semantik ve Web Güvenliği

## Usta-Çırak Başlangıç Hasbihali
Evladım, hoş geldin Hafta 09'a! Artık ağın fiziksel, veri bağı ve taşıma katmanlarını (TCP/UDP) geride bırakıp, siber güvenlik dünyasında en çok saldırı alan, en çok açık barındıran zirveye çıkıyoruz: **Uygulama Katmanı ve Web Güvenliği (HTTP)**.

Dünyadaki web trafiğinin neredeyse tamamı, Tim Berners-Lee'nin 1989'da basit bir metin paylaşım protokolü olarak tasarladığı, ardından RFC 7230 ve RFC 7231 ile standartlaştırılan **HTTP (Hypertext Transfer Protocol)** üzerinde akar. Dışarıdan baktığında HTTP sadece düz bir metin (ASCII) akışıdır. Fakat güvenlik gözlüğüyle baktığında, tek bir satır başı karakterinin (`\r\n` / CRLF) bile koskoca bir web uygulamasını nasıl çökertebileceğini, oturum çerezlerini nasıl çaldırabileceğini veya ön-uç (proxy) ile arka-uç sunucularını birbirine düşürüp **HTTP Request Smuggling** ile diğer kullanıcıların şifrelerini nasıl ele geçirebileceğini görürsün. Bugün seninle HTTP/1.1'in anatomisini, metot semantiğini, durum kodlarını ve sunucuları birer kaleye dönüştüren **OWASP Güvenlik Başlıklarını** santim santim işleyeceğiz.

---

## 1. HTTP/1.1 Mesaj Anatomisi ve Tel Formatı (Wire Format)

HTTP, istemci-sunucu modeline dayalı, durumsuz (stateless) bir metin protokolüdür. İster bir resim isteği olsun ister devasa bir API çağrısı; mesaj yapısı istisnasız 4 ana parçadan oluşur:

### A. İstek Mesajı Anatomisi (HTTP Request)
```http
GET /api/v1/users?role=analyst HTTP/1.1\r\n   <--- [1. İstek Satırı: Metot + Yol + Sürüm]
Host: api.kurum.local\r\n                     <--- [2. Başlıklar: Header-Name: Value]
User-Agent: Mozilla/5.0...\r\n
Accept: application/json\r\n
Content-Length: 0\r\n
\r\n                                          <--- [3. Boş Satır (CRLF CRLF Sınır İşareti)]
                                              <--- [4. Mesaj Gövdesi (Body)]
```

1. **İstek Satırı (Request-Line):**
   - **Metot:** Sunucuya ne yapılacağını söyler (`GET`, `POST`, `PUT`, `DELETE` vb.).
   - **İstek Yolu (Request-URI):** Sunucuda hedeflenen kaynak veya API uç noktası (`/index.html`, `/api/v1/auth`).
   - **HTTP Sürümü:** Protokol kurallarını belirler (`HTTP/1.0`, `HTTP/1.1`, `HTTP/2`).
2. **Başlıklar (Headers):**
   `İsim: Değer` formatında metadata taşır. Büyük-küçük harfe duyarsızdır (`Content-Type` == `content-type`).
   - **RFC 7230 §5.4 Kuralı:** HTTP/1.1 isteklerinde `Host` başlığı **ZORUNLUDUR**. Tek bir IP üzerinde yüzlerce sanal web sitesi (Virtual Hosting) çalıştığı için sunucu isteğin hangi alan adına geldiğini `Host` başlığıyla anlar. `Host` başlığı yoksa sunucu derhal `400 Bad Request` dönmelidir!
3. **Boş Satır (Empty Line - CRLF):**
   `\r\n` baytlarından oluşur. Ayrıştırıcıya (parser) başlıkların bittiğini ve bundan sonra gelen baytların gövdeye (payload) ait olduğunu bildirir.
4. **Mesaj Gövdesi (Message Body):**
   POST, PUT gibi metotlarda sunucuya iletilen JSON, XML, form veya ikili dosya verisidir. Boyutu `Content-Length` veya `Transfer-Encoding: chunked` ile bildirilir.

### B. Yanıt Mesajı Anatomisi (HTTP Response)
```http
HTTP/1.1 200 OK\r\n                           <--- [1. Durum Satırı: Sürüm + Kod + İfade]
Date: Thu, 29 Oct 2026 19:30:00 GMT\r\n        <--- [2. Yanıt Başlıkları]
Content-Type: application/json\r\n
Strict-Transport-Security: max-age=31536000\r\n
Content-Length: 27\r\n
\r\n                                          <--- [3. Boş Satır]
{"status": "authenticated"}                   <--- [4. Yanıt Gövdesi]
```

---

## 2. HTTP Metot Semantiği: Güvenli ve Eşgüçlü İlkeler (RFC 7231)

Güvenlik mimarları için metotların teorik özellikleri hayati önem taşır:

| Metot | Güvenli (Safe)? | Eşgüçlü (Idempotent)? | Açıklama ve Güvenlik Riski |
|---|---|---|---|
| **GET** | **EVET** | **EVET** | Yalnızca veri okur, sunucuda kalıcı durum değişikliği yapmaz. Hassas veriler asla URL parametresinde taşınmamalıdır (Access Log sızıntısı!). |
| **HEAD** | **EVET** | **EVET** | GET ile aynıdır fakat gövde dönmez; yalnızca başlıkları kontrol eder. |
| **POST** | **HAYIR** | **HAYIR** | Sunucuda yeni kaynak yaratır veya işlem yürütür. Tekrarlanması mükerrer kayıtlara yol açar. CSRF ve Replay saldırılarına açıktır. |
| **PUT** | **HAYIR** | **EVET** | Belirtilen URI'deki kaynağı tamamen yenisiyle değiştirir. 10 kere de çalışsa sonuç aynı kalır. |
| **DELETE**| **HAYIR** | **EVET** | Belirtilen kaynağı siler. İlk çağrıda silinir, sonrakilerde kaynak zaten yoktur (aynı durum korunur). |
| **OPTIONS**| **EVET** | **EVET** | Sunucunun desteklediği metotları döner (CORS Preflight). |
| **TRACE** | **EVET** | **EVET** | Sunucunun aldığı isteği aynen geri yankılamasıdır. **Aşırı Tehlikelidir!** Siteler arası izleme (XST - Cross-Site Tracing) ile tarayıcının koruduğu `HttpOnly` oturum çerezlerini çaldırır. Üretim ortamında kesinlikle kapatılmalıdır! |

---

## 3. Durum Kodları Taksonomisi (1xx - 5xx)

- **1xx (Bilgilendirme):** `101 Switching Protocols` (WebSocket geçişi).
- **2xx (Başarı):**
  - `200 OK`: İstek başarıyla karşılandı.
  - `201 Created`: POST ile yeni kaynak üretildi (`Location` başlığında URL verilir).
  - `204 No Content`: İşlem başarılı fakat istemciye dönecek gövde yok (ör. DELETE sonrası).
- **3xx (Yönlendirme):**
  - `301 Moved Permanently`: Kaynak kalıcı olarak taşındı. Tarayıcılar bu yönlendirmeyi önbelleğe (cache) alır. HTTP -> HTTPS geçişinde kullanılır.
  - `302 Found`: Geçici yönlendirme.
  - `304 Not Modified`: İstemcinin önbelleğindeki kopya hâlâ güncel (`ETag` / `If-None-Match`).
- **4xx (İstemci Hatası):**
  - `400 Bad Request`: Sözdizimi hatası, eksik Host başlığı, CRLF hatası.
  - `401 Unauthorized`: Kimlik doğrulama yapılmamış (Giriş yapılmalı).
  - `403 Forbidden`: Kimlik doğrulanmış fakat yetki yetersiz (Erişim engellendi).
  - `404 Not Found`: İstenen URI sunucuda mevcut değil.
  - `405 Method Not Allowed`: Kaynak bu metoda kapalı (ör. statik dosyaya POST atılması).
- **5xx (Sunucu Hatası):**
  - `500 Internal Server Error`: Kod patladı, işlenmemiş istisna (Ayrıntılı hata sayfası saldırgana bilgi sızdırabilir!).
  - `502 Bad Gateway`: Ön-uç ters vekil sunucu (Reverse Proxy) arka-uç sunucuya erişemedi.
  - `503 Service Unavailable`: Aşırı yük, bakım veya DoS saldırısı altındaki sunucu.

---

## 4. Web Sıkılaştırma: OWASP Güvenlik Başlıkları Zırhı

Bir web uygulamasının güvenlik olgunluğu, yanıt başlıklarından (Response Headers) 1 saniyede anlaşılır:

1. **`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` (HSTS):**
   Tarayıcıya der ki: *"Bu alan adına bundan sonra en az 1 yıl boyunca ASLA şifresiz HTTP ile bağlanma, doğrudan HTTPS'e yükselt!"* Bu başlık SSL Stripping saldırılarını kökünden engeller.
2. **`Content-Security-Policy: default-src 'self'` (CSP):**
   Tarayıcının sayfada hangi JavaScript, CSS, görsel ve betiklerin çalışabileceğini belirleyen katı beyaz listedir. Siteler Arası Betik Çalıştırma (XSS) saldırılarını ve veri sızıntılarını engeller.
3. **`X-Frame-Options: DENY` veya `SAMEORIGIN`:**
   Sayfanın başka bir web sitesi tarafından `<iframe>` içine gömülmesini engeller. Bu sayede kullanıcının görünmez butonlara tıklatıldığı **Clickjacking (Tıklama Sahteciliği)** saldırıları imkansız hale gelir.
4. **`X-Content-Type-Options: nosniff`:**
   Tarayıcının MIME türü tahmin etmesini (MIME Sniffing) engeller. Bir saldırganın resim dosyası (`avatar.png`) içine gizlediği zararlı JavaScript kodunun tarayıcı tarafından çalıştırılmasını önler.
5. **`Referrer-Policy: strict-origin-when-cross-origin`:**
   Kullanıcı siteden dışarıdaki bir bağlantıya tıkladığında, URL içerisindeki hassas oturum belirteçlerinin ve özel parametrelerin dış sunucuya sızmasını engeller.
6. **Sunucu Afiş Bilgisi Gizleme (Server Banner Suppression):**
   `Server: Apache/2.4.41 (Ubuntu)` ve `X-Powered-By: PHP/7.4.3` başlıkları kaldırılmalı veya genel bir ifadeye dönüştürülmelidir (`Server: WebServer`). Saldırganın sürüm hedefli hazır exploit (CVE) aramasını zorlaştırır.

---

## 5. Kritik HTTP Güvenlik Açıkları

### A. CRLF Enjeksiyonu ve HTTP Response Splitting
Saldırgan kullanıcı girdisine URL kodlu `%0d%0a` (`\r\n`) ekleyerek HTTP başlık ayrıştırıcısını kandırır. Sunucu bu girdiyi bir başlığa yazarsa (örneğin yönlendirme sayfasında `Location: /login?next=...`), saldırgan araya fazladan bir başlık (`Set-Cookie: session=attacker_cookie`) veya çift CRLF ile sahte bir HTML gövdesi (XSS) enjekte eder!

### B. HTTP Request Smuggling (CL.TE / TE.CL)
Ön-uç vekil sunucu (Front-end proxy) ile arka-uç web sunucusu (Back-end) aynı HTTP isteğini farklı yorumlarsa ortaya çıkar. Biri `Content-Length` başlığını esas alırken, diğeri `Transfer-Encoding: chunked` başlığına öncelik verirse; saldırgan arka-uçta bekleyen diğer kullanıcıların isteklerinin önüne kendi yetkisiz isteklerini yapıştırır (smuggle eder)!
- **Çözüm (RFC 7230 §3.3.3):** Bir istekte hem `Content-Length` hem de `Transfer-Encoding` varsa, sunucu bu isteği **derhal reddetmeli (400 Bad Request)** ve asla kuyruğa almamalıdır!

---

## Ustanın Öğüdü
Evladım; web güvenliği karmaşık WAF cihazlarından önce, uygulamanın HTTP standartlarını ne kadar ciddiye aldığıyla belirlenir. RFC standartlarına harfiyen uymayan, gelen girdideki bir `\r\n` karakterini doğrulamayan veya tek bir satırlık `Content-Security-Policy` başlığını eklemeyen bir geliştirici, dünyanın en pahalı güvenlik duvarını arkasına koysa bile hacklenmeye mahkumdur!
