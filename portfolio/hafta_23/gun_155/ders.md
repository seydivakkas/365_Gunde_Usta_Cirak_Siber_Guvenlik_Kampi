# Gün 155: Web Uygulama Mimarisi ve Güven Sınırı (Trust Boundaries)

## Usta-Çırak / Hoca Dersi Notu

Hoş geldin evlat! Bugün sadece yeni bir güne değil, siber güvenlik yolculuğumuzun en kritik, en hareketli ve en çok saldırıya uğrayan dünyasına adım atıyoruz: **Aşama 7: Web Uygulama ve API Güvenliği (Hafta 23 - 26)**.

Aşama 6'da işletim sistemi çekirdeğini, EDR telemetrisini, TPM donanım kökünü ve Active Directory kimlik omurgasını çelik bir kaleye dönüştürdük. Ancak o kale içindeki hizmetleri dünyaya sunabilmek için bir pencere açmak zorundayız: **Web Uygulaması**. Ve unutma çırağım; saldırganların %80'i kurumun iç ağına doğrudan değil, internete açık bu web pencerelerinden sızar.

Bugünkü ilk konumuz tüm web güvenliğinin temel aksiyomudur: **Web Mimarisi ve Güven Sınırları (Trust Boundaries)**. Gel, istemci ile sunucu arasındaki görünmez sınırları ve HTTP protokolünün güvenlik anatomisini en ince ayrıntısına kadar inceleyelim.

---

### 1. Web Uygulamasının Çok Katmanlı Anatomisi (Multi-Tier Architecture)

Modern bir web mimarisi tek bir monolit blok değildir; birbirine ağ üzerinden bağlı 4 temel katmandan oluşur:

1. **Sunum Katmanı (Presentation Tier / Client):**
   * Kullanıcının web tarayıcısı (Chrome, Firefox, Safari) veya mobil uygulaması.
   * HTML5, CSS3, React, Vue, Angular gibi JavaScript çatılarından oluşur.
   * **ALTIN KURAL:** İstemci katmanı, saldırganın kendi bilgisayarıdır! DOM'u, JavaScript kodlarını, LocalStorage'ı, ağ isteklerini istediği gibi değiştirebilir, tersine mühendislik yapabilir ve durdurabilir.
2. **Uç / Ters Proxy Katmanı (Edge / Reverse Proxy / WAF):**
   * Cloudflare, AWS CloudFront, Nginx, Envoy veya F5 BIG-IP.
   * TLS 1.3 sonlandırma, HSTS zorlama, hız sınırlama (Rate Limiting), WAF kural filtreleme ve statik önbellekleme yapar.
3. **Uygulama Katmanı (Application Tier / Business Logic):**
   * Spring Boot, FastAPI, Node.js/Express, Django, ASP.NET Core.
   * İş mantığı, kimlik doğrulama oturumları, yetkilendirme kontrolleri ve veri işleme burada gerçekleşir.
4. **Veri Katmanı (Data Tier / Persistence):**
   * PostgreSQL, MySQL, MongoDB, Redis, Elasticsearch.
   * En hassas kurumsal verilerin, müşteri kayıtlarının ve parola hash'lerinin saklandığı en derin güvenli bölgedir.

---

### 2. Güven Sınırı (Trust Boundary) Nedir?

Bir sistemde farklı güvenlik seviyelerine veya yetki alanlarına sahip iki bileşenin karşılaştığı çizgiye **Güven Sınırı (Trust Boundary)** denir.

Web dünyasında en tehlikeli güven sınırı **İstemci (Client) ile Sunucu (Server)** arasındaki sınırdır:
* **Güvenilmeyen Bölge (Untrusted Zone):** İstemci tarafı. Kullanıcının gönderdiği her HTTP isteği, başlığı, çerezi, query parametresi ve JSON gövdesi **potansiyel olarak zehirlidir ve saldırgan tarafından manipüle edilmiştir**.
* **Güvenilir Bölge (Trusted Zone):** Sunucu tarafı. Ancak sunucu güvenilir bölge kalabilmek için güvenilmeyen bölgeden gelen her baytı sınır kapısında (Trust Boundary Gateway) acımasızca denetlemelidir.

#### Ölümcül İstemci Tarafı Güven Varsayımı (Client-Side Trust Fallacy):
Acemi yazılımcıların en büyük hatası, tarayıcıda yazdıkları JavaScript kontrollerine güvenmektir:
* *"Sepetteki fiyatı `<input type="hidden" value="100.00">` olarak koydum, kullanıcı değiştiremez."* -> Saldırgan Burp Suite ile araya girer ve `price: 0.01` yapar!
* *"Kullanıcı rolünü formda `role: user` gönderiyorum, admin yapamaz."* -> Saldırgan isteği yakalayıp `role: admin` yapar!
* *"HTML formunda `required minlength="8"` yazdım, geçersiz veri gelemez."* -> Saldırgan cURL veya Python ile doğrudan API'ye ham POST isteği atar!

**Ustanın İlkesi:** Fiyat, rol, bakiye, yetki ve güvenlik kararları **asla istemciden kabul edilemez**; daima sunucu tarafında doğrulanmalı ve veritabanından çekilmelidir.

---

### 3. HTTP Protokol Güvenliği ve Zorunlu Güvenlik Başlıkları (Security Headers)

HTTP/1.1 ve HTTP/2 metin tabanlı protokollerdir. Sunucunun istemciye döndüğü yanıt başlıkları (Response Headers), tarayıcının güvenlik davranışını doğrudan yönetir:

1. **Strict-Transport-Security (HSTS):**
   * `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
   * Tarayıcıya der ki: *"Bu alan adına sonraki 1 yıl boyunca ASLA şifresiz HTTP ile bağlanma! Kullanıcı adres çubuğuna `http://` yazsa bile sen kendin `https://` yap."* SSL Strip ve sahte Wi-Fi şifre çözme saldırılarını engeller.
2. **Content-Security-Policy (CSP):**
   * `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';`
   * Tarayıcının hangi kaynaklardan script, stil, görsel veya font yükleyebileceğini belirler. XSS (Cross-Site Scripting) ve veri sızdırmaya karşı en güçlü savunmadır. `'unsafe-inline'` kullanılmamalıdır.
3. **X-Frame-Options (Clickjacking Koruması):**
   * `X-Frame-Options: DENY` (veya `SAMEORIGIN`)
   * Sitenizin başka bir kötü niyetli web sitesi içinde `<iframe>` ile gömülmesini engeller; böylece kullanıcının görünmez butonlara tıklatılması önlenir.
4. **X-Content-Type-Options (MIME Sniffing Koruması):**
   * `X-Content-Type-Options: nosniff`
   * Tarayıcının sunucunun bildirdiği `Content-Type` başlığını ezmesini ve zararlı JavaScript içeren bir metin/resim dosyasını script gibi çalıştırmasını engeller.
5. **Referrer-Policy:**
   * `Referrer-Policy: strict-origin-when-cross-origin`
   * Bir bağlantıya tıklandığında hedef siteye URL'deki hassas parametrelerin (token, ID) sızmasını engeller.
6. **Permissions-Policy:**
   * `Permissions-Policy: camera=(), microphone=(), geolocation=()`
   * Web sayfasının donanım API'lerine (kamera, mikrofon, GPS) erişim yetkisini kısıtlar.

---

### 4. Çerez ve Oturum Güvenliği (Cookie & Session Hygiene)

Sunucu bir kullanıcının kimliğini hatırlamak için `Set-Cookie` başlığı kullanır. Bir oturum çerezi şu 3 altın bayrağa sahip değilse açık bir davetiyedir:

* **`Secure`:** Çerezin yalnızca TLS/HTTPS şifreli kanalı üzerinden iletilmesini zorunlu kılar. Düz metin HTTP bağlantılarında çerez ağa asla dökülmez.
* **`HttpOnly`:** Çereze JavaScript (`document.cookie`) üzerinden erişimi tamamen yasaklar. Sayfada bir XSS açığı olsa bile saldırgan oturum çerezini çalamaz!
* **`SameSite=Lax` veya `Strict`:** Çerezin üçüncü taraf sitelerden gelen isteklerle birlikte otomatik gönderilmesini engeller. Bu bayrak Siteler Arası İstek Sahteciliği (CSRF - Cross-Site Request Forgery) saldırısını tarayıcı seviyesinde felç eder.
* **Yüksek Entropi:** Oturum belirteçleri (Session Tokens) en az 128 bit kriptografik güvenli rastgelelik (`secrets.token_hex(16)`) içermelidir; sıralı veya tahmin edilebilir olmamalıdır.

---

### 5. Günün Özeti ve Usta Öğüdü

Evlat! Aşama 7 boyunca göreceğin SQL Injection, XSS, SSRF, IDOR gibi tüm ölümcül zafiyetlerin tek bir ortak kök nedeni vardır: **Güven sınırını ihlal etmek ve istemciden gelen veriye güvenmek.**
Eğer bir mimar olarak istemciyi "potansiyel bir saldırgan ortamı" olarak görür ve sunucuna giren her baytı bir kapı dedektöründen geçirirsen, saldırganların işini imkânsız kılarsın. Web güvenliğinin alfabesi budur!
