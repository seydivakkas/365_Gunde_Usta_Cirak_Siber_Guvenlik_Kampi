# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

# Gün 057: HTTP İstek ve Yanıt Yapısı — Soru, Cevap ve Senaryo Analizleri

Bu dokümanda, kurumsal web altyapılarında karşılaşılan HTTP protokol zafiyetleri, HTTP Request Smuggling desenkronizasyonu, CRLF Enjeksiyonu / Response Splitting ve OWASP Güvenlik Başlıkları sıkılaştırması derinlemesine incelenmektedir.

---

## Senaryo G057-SC1: HTTP Request Smuggling (CL.TE / TE.CL) Mekanizması ve Desenkronizasyon Savunması

### Soru / Senaryo
Yüksek trafikli bir e-ticaret platformunun önünde Nginx (Reverse Proxy / CDN) bulunmakta, arkasında ise Tomcat tabanlı bir arka-uç web sunucusu çalışmaktadır. Nginx ile Tomcat arasındaki TCP bağlantıları performans amacıyla sürekli açık (`Connection: keep-alive`) tutulmaktadır. Bir siber saldırgan, özel olarak kurguladığı bir HTTP POST isteği göndererek, arkasından gelen tamamen alakasız bir yöneticinin oturumunu ele geçirmeyi başarmıştır. Saldırgan bu isteğe hem `Content-Length` hem de `Transfer-Encoding: chunked` başlıklarını yerleştirmiştir. Bu HTTP Request Smuggling saldırısının çalışma mantığı nedir ve mimari seviyede nasıl engellenir?

### Ustanın Cevabı / Çözüm Yaklaşımı
Evladım, **HTTP Request Smuggling**, ön-uç (Front-end proxy) ile arka-uç (Back-end) sunucuların aynı TCP akışındaki HTTP mesaj sınırlarını (boundaries) farklı yorumlamasından kaynaklanan ölümcül bir desenkronizasyon zafiyetidir.

Senaryodaki CL.TE Mekanizması:
1. **Ön-Uç (Nginx) Yorumu:**
   Nginx, `Content-Length` başlığına bakar (ör. `Content-Length: 13`). Gelen isteğin gövdesinden tam 13 baytı okur ve bu isteği tek bir paket olarak arka-uç Tomcat sunucusuna iletir.
2. **Arka-Uç (Tomcat) Yorumu:**
   Tomcat ise `Transfer-Encoding: chunked` başlığına öncelik verir. `0\r\n\r\n` gördüğü anda ilk isteğin bittiğini varsayar. Ancak bu baytların arkasında kalan `SMUGGLED` metni Tomcat'in gelen TCP soket kuyruğunda sahipsiz baytlar olarak beklemeye başlar!
3. **Kurban İsteğinin Zehirlenmesi:**
   Birkaç milisaniye sonra meşru bir şirket yöneticisi `GET /admin/dashboard HTTP/1.1\r\nCookie: session=ADMIN_TOKEN` isteği gönderir. Tomcat, soket kuyruğunda bekleyen sahipsiz `SMUGGLED` baytlarını bu yöneticinin isteğinin başına yapıştırır:
   `SMUGGLEDGET /admin/dashboard HTTP/1.1...`
   Sonuçta saldırgan yöneticinin oturum token'ını ele geçirebilir, yönlendirmeleri manipüle edebilir veya sahte içerik servis edebilir.

Çözüm:
1. **RFC 7230 §3.3.3 Sıkı Uyumu:** Ön-uç ve arka-uç sunucular, aynı istekte hem `Content-Length` hem de `Transfer-Encoding` başlığı gördüğü anda isteği hiçbir sunucuya iletmeden **derhal `400 Bad Request` ile reddetmelidir**.
2. **HTTP/2 Uçtan Uca Geçişi:** HTTP/2 ikili (binary framing) protokol yapısına sahip olduğu için metin tabanlı sınır belirsizlikleri ortadan kalkar.
3. **Bağlantı İzolasyonu:** Ön-uç ile arka-uç arasındaki TCP bağlantılarının farklı kullanıcı istekleri arasında ortak kullanılmasını (connection reuse) sınırlamak veya her hassas istek için yeni soket açmak riski düşürür.

### Kritik Güvenlik Çıkarımı
HTTP Request Smuggling, kod seviyesindeki bir SQLi veya XSS değildir; doğrudan altyapı protokol ayrıştırıcılarının (parsers) standartları farklı yorumlamasından doğan bir mimari zafiyettir. WAF cihazları tek başına yeterli olamaz; ters vekil sunucu ile arka-uç sunucu kesin olarak aynı HTTP sınır kurallarıyla yapılandırılmalıdır.

### Savunma / Uygulama Kontrol Listesi
- [ ] Ters vekil sunucuda çift uzunluk başlığı içeren istekleri engelleyin (`proxy_set_header Transfer-Encoding ""` veya katı RFC uyumu).
- [ ] Ön-uç ve arka-uç sunucu yazılımlarını (Nginx, Apache, Tomcat, HAProxy) en güncel sürümlerine yükseltin (HTTP Smuggling yamaları).
- [ ] Ön-uç ile arka-uç arasında mümkünse HTTP/2 tünellemesi kullanın.
- [ ] Uygulama katmanında `Transfer-Encoding` içeren istekleri WAF seviyesinde inceleyin ve `chunked` dışındaki garip kodlamaları (`chunked, identity` vb.) engelleyin.
- [ ] Ters vekil sunucuda şüpheli istek sınır hatalarını (`HTTP 400`, `client intended to send too large body`) SIEM alarmlarına bağlayın.

---

## Senaryo G057-SC2: CRLF Injection ile HTTP Response Splitting ve XSS Zincirleme Saldırısı

### Soru / Senaryo
Bir bankacılık uygulamasında kullanıcı giriş yaptıktan sonra geldiği sayfaya geri yönlendirilmektedir. Yönlendirme kodu şu şekildedir:
`HTTP/1.1 302 Found\r\nLocation: /dashboard?user_input=[PARAM]\r\n...`
Bir siber güvenlik uzmanı, parametre alanına şu girdiyi yollamıştır:
`test%0d%0aSet-Cookie:%20admin_override=true;%20Path=/%0d%0a%0d%0a<html><script>alert(document.cookie)</script></html>`
Tarayıcı bu yanıtı aldığında sahte bir çerez kaydetmiş ve ekranda XSS penceresi açmıştır. Bu saldırı zinciri (CRLF Enjeksiyonu -> Yanıt Bölme -> XSS) nasıl çalışmıştır ve sunucu seviyesinde nasıl çözülür?

### Ustanın Cevabı / Çözüm Yaklaşımı
Evladım, **CRLF Enjeksiyonu**, adını HTTP protokolünün satır sonu göstergesi olan `Carriage Return` (`\r` - `%0D`) ve `Line Feed` (`\n` - `%0A`) karakterlerinden alır.

Saldırının Aşamaları:
1. **Başlık Manipülasyonu (Header Injection):**
   Geliştirici kullanıcı girdisini doğrulamadan ve temizlemeden doğrudan HTTP yanıt başlığına (`Location`) yazmıştır. Girdideki ilk `%0d%0a`, ayrıştırıcı tarafından başlığın bittiği ve yeni bir başlığın başladığı şeklinde yorumlanmıştır. Böylece `Set-Cookie: admin_override=true` başlığı meşru bir sunucu başlığı gibi yanıtın içine sızmıştır.
2. **Yanıt Bölme (HTTP Response Splitting):**
   Girdideki ikinci ardışık `%0d%0a%0d%0a` (çift CRLF), HTTP standardına göre "Tüm başlıklar bitti, artık gövde (body) başlıyor!" demektir. Ayrıştırıcı başlık bloğunu kapatmış ve saldırganın enjekte ettiği `<html><script>...` metnini sayfanın gövdesi olarak tarayıcıya çizdirmiştir.
3. **Zehirli Önbellek (Cache Poisoning):**
   Eğer aradaki bir vekil sunucu (Proxy/CDN) bu bölünmüş iki yanıtı ayrı mesajlar gibi algılarsa, ikinci sahte yanıtı önbelleğe alır ve sonraki tüm meşru kullanıcılar saldırganın HTML/JS kodunu görüntüler!

Çözüm:
1. **Girdi Doğrulama ve Karakter Temizleme (Sanitization):** HTTP başlıklarına yazılacak hiçbir kullanıcı verisinde `\r` (`0x0D`) ve `\n` (`0x0A`) karakterlerine izin verilmemelidir. Bu karakterler tespit edildiği anda istek ya `400 Bad Request` ile reddedilmeli ya da karakterler tamamen silinmelidir.
2. **Güvenli API Kullanımı:** Modern web çatılarının (Django, Flask, Spring, Express) yerleşik yönlendirme kütüphaneleri (ör. `response.redirect()`) CRLF karakterlerini otomatik kontrol eder; ham string birleştirme (`f"Location: {url}"`) yapılmamalıdır.

### Kritik Güvenlik Çıkarımı
HTTP protokolünde veri ile kontrol sinyali (başlık ayırıcılar) aynı ASCII kanalı üzerinden iletilir (In-band signaling). Kontrol karakterleri olan CRLF'in kullanıcı verisinden izole edilmemesi, protokolün mantıksal sınırlarının çökmesine ve XSS'ten Cache Poisoning'e kadar uzanan bir yıkım zincirine sebep olur.

### Savunma / Uygulama Kontrol Listesi
- [ ] Tüm kullanıcı parametrelerini HTTP başlıklarına (Location, Set-Cookie vb.) basmadan önce `\r` ve `\n` karakterlerine karşı kesin olarak regex ile denetleyin (`r"[\r\n]"`).
- [ ] Web sunucusu yapılandırmasında başlık katlama (header folding - RFC 7230 §3.2.4 tarafından yasaklanmıştır) özelliklerini kapatın.
- [ ] Yönlendirme fonksiyonlarında yalnızca beyaz listedeki güvenli URL ve yollara izin verin (Open Redirect engeli).
- [ ] Uygulama yanıtlarında `Content-Type: text/html; charset=UTF-8` gibi açık MIME türü belirterek tarayıcının yanıtı yanlış yorumlamasını zorlaştırın.

---

## Senaryo G057-SC3: OWASP Güvenlik Başlıkları ile Katmanlı Web Savunması (HSTS, CSP, X-Frame-Options)

### Soru / Senaryo
Bir siber güvenlik denetiminde, bir kamu kurumunun internet bankacılığı portalında hiçbir kod zafiyeti (SQLi, IDOR vb.) bulunamamıştır. Ancak denetim raporunda sistem "YÜKSEK RİSKLİ" olarak derecelendirilmiştir. Gerekçe olarak HTTP yanıtlarında `Strict-Transport-Security`, `Content-Security-Policy` ve `X-Frame-Options` başlıklarının tamamen eksik olduğu, buna karşılık `Server: Microsoft-IIS/10.0` ve `X-Powered-By: ASP.NET` başlıklarının açıkça yayınlandığı belirtilmiştir. Geliştiriciler *"Sayfamızda açık yok, bu başlıklar sadece formalitedir"* diyerek rapora itiraz etmiştir. Bu başlıkların eksikliği hangi somut saldırılara yol açar ve geliştiricilere nasıl savunulmalıdır?

### Ustanın Cevabı / Çözüm Yaklaşımı
Evladım, *"Uygulamamda açık yok, güvenlik başlığına gerek yok"* diyen bir geliştirici, *"Evimde yangın çıkmaz, o yüzden yangın kapısına ve duman dedektörüne gerek yok"* diyen adama benzer! Güvenlik başlıkları, uygulamanın dışındaki tarayıcı ortamında çalışan **Savunma Derinliği (Defense-in-Depth)** kalkanlarıdır.

Somut Saldırı Senaryoları:
1. **HSTS Eksikliği -> SSL Stripping (MitM):**
   Kullanıcı kafede ortak Wi-Fi'a bağlandığında adres çubuğuna sadece `banka.com` yazar. İlk istek şifresiz HTTP ile çıkar. Saldırgan araya girerek (`bettercap` / `sslstrip`) HTTPS yönlendirmesini yutar ve kullanıcıyla şifresiz konuşurken bankayla HTTPS konuşur. Kullanıcının tüm şifreleri açık metin akar. `Strict-Transport-Security` olsaydı, tarayıcı daha kablodan çıkmadan isteği HTTPS'e çevirirdi!
2. **CSP Eksikliği -> Sıfırıncı Gün (0-Day) XSS ve Veri Kaçırma:**
   Yarın sitede kullanılan üçüncü parti bir JavaScript kütüphanesinde (ör. analiz aracı) bir açık çıkarsa; saldırgan sayfaya zararlı script enjekte ettiğinde `Content-Security-Policy` yoksa script çalışır ve kullanıcının form verilerini saldırganın sunucusuna postalar. CSP olsaydı, dışarıya veri çıkışı tarayıcı tarafından anında bloke edilirdi.
3. **X-Frame-Options Eksikliği -> Clickjacking:**
   Saldırgan sahte bir oyun sitesi açar. Arka plana şeffaf bir `<iframe>` içinde bankanın havale onay sayfasını koyar. Kullanıcı oyundaki "Ödülü Al" butonuna bastığını sanırken aslında bankadaki "Parayı Gönder" butonuna tıklar.
4. **Server Banner Sızıntısı:**
   `Server: Microsoft-IIS/10.0` ve `ASP.NET` afişleri, saldırgana doğrudan hangi exploit kodlarını denemesi gerektiğini fısıldar (Keşif kolaylığı).

### Kritik Güvenlik Çıkarımı
Uygulama kodu ne kadar temiz olursa olsun, istemci tarafındaki tarayıcıyı kontrol edemezsiniz. OWASP Güvenlik Başlıkları, sunucunun tarayıcıya verdiği katı güvenlik talimatlarıdır. Bu başlıklar olmadan modern bir web uygulamasının güvenliğinden bahsedilemez.

### Savunma / Uygulama Kontrol Listesi
- [ ] `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` başlığını tüm HTTPS yanıtlarına ekleyin.
- [ ] `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';` kuralını devreye alın.
- [ ] `X-Frame-Options: DENY` başlığı ile sayfaların çerçevelenmesini tamamen kapatın.
- [ ] `X-Content-Type-Options: nosniff` ekleyerek MIME karmaşasını önleyin.
- [ ] `Referrer-Policy: strict-origin-when-cross-origin` ile URL sızıntılarını sınırlandırın.
- [ ] Web sunucu ayarlarından (IIS, Nginx, Apache) `ServerTokens Prod` veya `Server: ""` yaparak sunucu ve teknoloji afişlerini kaldırın.
