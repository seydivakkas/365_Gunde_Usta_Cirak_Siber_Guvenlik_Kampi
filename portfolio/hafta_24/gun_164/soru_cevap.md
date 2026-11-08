# Gün 164: CSRF ve Oturum Bağlamı — Mülakat ve Teknik Soru-Cevap Rehberi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

### Soru:
1. Tarayıcıların "Ortam Yetkisi (Ambient Authority)" mekanizması nedir ve Siteler Arası İstek Sahteciliği (CSRF / CWE-352) saldırısının ortaya çıkmasındaki kök rolü nasıl işler?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın CSRF'i yalnızca "kullanıcı adına sahte istek gönderilmesi" şeklinde ezbere tanımlamak yerine, web tarayıcılarının köklü mimari tasarımındaki **ambient authority** kavramını açıklayabilmesini bekliyorum. Adaydan; bir HTTP isteği başlatıldığında tarayıcının o alan adına ait tanımlı oturum çerezlerini (cookies) istek kaynağının meşru olup olmadığını sorgulamadan otomatik olarak eklemesini ve sunucunun gelen çerezi görünce isteği kullanıcının iradesiyle yapılmış saymasını teknik olarak anlatmasını istiyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
Ortam Yetkisi (Ambient Authority), bir sistemin veya istemcinin sahip olduğu kimlik ve yetkilendirme bilgilerini (örneğin oturum çerezlerini), işlemin bağlamından ve kullanıcının gerçek iradesinden bağımsız olarak her ilgili isteğe otomatik olarak iliştirmesidir. Web tarayıcıları, bir etki alanına giden her HTTP isteğine o etki alanına ait çerezleri otomatik olarak ekler. Saldırgan kendi zararlı sitesinden (`evil.com`) arka planda kurbanın bankasına (`banka.internal`) bir POST formu gönderdiğinde, tarayıcı kurbanın oturum çerezini bu isteğe otomatik olarak dahil eder. Sunucu isteği karşıladığında geçerli bir oturum çerezi gördüğü için işlemi kurbanın isteği kabul eder; bu durum CSRF zafiyetinin temel kök nedenidir.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
Ambient authority probleminin temelinde, **kimlik bilgisi (çerez) ile işlem bağlamının (istek niyeti) ayrışması** yatar. Yetkilendirme modeli "ortamdan otomatik çekilen" yapıda kaldığı sürece CSRF riski sürer.
Bu sorunun çözümü, yetkilendirmeyi ortamdan bağımsız hale getirmek, yani **Açık Yetkilendirme (Explicit Capability / Synchronizer Token)** modeline geçmektir. Anti-CSRF belirteci (STP), tarayıcının otomatik ekleyemeyeceği, yalnızca meşru web sayfasının JavaScript veya HTML içeriğinde bulunan ve kullanıcının açıkça gönderdiği bir parametredir. Saldırgan Same-Origin Policy nedeniyle bu belirteci üçüncü taraf siteden okuyamaz; böylece istekten ambient authority soyutlanmış olur.

---

### Soru:
2. Modern tarayıcılarda `SameSite=Lax` çerez özniteliği varsayılan hale gelmişken, bir web uygulamasında hala CSRF zafiyeti oluşabilir mi? Hangi senaryolarda `SameSite=Lax` koruması yetersiz kalır?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın güncel tarayıcı güvenlik gelişmelerini takip edip etmediğini ve "SameSite geldi, artık CSRF tamamen bitti" yanılgısına düşüp düşmediğini sınıyorum. Adaydan; `SameSite=Lax` modunun durum değiştiren GET isteklerinde (top-level navigation), eski tarayıcılarda, 2 dakikalık "Lax+POST" Chrome penceresinde veya alt alan adı (subdomain) devralma senaryolarında neden yetersiz kaldığını duymak istiyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
Evet, `SameSite=Lax` varlığında bile CSRF zafiyeti oluşabilir. İlk ve en yaygın senaryo, uygulamanın durum değiştiren (state-mutating) işlemleri hatalı bir şekilde HTTP GET yöntemiyle gerçekleştirmesidir; çünkü `SameSite=Lax` üst düzey bağlantı tıklamalarında (top-level navigation) ve GET isteklerinde çerezleri göndermeye devam eder. İkincisi, eski veya gömülü sistem tarayıcıları SameSite özniteliğini desteklemez ve görmezden gelir. Üçüncüsü, Chrome'un `Lax-allowing-unsafe` davranışı kapsamında yeni oluşturulan çerezlerde ilk 2 dakika boyunca siteler arası POST isteklerinde çerezin iletilebilmesidir. Dolayısıyla `SameSite` tek başına yeterli bir savunma değildir; Synchronizer Token Pattern ve Origin denetimi ile savunma derinliği (Defense-in-Depth) sağlanmalıdır.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
`SameSite` özniteliği "Site" kavramına dayanır, "Origin" kavramına değil! (Site = eTLD+1).
Bu şu anlama gelir: Eğer saldırgan aynı üst alan adına bağlı güvensiz bir alt alan adını (`vulnerable.kurum.internal`) ele geçirirse veya XSS bulursa, bu istek `SameSite` açısından "Same-Site" kabul edilir ve çerezler `banka.kurum.internal` adresine eksiksiz iletilir!
Ayrıca HTTP standardına aykırı olarak yazılmış `GET /account/delete?id=1` gibi uç noktalar, bir saldırganın phishing bağlantısına tıklanmasıyla Lax modunda dahi başarıyla tetiklenir. Bu sebeple kurumsal güvenlik standartlarında:
1. Kesinlikle hiçbir mutasyon GET ile yapılmamalıdır.
2. Anti-CSRF belirteçleri (STP) ve Origin başlığı denetimi ana kalkan olarak devrede tutulmalıdır.

---

### Soru:
3. XSS (Cross-Site Scripting) ile CSRF (Cross-Site Request Forgery) arasındaki güvenlik sınırı ve hiyerarşi nedir? Sistemde bir XSS açığı mevcutken Anti-CSRF belirteçleri (Synchronizer Token) neden koruma sağlayamaz?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın web zafiyetleri arasındaki hiyerarşik bağımlılığı ve yetki sınırlarını kavramasını ölçüyorum. Birçok junior geliştirici CSRF token'ın her koşulda isteği koruyacağını zanneder. Adaydan; XSS'in saldırgana doğrudan hedef origin bağlamında tam JavaScript çalıştırma yetkisi verdiğini, bu yetkiyle DOM'daki gizli CSRF token'ın okunup meşru isteğe eklenebileceğini ve dolayısıyla XSS'in CSRF korumalarını bypass ettiğini açıklamasını bekliyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
XSS, CSRF'ten çok daha üst seviyede ve yıkıcı bir zafiyettir. CSRF'te saldırgan kurbanın tarayıcısına körlemesine bir istek attırır ancak Same-Origin Policy nedeniyle dönen cevabı veya sayfadaki gizli verileri okuyamaz. Ancak bir sayfada XSS varsa, saldırgan kurbanın tarayıcısında meşru kökenin içinde JavaScript çalıştırır. DOM'a tam erişim elde eden saldırgan, sayfadaki gizli `csrf_token` alanını (`document.getElementById('csrf_token').value`) kolayca okur ve bu geçerli token'ı kendi oluşturduğu isteğin başlığına veya gövdesine ekleyerek sunucuya iletir. Bu nedenle sistemde XSS varken hiçbir Anti-CSRF belirteci koruma sağlayamaz.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
Kritik ayrım şudur: **CSRF yetkisiz istek tetikler (Unauthorized Request Issuance); XSS ise yetkili bağlamı ele geçirir (Context Hijacking).**
CSRF savunmaları (STP, Double Submit, Origin kontrolü), saldırganın hedef sitenin DOM ağacına ve bellek alanına erişemediği (SOP koruması) varsayımı üzerine kuruludur. XSS açığı bu temel varsayımı tamamen imha eder.
Tek istisna, işlem anında **Step-Up Authentication (Mevcut Parolanın Tekrar Girilmesi veya Donanımsal FIDO2/WebAuthn)** zorunluluğudur. Eğer kritik işlemde kullanıcının hafızasındaki parola veya donanım anahtarı tekrar isteniyorsa, XSS saldırganı sayfa içeriğini okusa bile o an kullanıcının haberi olmadan işlemi tamamlayamaz (ancak sahte form göstererek phishing yapmayı deneyebilir). Bu nedenle kurumsal mimaride CSP (Content Security Policy) ile XSS önlenmeli, işlem seviyesinde ise Step-up kimlik doğrulama uygulanmalıdır.
