# Gün 168: Mini Proje 23 — Güvenli Dosya Servisi Mülakat ve Teknik Soru-Cevap Rehberi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

### Soru:
1. Bir dosya yükleme servisinde istemcinin gönderdiği `Content-Type: image/png` HTTP başlığı neden bir güvenlik denetimi olarak kabul edilemez? Dosya uzantısı, MIME türü ve sihirli baytlar (Magic Bytes / File Signatures) arasındaki fark nedir ve "Polyglot Dosya" saldırılarına karşı nasıl savunma yapılır?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın istemci taraflı gönderilen HTTP başlıklarının saldırgan tarafından tamamen manipüle edilebileceğini (Burp Suite, curl vb.) bilmesini bekliyorum. Yalnızca dosya uzantısına (`.png`) veya `Content-Type` başlığına güvenmenin bir güvenlik yanılsaması olduğunu, gerçek dosya tipinin ancak dosyanın ilk baytları (Magic Bytes) okunarak anlaşılabileceğini ve geçerli bir dosya yapısı içine betik gömülerek oluşturulan "Polyglot" saldırılarına karşı statik imza taraması yapılması gerektiğini teknik detaylarıyla açıklamasını istiyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
İstemcinin gönderdiği `Content-Type` başlığı tamamen kullanıcı kontrolündedir. Bir saldırgan `shell.php` dosyasını yüklerken HTTP isteğindeki başlığı `Content-Type: image/png` olarak değiştirebilir. Sunucu yalnızca bu başlığa veya dosya uzantısına bakarsa zararlı PHP dosyasını kabul eder.
Gerçek dosya doğrulamasında üç katman birlikte işletilmelidir:
1. **Dosya Uzantısı Beyaz Listesi:** Yalnızca izin verilen güvenli uzantılar kabul edilir (`.png`, `.pdf`).
2. **Sihirli Baytlar (Magic Bytes):** Dosyanın ilk birkaç baytı okunarak gerçek imza denetlenir. Örneğin PNG dosyaları her zaman `0x89 0x50 0x4E 0x47` (`\x89PNG`) baytlarıyla başlar, PDF dosyaları `%PDF-` ile başlar.
3. **Polyglot ve Webshell Taraması:** Bir saldırgan meşru bir PNG dosyasının EXIF metaveri alanına veya PDF dosyasının akış (stream) içine `<?php system($_GET['c']); ?>` gömebilir (Polyglot). Bu tür saldırıları engellemek için dosya içeriği statik zararlı betik kalıplarına karşı taranmalı ve dosyalar yeniden derlenerek (örneğin resim kütüphanesiyle pikselleri yeniden işleyerek - Re-encoding) gereksiz baytlardan arındırılmalıdır.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
Sadece Magic Bytes denetimi yapmak da tek başına yetmez. Örneğin bir PHP dosyası şu şekilde yazılabilir:
`GIF89a<?php system($_GET['cmd']); ?>`
Bu dosyanın ilk 6 baytı `GIF89a` (GIF sihirli baytı) olduğu için naif bir resim kontrolünü geçer. Ancak dosya sunucu tarafından `.php` olarak kaydedilirse veya web sunucusu MIME sniffing ile bunu PHP olarak yorumlarsa webshell çalışır.
Bu nedenle kurumsal savunma kuralı şudur:
- Uzantı, Magic Bytes ve MIME türü birbiriyle %100 uyuşmalıdır.
- Dosya içeriğinde zararlı betik imzaları taranmalıdır.
- Dosya asla kullanıcının verdiği uzantıyla veya doğrudan çalıştırılabilir bir web dizininde saklanmamalıdır.

---

### Soru:
2. Kullanıcıların yüklediği dosyaları sunarken `Content-Disposition: attachment` ve `X-Content-Type-Options: nosniff` başlıkları kullanılmazsa, saldırgan meşru bir dosya (örneğin SVG veya HTML içeren dosya) yükleyerek nasıl Saklı XSS (Stored XSS) ve Oturum Çalma saldırısı gerçekleştirebilir?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın sadece dosya yükleme anını değil, dosyanın kullanıcıya sunulma anındaki tarayıcı davranışlarını (Rendering vs Downloading) bilmesini test ediyorum. SVG formatının bir XML dokümanı olduğunu ve `<script>` etiketleri içerebileceğini, tarayıcıların "MIME Sniffing" yaparak metin dosyalarını dahi HTML/JS olarak yorumlayabildiğini ve HTTP güvenlik başlıklarının bu tehlikeyi nasıl etkisizleştirdiğini duymak istiyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
Eğer sunucu dosyayı sunarken `Content-Disposition: attachment` başlığı kullanmazsa, tarayıcı dosyayı indirmek yerine kendi içinde görüntülemeye (inline render) çalışır.
Örneğin bir saldırgan sistemin izin verdiği bir SVG görseli içerisine `<svg><script>alert(document.cookie)</script></svg>` veya PDF içerisine JavaScript gömer. Kullanıcı bu dosyanın linkine tıkladığında tarayıcı SVG'yi doğrudan DOM içinde açar ve saldırganın gömdüğü JavaScript kodu kurbanın tarayıcısında çalışarak oturum çerezlerini çalar (Stored XSS).
Ayrıca `X-Content-Type-Options: nosniff` başlığı bulunmadığında, saldırgan `.txt` uzantısıyla HTML/JS içeren bir dosya yüklediğinde modern tarayıcılar dosya içeriğini koklayarak (MIME Sniffing) `text/plain` yerine `text/html` olarak yorumlayabilir ve XSS tetiklenebilir.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
İndirme ağ geçidinde (Download Gateway) şu başlıklar zorunlu kılınmalıdır:
```http
Content-Disposition: attachment; filename="guvenli_dosya.pdf"
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; sandbox
Cache-Control: no-store, no-cache, must-revalidate
```
1. `attachment`: Tarayıcıya bu içeriği asla ekranda render etmemesini, doğrudan işletim sisteminin indirme iletişim kutusuna göndermesini emreder.
2. `nosniff`: Tarayıcının MIME türünü tahmin etmesini engeller, sunucunun bildirdiği türe sadık kalmasını sağlar.
3. `Content-Security-Policy: sandbox`: Dosya bir şekilde tarayıcıda açılsa dahi JavaScript çalıştırma, form gönderme ve Same-Origin haklarını sıfırlar.
4. Dosyaların ana uygulama alan adı (örneğin `app.kurum.com`) yerine tamamen izole edilmiş bir CDN/Depolama alt alan adından (`downloads-usercontent.kurum.com`) sunulması, XSS gerçekleşse dahi ana uygulamanın çerezlerine ve localStorage verilerine erişimi Same-Origin Policy gereği engeller.

---

### Soru:
3. Çok kiracılı (Multi-Tenant) SaaS bulut mimarilerinde dosya servislerine yönelik Kırık Nesne Seviyesinde Yetkilendirme (BOLA / IDOR / CWE-639) saldırıları nasıl gerçekleşir? İndirekt Nesne Referansı (UUIDv4 Mapping) ve Kiracı İzolasyonu mimarisi bu riski nasıl bertaraf eder?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın kurumsal bulut mimarilerinde veri izolasyonunun önemini kavramış olmasını bekliyorum. Otomatik artan ID'lerin (`/download?file_id=105`) tahmin edilebilirliğini, UUID kullanmanın avantajlarını ve UUID kullanılsa bile sunucu tarafında aktif yetkilendirme ve kiracı denetimi (Tenant Isolation) yapılmadığında güvenliğin sağlanamayacağını bilmesini istiyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
BOLA / IDOR açığı, uygulamanın dosya indirme veya silme isteklerinde kullanıcının o nesneye erişim yetkisi olup olmadığını denetlememesinden kaynaklanır. Sıralı tamsayı ID'ler kullanıldığında (`file_id=1`, `file_id=2`), saldırgan bir döngüyle tüm ID'leri tarayarak diğer kullanıcıların ve rakip şirketlerin yüklediği tüm gizli belgeleri indirebilir.
Çözüm iki katmandan oluşur:
1. **İndirekt Nesne Referansı (UUIDv4):** Dosya kimlikleri tahmin edilemez 128-bitlik rastgele UUID formatında atanır (`b4f8a12c-9d62-4a11-...`). Bu sayede sıralı tahmin (enumeration) saldırıları imkansız hale gelir.
2. **Kiracı İzolasyonu ve Sahiplik Doğrulaması:** UUID tek başına bir güvenlik mekanizması değildir (güvenlik belirsizliğe dayandırılamaz). Sunucu, gelen her indirme isteğinde oturum açmış kullanıcının `tenant_id`'sini dosyanın veritabanındaki `tenant_id`'si ile karşılaştırır. Eşleşmiyorsa veya kullanıcı kurum içinde o dosyaya erişim yetkisine sahip değilse istek anında `403 Forbidden` ile reddedilir.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
Fiziksel depolama seviyesinde de Kiracı İzolasyonu uygulanmalıdır:
- Dosyalar diskte `/storage/tenants/<tenant_id>/<file_uuid>.dat` şeklinde hiyerarşik olarak saklanır.
- Sunucu kodunda dosya yolu birleştirilirken `os.path.realpath` ve `os.path.commonpath` kullanılarak bir kiracının diskte başka bir kiracının klasörüne traversal yapması fiziksel olarak engellenir.
- Veritabanı sorgularında kiracı filtresi (`WHERE file_id = ? AND tenant_id = ?`) zorunlu tutulmalıdır; böylece veritabanı düzeyinde de çapraz veri sızıntısı önlenmiş olur.
