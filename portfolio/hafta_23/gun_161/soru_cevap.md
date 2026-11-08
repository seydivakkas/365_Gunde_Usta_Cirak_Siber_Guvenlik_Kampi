# Gün 161: Mini Proje 22 - Güvenli Form Arayüzü Mülakat Soru & Cevap Paketi

---

### Soru:
Web formlarında CSRF savunması için kullanılan "Synchronizer Token Pattern" ile "Double Submit Cookie Pattern" arasındaki mimari farklar nelerdir? Bir alt alan adının (subdomain) saldırgan tarafından ele geçirilmesi durumunda Double Submit Cookie deseni nasıl manipüle edilebilir ve Synchronizer Token neden bu saldırıya karşı dirençlidir?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Mülakatçı; adayın CSRF koruma yöntemlerinin iç mekanizmalarını bilip bilmediğini, sunucu tarafında oturum durumu (state) saklayan Synchronizer Token ile durumsuz (stateless) Double Submit Cookie arasındaki takasları (trade-offs) kavrayıp kavramadığını ölçmek ister. Özellikle çerezlerin alan adı kapsamı (domain scoping) kurallarını, bir alt alan adının (`attacker.banka.com`) üst alan adına (`banka.com`) çerez yazabilme yeteneğini ve bunun Double Submit Cookie desenini nasıl tamamen çökerttiğini adayın teknik derinlikle açıklamasını bekler.

### Doğru Yanıt (Çırak / Aday İfadesi)
"İki desen arasındaki temel mimari farklar şunlardır:
1. **Synchronizer Token Pattern:** Sunucu her kullanıcı oturumu için rastgele bir CSRF tokenı üretir ve bunu sunucu tarafı oturum deposunda saklar. Form render edilirken token gizli bir girdi (`<input type="hidden">`) olarak eklenir. POST isteği geldiğinde sunucu formdaki token ile oturumdaki tokenı karşılaştırır.
2. **Double Submit Cookie Pattern:** Sunucu taraflı oturum saklanmaz (stateless). Token hem bir HTTP çerezi (`csrf_token`) olarak istemciye verilir hem de form gövdesine yazılır. Form gönderildiğinde sunucu çerezdeki değer ile formdaki değerin birbirine eşit olup olmadığını denetler.

**Subdomain Ele Geçirilmesi Durumunda Double Submit Cookie Zaafı:**
HTTP çerez spesifikasyonu (RFC 6265) gereğince, bir alt alan adını (`blog.banka.com`) ele geçiren saldırgan, üst alan adı (`Domain=banka.com`) için geçerli bir çerez yazabilir. Saldırgan kurbanın tarayıcısına sahte bir `csrf_token=SALDIRGAN_TOKEN` çerezi enjekte eder ve kendi hazırladığı formda aynı değeri POST ettirir. Sunucu iki değerin birbirine eşit olduğunu görerek işlemi onaylar.

**Synchronizer Token Pattern Neden Dirençlidir?**
Çünkü token sunucunun kendi yetkili oturum belleğinde (Redis / veritabanı) saklanır. Saldırgan istemciye hangi çerezi veya formu enjekte ederse etsin, sunucunun belleğindeki gerçek oturum tokenı ile eşleşmeyeceği için saldırı kesin olarak engellenir."

### Derinlemesine Teknik Analiz ve Kritik Ayrım
- **Şifreli / HMAC Tabanlı Double Submit Cookie Çözümü:**
  Eğer uygulamanın mikroservis veya durumsuz (stateless) mimarisi gereği sunucuda oturum tutulamıyorsa, saf Double Submit Cookie yerine **Encrypted Token Pattern** veya **HMAC Double Submit** kullanılmalıdır:
  \[
  \text{CSRF\_Cookie} = \text{SessionID} \parallel \text{Timestamp} \parallel \text{HMAC}(\text{ServerSecret}, \text{SessionID} \parallel \text{Timestamp})
  \]
  Bu durumda saldırgan rastgele bir çerez değeri üretemez; çünkü sunucu gizli anahtarını bilmediği için geçerli bir HMAC imzası taklit edemez.
- **Kritik Ayrım:**
  Modern webde en güçlü çözüm, `SameSite=Strict` çerezleri ile birlikte sunucu taraflı tek kullanımlık (single-use) nonce içeren HMAC Synchronizer Token deseninin birlikte kullanılmasıdır.

---

### Soru:
Bir web formunda parola güvenlik kontrolü yapılırken yalnızca klasik kuralların (örneğin "en az 8 karakter, 1 büyük harf, 1 rakam, 1 özel sembol") kullanılması neden modern kimlik doğrulama saldırılarına karşı yetersizdir? Shannon Bilgi Entropisi ve yaygın parola listesi denetimleri form arayüzüne nasıl entegre edilmelidir?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Mülakatçı; adayın NIST SP 800-63B (Dijital Kimlik Kılavuzu) standartlarını bilip bilmediğini test eder. Klasik kuralların kullanıcıları `P@ssword1!` veya `Istanbul2026!` gibi tahmin edilmesi son derece kolay, şablon bazlı parolalar oluşturmaya ittiğini; buna karşılık parola uzunluğu, sızıntı veritabanı kontrolleri (HaveIBeenPwned API) ve Shannon Entropi hesaplamasının gerçek güvenliği nasıl sağladığını duymak ister.

### Doğru Yanıt (Çırak / Aday İfadesi)
"Klasik parola kuralları ('en az 1 büyük harf, 1 rakam, 1 sembol') modern siber saldırılara karşı yetersizdir; hatta çoğu zaman ters teper. Çünkü kullanıcılar kuralı geçmek için ilk harfi büyük yapar (`P`), sonuna bir rakam (`1`) ve bir sembol (`!`) koyarak `P@ssword1!` gibi kalıplar üretir. Bu kalıplar kaba kuvvet (brute-force) ve maske (mask attack) saldırı araçlarının (Hashcat / John the Ripper) sözlüklerinde ilk sırada yer alır.

Bu sorunu çözmek için form arayüzüne üç aşamalı modern denetim entegre edilmelidir:
1. **Asgari Uzunluk Odaklı Yaklaşım:** Parola uzunluğu en az 10-12 karaktere çıkarılmalıdır. Uzunluk, arama uzayını (search space) üstel olarak genişletir.
2. **Shannon Bilgi Entropisi Hesabı:** Paroladaki karakterlerin çeşitliliği ve öngörülemezliği matematiksel olarak ölçülür:
   \[
   H = -\sum_{i=1}^n P(x_i) \log_2 P(x_i)
   \]
   Karakter başına düşen entropi eşiği (örneğin $\ge 3.0$ bit/karakter) konarak tekrarlayan veya tekdüze karakter dizileri (`aaaaaaaaa!1A`) reddedilir.
3. **Sızdırılmış Parola Kontrolü (Breached Password Check):** NIST standartları uyarınca, daha önce veri sızıntılarında ifşa olmuş en yaygın 100.000 parola listesi ile karşılaştırma yapılmalı ve tehlikedeki parolalar doğrudan engellenmelidir."

### Derinlemesine Teknik Analiz ve Kritik Ayrım
- **K-Anonymity Modeli ile HaveIBeenPwned Entegrasyonu:**
  Form arayüzünde parolanın sızdırılıp sızdırılmadığı kontrol edilirken parolanın kendisi asla üçüncü partilere gönderilmez. Parolanın SHA-1 özetinin ilk 5 karakteri API'ye gönderilir (K-Anonymity). API dönen eşleşen özetler listesini verir ve istemci kalan karakterleri kendi belleğinde eşleştirir.
- **Kritik Ayrım:**
  Geliştiricinin formda yaptığı en büyük hata parolaya azami sınır (ör. 16 karakter) koymak veya kullanıcıların parola yöneticisi (password manager) kullanarak rastgele 30 karakterlik parola yapıştırmasını engellemektir (`onpaste="return false"`). Güvenli form arayüzleri parola yapıştırmaya tam izin vermeli ve en az 128 karaktere kadar parolaları kabul etmelidir.

---

### Soru:
Form gönderimlerinde kaba kuvvet (brute-force) ve DoS saldırılarını engellemek amacıyla uygulanan Rate Limiting (İstek Hız Sınırlandırması) mekanizmasında, yalnızca istemci IP adresine (`request.remote_addr`) güvenmek ne gibi operasyonel ve güvenlik zafiyetlerine yol açar? Kurumsal bir web mimarisinde IP, Oturum (Session) ve İstemci Parmak İzi (Fingerprint) hibrit sınırlandırması nasıl kurgulanmalıdır?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Mülakatçı; adayın gerçek dünya ağ altyapılarını ne kadar tanıdığını ölçmek ister. Büyük bir üniversite, şirket veya mobil operatör ağında binlerce kullanıcının tek bir CGNAT (Carrier-Grade NAT) veya kurumsal çıkış proxy IP'si arkasından gelebileceğini; yalnızca IP'ye göre sınır koymanın binlerce masum kullanıcıyı hizmet dışı (Denial of Service) bırakacağını adayın bilmesini bekler. Ayrıca saldırganların Tor, VPN veya proxy havuzları ile IP adresini saniyeler içinde değiştirebildiğini; bu nedenle hibrit çok katmanlı sınırlandırmanın zorunlu olduğunu duymak ister.

### Doğru Yanıt (Çırak / Aday İfadesi)
"Yalnızca istemci IP adresine dayanarak rate limiting uygulamak iki büyük zafiyete yol açar:
1. **Yanlış Pozitifler ve Hizmet Kesintisi (False Positives & DoS):** Büyük bir kurumsal şirket, kamu dairesi veya mobil hücresel ağda (CGNAT) yüzlerce meşru kullanıcı aynı genel IP adresi üzerinden internete çıkar. Tek bir kullanıcının formu sık doldurması veya hata yapması durumunda tüm kurumun IP'si engellenir ve yüzlerce masum personel sisteme erişemez.
2. **Saldırgan Tarafından Kolayca Aşılabilirlik:** Dağıtık kaba kuvvet (distributed brute-force) saldırılarında saldırganlar IP rotasyonu yapan botnet'ler, Tor ağları veya konut (residential) proxy havuzları kullanır. Her istek farklı bir IP'den geldiği için IP bazlı limit tamamen etkisiz kalır.

**Hibrit ve Çok Katmanlı Sınırlandırma Çözümü:**
Kurumsal form arayüzlerinde üç katmanlı bir anahtar yapısı kullanılır:
- **Katman 1 (Oturum / Kullanıcı Bazlı):** `session_id` veya doğrulanmış `user_id` bazında limit (ör. dakikada 5 transfer). Bu sayede aynı IP'deki diğer meşru kullanıcılar etkilenmez.
- **Katman 2 (IP Bazlı Geniş Eşik):** Bütün kurumu engellemeyecek kadar yüksek, ancak botnet akınlarını durduracak makul bir global tavan (ör. IP başına dakikada 100 istek).
- **Katman 3 (İstemci Parmak İzi - Fingerprint):** TLS parmak izi (JA3/JA4), HTTP başlık sırası ve User-Agent bileşenlerinin özetinden üretilen imza ile IP değiştirse dahi aynı bot yazılımı tespit edilip sınırlandırılır."

### Derinlemesine Teknik Analiz ve Kritik Ayrım
- **Algoritmik Ayrım (Fixed Window vs. Sliding Window Log vs. Token Bucket):**
  - *Sabit Pencere (Fixed Window):* Dakika başında sıfırlanır; dakikanın 59. saniyesinde 5 istek ve 01. saniyesinde 5 istek atılarak 2 saniyede 10 istek geçirilmesine (Bursting Vulnerability) izin verir.
  - *Kayan Pencere Günlüğü (Sliding Window Log):* İsteklerin zaman damgalarını Redis Sorted Set (`ZADD` / `ZREMRANGEBYSCORE`) içinde tutar. Her an geriye dönük 60 saniyelik kesin aralığı ölçtüğü için patlama açığı barındırmaz. Mini projemizde bu kayan pencere mantığı uygulanmıştır.
- **Kritik Yanıt Standartları (RFC 6585 & 7231):**
  Hız sınırı aşıldığında sunucu `HTTP 429 Too Many Requests` yanıtı ile birlikte `Retry-After: 60` başlığını dönmelidir. Bu başlık meşru API ve mobil istemcilerin gereksiz tekrar denemeler yaparak sunucuyu daha fazla boğmasını engeller.
