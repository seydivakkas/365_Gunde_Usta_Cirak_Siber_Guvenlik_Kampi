# Gün 160: XSS Türleri ve Savunma - Mülakat Soru & Cevap Paketi

---

### Soru:
Reflected, Stored ve DOM-based XSS arasındaki temel mimari ve veri akışı farkları nelerdir? Özellikle web sunucusu erişim günlüklerinde (access logs) hangi XSS türü tamamen görünmez kalabilir ve bunun teknik sebebi nedir?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Mülakatçı; adayın XSS'i sadece ezbere tanımlarla bilip bilmediğini değil, HTTP protokolü ve tarayıcı DOM mimarisinin nasıl etkileşime girdiğini kavrayıp kavramadığını ölçmek ister. Özellikle URL'deki `#` (fragment identifier / hash) kısmının RFC 3986 gereğince HTTP isteklerinde sunucuya ASLA iletilmediğini, dolayısıyla fragment üzerinden tetiklenen bir DOM XSS atağının sunucu loglarında, WAF'ta ve IDS'te hiçbir iz bırakmadan doğrudan istemci belleğinde çalışacağını net bir şekilde ifade etmesini bekler.

### Doğru Yanıt (Çırak / Aday İfadesi)
"XSS saldırıları verinin geçtiği yol ve saklanma biçimine göre üçe ayrılır:
1. **Reflected XSS:** Zararlı girdi (URL sorgu parametresi veya form verisi) HTTP isteğiyle sunucuya gider, sunucu girdiyi doğrulamadan anında HTTP yanıt gövdesine yansıtır. Sunucu erişim loglarında URL parametresi görünür.
2. **Stored XSS:** Zararlı girdi veritabanı veya sunucu oturumunda kalıcı olarak saklanır ve sayfayı ziyaret eden tüm kullanıcılara sunulur. İlk enjeksiyon anındaki POST isteği sunucu loglarına yansır.
3. **DOM-based XSS:** Zafiyet tamamen istemci tarafında (tarayıcıda) gerçekleşir. Tarayıcıda çalışan JavaScript kodu, `location.hash` gibi bir kaynaktan (Source) okuduğu veriyi `element.innerHTML` gibi tehlikeli bir yürütücü havuza (Sink) iletir.

Özellikle **URL fragment (`#`) üzerinden gerçekleştirilen DOM-based XSS saldırıları, web sunucusu erişim günlüklerinde (access log) TAMAMEN GÖRÜNMEZDİR**. Çünkü HTTP standardı uyarınca tarayıcılar `#` işaretinden sonraki kısmı sunucuya gönderilen HTTP istek paketine dahil etmez. Sunucu yalnızca temel URL'yi görür; zararlı yük doğrudan kurbanın tarayıcı belleğinde işlenir."

### Derinlemesine Teknik Analiz ve Kritik Ayrım
- **Protokol Seviyesinde Ayrım (RFC 3986):**
  Bir kullanıcı tarayıcısında `https://target.com/app#<img src=x onerror=alert(1)>` bağlantısını açtığında:
  - Tarayıcının gönderdiği HTTP GET isteği: `GET /app HTTP/1.1\r\nHost: target.com\r\n...`
  - Fragment identifier (`#<img...`) istemci tarafında kalır; TCP üzerinden sunucuya gönderilmez.
  - Sunucu tarafındaki WAF (Web Application Firewall) veya SIEM logları bu saldırıyı tespit edemez.
- **İstemci Kodunun Hatası:**
  Sayfa yüklendiğinde istemci tarafında çalışan şu kod tetiklenir:
  ```javascript
  let section = window.location.hash.substring(1);
  document.getElementById('content').innerHTML = section; // ZAFİYETLİ SINK!
  ```
- **Kritik Savunma Ayrımı:**
  Sunucu tarafı girdi doğrulama veya sunucu WAF kuralları DOM XSS'e karşı tek başına yetersizdir. Çözüm; istemcide `innerHTML` yerine `textContent` kullanmak, veriyi DOM'a basmadan önce istemci tarafında `DOMPurify` ile arındırmak ve `Trusted Types` API'sini zorunlu kılmaktır.

---

### Soru:
Content Security Policy (CSP) Seviye 3'te "nonce-based" politika ile "strict-dynamic" yönergesi birlikte nasıl çalışır? Geleneksel alan adı izin listesi (domain allowlist - ör. `script-src 'self' https://trusted-cdn.com`) yaklaşımına kıyasla neden modern mimarilerde çok daha üstün ve güvenlidir?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Mülakatçı; alan adı allowlist'lerinin (domain whitelisting) modern webde neden başarısız olduğunu (örneğin güvenilen CDN'lerde barınan JSONP açıkları, Angular/Vue kütüphaneleri üzerinden sandbox bypass veya açık dosya yükleme noktaları) adayın bilip bilmediğini test eder. Adayın, CSP Seviye 3'teki kriptografik nonce (`'nonce-...'`) ve `'strict-dynamic'` yönergelerinin meşru betiklerin dinamik alt betik yüklemesine izin verirken enjekte edilen sahte inline betikleri nasıl kesin olarak kilitlediğini teknik ayrıntılarıyla anlatması beklenir.

### Doğru Yanıt (Çırak / Aday İfadesi)
"Geleneksel alan adı izin listesi (örneğin `script-src 'self' cdn.example.com`) günümüzde güvenilmez kabul edilmektedir. Çünkü izin verilen devasa CDN'lerde genellikle saldırganın XSS yükünü tetikleyebileceği bir JSONP endpoint'i veya eski bir JavaScript kütüphanesi (Angular bypass) barınabilir. Ayrıca uygulamanın kendi domaininde kullanıcıların dosya yükleyebildiği bir dizin varsa, `'self'` yönergesi saldırganın yüklediği JS dosyasını çalıştırmasına olanak tanır.

CSP Seviye 3 ile gelen **Nonce-based + 'strict-dynamic'** yaklaşımı bu sorunu kökten çözer:
1. Sunucu her HTTP isteğinde tahmin edilemez, 128-bitlik kriptografik rastgele bir `nonce` (number used once) üretir.
2. Bu nonce hem CSP HTTP yanıt başlığına (`script-src 'nonce-XYZ' 'strict-dynamic'`) hem de sunucunun ürettiği meşru `<script nonce="XYZ">` etiketlerine eklenir.
3. `'strict-dynamic'` direktifi sayesinde, bu güvenli nonce ile başlatılan meşru ana betik, çalışma zamanında dinamik olarak başka betikler yükleyebilir (örneğin Google Tag Manager, modern Webpack/Vite parçaları). Tarayıcı, güvenilen ana betiğin yüklediği alt betiklere otomatik olarak güvenir.
4. Saldırgan sayfaya `<script>alert(1)</script>` veya `<script src="evil.js">` enjekte etmeye kalktığında, geçerli nonce değerini tahmin edemediği için tarayıcı bu betikleri anında bloke eder."

### Derinlemesine Teknik Analiz ve Kritik Ayrım
- **Nonce Güvenlik Kriterleri:**
  - Nonce tahmin edilemez olmalıdır (CSPRNG kullanılmalıdır: `secrets.token_urlsafe(16)`).
  - Her HTTP yanıtında yeniden üretilmelidir; asla statik veya oturum boyunca sabit tutulmamalıdır.
  - Sayfa içinde DOM üzerinden veya yansıyan çıktılarda sızdırılmamalıdır (Nonce Exfiltration koruması).
- **'strict-dynamic' Geriye Dönük Uyumluluğu:**
  CSP Seviye 3 destekleyen modern tarayıcılarda `'strict-dynamic'` yönergesi aktif olduğunda, `script-src` içerisinde yer alan `'self'`, `'unsafe-inline'` ve host allowlist'leri otomatik olarak yoksayılır. Bu sayede eski tarayıcılar için fallback kurallar tanımlanırken modern tarayıcılarda en yüksek güvenlik sağlanır:
  ```http
  Content-Security-Policy: default-src 'self'; script-src 'nonce-a8F3dK99xL2pQ==' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none';
  ```
- **Kritik Zayıflık Engeli:**
  `object-src 'none'` ve `base-uri 'none'` direktifleri ile birlikte kullanılmalıdır. Aksi halde saldırgan `<base href="https://evil.com">` enjekte ederek göreceli script yollarını kendi sunucusuna yönlendirebilir (Base Tag Hijacking).

---

### Soru:
Bir web uygulamasında zengin metin (Rich Text / WYSIWYG) editörü kullanılması gerekmektedir. Kullanıcının `<b>`, `<i>`, `<a>` etiketleri girmesine izin verilmekte, ancak `onload`, `onerror` gibi olay dinleyicileri engellenmek istenmektedir. Geliştiricinin kendi yazdığı bir Regex filtresi neden güvenli değildir? Mutation XSS (mXSS) nedir ve W3C Trusted Types standardı DOM manipülasyonu güvenliğini nasıl kökten değiştirir?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Mülakatçı; adayın "Regex ile HTML temizleme" gafletinin farkında olup olmadığını, tarayıcıların HTML5 ayrıştırıcısının (parsing algorithm) kuralları ve mutasyon mekanizmasını ne kadar derin bildiğini anlamak ister. HTML dilinin bağlamdan bağımsız bir dil olmadığını (Context-Free Grammar olmadığını), dolayısıyla düzenli ifadelerle hatasız ayrıştırılamayacağını ve `mXSS` açığının tarayıcı parser'ının iç yapısından kaynaklandığını bilip bilmediğini test eder. Ayrıca modern tarayıcılarda `Trusted Types` API'sinin güvensiz string atamalarını derleme/çalışma anında nasıl engellediğini duymak ister.

### Doğru Yanıt (Çırak / Aday İfadesi)
"HTML dilini düzenli ifadelerle (Regex) veya kendi yazdığımız basit kara liste filtreleriyle temizlemek kesinlikle güvenli değildir. Çünkü:
1. HTML parser'ı garip karakter kodlamaları, iç içe yorum satırları (`<!--`), boşluksuz nitelik tanımları (`<img src=x onerror=alert(1)>`) ve SVG/MathML ad alanları gibi sayısız karmaşık durumu yorumlayabilir. Regex bu varyasyonların tümünü yakalayamaz.
2. **Mutation XSS (mXSS):** Bir temizleme filtresi girdiyi güvenli sanıp kabul etse bile, tarayıcı bu HTML'i bellekteki DOM ağacına dönüştürürken (özellikle `innerHTML` atamasında) HTML standardı gereği kapatılmamış etiketleri düzeltir veya SVG/XML ad alanlarını HTML ad alanına geçirir. Bu 'mutasyon' esnasında zararsız görünen bir metin parçası birdenbire aktif ve çalışan bir JavaScript olay dinleyicisine (`onerror`) dönüşebilir.

Bu riski engellemenin en doğru yolu üretimde **DOMPurify** gibi tarayıcının kendi DOM parser'ını kullanarak temizlik yapan kütüphaneleri kullanmak ve W3C **Trusted Types** standardını devreye almaktır. Trusted Types aktif edildiğinde (`require-trusted-types-for 'script'`), tarayıcı `element.innerHTML` veya `script.src` havuzlarına doğrudan ham string (`string`) atanmasını reddeder; mutlaka denetlenmiş bir güvenlik politikasından geçmiş özel bir `TrustedHTML` nesnesi atanmasını zorunlu kılar."

### Derinlemesine Teknik Analiz ve Kritik Ayrım
- **mXSS Örneği:**
  ```html
  <noscript><p title="</noscript><img src=x onerror=alert(1)>">
  ```
  Eğer sanitizer bu girdiyi `<noscript>` açıkken dize olarak incelerse `title` niteliği içinde görür. Ancak tarayıcıda JavaScript etkin olduğunda `<noscript>` içeriği metin olarak değil ayrıştırılmış DOM olarak ele alınır ve `img` etiketi dışarı fırlayarak `onerror` tetiklenir.
- **W3C Trusted Types Mimarisi:**
  Tarayıcıda CSP başlığı ile aktive edilir:
  ```http
  Content-Security-Policy: require-trusted-types-for 'script';
  ```
  Bu başlık devredeyken aşağıdaki kod `TypeError` fırlatır:
  ```javascript
  // HATA: Doğrudan string ataması engellenir!
  document.getElementById('profile').innerHTML = rawUserInput; 
  ```
  Bunun yerine yalnızca onaylı bir politika üzerinden geçirilmiş nesne atanabilir:
  ```javascript
  const sanitizePolicy = trustedTypes.createPolicy('default', {
    createHTML: (string) => DOMPurify.sanitize(string, {RETURN_TRUSTED_TYPE: true})
  });
  document.getElementById('profile').innerHTML = sanitizePolicy.createHTML(rawUserInput);
  ```
- **Kritik Ayrım:**
  Trusted Types, insan hatasını mimari düzeyde engeller. Büyük bir yazılım ekibinde tek bir acemi geliştiricinin bile yanlışlıkla `innerHTML = userInput` yazmasını tarayıcı motoru seviyesinde imkansız hale getirir.
