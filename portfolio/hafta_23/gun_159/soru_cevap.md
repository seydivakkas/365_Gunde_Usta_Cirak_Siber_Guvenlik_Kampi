# Hafta 23 / Gün 159: Soru & Cevap

---

## 1. Soru: Kanonikleştirme (Canonicalization) ve Çift Kodlama Atlatmaları

### Soru
Siber güvenlik mimarisinde **Kanonikleştirme (Canonicalization / Normalization)** adımı neden girdi doğrulamasından (Input Validation) **önce** çalıştırılmak zorundadır? Çift URL Kodlaması (Double URL Encoding - örneğin `%252e%252e%252f`) ve Unicode homoglyph (eşbiçimli) karakterler kullanılarak WAF ve girdi filtreleri nasıl atlatılır?

### Detaylı ve Kapsamlı Teknik Cevap
Kanonikleştirme; bir verinin farklı biçimlerdeki temsil edilme şekillerini (URL-encode, Unicode, Hex, HTML Entity) tek bir standart ve indirgenemez biçime (Kanonik biçim) dönüştürme işlemidir.

**Sıralama Hatasının Doğurduğu Felaket:**
Eğer bir güvenlik filtresi kanonikleştirmeden **önce** çalışırsa:
1. **Çift Kodlama Saldırısı (Double Encoding):**
   - Saldırgan `/etc/passwd` dosyasını okumak için `../../etc/passwd` dizin geçişi (Path Traversal) yapmak ister.
   - Nokta karakteri `.` standart URL kodlamasında `%2e`'dir.
   - Saldırgan `%` karakterini bir kez daha kodlayarak `%25` yapar: Böylece `.` -> `%252e` haline gelir.
   - `../../` dizesi saldırgan tarafından `%252e%252e%252f%252e%252e%252f` olarak sunucuya gönderilir.
   - Girdi filtresi metni tarar; metinde `../` görmez (çünkü metin `%252e%252e%252f` halindedir) ve girdiyi "GÜVENLİ" sayıp geçirir.
   - Backend web sunucusu veya veritabanı sürücüsü isteği işlerken URL decode yapar; `%252e` önce `%2e`'ye, ardından arka plandaki ikinci bir çağrıda `.` haline çözülür! Dizin geçişi gerçekleşir ve sistem dosyası ifşa olur.
2. **Unicode Homoglyph / Tam Genişlik (Fullwidth) Atlatması:**
   - Saldırgan `<script>` kelimesini standart ASCII yerine tam genişlikli Unicode karakterlerle yazar: `＜ｓｃｒｉｐｔ＞`.
   - Standart ASCII regex filtresi bunu tanıyamaz ve izin verir.
   - Daha sonra uygulama veritabanına yazarken veya UTF-8 normalizasyonu yaptığında bu karakterler standart `<script>` haline gelir ve XSS patlar.

**Mühendislik Çözümü:**
- Veri girdi sınırından girdiği an;
  1. Recursive unquoting (artık çözülecek yüzde kalmayana kadar döngüsel decode),
  2. `unicodedata.normalize('NFKC', value)` (Uyumluluk ayrıştırma ve birleştirme normalizasyonu),
  3. Null byte (`\x00`, `%00`) ve görünmeyen ASCII kontrol karakterlerinin silinmesi,
  adımları tamamlanır. Filtreleme ve regex kontrolleri **yalnızca bu kanonik veri üzerinde** yürütülür.

### Ustanın Çırağa Tavsiyesi / Altın Kural
> *"Çırak! Bir şüphelinin üstünü aramadan önce montunu ve maskesini çıkaracaksın. Çift kodlanmış veri, maskeli saldırgandır. Kanonikleştirme yapmadan regex çalıştırırsan, saldırganın kostümüne bakıp içeri alırsın; sonra içeride maskesini çıkarıp bombayı patlatır!"*

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2001 yılında Microsoft IIS 4.0 ve 5.0 web sunucularında ortaya çıkan meşhur "IIS Unicode / Double Decode" açığı (CVE-2001-0333), kanonikleştirme hatasının tarihteki en büyük örneğidir. Saldırganlar `http://victim.com/scripts/..%255c..%255cwinnt/system32/cmd.exe?/c+dir` isteği göndererek IIS'in filtrelerini atlatmış ve internete bağlı yüz binlerce Windows sunucuda SYSTEM yetkisinde uzaktan komut çalıştırmıştır (RCE). Olay, web sunucu mimarilerinde kanonikleştirmeyi zorunlu bir güvenlik standardı haline getirmiştir.

---

## 2. Soru: Bağlama Duyarlı Çıktı Kodlama (Context-Aware Output Encoding)

### Soru
Neden tek tip bir HTML kodlama fonksiyonu (örneğin Python `html.escape()` veya PHP `htmlspecialchars()`) bir web uygulamasını XSS açıklarına karşı korumak için **yetersizdir**? HTML Gövdesi (Body), HTML Özniteliği (Attribute), JavaScript İçi Değişken (JS Context) ve URL Parametresi bağlamları arasındaki kodlama farkları nelerdir ve bağlam karıştırıldığında ne tür felaketler meydana gelir?

### Detaylı ve Kapsamlı Teknik Cevap
Web sayfaları tek bir monolitik dilden oluşmaz; HTML, CSS, JavaScript ve URL kuralları aynı sayfada iç içe çalışan farklı yorumlayıcı motorlara (Interpreters) sahiptir. Her yorumlayıcının sözdizimini (syntax) kıran özel karakterler tamamen farklıdır.

Standart `html.escape()` fonksiyonu yalnızca `&, <, >, ", '` karakterlerini HTML varlıklarına (`&lt;, &gt;` vb.) dönüştürür. Bu dönüşüm **yalnızca HTML Gövdesi (`<div>...</div>`)** bağlamında güvenlidir.

**Farklı Bağlamlar ve Zafiyet Senaryoları:**

1. **HTML Öznitelik Bağlamı (HTML Attribute Context):**
   - Kod parçası: `<input type="text" name="city" value="KULLANICI_VERISI">`
   - Eğer geliştirici tırnak işaretlerini kodlamazsa veya tek tırnaklı bir öznitelikte (`value='...'`) kullanıcı `' onfocus='alert(1)` girerse;
   - Standart HTML kaçışı tırnağı bazen atlayabilir.
   - Doğru Çözüm: Alfanümerik dışındaki tüm özel karakterler `&#xHH;` hex formatında kodlanmalıdır (`"` -> `&#x22;`, `'` -> `&#x27;`).

2. **JavaScript Değişken Bağlamı (JavaScript Context):**
   - Kod parçası: `<script>var customerName = 'KULLANICI_VERISI';</script>`
   - Saldırgan verisi: `'; alert(document.domain); //`
   - Geliştirici burada `html.escape()` uygularsa ne olur?
   - Çıktı: `<script>var customerName = '&#x27;; alert(document.domain); //';</script>`
   - Tarayıcının JavaScript motoru HTML entity kodlamasını **yorumlamaz**; doğrudan JavaScript sözdizimi olarak çalıştırır ve XSS patlar!
   - Doğru Çözüm: JavaScript içinde yalnızca **Unicode Kaçışı (Unicode Escaping - `\u00XX`)** kullanılmalıdır. Tek tırnak `\u0027`, noktalı virgül `\u003B` olarak kodlanmalı; böylece JavaScript dize sınırından çıkış imkansız hale getirilmelidir.

3. **URL Parametresi Bağlamı (URL Context):**
   - Kod parçası: `<a href="/redirect?url=KULLANICI_VERISI">Tıklayın</a>`
   - Saldırgan verisi: `javascript:alert(document.cookie)`
   - HTML kaçışı `javascript:` kelimesini bozmaz; kullanıcı linke tıkladığı an JavaScript kodu kurbanın oturumunda çalışır.
   - Doğru Çözüm: URL önce `http://` veya `https://` protokolü ile mi başlıyor diye doğrulanmalı (Allowlist), ardından parametreler RFC 3986 percent-encoding (`urllib.parse.quote_plus`) işleminden geçirilmelidir.

### Ustanın Çırağa Tavsiyesi / Altın Kural
> *"Çırak! Çıktıyı kodlarken daima soracaksın: 'Bu veri şu an hangi motorun midesine inecek?' HTML motoruna mı, JavaScript motoruna mı, URL motoruna mı? Yanlış motora yanlış kodlama verirsen, yangını söndürmek için su yerine benzin sıkmış olursun. JavaScript içindeki değişkene asla HTML kaçışı basma; Unicode kaçışı basacaksın!"*

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2014 yılında küresel bir e-ticaret devinin arama kutusunda ilginç bir XSS bulundu. Arama terimi HTML gövdesinde `&lt;script&gt;` olarak kusursuz kodlanıyordu. Ancak sayfanın altındaki analitik izleme kodunda geliştirici şöyle bir satır yazmıştı: `<script>trackSearch('<?php echo htmlspecialchars($search); ?>');</script>`. Saldırgan aramaya `test\'); alert(document.cookie); //` yazdı. `htmlspecialchars` ters bölü (`\`) karakterini dönüştürmediği için saldırgan tek tırnağı kaçırdı ve JavaScript fonksiyonunu kapatıp kendi XSS kodunu çalıştırdı. Bağlam hatası, şirkete yüz binlerce dolarlık ödül avcılığı (Bug Bounty) maliyetine mal oldu.

---

## 3. Soru: Pozitif İzin Listesi (Allowlist) vs. Negatif Kara Liste (Blocklist)

### Soru
Yazılım güvenliğinde **Pozitif Güvenlik Modeli (Allowlist / Whitelist)** ile **Negatif Güvenlik Modeli (Blocklist / Blacklist)** arasındaki felsefi ve mimari fark nedir? Neden kara liste temelli girdi temizleme (Sanitization) yaklaşımları siber saldırganlar karşısında daima mağlup olmaya mahkumdur?

### Detaylı ve Kapsamlı Teknik Cevap
Güvenlik mimarisinde sistemin güvenilmeyen girdileri nasıl karşıladığı iki temel modele ayrılır:

1. **Negatif Güvenlik Modeli (Blocklist / Denylist):**
   - **Felsefe:** "Neyin kötü olduğunu biliyorum; kötü olanları engelleyeyim, geri kalan her şeye izin vereyim."
   - **Örnek:** Girdide `<script>`, `SELECT`, `UNION`, `../` kelimeleri varsa bunları silmek veya engellemek.
   - **Neden Başarısız Olur?**
     - **Tükenmez Saldırı Çeşitliliği:** Bir saldırıyı gerçekleştirmenin sonsuz sayıda sözdizimsel varyasyonu vardır. Örneğin XSS için WAF kuralına `<script>` yazarsanız; saldırgan `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>`, `<audio src/onerror=alert(1)>`, `<iframe src="javascript:alert(1)">`, `<body onload=alert(1)>` veya büyük-küçük harf (`<sCrIpt>`) dener.
     - **Bypass / Atlatma:** Geliştirici `replace("<script>", "")` yazarsa; saldırgan `<scr<script>ipt>` yazar. İçteki `<script>` silinince dıştakiler birleşir ve yine `<script>` oluşur.
     - **Gelecekteki Özellikler (0-Day):** HTML5 veya ECMAScript standardına yeni bir etiket veya öznitelik eklendiğinde kara listeniz bu yeni vektörden haberdar olamaz ve sistem savunmasız kalır.

2. **Pozitif Güvenlik Modeli (Allowlist / Safelist):**
   - **Felsefe:** "Sadece neyin geçerli ve meşru olduğunu biliyorum; açıkça izin verdiğim kurallara uyanları kabul ederim, geri kalan her şeyi istisnasız reddederim!"
   - **Örnek:**
     - T.C. Kimlik No: Yalnızca `^[1-9][0-9]{10}$` (Tam 11 basamak ve rakam).
     - Kullanıcı Adı: Yalnızca `^[a-zA-Z0-9_-]{3,30}$`.
     - Sıralama Parametresi (`sort`): Yalnızca `["asc", "desc"]` değerleri.
   - **Neden Yenilmezdir?**
     - Saldırgan sisteme ne tür egzotik bir payload gönderirse göndersin, girdi önceden belirlenmiş katı kalıba uymadığı için içeri dahi alınmaz. Sıfırıncı gün (0-day) saldırıları ve karmaşık WAF atlatmaları pozitif model karşısında tamamen etkisizdir.

### Ustanın Çırağa Tavsiyesi / Altın Kural
> *"Çırak! Dünyadaki tüm zehirlerin listesini tutamazsın; her gün yeni bir zehir icat edilir. Ama ekmeğin, suyun ve buğdayın ne olduğunu bilirsin. Sisteme alacağın girdiyi tanımla: 'Benim bu alanda sadece rakam görmem lazım.' Rakam dışındaki her şeyi kapıda atacaksın. Kötüyü kovalamayacaksın, sadece iyiyi içeri alacaksın!"*

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2016 yılında popüler bir içerik yönetim sistemi (CMS) eklentisi, SQL enjeksiyonunu engellemek için kara liste kullanıyordu: `UNION`, `SELECT`, `INSERT`, `UPDATE` kelimeleri filtreleniyordu. Bir saldırgan, MySQL'in bilinmeyen bir sözdizimi özelliğini kullanarak hiçbir yasaklı kelimeyi içermeyen boolean-tabanlı kör bir SQLi enjeksiyonu (`' OR 1=(SELECT 1) --` yerine bitwise işlemlerle `1 & 1`) geliştirdi. Kara liste filtresi hiçbir kelimeye takılmadı ve yarım milyondan fazla web sitesinin veritabanı saldırganlar tarafından sızdırıldı. Eğer eklenti sayısal ID alanında pozitif model uygulayıp `is_numeric($id)` kontrolü yapsaydı, tek satır kodla felaket önlenecekti.
