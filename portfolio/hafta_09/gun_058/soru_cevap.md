# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

# Gün 058: HTTP Yöntemleri ve Idempotency — Soru, Cevap ve Senaryo Analizleri

Bu dokümanda, dağıtık finansal API'lerde Idempotency-Key yönetimi, çifte çekim (double charge) koruması, HTTP Verb Tampering ile kimlik doğrulama atlatma ve GET metodunun durum değiştirici suiistimali derinlemesine incelenmektedir.

---

## Senaryo G058-SC1: Dağıtık Finansal Sistemlerde Idempotency-Key Mekanizması ve Çift Para Çekme (Double Charge) Savunması

### Soru / Senaryo
Bir dijital cüzdan uygulamasında kullanıcılar zayıf 4G/3G sinyaline sahip metro istasyonlarında veya otoparklarda ödeme yaparken zaman aşımı (timeout) hatasıyla karşılaşmaktadır. Kullanıcı arayüzünde "İşlem Zaman Aşımına Uğradı, Lütfen Tekrar Deneyin" mesajı çıktığı için kullanıcılar butona art arda 2-3 kez basmaktadır. Muhasebe ekibi, gün sonu mutabakatlarında yüzlerce kullanıcının kartından aynı sipariş için mükerrer tahsilat yapıldığını (örneğin 150 TL yerine 300 veya 450 TL çekildiğini) tespit etmiştir. Bu problem HTTP protokolünün hangi doğasından kaynaklanır ve `Idempotency-Key` deseniyle nasıl kesin olarak çözülür?

### Ustanın Cevabı / Çözüm Yaklaşımı
Evladım, bu vaka dağıtık sistemlerin en temel gerçeğidir: **İki Generaller Problemi (Two Generals' Problem)** ve HTTP `POST` metodunun eşgüçlü (idempotent) olmaması!

Olayın Gerçekleşme Zinciri:
1. İstemci `POST /api/v1/payments` isteğini gönderir.
2. İstek bankaya ulaşır; banka veritabanında bakiyeyi düşer ve işlemi onaylar.
3. Ancak sunucunun ürettiği `201 Created` yanıtı metro tünelindeki baz istasyonu kopması yüzünden istemciye geri dönemez.
4. İstemci cevabı alamadığı için işlemin başarısız olduğunu sanır ve tekrar deneme (retry) kuralı gereğince aynı isteği yeniden postalar.
5. Sunucu bunu tamamen "yeni bir ödeme" gibi karşılar ve bakiyeyi ikinci kez düşer!

Kesin Çözüm: Idempotency-Key Deseni (Stripe / IETF Standardı)
1. **İstemci Tarafı:** Mobil uygulama, ödeme butonuna basıldığı anda istemci tarafında bir UUIDv4 üretir ve isteğe başlık olarak ekler:
   `Idempotency-Key: e82b203c-7729-4d64-9418-2e0f4cb7331c`
2. **Atomik Kilit (Distributed Lock):** Sunucu isteği aldığında Redis üzerinde bu anahtarla dağıtık kilit (`SET key in_progress NX EX 30`) edinir. Aynı anda gelen paralel istekler (Race Condition) anında `409 Conflict` ile engellenir.
3. **Özet Doğrulama (Payload Fingerprint):** Gövdenin SHA-256 özeti alınır. Eğer aynı anahtarla farklı bir tutar veya hesap gönderilirse işlem reddedilir (`422 Unprocessable Entity`).
4. **Yanıtın Önbelleğe Alınması:** İşlem başarıyla bittiğinde, üretilen yanıt (`status_code`, `headers`, `body`) bu anahtarla 24 saat boyunca önbelleğe yazılır.
5. **Yeniden Denemede Önbellek Dönüşü:** Zaman aşımına uğrayıp ikinci kez aynı anahtarla gelen istekte, **bankacılık mantığı ve para düşüm kodu ASLA çalıştırılmaz!** Doğrudan önbellekteki ilk başarılı yanıt (`Idempotent-Replayed: true` başlığı ile) dönülür.

### Kritik Güvenlik Çıkarımı
FinTech ve e-ticaret dünyasında `POST` isteklerine Idempotency mekanizması kurmamak, sisteme kasıtlı olarak finansal açık (Race Condition & Double Spend) bırakmakla eşdeğerdir. Ağ katmanında paketlerin kaybolması veya yinelenmesi kaçınılmaz bir fizik kuralıdır; yazılım mimarisi bu yinelenmeleri güvenle karşılayabilmelidir.

### Savunma / Uygulama Kontrol Listesi
- [ ] Para transferi, kredi kartı tahsilatı, sipariş oluşturma gibi tüm durum değiştiren `POST` uç noktalarında `Idempotency-Key` başlığını zorunlu kılın.
- [ ] Dağıtık önbellekte (Redis vb.) her anahtar için gövde özeti (SHA-256 hash), HTTP durum kodu ve yanıt gövdesini saklayın (makul TTL: 24-48 saat).
- [ ] Eşzamanlı yarış durumlarını (Race Condition) önlemek için işlem başında `IN_PROGRESS` kilidi koyun.
- [ ] Önbellekten dönülen yinelenen yanıtlara `Idempotent-Replayed: true` başlığı ekleyerek istemci tarafındaki analitiği ve loglamayı netleştirin.
- [ ] Aynı anahtarla farklı gövde gönderilmesini (Key Tampering) tespit ederek `409 Conflict` veya `422 Unprocessable Entity` ile reddedin.

---

## Senaryo G058-SC2: HTTP Verb Tampering (Metot Değiştirme) ile Kimlik Doğrulama Atlatma ve Güvenli ACL Tasarımı

### Soru / Senaryo
Bir web güvenlik denetiminde analistler, şirketin intranetindeki gizli bir yönetim paneline (`/admin/system/users`) erişmeyi başarmıştır. Uygulamanın önündeki Web Application Firewall (WAF) ve web sunucu yetkilendirme yapılandırmasında şu kural yer almaktadır:
`<Limit POST GET> require valid-user admin </Limit>`
Yetkisiz bir saldırgan, tarayıcısında veya komut satırında isteği `HEAD /admin/system/users` veya `OPTIONS` olarak değiştirdiğinde güvenlik filtresinin devre dışı kaldığını ve arkadaki uygulamanın kullanıcı listesini döndürdüğünü görmüştür. Bu zafiyet nasıl oluşmuştur ve erişim denetimi mimarisi nasıl düzeltilmelidir?

### Ustanın Cevabı / Çözüm Yaklaşımı
Evladım, bu zafiyet siber güvenlik literatüründe **HTTP Verb Tampering (Metot Kurcalama / Atlatma)** olarak adlandırılır.

Zafiyetin Kök Nedeni:
Web sunucusu veya WAF yapılandırmasında geliştirici "İzin Verilen / Korunan Metotlar" listesi (Allow-list) yerine hatalı bir mantıkla sadece akla gelen `GET` ve `POST` metotlarını korumaya almıştır. Ancak HTTP standardında `HEAD`, `OPTIONS`, `PUT`, `DELETE`, `TRACE` ve hatta RFC dışı rastgele metotlar (`CUSTOM`, `FOO`) gönderilebilir.
1. Güvenlik filtresi gelen pakete bakar: Metot `HEAD` midir? Evet. Kuralda `HEAD` yazıyor mu? Hayır, sadece `POST GET` yazıyor.
2. Filtre: *"O zaman bu kural bu isteği bağlamaz, geçsin"* der ve isteği web sunucusuna iletir.
3. Arka plandaki zayıf web çerçevesi (framework) ise `HEAD` isteğini `GET` gibi yorumlayıp kodunu çalıştırır ve veriyi hazırlar (veya Apache/Tomcat gibi sunucularda kimlik denetimini tamamen baypas ederek içerik sunar).

Çözüm Yaklaşımı:
1. **Varsayılan Olarak Yasakla (Deny-by-Default):** Güvenlik kuralları metot bazlı değil, **URL/Yol bazlı** tanımlanmalıdır. `/admin/*` yoluna gelen HERHANGİ bir istek kimlik doğrulamasına tabi tutulmalıdır.
2. **Kullanılmayan Metotların Küresel Olarak Kapatılması:** Uygulamanın yalnızca `GET` ve `POST` ihtiyacı varsa; `TRACE`, `CONNECT`, `PUT`, `DELETE` gibi metotlar sunucu seviyesinde tamamen devre dışı bırakılmalıdır (`405 Method Not Allowed`).
3. **Java web.xml Sıkılaştırması:** `<http-method>` yerine `<http-method-omission>` kullanılarak veya hiçbir metot filtresi belirtilmeyerek tüm HTTP fiilleri koruma altına alınmalıdır.

### Kritik Güvenlik Çıkarımı
Güvenlik filtrelerinde pozitif liste (Whitelisting) yerine kısmi listeler kullanmak felakettir. Bir saldırgan HTTP standardının sunduğu tüm meşru veya gayrimeşru metot alternatiflerini dener. Bir URL korunuyorsa, oraya hangi fiille (GET, POST, HEAD, PUT) gelinirse gelinsin kapı kapalı olmalıdır!

### Savunma / Uygulama Kontrol Listesi
- [ ] Web sunucu (Nginx/Apache) ve framework seviyesinde kullanılmayan metotları (TRACE, TRACK, CONNECT vb.) küresel olarak engelleyin.
- [ ] Yetkilendirme ve kimlik doğrulama filtrelerini (Authentication Filters) HTTP metotlarından bağımsız olarak tüm URL yollarına uygulayın.
- [ ] Java/Tomcat ortamlarında `web.xml` içinde tek tek `<http-method>` tanımlamaktan kaçının.
- [ ] API Gateway üzerinde yalnızca OpenAPI/Swagger şemasında tanımlı olan metotların geçişine izin veren katı bir şema doğrulayıcı çalıştırın.
- [ ] Zafiyet taramalarında `nmap --script http-methods` ile tüm sistemlerde açık metotları periyodik denetleyin.

---

## Senaryo G058-SC3: GET ile Durum Değiştirme (State-Changing GET) Anti-Pattern'ı ve Tarayıcı Ön-Yükleme (Prefetching) Zafiyeti

### Soru / Senaryo
Popüler bir kurumsal insan kaynakları yazılımında, bir personeli işten çıkarmak veya izin talebini onaylamak için arayüzde şu şekilde bir bağlantı (link) kullanılmıştır:
`<a href="/employees/terminate?id=455&token=xyz">Çalışanı Sil</a>`
Şirket yöneticisi Google Chrome kullanırken, internet hızlandırıcı ve "Önceden Yükle (Page Prefetching)" eklentisi tarayıcıda aktiftir. Yönetici personel listesi sayfasını açtığında fareyi hiçbir linkin üzerine getirmemesine rağmen, birkaç saniye içinde sistemdeki 20 çalışanın işten çıkarıldığı görülmüştür! Dahası, bu link bir şirket içi sohbet grubuna atıldığında, linkin önizlemesini (link preview) çeken sohbet botunun da personeli sildiği anlaşılmıştır. Bu felaketin sebebi nedir ve mimari nasıl düzeltilir?

### Ustanın Cevabı / Çözüm Yaklaşımı
Evladım, bu olay yazılım geliştirme dünyasındaki en utanç verici anti-pattern'lardan biridir: **GET Metodunun Durum Değiştirici Olarak Kullanılması (RFC 7231 İhlali)**.

Mekanizma Nasıl Çöktü?
1. **RFC 7231 §4.2.1 İhlali:** HTTP standardı der ki: *"GET güvenli (Safe) bir metottur. GET isteği sunucunun durumunu değiştiremez, veri silemez veya finansal işlem tetikleyemez."*
2. **Tarayıcı ve Bot Davranışı:** Google Chrome, arama motoru örümcekleri (Googlebot) ve Slack/Teams gibi sohbet uygulamalarının önizleme robotları, sayfada gördükleri tüm `<a>` linklerine arka planda sessizce birer **`GET`** isteği gönderirler. Çünkü standarda göre GET güvenlidir, veri okumaktan başka bir zarar vermez!
3. **Felaket:** Yazılımcı silme işlemini `GET` ile tetiklediği için; Chrome eklentisi sayfayı hızlı açmak amacıyla sayfadaki tüm silme linklerine önden GET basmış ve personelleri sistemden temizlemiştir!

Mimari Çözüm:
1. **Metot Semantiğine Mutlak İtaat:** Durum değiştiren (Create, Update, Delete) HER işlem kesinlikle `POST`, `PUT`, `DELETE` veya `PATCH` metoduyla yapılmalıdır.
2. **Form veya AJAX Kullanımı:** Arayüzde basit bir `<a>` etiketi yerine; CSRF token korumalı bir form butonu veya JavaScript `fetch(..., {method: 'DELETE'})` çağrısı kullanılmalıdır.
3. **Çift Onay (Confirmation Dialog) ve POST:** Kritik işlemler asla doğrudan bir GET bağlantısıyla tetiklenmemelidir.

### Kritik Güvenlik Çıkarımı
İnternet mimarisi (tarayıcılar, önbellekler, arama motorları, CDN'ler) RFC 7231 metot semantiği üzerine kuruludur. GET metoduna yıkıcı bir yan etki yüklemek, tüm internet ekosistemini (arama motorları, proxy'ler, tarayıcı hızlandırıcılar) istemeden birer Hizmet Engelleme (DoS) veya veri silme silahına dönüştürmek demektir.

### Savunma / Uygulama Kontrol Listesi
- [ ] Kod tabanında statik kod analizi (SAST) ile veri silen veya güncelleyen tüm GET rotalarını denetleyin ve yasaklayın.
- [ ] Durum değiştiren tüm API uç noktalarında `POST`, `PUT`, `PATCH`, `DELETE` metotlarını zorunlu kılın; GET geldiğinde `405 Method Not Allowed` dönün.
- [ ] Web arayüzlerinde silme/güncelleme işlemleri için link (`<a>`) yerine CSRF korumalı `<form method="POST">` veya güvenli buton bileşenleri kullanın.
- [ ] Önbellek ve CDN sistemlerinde GET isteklerinin önbelleğe alınmasını sağlarken, arka planda veri tabanını tetikleyen sahte GET isteklerini mimariden arındırın.
