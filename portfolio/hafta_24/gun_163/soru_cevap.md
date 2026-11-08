# Gün 163: NoSQL ve ORM Sınırları — Mülakat ve Teknik Soru-Cevap Rehberi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

### Soru:
1. NoSQL veritabanlarında (örneğin MongoDB) SQL sözdizimi olmamasına rağmen nasıl enjeksiyon zafiyeti (NoSQL Injection) oluşur? Bir saldırgan `$ne` veya `$regex` operatörleri ile kimlik doğrulamayı nasıl aşabilir?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın SQLi ile NoSQLi arasındaki temel mekanizma farkını kavrayıp kavramadığını ölçüyorum. Birçok aday NoSQL'in injection'a bağışık olduğunu zanneder. Adaydan; istemciden gelen JSON/BSON gövdesinin tipleriyle birlikte (nesne/sözlük olarak) ayrıştırılıp doğrudan sürücünün sorgu metoduna verilmesi durumunda, MongoDB operatörlerinin (`$ne`, `$gt`, `$regex`) birer filtre mantığı olarak çalıştığını ve parolayı bilmeden `True` şartı oluşturduğunu veya karakter karakter kör sızdırma yapabildiğini teknik seviyede anlatmasını bekliyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
NoSQL enjeksiyonu, SQL'deki metin birleştirme yerine **veri tipi ve nesne yapısı manipülasyonu** ile meydana gelir. Express.js veya Flask gibi çatılarda gelen JSON gövdesi ayrıştırıldığında bir alanın değeri dize yerine sözlük nesnesi olabilir. Örneğin `{"username": "admin", "password": {"$ne": ""}}` gönderildiğinde, MongoDB sorgu motoru bunu *"parola boş string'e eşit olmayan admin kullanıcısı"* olarak değerlendirir. Admin hesabının parolası dolu olduğu için bu şart daima `True` döner ve parola doğrulanmadan kimlik aşılır. `$regex` ile ise saldırgan `^a.*`, `^b.*` şeklinde düzenli ifadeler göndererek sistemin dönütüne (başarılı/başarısız HTTP yanıtı) göre gizli parolaları harf harf çıkartabilir.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
NoSQL enjeksiyonunun kök nedeni, HTTP katmanındaki dinamik JSON parser ile veritabanı sürücüsü arasındaki **tip varsayımı uyuşmazlığıdır**. Geliştirici `req.body.password` alanının bir `string` olduğunu varsayar. Ancak JSON standardında bir anahtarın değeri bir obje (`{}`) olabilir. MongoDB sürücüsü (örneğin Mongoose veya PyMongo), sorgu nesnesinde bir anahtarın değeri sözlük olduğunda ve anahtar `$` ile başladığında onu bir sorgu operatörü olarak yürütür.
Savunmada yalnızca dize kaçırma (string escaping) işe yaramaz; çünkü saldırgan tırnak işareti kullanmamaktadır! Asıl savunma, **Katı Tip Denetimi (Type Enforcement)** ile gelen parametrenin kesinlikle bir ilkel veri tipi (`str`, `int`) olduğunu doğrulamak ve `$` ya da `.` içeren tüm nesne yapılarını reddetmektir.

---

### Soru:
2. ORM (Object-Relational Mapping) kullanılan bir projede Kütlesel Atama (Mass Assignment / Over-Posting) zafiyeti nasıl ortaya çıkar ve saldırgan bu zafiyeti kullanarak nasıl yetki yükseltebilir?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın sadece veritabanı sorgularına değil, uygulama mimarisine ve veri transfer katmanına hakim olup olmadığını test ediyorum. ORM'lerin veritabanı modellerini otomatik doldurma (auto-binding) özelliğinin kötüye kullanımını, model ile DTO (Data Transfer Object) arasındaki farkı ve saldırganın HTTP gövdesine gizlice eklediği `is_admin`, `role`, `balance` gibi kritik alanların nasıl istismar edildiğini bilmesini istiyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
Kütlesel Atama, istemciden gelen HTTP istek gövdesindeki tüm alanların hiçbir filtreleme veya beyaz liste denetiminden geçirilmeksizin doğrudan ORM modeline atanması (binding) durumunda oluşur. Örneğin bir profil güncelleme formunda kullanıcı yalnızca `ad_soyad` ve `telefon` alanlarını görür. Ancak bir saldırgan HTTP PUT isteğine elle `{"is_admin": true, "role": "ADMIN", "balance": 999999}` parametrelerini ekler. Eğer backend bu JSON nesnesini doğrudan veritabanı modeline yazıp `commit` ederse, saldırgan yetkisiz bir şekilde sistem yöneticisi olur veya bakiyesini manipüle eder.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
Mass Assignment, MVC ve modern REST API mimarilerinde çok yaygındır (GitHub'ın 2012'de Egor Homakov tarafından hacklenmesi bu zafiyetle gerçekleşmiştir).
Kritik ayrım şudur: **ORM veritabanı modelinin sorumluluğu veri kalıcılığıdır; API kabul edilebilirliğinin sınırını çizmek değildir.**
Savunma için:
1. **Asla modeli doğrudan bağlama:** İstek gövdesi asla doğrudan model örneğine kopyalanmamalıdır.
2. **DTO / Form Request Kullanımı:** Her uç nokta için yalnızca güncellenmesine izin verilen alanları içeren katı bir DTO (Data Transfer Object) beyaz listesi tanımlanmalıdır (Pydantic, Marshmallow, Spring DTO, NestJS DTO).
3. **Model Düzeyinde Korumalar:** Rails'deki `strong_parameters` veya C#'taki `[Bind]` öznitelikleri gibi framework düzeyinde izinli alan kısıtlamaları uygulanmalıdır.

---

### Soru:
3. MongoDB'de `$where` operatörünün doğurduğu güvenlik riskleri nelerdir ve NoSQL mimarilerinde "Path Pollution" (Nokta Notasyonu ile Nesne Yolu Manipülasyonu) nasıl engellenir?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Adayın NoSQL'in derin iç mimarisini bilip bilmediğini sınıyorum. `$where` operatörünün veritabanı içinde JavaScript kodunu `eval` benzeri çalıştırdığını, bunun RCE ve DoS riskleri taşıdığını; nokta notasyonunun (`profile.role`) ise gömülü nesnelerde beklenmeyen alanları ezerek yetki atlatmalarına yol açtığını bilmesini bekliyorum.

### Doğru Yanıt (Çırak / Aday İfadesi)
`$where` operatörü, MongoDB'nin sunucu tarafında JavaScript kod parçacıklarını çalıştırmasına izin veren bir mekanizmadır. Kullanıcı girdisi bu operatöre ulaştığında, SQL'deki kod enjeksiyonunun NoSQL'deki tam karşılığı olan Server-Side JavaScript Injection oluşur. Bu durum DoS, bellek kilitlenmesi ve veritabanı sunucusunda kod yürütme riski taşır. Nokta notasyonu (`a.b.c`) manipülasyonu ise, saldırganın anahtar isimlerini dinamik olarak ileterek iç içe geçmiş nesnelerin korumalı alanlarını (`profile.is_admin`) sorgulamasına veya ezmesine imkan tanır. Savunmada `$where` operatörü veritabanı seviyesinde tamamen kapatılmalı (`--noscripting`), anahtarlarda nokta karakteri (`.`) kesinlikle yasaklanmalı ve katı bir alan şeması uygulanmalıdır.

### Derinlemesine Teknik Analiz ve Kritik Ayrım
`$where` kullanımı, veritabanının indeksleme mekanizmasını devre dışı bırakır ve her belge için JS motorunu (SpiderMonkey/V8) tetikler. Bu nedenle saldırgan bir regex veya karmaşık matematik döngüsü göndererek CPU tüketimini %100'e kilitleyip DoS gerçekleştirebilir.
Path Pollution ise NoSQL'in esnek şema yapısının bir yan etkisidir. MongoDB, iç içe nesneleri düzleştirmek için nokta notasyonunu standart kabul eder. Eğer sorgu parametrelerinin anahtarları güvenilmeyen kaynaktan dinamik alınıyorsa (örn. `user_input_key: value`), saldırgan `auth.permissions.can_delete` gibi dahili bir anahtarı tetikleyebilir.
Bu nedenle:
1. Veritabanı başlatılırken `--noscripting` bayrağı ile JavaScript çalıştırma motoru devre dışı bırakılmalıdır.
2. Sorgu ve güncelleme anahtarları `^[a-zA-Z0-9_]+$` regex'i ile denetlenmeli, `$` ve `.` karakterleri kesinlikle reddedilmelidir.
