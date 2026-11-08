# Gün 162: SQL Injection Neden Oluşur? - Mülakat Soru & Cevap Paketi

---

### Soru:
SQL Injection (SQLi) zafiyetinin bilgisayar bilimleri ve derleyici teorisi (compiler theory) açısından temel kök nedeni nedir? Neden kullanıcı girdisindeki tehlikeli karakterleri temizlemeye veya kaçışa (escaping) tabi tutmaya dayalı kara liste yaklaşımları kesin bir çözüm sunamaz?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Mülakatçı; adayın SQLi'yi sadece "kötü karakterlerin temizlenmemesi" olarak gören sığ bir bakış açısına mı sahip olduğunu, yoksa derleyici ve yorumlayıcı düzeyinde "Kod ve Veri Ayrımı" (Code vs. Data Ambiguity / Equivalence) ilkesini kavrayıp kavramadığını ölçmek ister. Adayın, bir yorumlayıcıya dinamik dize gönderildiğinde sözcüksel analiz (lexer) ve sözdizim ağacı (AST) seviyesinde verinin komuta dönüşmesini matematiksel bir kesinlikle anlatmasını ve kaçış algoritmalarının karakter kodlamaları (Unicode, çok baytlı karakterler, veritabanı motoru ayrıştırma nüansları) karşısında neden çöktüğünü ifade etmesini bekler.

### Doğru Yanıt (Çırak / Aday İfadesi)
"SQL Injection'ın temel kök nedeni, bir programlama dilinin veya yorumlayıcının **yürütülebilir komut yapısı (Kod) ile işlenen girdiyi (Veri) aynı metin akışında birleştirmesidir** (Code vs. Data Ambiguity).

Dinamik dize birleştirme (`"SELECT ... WHERE user = '" + input + "'"`):
1. Veritabanının Sözcüksel Analizcisi (Lexer) metni okurken tırnak karakteri ile veri sınırından çıkar.
2. Ardından gelen `OR`, `UNION` veya `DROP` kelimelerini birer sözdizimsel anahtar kelime (token) olarak etiketler.
3. Sözdizim Ayrıştırıcısı (Parser) bu token'ları kullanarak Soyut Sözdizim Ağacını (AST - Abstract Syntax Tree) saldırganın lehine yeniden yapılandırır. Kodun çalışma mantığı tahrif edilmiş olur.

**Kara Liste ve Kaçış Neden Çözüm Değildir?**
Karakter temizleme (blacklisting) veya kaçış (escaping) yöntemleri temelde yetersizdir çünkü:
- *Bağlam Bağımlılığı:* Sayısal alanlarda (`WHERE id = " + id`) tırnak işareti gerekmez; dolayısıyla tırnak kaçışı sayısal enjeksiyonu (`id = 1 OR 1=1`) engelleyemez.
- *Karakter Kodlama Çakışmaları:* GBK, Big5 gibi çok baytlı karakter setlerinde `0xbf27` gibi dizilimler ters bölüyü (`\`) yutarak tırnak filtresini bypass edebilir (Null Byte / Multi-byte encoding bypass).
- *Tek Çözüm:* Kodu ve veriyi fiziksel veya mantıksal olarak iki ayrı kanaldan ileten **Parametrik Sorgular (Prepared Statements)** kullanmaktır."

### Derinlemesine Teknik Analiz ve Kritik Ayrım
- **Derleyici Teorisi Açısından AST Karşılaştırması:**
  - *Dinamik Birleştirmede:*
    ```
    BinaryOp (OR)
    ├── BinaryOp (AND)
    │   ├── Compare (username = 'admin')
    │   └── Compare (password = '')
    └── Compare ('1' = '1')  <-- Saldırganın AST'ye eklediği yeni mantık dalı!
    ```
  - *Prepared Statement'ta:*
    Sorgu motoru `SELECT ... WHERE username = ? AND password = ?` şablonunu önceden derler. AST düğümleri sabittir: `Compare(username, PARAM_0)` ve `Compare(password, PARAM_1)`. Kullanıcı `"admin' OR '1'='1"` girdiğinde, bu dize AST'ye yeni bir düğüm olarak eklenemez; yalnızca `PARAM_0` yaprağının içindeki düz bir metin literali olarak kalır.
- **Kritik Ayrım:**
  Girdi temizleme (sanitization) bir savunma derinliği tedbiridir, ancak SQLi'nin birincil çözümü değildir. Birincil çözüm her zaman AST'nin değiştirilmesini imkansız kılan parametrik bağlamadır.

---

### Soru:
Prepared Statements (Parametrik Sorgular) veritabanı sürücüsü ve veritabanı sunucusu seviyesinde ikili (binary) protokolde nasıl işletilir? Kullanıcı `' OR '1'='1` girdiğinde veritabanı motoru neden bu ifadeyi mantıksal bir şart olarak değerlendirmez?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Mülakatçı; adayın "veritabanı kütüphanesinin tırnakları otomatik escape ettiği" şeklindeki yaygın yanlış bilgiyi mi taşıdığını, yoksa modern veritabanlarında (PostgreSQL Extended Query Protocol, MySQL Binary Protocol vb.) sorgunun iki ayrı ağ paketinde (Prepare / Parse ve Execute / Bind) nasıl işlendiğini bilip bilmediğini test eder.

### Doğru Yanıt (Çırak / Aday İfadesi)
"Modern veritabanlarında Prepared Statement mekanizması tırnak kaçışıyla çalışmaz; sorgunun iki ayrı protokol aşamasında yürütülmesiyle çalışır:
1. **Hazırlık / Derleme Aşaması (PREPARE / PARSE):**
   Uygulama sunucusu veritabanına SQL şablonunu gönderir: `SELECT * FROM users WHERE username = $1 AND password = $2`. Veritabanı motoru bu sorguyu sözcüksel ve sözdizimsel olarak ayrıştırır, AST'yi oluşturur, indeks optimizasyonunu tamamlar ve bellekte bir 'Sorgu Planı' (Execution Plan) hazırlar. Bu aşamada henüz hiçbir kullanıcı verisi yoktur.
2. **Bağlama ve Çalıştırma Aşaması (BIND / EXECUTE):**
   Kullanıcı girdileri (`"admin' OR '1'='1"`) veritabanına ayrı bir ikili (binary) veri paketi içinde gönderilir. Veritabanı motoru bu veriyi doğrudan daha önce derlenmiş olan sorgu planındaki `$1` yer tutucusuna yerleştirir.

Kullanıcının girdisindeki `'` tırnakları veya `OR` kelimesi, veritabanı motorunun ayrıştırıcısına (parser) ASLA uğramaz. Veritabanı bu girdiyi, adı tam olarak `admin' OR '1'='1` olan bir kullanıcı var mı diye arar. Böyle bir kullanıcı bulunamayacağı için sorgu sıfır kayıt döner ve saldırı %100 başarısız olur."

### Derinlemesine Teknik Analiz ve Kritik Ayrım
- **İstemci Tarafı Emülasyonu Tuzağı (Client-Side Prepared Statement):**
  Bazı veritabanı sürücülerinde (ör. PHP PDO'nun eski varsayılanı `PDO::ATTR_EMULATE_PREPARES = true`) gerçek sunucu taraflı parametrik sorgu kullanılmaz. Sürücü sorguyu sunucuya göndermeden önce istemci tarafında dize kaçışı yaparak birleştirir. Eğer karakter kodlaması doğru ayarlanmamışsa bu durum zafiyete yol açabilir. Bu nedenle kurumsal sistemlerde emülasyon kapatılmalı ve sunucu taraflı gerçek prepared statement (`PDO::ATTR_EMULATE_PREPARES = false`) zorunlu kılınmalıdır.
- **Kritik Ayrım:**
  Parametrik sorgularda veri türü (data type) kesin olarak tanımlıdır. Eğer parametre tamsayı (`INTEGER`) olarak tanımlanmışsa, string girilse bile veritabanı protokol seviyesinde tip uyuşmazlığı hatası üretir.

---

### Soru:
Bir kurumsal projede ORM (örneğin SQLAlchemy, Hibernate, Entity Framework) ve Stored Procedure kullanılmasına rağmen SQL Injection açığı nasıl ortaya çıkabilir? Özellikle dinamik sıralama (`ORDER BY`), tablo adı belirleme ve dinamik arama filtrelerinde geliştiricilerin sıklıkla düştüğü mimari tuzaklar nelerdir?

### Mülakatçı Ne Duymak İstiyor? (Usta Bakışı)
Mülakatçı; adayın "Biz ORM kullanıyoruz, dolayısıyla SQLi açığımız olamaz" yanılgısına düşüp düşmediğini sınar. Adayın, ORM'lerin sağladığı kolaylığın yanı sıra ham (raw) SQL kaçış noktalarını, dinamik sıralama (`ORDER BY`) parametrelerinin neden Prepared Statement ile korunamadığını ve Stored Procedure'ler içinde dinamik SQL (`EXECUTE IMMEDIATE`) kullanmanın oluşturduğu riskleri örneklerle açıklamasını bekler.

### Doğru Yanıt (Çırak / Aday İfadesi)
"ORM veya Stored Procedure kullanmak tek başına SQL Injection'a karşı mutlak bir bağışıklık sağlamaz. Zafiyet genellikle şu senaryolarda ortaya çıkar:

1. **ORM İçinde Ham (Raw) SQL veya Güvensiz Metot Kullanımı:**
   Karmaşık raporlama sorgularında geliştiriciler ORM'in sınırlarını aşmak için ham SQL çağrıları yapar. Örneğin Django'da `extra(where=[f"status = '{user_input}'"])` veya SQLAlchemy'de `text(f"SELECT ... WHERE id = {user_input}")` yazıldığı an tüm ORM koruması devre dışı kalır.
2. **Dinamik Belirteçler (Table / Column Names & ORDER BY):**
   SQL standardı gereği Prepared Statement'lar yalnızca **veri değerlerini** parametre yapabilir. Tablo adları (`FROM ?`) veya kolon adları (`ORDER BY ?`) parametre olarak bağlanamaz; çünkü veritabanı sorgu planını derlerken hangi tablodan ve kolondan veri okuyacağını bilmek zorundadır. Geliştirici kullanıcıdan gelen sıralama girdisini dize olarak yapıştırdığında (`order_by(user_input)`), saldırgan `balance; DROP TABLE users;` veya kör zaman tabanlı enjeksiyon (`CASE WHEN (1=1) THEN id ELSE balance END`) enjekte edebilir.
3. **Stored Procedure İçinde Dinamik SQL:**
   Saklı yordam parametrik çağrılsa bile, yordamın gövdesi içinde dize birleştirme ile dinamik komut çalıştırılıyorsa (`EXECUTE IMMEDIATE 'SELECT ... WHERE id = ' || p_id`), SQLi aynen devam eder."

### Derinlemesine Teknik Analiz ve Kritik Ayrım
- **Dinamik Belirteçler İçin Doğru Savunma Mimarisi:**
  Dinamik kolon veya tablo seçimi gereken durumlarda uygulanacak tek geçerli yöntem **Katı Beyaz Liste (Allowlist Mapping)** modelidir:
  ```python
  # KESİN GÜVENLİ MİMARİ
  ALLOWED_SORT_FIELDS = {
      "tarih": "created_at",
      "tutar": "amount",
      "kullanici": "username"
  }
  # Kullanıcı girdisi harici ise güvenli varsayılana dönülür
  sort_column = ALLOWED_SORT_FIELDS.get(request.args.get("sort"), "created_at")
  query = f"SELECT * FROM transactions ORDER BY {sort_column} ASC"
  ```
- **Kritik Ayrım:**
  ORM'in varlığı geliştiriciyi dikkatli olma sorumluluğundan kurtarmaz. ORM kullanırken de her zaman parametrik bağlayıcılar (`params={"val": user_input}`) kullanılmalı ve dinamik belirteçler için haritalama (mapping) uygulanmalıdır.
