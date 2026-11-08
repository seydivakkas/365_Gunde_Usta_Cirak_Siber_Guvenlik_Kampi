# Gün 162: SQL Injection Neden Oluşur? (Kök Neden ve Parametrik Savunma)

## Usta-Çırak Başlangıç Hasbihali
**Usta:** Evlat, bugün bilişim güvenliği tarihinin en eski, en bilinen ve maalesef hala en çok can yakan zafiyetine adım atıyoruz: SQL Injection (SQLi - CWE-89). Otuz yıldır her güvenlik rehberinde anlatılır, her üniversitede dersi verilir; ama yine de devasa şirketler veritabanlarını saldırganlara kaptırmaya devam eder. Sence neden?

**Çırak:** Ustam, geliştiriciler kullanıcı girdisindeki tek tırnakları (`'`) ve tireleri (`--`) temizlemeyi unuttukları için mi?

**Usta:** Hayır evlat! İşte en temel hata tam olarak bu düşünce tarzıdır. SQL Injection bir "karakter filtreleme" sorunu değildir. SQL Injection, bilgisayar bilimlerinin en köklü mimari açmazlarından biridir: **"Kod ile Verinin Birbirine Karışması" (Code vs. Data Ambiguity)**. Bir veritabanı motoruna bir SQL sorgusu gönderdiğinde, motor o cümlenin neresinin emir (komut/kod), neresinin ise işlenecek ham malzeme (veri) olduğunu ayırt etmek zorundadır. Sen `"SELECT * FROM users WHERE user = '" + input + "'"` yazdığın an, kullanıcıdan gelen veriyi derleyicinin sözdizim ağacına (AST - Abstract Syntax Tree) bir komut parçası olarak enjekte etmiş olursun. Bugün seninle SQL enjeksiyonunun felsefi ve matematiksel kök nedenini, saldırı varyantlarını ve gerçek çözümü olan Parametrik Sorguları (Prepared Statements) en ince detayına kadar inceleyeceğiz.

---

## 1. SQL Injection'ın Kök Nedeni: Kod ve Veri Karışımı

```
+-----------------------------------------------------------------------------------+
|                        KOD VE VERİ AYRIŞIMI PROBLEMİ                              |
+-----------------------------------------------------------------------------------+
| 1. Dinamik Dize Birleştirme (Hatalı Yaklaşım):                                    |
|    "SELECT * FROM users WHERE username = '" + INPUT + "'"                         |
|    Eğer INPUT = "admin' OR '1'='1" ise:                                           |
|    SQL Motoru: Metin ayrıştırılırken tek tırnak kapanır, 'OR' bir mantıksal       |
|    operatör (KOD) olarak AST düğümüne eklenir. Sorgunun yapısı değişir!           |
+-----------------------------------------------------------------------------------+
| 2. Parametrik Sorgu / Prepared Statement (Doğru Yaklaşım):                        |
|    "SELECT * FROM users WHERE username = ?"                                       |
|    SQL Motoru: Sorgu şablonu ve mantık ağacı (AST) ÖNCEDEN DERLENİR ve SABİTLENİR.|
|    INPUT = "admin' OR '1'='1" -> Parametre kanalından gönderilir.                |
|    SQL Motoru: Girdiyi asla komut olarak görmez; içinde tırnak veya OR olan       |
|    tek bir ham dize (VERİ) olarak kullanıcı tablosunda arar. Giriş engellenir!   |
+-----------------------------------------------------------------------------------+
```

### 1.1 Veritabanı Ayrıştırma Ağacı (Abstract Syntax Tree - AST) Nasıl Manipüle Edilir?
Bir SQL motoru (PostgreSQL, MySQL, Oracle, SQLite) bir metin sorgusu aldığında şu aşamalardan geçer:
1. **Sözcüksel Analiz (Lexical Analysis / Tokenization):** Metin anahtar kelimelere (`SELECT`, `FROM`, `WHERE`), belirteçlere (`users`, `username`) ve değişmezlere (literals) bölünür.
2. **Sözdizimsel Analiz (Parsing / AST Generation):** Token'lar bir mantık ağacına dönüştürülür.
3. **Sorgu Optimizasyonu ve Yürütme Planı:** AST üzerinden en uygun indeks ve tarama algoritması seçilir ve çalıştırılır.

Geliştirici dize birleştirme (`format` veya `+`) yaptığında, saldırgan tırnak işareti (`'`) ile veri alanından dışarı fırlar (escape) ve doğrudan Sözcüksel Analiz aşamasına yeni SQL token'ları (`OR`, `UNION`, `DROP`) enjekte eder. SQL parser bu yabancı token'ları meşru komutlar olarak AST'ye ekler.

---

## 2. SQL Injection Varyantları ve Anatomisi

### 2.1 Mantıksal Totoloji ve Boolean Bypass
- **Örnek:** `admin' OR '1'='1`
- **Mekanizma:** `WHERE username = 'admin' AND password = '' OR '1'='1'`
- Mantık tablosunda `YANLIŞ AND YANLIŞ OR DOĞRU` ifadesi `DOĞRU` sonucunu verir. Veritabanı tablodaki ilk kaydı (genellikle `admin` kullanıcısını) döndürür ve kimlik doğrulama aşılır.

### 2.2 UNION Tabanlı SQL Injection
- **Örnek:** `' UNION SELECT 1, credit_card_number, cvv, 4, 5 FROM payments --`
- **Mekanizma:** Orijinal sorgunun kolon sayısı ve veri tipleri tespit edildikten sonra `UNION` operatörü ile uygulamanın erişmemesi gereken tamamen farklı bir tablodan veri çekilir ve tek bir sonuç kümesinde istemciye sızdırılır.

### 2.3 Hata Tabanlı (Error-Based) SQL Injection
- **Örnek:** `' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version))) --`
- **Mekanizma:** Sayfa veritabanı kayıtlarını doğrudan ekrana basmasa bile veritabanı hata mesajlarını kullanıcıya gösteriyorsa kullanılır. Veritabanının tip dönüştürme fonksiyonları kasıtlı olarak patlatılır ve hata metninin içine veritabanı şeması veya parola özetleri gömülür.

### 2.4 Kör (Blind) SQL Injection: Boolean ve Time-Based
Sayfada hiçbir veri veya hata mesajı görünmüyorsa:
- **Boolean Blind:** Sunucunun yanıtındaki ufak bir farktan (ör. "Kullanıcı bulundu" vs "Kullanıcı bulunamadı") yola çıkarak veritabanına Evet/Hayır soruları sorulur (`SUBSTRING(password, 1, 1) = 'a'`).
- **Time-Based Blind:** Veritabanına şart doğru olduğunda belirli bir süre uyuması emredilir (`IF(condition, SLEEP(5), 0)` veya `WAITFOR DELAY '0:0:5'`). Sunucunun HTTP yanıt süresi ölçülerek karakter karakter veri çalınır.

### 2.5 Yığılmış Sorgular (Stacked Queries)
- **Örnek:** `user'; DROP TABLE users; --`
- **Mekanizma:** Noktalı virgül (`;`) ile orijinal sorgu bitirilir ve veritabanı sürücüsü (ör. MSSQL veya PostgreSQL `pg_query`) çoklu komut yürütmeyi destekliyorsa ikinci bir yıkıcı komut çalıştırılır.

---

## 3. Kurumsal Savunma Stratejileri

### 3.1 Birincil Savunma: Parametrik Sorgular (Prepared Statements)
Tüm yazılım dillerinde (Python `sqlite3`, `psycopg2`, Java `PreparedStatement`, PHP `PDO`, C# `SqlCommand`) kural tektir:
- Sorgu şablonu veritabanına önceden gönderilir (`?` veya `$1` yer tutucularıyla).
- Veritabanı sorguyu derler ve planını dondurur.
- Parametreler ayrık bir ikili (binary) protokol kanalıyla gönderilir.
- Kullanıcı ne yazarsa yazsın (içinde 50 adet tırnak, `UNION`, `DROP` olsa dahi), veritabanı bunu yalnızca bir dize literali olarak ele alır.

### 3.2 Dinamik Belirteç Güvenliği (Table / Column Identifiers)
Prepared statement'lar yalnızca **değerleri (data values)** parametre yapabilir. Tablo adları (`FROM ?`) veya kolon adları (`ORDER BY ?`) parametre olarak bağlanamaz!
- **Hata:** Geliştirici kullanıcıdan gelen sıralama parametresini dize olarak yapıştırır: `ORDER BY " + sortColumn`.
- **Doğru Çözüm:** Katı Beyaz Liste (Allowlist) eşlemesi:
  ```python
  ALLOWED_COLUMNS = {"id": "id", "name": "full_name", "date": "created_at"}
  sort_col = ALLOWED_COLUMNS.get(user_input, "id") # Eşleşmezse varsayılan
  sql = f"SELECT * FROM items ORDER BY {sort_col} ASC"
  ```

### 3.3 En Az Yetki İlkesi (Principle of Least Privilege)
Web uygulamasının veritabanı kullanıcısına asla `DBA`, `sa` veya `root` yetkisi verilmemelidir. Tablo silme (`DROP`), şema değiştirme (`ALTER`) yetkileri kaldırılmalı; yalnızca uygulamanın ihtiyaç duyduğu `SELECT`, `INSERT`, `UPDATE` yetkileri tanımlanmalıdır.

---

## Usta Öğüdü ve Altın Kurallar
1. **"Kara Liste Filtreleri Birer İllüzyondur":** Tek tırnağı escape eden veya `OR` kelimesini silen fonksiyonlar yazma. Saldırgan `OORR`, URL kodlama (`%27`), Unicode varyantları veya Hex kodlamaları ile kara listeleri daima aşar. Çözüm filtre değil, Prepared Statement'tır.
2. **"Stored Procedure Kullanmak Otomatik Güvenlik Sağlamaz":** Eğer saklı yordam (Stored Procedure) içinde `EXECUTE IMMEDIATE 'SELECT ... ' || input` şeklinde dinamik SQL çalıştırılıyorsa, SQLi aynen devam eder.
3. **"ORM Kullanmak da Tam Kalkan Değildir":** SQLAlchemy veya Hibernate kullanırken `.raw()` veya `.extra(where=[...])` gibi ham SQL metotlarına girildiği an SQLi zafiyeti hortlar.
