# Gün 167: Path Traversal ve Dosya Erişimi — Usta-Çırak Derinlemesine Teknik Rehberi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

## 1. Usta Girişi: "Web Kök Dizininin Hapishane Duvarlarını Aşmak"

Evlat, bir web sunucusu kurduğunda dosyalarını belirli bir dizine koyarsın: örneğin `/var/www/html/` veya `/var/www/uploads/`.
Senin zihninde bu dizin tüm dünyadır. İstemcinin sadece bu dizindeki resimleri, PDF faturaları veya dokümanları görmesini istersin.

Ancak işletim sisteminin gözünde o dizin sadece devasa bir dosya ağacının küçük bir dalıdır!
O dalın yukarısında `/etc/passwd`, `/etc/shadow`, `/var/www/.env`, Windows tarafında ise `C:\Windows\win.ini` ve sistem kayıt kütükleri (Registry) yatar.

Eğer sen istemciden bir dosya adı alıp onu dosya sistemine doğrudan sorarsan:
`open("/var/www/uploads/" + filename)`
Saldırgan sana `fatura.pdf` yerine `../../../../etc/passwd` der!
İşletim sisteminin dosya yolu çözümleyicisi her `..` gördüğünde bir üst dizine tırmanır; ta ki kök dizine (`/`) ulaşana kadar. Sonra da `/etc/passwd` dosyasını çeker ve senin ellerinle saldırgana teslim eder!
İşte bu felaketin adı **Dizin / Yol Atlama (Path / Directory Traversal - CWE-22)**'dir.

Bugün bu derste basit `../` atlamalarından çift URL kodlamalarına, `os.path.join` fonksiyonunun meşhur tasarım tuzaklarından kanonik hapis (Canonical Jail) mimarisine kadar her ayrıntıyı ilmek ilmek işleyeceğiz.

---

## 2. Path Traversal Saldırı Vektörleri ve Tuzaklar

### 2.1 Tuzak 1: Meşhur `os.path.join` Tasarım Kusuru
Python, Node.js veya C#'ta geliştiricilerin en sık düştüğü ölümcül hata şudur:
*"Ben `os.path.join(BASE_DIR, user_filename)` kullanıyorum, güvenli birleştiriyor."*

Evlat, aç Python belgelerini oku! `os.path.join` ne der bilir misin?
> *"Eğer birleştirilen bileşenlerden biri mutlak bir yol ise (yani `/` veya Windows'ta `C:\` ile başlıyorsa), önceki tüm bileşenler atılır ve birleştirme o mutlak yoldan devam eder!"*

Yani geliştirici şunu yazar:
```python
base_dir = "/var/www/uploads"
user_input = "/etc/passwd"  # Saldırgan mutlak yol yolladı!
target = os.path.join(base_dir, user_input)
# target ARTIK "/var/www/uploads/etc/passwd" DEĞİLDİR!
# target DOĞRUDAN "/etc/passwd" OLUR!
```
Geliştirici yolu birleştirdiğini zannederken, `os.path.join` kök dizini çöpe atıp doğrudan sistem dosyasını açar!

### 2.2 Tuzak 2: Gevşek Dize Değiştirme (Non-Recursive String Replacement)
Geliştirici aklınca filtre yazar:
`clean_filename = filename.replace("../", "")`

Saldırgan ne yapar?
Şunu yollar: `....//....//etc/passwd`
Sen tek bir `replace("../", "")` çalıştırdığında:
`....//` içindeki ortadaki `../` silinir; geriye ne kalır?
Tam olarak **`../`** kalır!
Filtre kendi kendini temizleyerek saldırganın istediği payload'ı yeniden üretir!

### 2.3 Tuzak 3: URL ve Çift URL Kodlaması (Double Encoding)
Web sunucusu veya ters vekil sunucu (Reverse Proxy) URL'yi bir kez çözer.
Saldırgan karakterleri iki kez kodlar:
- `.` -> `%2e` -> `%252e`
- `/` -> `%2f` -> `%252f`
Saldırgan şunu gönderir:
`%252e%252e%252f%252e%252e%252fetc/passwd`
1. Proxy veya WAF `%252e`'yi görür. `%`'yi çözer ve uygulamaya `%2e%2e%2f` gönderir. WAF `..` görmediği için engellemez!
2. Backend uygulaması veya web framework'ü ikinci çözmeyi yapar: `%2e%2e%2f` -> `../../` olur ve dosya okunur!

### 2.4 Tuzak 4: Null Byte (%00) Enjeksiyonu
Özellikle C/C++ tabanlı eski dillerde veya eski PHP/Python modüllerinde dizeler sıfır baytı (`\0`) ile sonlandırılır.
Geliştirici uzantı kontrolü yapar:
`if not filename.endswith(".png"): error()`
Saldırgan şunu yollar:
`../../../../etc/passwd%00.png`
Kod bakar: `.png` ile bitiyor mu? Evet! Onaylar.
Dosya sistemi `open()` çağrısına gittiğinde C kütüphanesi `%00` karakterini görünce dizeyi orada keser ve `/etc/passwd` dosyasını açar!

---

## 3. Kurumsal Çok Katmanlı Savunma Mimarisi (Defense-in-Depth)

Evlat, dizin atlama saldırılarına karşı "kara liste" temizliği yapmak beyhudedir. Güvenlik, matematiksel ve mimari olarak garanti altına alınmalıdır:

### 3.1 Katman 1: Çok Geçişli URL Çözümlemesi (Multi-Pass Unquote)
Girdi, üzerinde hiçbir kontrol yapılmadan önce döngüsel olarak çözümlenir. İki veya daha fazla çözme gerektiren (Double Encoding) girdiler doğrudan kötü niyetli kabul edilerek reddedilir.

### 3.2 Katman 2: Saf Dosya Adı Beyaz Listesi (Strict Basename Whitelist)
Kullanıcının dosya sisteminde alt dizinlere erişmesine gerek yoksa, dosya adında hiçbir eğik çizgi (`/` veya `\`) bulunmasına izin verilmez:
```python
# Yalnızca alfanümerik, alt tire, tire ve nokta kabul edilir:
SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9_\-\.]+$")
if not SAFE_FILENAME_RE.match(filename):
    raise PermissionError("Geçersiz dosya adı formatı.")
```

### 3.3 Katman 3: Kanonik Hapis (Canonical Jail / Path Chroot)
Savunmanın kalbi burasıdır evlat!
Ne yaparsan yap, işletim sisteminden **mutlak fiziksel kanonik yolu (Realpath)** çözmesini isteyeceksin:

```python
base_canonical = os.path.realpath(BASE_DIR)
target_canonical = os.path.realpath(os.path.join(base_canonical, user_filename))

# Hedef yol temel dizinin alt kümesi mi?
common = os.path.commonpath([base_canonical, target_canonical])
if common != base_canonical:
    raise SecurityException("DİZİN HAPSİNDEN KAÇIŞ TESPİT EDİLDİ! Erişim reddedildi.")
```
Bu yöntem; `..`, `.` sembolik bağlar (symlinks) ve sürücü atlamalarının tümünü işletim sistemi düzeyinde çözümler. Hedef yol `base_dir` dışına taştığı milisaniyede `commonpath` eşleşmesi bozulur ve kapı kilitlenir!

### 3.4 Katman 4: Dosya Uzantısı Beyaz Listesi
Yalnızca önceden tanımlanmış iş uzantılarına (`.pdf`, `.png`, `.jpg`, `.docx`, `.txt`) izin verilir. `.env`, `.sh`, `.exe`, `.php` gibi uzantılar derhal elenir.

### 3.5 Katman 5: Dolaylı Referanslama (Indirect Object Reference / UUID Mapping)
En mükemmel yöntem: Kullanıcıya dosya sistemindeki adı asla göstermemektir!
Veritabanında rastgele bir UUID tutulur:
`UUID: e4b2d1... -> Disk Yolu: /var/www/kurumsal_depo/fatura_99.pdf`
Kullanıcı dosyayı `GET /download?id=e4b2d1...` ile ister. Kullanıcı disk yolunu veya dosya adını hiç görmediği için hiçbir enjeksiyon yapamaz!

---

## 4. Çırağa Altın Kurallar
1. `os.path.join` fonksiyonuna güvenip arkana yaslanma; mutlak yol görünce kökü siler.
2. `replace("../", "")` ile güvenlik sağlamaya çalışma; iç içe `....//` yazan saldırgana rezil olursun.
3. Dosya yolunu daima `os.path.realpath` ve `os.path.commonpath` ile kanonik hapiste tut.
4. Çift URL kodlamasını ve Null Byte'ı kapıda yakala.
5. Mümkün olan her yerde doğrudan dosya adı yerine UUID tabanlı dolaylı referans kullan.
