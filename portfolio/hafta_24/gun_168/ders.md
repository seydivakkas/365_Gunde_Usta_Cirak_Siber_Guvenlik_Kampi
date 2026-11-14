# Gün 168: Mini Proje 23 — Güvenli Dosya Servisi ve İndirme Ağ Geçidi
## Hafta 24: Enjeksiyon ve İstek Güvenliği Sentez Kapanış Dersi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, çoğaltılamaz, dağıtılamaz.

---

## 1. Usta-Çırak Açılış Diyaloğu

**Usta:** Hoş geldin evlat. Hafta 24 boyunca çok çetin yollardan geçtik. SQL enjeksiyonunun AST ağacını nasıl büktüğünü, NoSQL ve ORM'lerin sözde güvenli filtrelerinin operatör enjeksiyonlarıyla nasıl delindiğini gördün. Ardından tarayıcı dünyasına inip CSRF belirteçlerini, CORS rahatlatmasının tehlikelerini, bulut metaverilerini soyan SSRF canavarını ve işletim sistemi dosya sistemini sarsan Path Traversal açıklarını inceledik. Bugün bu haftanın tacı olan **Mini Proje 23: Güvenli Dosya Servisi (Secure File Service Gateway)** projesini inşa ediyoruz. Dosya servisleri siber dünyada neden en çok vurulan kalelerdir, biliyor musun?

**Çırak:** Usta, web uygulamalarının çoğu sadece veri tabanıyla konuşur; ancak dosya servisi dediğimiz an işin içine doğrudan işletim sisteminin dosya sistemi (VFS, Inodes, Syscalls) ve harici dosya yorumlayıcıları giriyor. Saldırgan kullanıcıya açık bir yükleme veya indirme kapısı bulduğunda hem sunucunun yerel dosyalarını sızdırabilir (`/etc/shadow`) hem de sunucuya webshell yükleyip sistemi bütünüyle ele geçirebilir (RCE).

**Usta:** Aynen öyle evlat! Bir dosya servisi kurarken "Yükle butonuna basıldı, `file.save('/var/www/uploads/' + filename)` dedim, bitti" diyen bir yazılımcı, kurumun kapısını saldırganlara ardına kadar açmış demektir. Bugün bu projede bir dosyanın kabul edilişinden, derin bayt incelemesine, UUID soyutlamasından, kanonik hapishane sınırlarına ve güvenli indirme başlıklarına kadar uçtan uca kurumsal bir ağ geçidi kuracağız.

---

## 2. Web Dosya Servislerinde Tehdit Anatomisi

Bir dosya servisi mimarisinde dört kritik saldırı yüzeyi bir arada bulunur:

```
[İstemci / Saldırgan]
        │
        ├─ 1. ZARARLI DOSYA YÜKLEME (CWE-434)  --> Webshell, Polyglot (.php, .exe, <?php ...)
        ├─ 2. DİZİN ATLAMA / TRAVERSAL (CWE-22) --> ../../etc/passwd, %252e, Null Byte
        ├─ 3. BOLA / YETKİ AŞIMI (CWE-639)      --> Başka kullanıcının / kiracının dosyası
        └─ 4. SSRF İLE UZAK GETİRME (CWE-918)   --> 169.254.169.254, 127.0.0.1 link-local
```

### 1. Kısıtlanmamış Dosya Yükleme (Unrestricted File Upload - CWE-434)
Saldırgan sunucuya çalıştırılabilir bir betik (`shell.php`, `backdoor.jsp`, `malware.exe`) yükler. Eğer bu dosya web kök dizini altında saklanırsa ve web sunucusu (Apache, Nginx, IIS, PHP-FPM) bunu doğrudan çalıştırırsa sistemde Uzaktan Kod Yürütme (RCE) gerçekleşir.

### 2. Dosya Yolu Manipülasyonu ve Dizin Atlama (CWE-22)
Saldırgan dosya adını `../../../../etc/shadow` veya `C:\Windows\System32\drivers\etc\hosts` yaparak meşru dosya yükleme/indirme mekanizmasını işletim sisteminin kritik dosyalarını ezmek veya ifşa etmek için kullanır.

### 3. Kırık Nesne Seviyesinde Yetkilendirme (BOLA / IDOR - CWE-639)
Çok kiracılı (Multi-Tenant) SaaS sistemlerinde, A şirketinin kullanıcısı URL'deki ID'yi değiştirerek (`/download?file_id=102`) B şirketinin bordrolarını veya gizli sözleşmelerini indirebilir.

### 4. Uzak Dosyayı Çekme Sırasında SSRF (CWE-918)
Kullanıcı profil resmi veya belge aktarımı için URL verdiğinde, sunucu bu URL'i doğrulamadan çağırırsa saldırgan AWS/GCP metaveri servisini (`169.254.169.254`) veya iç ağdaki yönetim panellerini (`http://10.0.0.5/admin`) hedef alabilir.

---

## 3. Derinlemesine Savunma Hattı (Defense-in-Depth)

Geliştirdiğimiz `SecureFileService` mimarisinde uyguladığımız 6 kademeli savunma kalkanı şunlardır:

### 1. Girdi ve Dosya Adı Normalizasyonu
- **Null Byte Temizliği:** Girdide `%00` veya `\x00` baytları aranır; tespit edildiğinde dosya derhal reddedilir.
- **Çok Katmanlı Kod Çözme (Multi-Pass Unquote):** `%252e%252e%252f` gibi çift kodlu traversal dizgileri açığa çıkarılır.
- **Tehlikeli Çift Uzantı Kalkanı:** `invoice.pdf.php` veya `avatar.png.sh` gibi çoklu uzantılarda herhangi bir uzantı tehlikeli kümede (`php`, `exe`, `sh`, `asp`) ise reddedilir.
- **Beyaz Liste Alfanümerik Filtreleme:** Dosya adları yalnızca `^[a-zA-Z0-9_\-\.]+$` kümesine indirgenir.

### 2. Uzantı ve Sihirli Bayt (Magic Bytes) Eşleştirmesi
Kullanıcının gönderdiği `Content-Type: image/png` HTTP başlığı tamamen sahte olabilir. Bu nedenle dosya içeriğinin ilk baytları okunur:
- **PDF:** `%PDF-` (`0x25 0x50 0x44 0x46 0x2d`)
- **PNG:** `\x89PNG\r\n\x1a\n` (`0x89 0x50 0x4e 0x47 0x0d 0x0a 0x1a 0x0a`)
- **JPEG:** `\xff\xd8\xff`
- **DOCX / ZIP:** `PK\x03\x04` (`0x50 0x4b 0x03 0x04`)

Uzantı `.png` beyan edilip içi PDF veya metin ise `MAGIC_BYTES_MISMATCH` ile derhal 403 verilir.

### 3. Polyglot Dosya ve Webshell Statik Taraması
Saldırganlar geçerli bir PNG veya PDF dosyasının metadata veya yorum alanına PHP kodu gömerler (`Polyglot JPEG/PDF`). Dosya içeriği taranarak:
`<?php`, `eval(`, `system(`, `passthru(`, `shell_exec(`, `base64_decode(`, `<script`, `/bin/sh` kalıpları denetlenir.

### 4. İndirekt Nesne Referansı (UUIDv4) ve Kanonik Hapishane
- Dosya diske asla kullanıcının verdiği isimle yazılmaz!
- Her dosyaya bir `UUIDv4` (`6dca9cfa-6740-...`) atanır.
- Disk yolu: `/storage/tenants/<tenant_id>/<UUID>.dat`.
- `os.path.realpath` ve `os.path.commonpath([base_dir, target]) == base_dir` doğrulamasıyla sembolik bağ ve mutlak yol sıçramaları işletim sistemi düzeyinde fiziksel olarak imkansız kılınır.

### 5. Kiracı İzolasyonu ve Yetkilendirme (BOLA Kalkanı)
Bir dosya talep edildiğinde:
1. `meta.tenant_id == requesting_tenant_id` doğrulanır (Çapraz kiracı erişimi kesinlikle yasaktır).
2. Kullanıcı dosyanın sahibi (`owner_id`) değilse veya `admin` rolünde değilse indirme engellenir.

### 6. Güvenli İndirme HTTP Başlıkları
İndirme sırasında tarayıcıya gönderilen başlıklar MIME sniffing ve Stored XSS saldırılarını sıfırlar:
```http
Content-Type: application/pdf
Content-Disposition: attachment; filename="rapor.pdf"
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; sandbox
X-Frame-Options: DENY
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
```
- `attachment`: Dosyanın tarayıcı içinde HTML/JS gibi çalıştırılmasını önler, doğrudan diske indirmeye zorlar.
- `nosniff`: Tarayıcının dosya içeriğine bakıp MIME türünü tahmin etmesini engeller.
- `sandbox`: Herhangi bir şekilde görüntülenirse dahi JavaScript çalıştırma, form gönderme ve çerez erişim yetkilerini sıfırlar.

---

## 4. Hafta 24 Sentezi: Web Güvenliğinde Savunma Piramidi

Hafta 24 boyunca incelediğimiz tüm modüller, modern bir web uygulamasının güvenlik katmanlarını oluşturur:

| Gün | Konu | Birincil Tehdit | Çözüm ve Mimari Kalkan |
| :---: | :--- | :--- | :--- |
| **Gün 162** | SQL Injection | CWE-89 | Parametreli Sorgular, Prepared Statements, AST Ayrımı |
| **Gün 163** | NoSQL & ORM Sınırları | CWE-943 | Operatör Yasaklama (`$`), Dize Tip Zorunluluğu, Katı Şema |
| **Gün 164** | CSRF ve Oturum Bağlamı | CWE-352 | Synchronizer Token (HMAC-SHA256), SameSite Cookies, Step-Up Auth |
| **Gün 165** | CORS ile Güvenlik Sınırı | CWE-942 | Katı Origin Beyaz Listesi, Null Origin Yasağı, Vary: Origin |
| **Gün 166** | SSRF ve Savunma | CWE-918 | Pre-Request DNS, IP Sabitleme, Egress Firewall, IMDSv2 |
| **Gün 167** | Path Traversal | CWE-22 | Kanonik Hapishane (`realpath`), Alfanümerik Whitelist, Multi-pass Unquote |
| **Gün 168** | Mini Proje 23: Güvenli Dosya Servisi | Sentez | UUID İndirekt Referans, Magic Bytes, Webshell Taraması, Secure Headers |

---

## 5. Usta Sözü ve Çırağa Öğüt

Evlat, web güvenliğinde en büyük zaaf yazılımcının "istemciye veya dosya sistemine güvenmesi" ile başlar. Kullanıcının gönderdiği dosya adı, beyan ettiği MIME türü, URL'deki hedef adres veya HTTP başlıklarının tamamı saldırganın kontrolündedir. Bir usta güvenlik mühendisi girdi sınırında her veriyi potansiyel bir silah kabul eder, veriyi soyutlar, UUID ile etiketler, kanonik hapishanede izole eder ve sunarken tarayıcıyı kısıtlayan zırhlı başlıklarla teslim eder. Hafta 24'ü büyük bir gurur ve tam 100/100 başarıyla tamamladın. Yolun açık olsun!
