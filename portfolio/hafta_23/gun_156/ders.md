# Hafta 23 / Gün 156: OWASP Top 10 Haritası ve Web Güvenlik Değerlendirmesi

## Usta-Çırak / Hoca Dersi Notları

> **Usta:** *"Evladım, web güvenliğinde en büyük yanılgı, güvenlik açıklarını rastgele ve izole hatalar olarak görmektir. Bir saldırgan sistemine baktığında münferit bir 'bug' değil, savunma zincirindeki en zayıf halkayı ve zafiyet taksonomisindeki boşlukları arar. OWASP Top 10, bu zayıflıkların dünyadaki istatistiksel ve etki temelli haritasıdır. Bir web uygulamasını savunmak istiyorsan, A01 Kırık Erişim Denetimi'nden A10 SSRF'e kadar her kategoriyi hem mimari tasarımında hem de kodunun her satırında bir kalite kapısı (Quality Gate) olarak denetleyeceksin."*
>
> **Çırak:** *"Ustamm, OWASP Top 10 listesi sadece bir kontrol listesi (checklist) midir, yoksa arkasında CWE ve CVSS gibi derin taksonomiler mi yatar? Bir mimar olarak bu haritayı uygulamamıza nasıl entegre etmeliyiz?"*
>
> **Usta:** *"Bak evlat, kontrol listesi zihniyetiyle güvenlik yapılmaz. Kontrol listesi kutucuk işaretletir, taksonomi ise zafiyetin kök nedenini (Root Cause) anlamanı sağlar. CWE (Common Weakness Enumeration), zafiyetin yazılım seviyesindeki genetik kodudur; örneğin CWE-89 SQL Enjeksiyonudur. OWASP Top 10 ise bu genetik kusurların birleşerek oluşturduğu makro risk kategorileridir (A03: Injection gibi). Bugün seninle kurumsal bir web uygulamasını 10 kategori üzerinden röntgen cihazına sokacak bir denetim motoru kuracağız."*

---

## 1. OWASP Top 10 Evrimi ve Makro Risk Kategorileri

OWASP (Open Web Application Security Project), küresel çapta toplanan telemetri verileri, sızma testi raporları ve sektör anketleriyle her birkaç yılda bir web dünyasının en kritik 10 güvenlik riskini yayımlar. 2021 ve 2025 sürümleri, geleneksel sözdizimsel açıkların (SQLi, XSS) ötesine geçerek **tasarım hatalarına, erişim denetimine ve yazılım tedarik zincirine** odaklanmıştır:

```
+----------------------------------------------------------------------------------------------------+
|                                    OWASP TOP 10 TAKSONOMİSİ                                       |
+----------------------------------------------------------------------------------------------------+
| A01: Broken Access Control               | Yetki kontrollerinin atlatılması, IDOR, eksik RBAC      |
| A02: Cryptographic Failures              | Düz metin veri iletimi, zayıf algoritmalar (MD5, DES)    |
| A03: Injection                           | SQLi (CWE-89), XSS (CWE-79), Komut Enjeksiyonu         |
| A04: Insecure Design                     | Tehdit modelleme eksikliği, rate limit yokluğu          |
| A05: Security Misconfiguration           | Açık debug modu (CWE-16), varsayılan parolalar          |
| A06: Vulnerable and Outdated Components  | CVE'li paketler (CWE-1104), SCA taraması eksikliği      |
| A07: Identification and Auth Failures    | MFA yokluğu (CWE-287), brute-force hesap kilitleme yok |
| A08: Software and Data Integrity Failures| Güvensiz deserialization (CWE-502), imzasız CI/CD       |
| A09: Security Logging & Monitoring Fail. | Denetim izi tutmama (CWE-778), geç alarm üretimi        |
| A10: Server-Side Request Forgery (SSRF)  | İç ağ tarama, bulut metadata sızıntısı (CWE-918)        |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Derinlemesine Zafiyet Analizi ve Savunma Prensipleri

### A01: Kırık Erişim Denetimi (Broken Access Control)
Erişim denetimi, kullanıcının yalnızca yetkili olduğu kaynakları görebilmesini ve değiştirebilmesini güvenceye alır.
- **Kök Neden:** Sunucu tarafında oturum sahibinin (Subject) işlem yapacağı nesneye (Object) erişim hakkının doğrulanmaması.
- **CWE-639 (IDOR):** `/api/invoices/1004` adresindeki `1004` ID'sini `1005` yaparak başkasının faturasını indirmek.
- **Savunma:** İstemciden gelen ID'lere asla güvenilmez. Tüm sorgularda oturumdaki kullanıcı kimliği (`current_user.id`) filtre şartı olarak zorunlu tutulmalıdır:
  ```python
  # YANLIŞ: IDOR'a açık
  invoice = db.query(Invoice).filter_by(id=request_id).first()
  
  # DOĞRU: Çok kiracılı (Multi-tenant) ve nesne seviyesinde yetkili
  invoice = db.query(Invoice).filter_by(id=request_id, tenant_id=current_user.tenant_id).first()
  ```

### A02: Kriptografik Hatalar (Cryptographic Failures)
Verilerin transit (aktarım) ve at-rest (durgun) halinde yetkisiz gözlerden saklanamaması.
- **Kök Neden:** Kullanımdan kalkmış TLS sürümleri (TLS 1.0, 1.1), zayıf şifreleme blok modları (AES-ECB), zayıf parola özet algoritmaları (MD5, SHA-1).
- **Savunma:** Parolalarda kesinlikle Argon2id veya bcrypt (work factor >= 12) kullanılır. Aktarımda TLS 1.3 ve HSTS (max-age=31536000; includeSubDomains) zorunlu tutulur.

### A03: Enjeksiyon Zafiyetleri (Injection)
Güvenilmeyen verilerin bir komut veya sorgu yorumlayıcısına doğrudan girdi olarak verilmesi.
- **Kök Neden:** Kod ile verinin aynı kanalda karıştırılması.
- **CWE-89 (SQL Injection):** `' OR 1=1 --` girdisiyle sorgu yapısının bozulması.
- **Savunma:** Parametreli sorgular (Prepared Statements). Veritabanı sürücüsü kodu derler, veriyi ayrı bir parametre akışı olarak işler; veri hiçbir zaman kod olarak çalışamaz.

### A04: Güvensiz Tasarım (Insecure Design)
Kodlama hatası değil, mimari ve iş mantığı tasarımındaki güvenlik eksiklikleri.
- **Kök Neden:** Tehdit modelleme (Threat Modeling - STRIDE) yapılmaması, hız sınırlama (Rate Limiting) konulmaması.
- **Savunma:** Tasarım aşamasında kimlik doğrulama noktalarına, şifre sıfırlama akışlarına ve hassas API'lere IP ve kullanıcı bazlı Leaky Bucket / Token Bucket hız sınırlaması entegre edilmelidir.

### A05: Güvenlik Yanlış Yapılandırması (Security Misconfiguration)
Uygulama, web sunucusu veya veritabanının varsayılan, güvensiz ayarlarla yayına alınması.
- **Kök Neden:** Üretim ortamında `DEBUG = True` bırakılması, stack trace sızıntıları, eksik HTTP güvenlik başlıkları (CSP, HSTS, X-Content-Type-Options).
- **Savunma:** Otomatik CI/CD denetimleri ile debug modunun kapatıldığının doğrulanması, gereksiz servis ve HTTP metodlarının (TRACE, OPTIONS) kapatılması.

### A06: Savunmasız ve Güncel Olmayan Bileşenler (Vulnerable Components)
Uygulamanın kullandığı üçüncü taraf kütüphanelerin bilinen CVE zafiyetleri barındırması.
- **Kök Neden:** Yazılım Malzeme Listesi (SBOM) tutulmaması, bağımlılıkların periyodik güncellenmemesi (Örn: Log4j CVE-2021-44228).
- **Savunma:** CI/CD sürecinde otomatik SCA (Software Composition Analysis) araçları (pip-audit, Snyk, Dependabot) çalıştırılmalı ve kritik CVE barındıran yapılar otomatik reddedilmelidir.

### A07: Kimlik Tanımlama ve Doğrulama Hataları (Auth Failures)
Kullanıcı kimliğinin doğrulanmasında zayıflık bulunması.
- **Kök Neden:** Yönetici hesaplarında MFA bulunmaması, kaba kuvvet (Brute Force) saldırılarına karşı hesap kilitleme olmaması, zayıf oturum tanımlayıcıları.
- **Savunma:** FIDO2/WebAuthn veya TOTP MFA zorunluluğu, 5 başarısız denemede kilitlenen geçici hesap askıya alma politikaları.

### A08: Yazılım ve Veri Bütünlüğü Hataları (Integrity Failures)
Güvenilmeyen kaynaklardan gelen nesnelerin veya kodların bütünlüğü doğrulanmadan çalıştırılması.
- **Kök Neden:** Güvensiz serileştirme (Insecure Deserialization - Python `pickle.loads()`, Java `ObjectInputStream`), imzasız CI/CD boru hatları.
- **Savunma:** Deserialization için binary formatlar yerine katı şema doğrulamalı JSON/Protocol Buffers kullanılmalı, CI/CD artifact'leri Cosign ile imzalanmalıdır.

### A09: Güvenlik Günlüğü ve İzleme Hataları (Logging & Monitoring)
Saldırı girişimlerinin kaydedilmemesi ve anında fark edilememesi.
- **Kök Neden:** Başarısız oturum denemelerinin, yetki aşımlarının loglanmaması, merkezi SIEM'e log akışının olmaması.
- **Savunma:** Olayların RFC 5424 Syslog formatında merkezi SIEM'e (Splunk, Elastic) gönderilmesi ve kritik alarmların 15 dakikadan kısa sürede SOC analistine ulaşması.

### A10: Sunucu Taraflı İstek Sahteciliği (SSRF)
Sunucunun, kullanıcıdan aldığı URL parametresini kullanarak kendi iç ağına veya dışarıya kontrolsüz istek yapması.
- **Kök Neden:** Kullanıcı girdisi URL'lerin doğrulanmadan HTTP istemcisine (requests, curl) verilmesi.
- **CWE-918 (SSRF):** Bulut ortamlarında `http://169.254.169.254/latest/meta-data/iam/security-credentials/` adresine istek attırılarak AWS/GCP IAM anahtarlarının ele geçirilmesi.
- **Savunma:** Katı alan adı beyaz listesi (Allowlist), özel IP adreslerinin (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) ve bulut meta veri adreslerinin (169.254.169.254) DNS çözümlemesinden sonra filtrelenmesi.

---

## 3. OWASP Top 10 Haritalama Motoru Mimarisi

Bugün geliştirdiğimiz `OwaspMapperEngine`, kurumsal bir web uygulamasının güvenlik parametrelerini 10 kategoride bağımsız puanlar:
1. **Her Kategori İçin Ağırlıklı Ceza Puanlama:** Eksik olan her kontrol, kategorinin puanını düşürür (Örn: A01'de RBAC yoksa -50, IDOR yoksa -40 puan).
2. **Geçme Eşiği:** Her kategori için minimum **%80.0**, genel uygulama uyumluluğu için minimum **%85.0** puan şartı aranır.
3. **Tek Kategori İhlali Kuralı:** Genel puan %90 olsa dahi, tek bir kategoriden kalınırsa uygulama **"UYGUNSUZ - ÜRETİME ALINAMAZ"** statüsüne düşer.
4. **CWE Köprüsü:** Tespit edilen zafiyetler doğrudan küresel CWE kodlarıyla ilişkilendirilir ve geliştiriciye özel iyileştirme yol haritası sunulur.

---

## Özet ve Ustanın Öğüdü

> *"Evladım, OWASP Top 10'u öğrenmek sadece sınav geçmek için değil, kurduğun sistemin kalbini saldırganların zehrinden korumak içindir. Bir web uygulamasının güvenliği; en şık butonunda değil, istemciden gelen her baytı güven sınırında sorgulayan yetkilendirme ara katmanında başlar. Koduna güvenmeyeceksin, doğrulayacaksın!"*
