<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 004: NIST CSF 2.0 İşlevleri — Govern, Identify, Protect, Detect, Respond, Recover

---

## 1. Hocanın Giriş Sohbeti & Zihinsel Model (Mental Model)

Evlat, masamıza hoş geldin. İlk üç günde siber güvenliğin felsefesini, riskin kalbini ve etik sınırları konuştuk. Bugün ise bir siber güvenlik analistinin, mühendisinin ve hatta CISO'sunun (Chief Information Security Officer) elindeki en güçlü pusulayı masaya yatırıyoruz: **NIST Cybersecurity Framework (CSF) 2.0**.

Sana sormak istiyorum: Bir kaleyi nasıl savunursun?
Çoğu acemi hemen atılır: *"Hocam, 20 metre kalınlığında surlar örerim! Hendek kazar içine timsah doldururum!"*
İşte bu, siber güvenlikte **"Savunma Miyopluğu" (Protect Bias)** dediğimiz ölümcül bir tuzaktır. Eğer kalenin surlarını 20 metre yapıp; içindeki ambarlarda ne kadar erzak olduğunu bilmezsen (**Identify** eksikliği), gece nöbet tutacak gözcü kuleleri koymazsan (**Detect** eksikliği), bir casus gizlice kapıyı açtığında kılıcını çekecek nöbetçi mangası görevlendirmezsen (**Respond** eksikliği), kale kuşatılıp duvarın bir kısmı yıkıldığında taş ustalarıyla tamir planı yapmamışsan (**Recover** eksikliği) ve en önemlisi krallığın kanunlarını, tedarik kervanlarını, hazinesini ve genel savunma doktrinini yöneten bir Divan/Kral meclisi kurmazsan (**Govern** eksikliği)... O kale tek bir gecede içeriden düşer!

NIST (National Institute of Standards and Technology), 2014 yılında CSF 1.0'ı çıkardığında 5 temel işlev tanımlamıştı: **Identify, Protect, Detect, Respond, Recover**. On yıl boyunca dünya bu beş sütunla yönetildi. Fakat Şubat 2024'te NIST çok kritik bir hamle yaptı ve **NIST CSF 2.0**'ı yayınladı. Peki ne değişti?
En tepeye yepyeni bir taç eklendi: **GOVERN (Yönetişim)**.

Neden biliyor musun? Çünkü dünyanın en pahalı yeni nesil güvenlik duvarını (NGFW) veya en gelişmiş EDR (Endpoint Detection & Response) yazılımını satın alabilirsin. Fakat şirket yönetim kurulunun siber risk iştahı net değilse, personelin güvenlik politikaları tanımlanmamışsa ve üçüncü parti bir yazılım tedarikçinin (Supply Chain) güvenliği denetlenmiyorsa; SolarWinds veya Target vakalarında olduğu gibi milyonlarca dolarlık yatırımlar tek bir taşeron klimacının şifresiyle çöp olur.

Bugün zihnine nakşedeceğimiz model şudur:
**Siber güvenlik bir araç kurulumu değil, yaşayan ve birbirini besleyen 6 işlevli bir orkestrasyondur.**

```
       +-------------------------------------------------------------+
       |                         GOVERN (GV)                         |
       |     (Yönetişim: Strateji, Liderlik, Tedarik Zinciri C-SCRM) |
       +------------------------------+------------------------------+
                                      |
             +------------------------+------------------------+
             |                                                 |
             v                                                 v
  +--------------------+                             +--------------------+
  |    IDENTIFY (ID)   |                             |    RECOVER (RC)    |
  |  - Varlık Envanteri|                             |  - Geri Yükleme    |
  |  - Risk Belirleme  |                             |  - BCP / DRP       |
  +---------+----------+                             +---------^----------+
            |                                                  |
            v                                                  |
  +--------------------+                             +---------+----------+
  |    PROTECT (PR)    |         Alarm & Telemetri   |    RESPOND (RS)    |
  |  - Kimlik & MFA    | --------------------------> |  - Triyaj          |
  |  - Veri Şifreleme  |                             |  - İzolasyon       |
  +---------+----------+                             +---------^----------+
            |                                                  |
            +------------------> DETECT (DE) ------------------+
                               - Sürekli İzleme (SIEM)
                               - Anomali Keşfi
```

---

## 2. Sıfırdan Başlayan Kristal Netliğinde Teori

NIST CSF 2.0, teknik hiyerarşide dört katmanlı bir piramit üzerine oturur:
1. **Functions (İşlevler):** 6 ana sütun (GV, ID, PR, DE, RS, RC).
2. **Categories (Kategoriler):** Her işlevin altındaki operasyonel hedefler (Örn: PR.AA, ID.AM).
3. **Subcategories (Alt Kategoriler):** Doğrudan teknik ve idari kontroller (Örn: PR.AA-01: Kimlik doğrulamada MFA zorunluluğu).
4. **Implementation Examples (Uygulama Örnekleri):** Kontrolün sahada nasıl hayata geçirileceğini gösteren pratik rehberler.

Şimdi bu altı işlevi cerrah hassasiyetiyle tek tek inceleyelim:

### 2.1. GOVERN (GV) — Yönetişim
NIST CSF 2.0'ın kalbidir. Diğer beş işlevin yönünü ve sınırlarını belirler.
* **GV.OC (Organizational Context):** Kurumun misyonu, vizyonu ve yasal sorumlulukları (KVKK, BDDK, GDPR, ISO 27001).
* **GV.RM (Risk Management Strategy):** Kurum ne kadar riski tolere edebilir? Risk iştahı (Risk Appetite) ve öncelikler.
* **GV.RR (Roles, Responsibilities, and Authorities):** Güvenlikten kim sorumlu? CISO, SOC lideri, sistem yöneticisi yetki sınırları.
* **GV.PO (Policy):** Şifre uzunluğundan USB kullanımına kadar kurumsal bilgi güvenliği politikaları.
* **GV.OV (Oversight):** Güvenlik stratejisinin işleyişi yönetim kurulu tarafından periyodik denetleniyor mu?
* **GV.SC (Cybersecurity Supply Chain Risk Management - C-SCRM):** Kullandığımız bulut sağlayıcıları, kütüphaneler (Open Source), SaaS araçları ve dış tedarikçiler ne kadar güvenli?

### 2.2. IDENTIFY (ID) — Tanımlama
Sahip olduğun şeyi bilmeden koruyamazsın.
* **ID.AM (Asset Management):** Ağdaki fiziksel sunucular, sanal makineler, IP adresleri, API uç noktaları, hassas veri depoları. (Gölge BT / Shadow IT tespiti).
* **ID.RA (Risk Assessment):** Varlıkların zafiyetleri (CVE) ve tehdit aktörlerinin yetenekleri (STRIDE / MITRE ATT&CK) ile oluşturulan risk puanları.
* **ID.IM (Improvement):** Önceki siber olaylardan ve testlerden çıkarılan derslerin varlık ve risk kayıtlarına yansıtılması.

### 2.3. PROTECT (PR) — Koruma
Saldırganın işini zorlaştıran, saldırı maliyetini artıran bariyerler.
* **PR.AA (Identity Management, Authentication & Access Control):** En az yetki prensibi (Least Privilege), FIDO2/MFA, Privileged Access Management (PAM).
* **PR.AT (Awareness and Training):** İnsan faktörünün eğitilmesi; oltalama (phishing) simülasyonları.
* **PR.DS (Data Security):** Durağan (At-Rest: AES-256) ve hareket halindeki (In-Transit: TLS 1.3) verilerin şifrelenmesi; DLP (Data Loss Prevention).
* **PR.PS (Platform Security):** İşletim sistemi sıkılaştırma (OS Hardening, CIS Benchmarks), düzenli yama yönetimi (Patch Management).
* **PR.IR (Technology Infrastructure Resilience):** Yüksek erişilebilirlik (HA), yük dengeleme ve yedeklilik mimarileri.

### 2.4. DETECT (DE) — Tespit
Modern siber güvenliğin amentüsü şudur: **"Assume Breach" (Saldırganın içeri sızdığını varsay).**
Duvarlar ne kadar yüksek olursa olsun sıfır-gün (0-Day) veya sosyal mühendislikle bir saldırgan içeri girebilir. Önemli olan içerideyken onu ne kadar hızlı fark ettiğindir.
* **DE.CM (Continuous Monitoring):** Uç noktalardan (EDR), ağdan (NDR) ve kimlik servislerinden (Active Directory / IdP) akan logların merkezi bir SIEM sisteminde 7/24 korelasyon kurallarıyla incelenmesi.
* **DE.AE (Adverse Event Analysis):** Normal dışı davranışların (örn: bir muhasebe kullanıcısının gece 03:00'te PowerShell açıp etraftaki IP'leri taraması) tespiti ve tehdit avcılığı (Threat Hunting).

### 2.5. RESPOND (RS) — Müdahale
Yangın çıktığında alarm ötmesi yetmez; itfaiyenin ne yapacağını adım adım bilmesi gerekir.
* **RS.MA (Incident Management):** Olay Müdahale Planının (IRP) işletilmesi, kriz masasının toplanması ve şiddet seviyesine göre triyaj.
* **RS.AN (Incident Analysis):** Saldırgan hangi makineden girdi? Nerelere yayıldı? Bellek dökümleri (RAM dump) ve disk adli bilişimi (DFIR).
* **RS.CO (Incident Response Reporting and Communication):** Yasal kurumlara (USOM, KVKK), müşterilere ve üst yönetime bildirimlerin zamanında yapılması.
* **RS.MI (Incident Mitigation):** Saldırganın yayılımını durdurmak için enfekte makinenin ağ fişinin çekilmesi (EDR Network Isolation), saldırgan IP'lerinin firewall'da engellenmesi.

### 2.6. RECOVER (RC) — Kurtarma
Bir saldırı yaşandı ve sistemler çöktü. Ne kadar sürede ayağa kalkacaksın?
* **RC.RP (Incident Recovery Plan Execution):** Yedeklerin doğrulanması, değiştirilemez (Immutable / WORM) ortamlardan temiz kurulum yapılması. RTO (Kurtarma Süresi Hedefi) ve RPO (Kayıp Veri Toleransı) metriklerinin karşılanması.
* **RC.CO (Recovery Communication):** Sistemlerin güvenle yeniden açıldığının paydaşlara duyurulması ve kamuoyu güveninin yeniden tesisi.

### 2.7. NIST CSF Aşamaları (Implementation Tiers)
Kurumlar bu işlevleri ne kadar profesyonelce uyguluyor?
* **Tier 1 - Partial:** Süreçler doğaçlama, kriz anında panik, kurumsal hafıza sıfır.
* **Tier 2 - Risk Informed:** Risklerin farkındalar ama departmanlar birbirinden kopuk, politikalar dağınık.
* **Tier 3 - Repeatable:** Süreçler yazılı, eğitimli ekipler var, periyodik denetimler ve tatbikatlar yapılıyor.
* **Tier 4 - Adaptive:** Yapay zeka ve otomasyon destekli; küresel tehdit istihbaratına göre savunmasını dinamik güncelleyen en üst olgunluk seviyesi.

---

## 3. İki Yönlü Bakış: Saldırganın Gözü (Offensive) vs Savunmacının Kalkanı (Defensive)

### Saldırganın Gözü (Offensive Angle)
Bir saldırgan kuruma yaklaşırken asla "Bu şirketin firewall markası ne?" diye başlamaz. Kurumun NIST CSF zafiyetlerini arar:
1. **Govern Zafiyeti:** Saldırgan, kurumun çalıştığı üçüncü parti yazılım tedarikçisini veya dış kaynak çağrı merkezini hedefler. Taşeronun kuruma açılan VPN tünelinde MFA olmadığını keşfeder. (Tedarik zinciri istismarı).
2. **Identify Zafiyeti:** Saldırgan, kurumun IT ekibinin unuttuğu 5 yıl önceki test sunucusunu (`dev-api.firma.com`) Shodan üzerinden bulur. Üzerinde yama yapılmamış Log4j zafiyeti vardır.
3. **Protect-Bias İstismarı:** Saldırgan bilir ki şirket sadece perimeter (çevre) güvenliğine para harcamış. Bir yöneticiye mızrak oltalama (Spear Phishing) atıp parola karmasını ele geçirdiğinde, içeride **Detect** mekanizması (EDR/SIEM) olmadığı için ağda 200 gün boyunca sessizce dolaşır (Lateral Movement).
4. **Recover Sabotajı:** Modern fidye yazılımı (Ransomware) çeteleri, canlı sistemleri şifrelemeden önce ilk olarak yedekleme sunucusunu (`Veeam`, `Commvault`, `NAS`) bulur. `vssadmin delete shadows` komutlarıyla gölge kopyaları siler ve online yedekleri bozar. Eğer kurum **Recover** işlevinde çevrimdışı (Air-Gapped) veya WORM depolama kullanmıyorsa, şirket fidyeyi ödemek zorunda kalır.

### Savunmacının Kalkanı (Defensive Angle)
Biz mavi takım (Blue Team) olarak savunmayı tek bir duvara indirgemeyiz:
1. **İhlali Varsay (Assume Breach):** Saldırganın Protect katmanını aştığı anı senaryolaştırırız.
2. **Sinyalden Eyleme Hızlı Akış:** `Detect` katmanındaki bir PowerShell anomali sinyali (Event ID 4104), SOAR (Security Orchestration, Automation and Response) aracılığıyla anında `Respond` katmanına aktarılır ve ilgili uç nokta 30 saniye içinde ağdan izole edilir.
3. **Değiştirilemez Yedeklilik:** `Recover` katmanında 3-2-1 yedekleme kuralını (3 kopya, 2 farklı ortam, 1 çevrimdışı/air-gapped kopya) zorunlu kılarız.
4. **Yönetişim Geri Beslemesi:** Yaşanan her olay `Govern` kuruluna raporlanır, bir sonraki çeyreğin bütçesi tespit edilen kör noktaların giderilmesine aktarılır.

---

## 4. Hocayla Birlikte Canlı Laboratuvar (Gerçek Kod & Canlı Sistem)

Şimdi teoriyi canlı bir mühendislik aracına dönüştürüyoruz.
Bugünkü laboratuvarımızda geliştirdiğimiz `nist_csf_evaluator.py` betiği, hayalî bir kurumun 6 NIST CSF 2.0 işlevindeki verilerini alır, matematiksel olarak olgunluk seviyesini hesaplar, ASCII radar grafiği çizer ve en önemlisi **"Protect Bias" (Yalancı Savunma Yanılsaması)** tuzaklarını otomatik olarak ifşa eder.

### Canlı Betiğimizin Kod Mimarisi ve Açıklamaları
Betiğimizin her satırı, siber güvenlik prensiplerini öğretmek üzere özel açıklama satırlarıyla donatılmıştır:

```python
# uygulama/nist_csf_evaluator.py dosyasından kritik bölüm:
# 6 işlev puanının hesaplanması ve 'Protect Bias' kontrol mekanizması

protect_puani = islev_puanlari.get("PROTECT", 0.0)
detect_puani  = islev_puanlari.get("DETECT", 0.0)
respond_puani = islev_puanlari.get("RESPOND", 0.0)
recover_puani = islev_puanlari.get("RECOVER", 0.0)

# 'Savunma Yanılsaması' Kontrolü:
# Kurum Protect'e 85 verip, Detect veya Recover'ı 50'nin altına düşürmüşse
# bu durum mimari bir kör noktadır. Duvar var ama nöbetçi ve doktor yok demektir!
if protect_puani >= 70.0:
    if detect_puani < 50.0:
        yanilsama_uyarisi = True
        yanilsama_detay.append("Detect çok zayıf! Duvar örülmüş ancak içeri sızan saldırganı izleyecek göz yok.")
    if recover_puani < 50.0:
        yanilsama_uyarisi = True
        yanilsama_detay.append("Recover çok zayıf! Fidye yazılımı bulaştığında yedekten geri dönülemez.")
```

### Canlı Terminal Yürütmesi
Aracımızı hazırladığımız kurumsal matris üzerinde çalıştırdığımızda aldığımız gerçek terminal çıktısı:

```text
================================================================================
  NIST CSF 2.0 OLGUNLUK RADARI: Anadolu Finansal Teknolojiler A.Ş.
  Genel Puan: 79.3 / 100  [Tier 3 - Repeatable (Tekrarlanabilir/Kurumsal)]
================================================================================
  GOVERN   [████████████████████████████████░░░░░░░░]  80.00%
  IDENTIFY [███████████████████████████████░░░░░░░░░]  78.33%
  PROTECT  [█████████████████████████████████░░░░░░░]  82.50%
  DETECT   [███████████████████████████████░░░░░░░░░]  77.50%
  RESPOND  [████████████████████████████████░░░░░░░░]  80.00%
  RECOVER  [███████████████████████████████░░░░░░░░░]  77.50%
--------------------------------------------------------------------------------
  [+] DENGELİ SAVUNMA: Altı işlev arasında kritik bir oransızlık saptanmadı.
================================================================================

--- ÖNCELİKLİ İYİLEŞTİRME VE EKSİKLİK ANALİZİ (GAP ANALYSIS) ---
Toplam 1 kategoride gelişim gerekmektedir (Öncelik Sırasıyla):
  1. [IDENTIFY] ID.IM - İyileştirme (Improvement) -> Puan: 70.0/100
```

---

## 5. Hocanın "Ölümcül Hatalar" Notu

Evlat, sahaya çıktığında veya teknik mülakatlara girdiğinde şu 5 ölümcül yanılgıya asla düşme:

1. **"Bizde Firewall ve Antivirüs Var, Güvendeyiz" Yanılgısı:**
   Bu durum sektördeki en yaygın **Protect Miyopluğudur**. Saldırgan içeri girdiğinde EDR/SIEM alarm üretmiyorsa veya alarmları inceleyecek analist yoksa kurum hacklendiğini ancak 9 ay sonra verileri 'Dark Web'e düştüğünde öğrenir.
2. **"Yedek Alıyoruz Ama Hiç Geri Yüklemedik" Felaketi (Recover Tuzağı):**
   Bir yedek, geri yükleme testi (Restore Drill) başarıyla tamamlanana kadar "yok" hükmündedir. Fidye yazılımı vurduğunda şifreli veriyi yedekten dönmeye çalışan onlarca dev şirketin, yedek dosyalarının da bozuk olduğunu o an fark edip battığını gördük.
3. **Yönetişimi (Govern) "Kırtasiyecilik" Sanmak:**
   "Mühendis adam evrakla uğraşmaz" diyen ekipler, taşeron bir şirketin geliştirdiği web kütüphanesindeki zafiyet yüzünden şirket veritabanı boşaltıldığında CISO koltuğundan olurlar. Güvenlik liderlikten ve tedarik zincirinden başlar.
4. **Alarm Yorgunluğu (Alert Fatigue) ile Detect'i Sessize Almak:**
   Günde 50.000 sahte pozitif (False Positive) üreten bir SIEM kurup sonra tüm alarmları susturmak, Detect işlevini sıfırlamaktır. Doğru olan kuralları sıkılaştırmak ve tehdit avcılığı yapmaktır.
5. **Olay Müdahale Planını (IRP) Kasaya Kilitlemek:**
   Kriz anında "Kim kimi arayacaktı, sunucu fişi çekilecek miydi yoksa bellek analizi için açık mı bırakılacaktı?" tartışması yaşanıyorsa o kurum felce uğrar. IRP yılda en az iki kez masa başı tatbikatıyla (Tabletop Exercise) denenmelidir.

---

## 6. Laboratuvar Görevi ve Beklenen Çıktılar

### Görev Tanımı
Hayalî bir finans kurumunun (`Anadolu Finansal Teknolojiler A.Ş.`) 6 işlevini temsil eden 16 kategorilik olgunluk girdilerini JSON matrisine işle, değerlendirici motor ile çalıştır, 6 işlevin aritmetik dengesini doğrula ve negatif kontrol senaryolarını test et.

### Girdi Verisi (`ornek_veri/nist_csf_matrisi.json`)
* **Govern:** GV.OC (85), GV.RM (80), GV.SC (75) -> Ort: 80.00%
* **Identify:** ID.AM (85), ID.RA (80), ID.IM (70) -> Ort: 78.33%
* **Protect:** PR.AA (90), PR.AT (75), PR.DS (85), PR.PS (80) -> Ort: 82.50%
* **Detect:** DE.CM (80), DE.AE (75) -> Ort: 77.50%
* **Respond:** RS.MA (85), RS.AN (75), RS.MI (80) -> Ort: 80.00%
* **Recover:** RC.RP (80), RC.CO (75) -> Ort: 77.50%

### Pozitif ve Negatif Kontroller
1. **Pozitif Kontrol:** 6 işlevin tamamı sağlandığında genel puan 79.30 çıkar, Tier 3 atanır, Protect-Bias uyarısı oluşmaz.
2. **Negatif Kontrol 1 (Eksik İşlev):** GOVERN veya RECOVER silindiğinde motor `NistCsfValidationError` fırlatarak çöker.
3. **Negatif Kontrol 2 (Savunma Yanılsaması):** Protect 95 yapılıp Detect/Recover 25'e düşürüldüğünde motor tehlike alarmı üretir.
4. **Negatif Kontrol 3 (Sınır Aşımı):** 100'den büyük veya negatif puanlar anında reddedilir.

---

## 7. Hocanın Soru Odası (Kapsamlı Soru-Cevap)

Aşağıdaki sorular, müfredatımızın `SORU BANKASI` gereksinimlerine göre 4 katı alt başlık kuralıyla cevaplanmıştır:

### Soru 1: NIST CSF 2.0 işlevleri: Temel mekanizmayı ve güvenlik önemini açıkla.

#### 1. Yanıt
NIST CSF 2.0; **Govern (Yönetişim)**, **Identify (Tanımlama)**, **Protect (Koruma)**, **Detect (Tespit)**, **Respond (Müdahale)** ve **Recover (Kurtarma)** olmak üzere birbirini tamamlayan ve sürekli besleyen altı temel işlevden oluşur. Bu çerçeve, güvenliği tekil bir yazılım veya donanım yatırımı olmaktan çıkarıp; üst yönetim stratejisinden teknik olay müdahalesine ve felaket kurtarmaya kadar uzanan döngüsel bir kurumsal risk yönetimi mekanizmasına dönüştürür.

#### 2. Teknik Gerekçe
Siber güvenlik statik bir durum değil, dinamik bir döngüdür. Varlıklarını tanımlamadan (Identify) koruma politikası belirleyemezsin; koruma bariyerlerin sızmaya uğradığında sürekli teleometri izlemesi (Detect) olmadan ihlali bilemezsin; ihlali keşfettiğinde SOAR ve IRP protokollerin (Respond) yoksa yayılımı durduramazsın; fidye yazılımı sonrası değiştirilemez yedekleme ve kurtarma planın (Recover) yoksa iş sürekliliğini sağlayamazsın. En tepedeki Govern işlevi ise tüm bu operasyonların kurumsal risk iştahı, mevzuat uyumu (KVKK/BDDK/GDPR) ve tedarik zinciri (C-SCRM) ile senkronize yürütülmesini garanti altına alır.

#### 3. Yaygın Hata
Güvenliği yalnızca "Protect" işlevinden (Firewall, IPS, Antivirüs) ibaret sanmak. Saldırganların içeri sızabileceğini peşinen reddederek tespit ve kurtarma yatırımlarını sıfırlamak en ölümcül sektörel hatadır.

#### 4. Standart ve Kaynak
* NIST Cybersecurity Framework Version 2.0 (NIST CSWP 29, Şubat 2024).
* NICE Framework (SP 800-181 Rev. 1) - Risk Yönetimi ve Güvenlik Yönetişimi Yetkinlikleri.

---

### Soru 2: NIST CSF 2.0 işlevleri: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

#### 1. Yanıt
Bağımsız laboratuvarımızın girdisi, hayalî bir finans kurumuna ait altı işlev ve alt kategorilerini içeren `nist_csf_matrisi.json` veri dosyasıdır. İşlem, `nist_csf_evaluator.py` motorunun yapıyı doğrulaması, ağırlıklı olgunluk puanlarını hesaplaması, ASCII radar grafiğini çizmesi ve mimari dengesizlikleri analiz etmesidir. Beklenen sonuç, 79.3 puan ile Tier 3 olgunluk seviyesinin belirlenmesi ve tek gelişim alanı olarak `ID.IM` kategorisinin listelenmesidir. Negatif kontrol ise zorunlu işlevlerden (örn: GOVERN veya RECOVER) biri eksik olduğunda veya Protect-Bias dengesizliği kurgulandığında sistemin hata fırlatıp analisti uyarmasıdır.

#### 2. Teknik Gerekçe
Bir değerlendirme aracının güvenilirliği, yalnızca hatasız senaryolarda doğru çalışmasıyla değil, eksik veya manipüle edilmiş verileri (anomali) yakalama kabiliyetiyle ölçülür. NIST CSF 2.0'da bir işlevin eksik olması tüm savunma zincirini kopardığından, doğrulama motorunun bunu sessizce görmezden gelmeyip `NistCsfValidationError` üretmesi matematiksel ve mantıksal bir zorunluluktur.

#### 3. Yaygın Hata
Laboratuvar testlerinde yalnızca olumlu ("happy path") senaryoları denemek; sınır değerleri, eksik sütunları ve mantıksal aykırılıkları (örn: Protect=100 iken Detect=0 olması) doğrulamamak.

#### 4. Standart ve Kaynak
* ISO/IEC 27004: Bilgi Güvenliği Yönetimi — İzleme, Ölçme, Analiz ve Değerlendirme.
* NIST SP 800-53 Rev. 5: CA-7 (Continuous Monitoring) ve PM-6 (Information Security Measures of Performance).

---

### Soru 3: 'NIST CSF 2.0 işlevleri' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Yanıt
Risk; kurumsal yönetişimin (Govern) eksikliği, varlıkların sahipsiz kalması (Identify), tedarikçilerin denetlenmemesi veya koruma duvarlarına aşırı güvenilip tespit (Detect) ve kurtarma (Recover) süreçlerinin terk edilmesiyle oluşur. Risk, periyodik NIST CSF olgunluk matrisi denetimleriyle, açığı olan alt kategorilerin (Gap Analysis) tespitiyle ve sızma testleriyle keşfedilir. Önleme ise 6 işlevi dengeli bir biçimde hayata geçiren kontrollerle (MFA, EDR/SIEM, SOAR, hava aralıklı yedekler ve kurumsal politikalar) sağlanır.

#### 2. Teknik Gerekçe
Risk formülü $Risk = Tehdit \times Zafiyet \times Etki$ dengesine dayanır. Bir kurumda `GV.SC` (Tedarik Zinciri Risk Yönetimi) yoksa, üçüncü taraf bir yazılım güncellemesi (örn: SolarWinds) tüm kurum ağını zafiyete boğar. Kurumda `DE.CM` (Sürekli İzleme) yoksa, saldırganın ağdaki dwell time'ı (barınma süresi) aylar sürer ve veriler dışarı sızdırılır. Risk tespiti, telemetrilerin MITRE ATT&CK matrisiyle eşleştirilmesi ve kontrol listesi boşluklarının analizi ile gerçekleşir.

#### 3. Yaygın Hata
Risk yönetimini sadece yıllık yapılan sızma testi (penetration test) raporundan ibaret görmek. Sızma testi anlık bir fotoğraftır; NIST CSF ise yaşayan bir kurumsal savunma kalkanıdır.

#### 4. Standart ve Kaynak
* NIST SP 800-30 Rev. 1: Guide for Conducting Risk Assessments.
* NIST SP 800-37 Rev. 2: Risk Management Framework for Information Systems and Organizations.
