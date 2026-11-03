<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 005: Varlık Envanteri ve Veri Sınıflandırması

---

## 1. Hocanın Giriş Sohbeti & Zihinsel Model (Mental Model)

Evlat, masamıza hoş geldin. Dün NIST CSF 2.0'ın altı büyük işlevini ve bunların orkestrasyonunu konuştuk. Hatırlarsan orada ikinci sütunumuz **IDENTIFY (Tanımlama)** idi. İşte bugün o sütunun en temel taşına, bir siber güvenlik operasyonunun başladığı sıfır noktasına iniyoruz: **Varlık Envanteri (Asset Inventory) ve Veri Sınıflandırması (Data Classification)**.

Sana siber güvenlik sektöründe milyonlarca dolarlık zararlara yol açan en trajik yanılgılardan birini anlatayım.
Bir şirketin bilgi işlem odasına girersin; cam fanusun arkasında 45.000 dolarlık pırıl pırıl, yedek güç kaynaklı, devasa bir omurga güvenlik duvarı (NGFW) durur. Yan taraftaki tozlu rafın en altında ise 6 yıl önce 2.500 dolara alınmış, fanı ses çıkaran eski bir sunucu yatar.
Şirketin muhasebe müdürüne sorarsan der ki: *"Hocam, en değerli varlığımız şu 45.000 dolarlık canavar cihazdır! Onu koruyun!"*

İşte bu, siber güvenlikte **"Donanım Miyopluğu"**dur!
Çünkü o 45.000 dolarlık güvenlik duvarının içinde sadece yönlendirme tabloları vardır; çalınsa veya yansa yerine yenisini takarsın. Ama o tozlu rafın altındaki 2.500 dolarlık eski sunucunun içinde şirketin 10 yıllık tüm müşteri kredi kartları, kimlik numaraları, ticari sırları ve bakiye kayıtları (**Crown Jewels / Tahtın Mücevherleri**) durmaktadır! O sunucu ele geçirildiğinde şirketin uğrayacağı ceza (KVKK/GDPR yaptırımları), müşteri tazminatları ve hisse değeri kaybı **15 milyon dolardır!**

Zihnine kazımanı istediğim ilk altın kural şudur:
> **Bir siber varlığın kritikliği, fatura üzerindeki donanım fiyatıyla ölçülemez! Kritiklik; o varlığın taşıdığı verinin sınıfına, iş sürekliliğine etkisine ve ihlal durumunda doğuracağı yıkıma göre belirlenir.**

Ve ikinci hayati kavram: **Sahiplik (Ownership)**.
Sahada gördüğümüz hacklenme vakalarının en az yarısı, IT ekibinin varlığından bile haberdar olmadığı veya *"Bu sunucu kimin?"* diye sorulduğunda herkesin birbirine baktığı **Sahipsiz Varlıklar (Orphan Assets / Shadow IT)** üzerinden gerçekleşir. Sahibi olmayan bir sunucuyu kimse güncellemez, kimse yamamaz, kimse loglarını incelemez. Saldırgan için sahipsiz bir varlık, içeri sızıp karargah kuracağı mükemmel bir açık kapıdır!

```
                                 /\
                                /  \
                               /    \
                              / ÇOK  \        [SEVİYE 4 - ÇOK GİZLİ / SIR]
                             / GİZLİ  \       - Kredi Kartı, Biyometri, PII
                            /   SIR    \      - Zorunlu: AES-256 + FIDO2 MFA + PAM
                           /------------\     - 'Crown Jewels' (İflas / Yasal Ceza Riski)
                          /              \
                         /     GİZLİ      \   [SEVİYE 3 - GİZLİ]
                        /                  \  - Kaynak Kod, Ticari Sır, AD NTDS
                       /--------------------\ - Zorunlu: Şifreli Depolama + RBAC
                      /                      \
                     /        DAHİLİ          \ [SEVİYE 2 - DAHİLİ / İÇ KULLANIM]
                    /                          \ - İç Prosedürler, Ağ Şemaları
                   /----------------------------\ - Zorunlu: Kimlik Doğrulama
                  /                              \
                 /          KAMUYA AÇIK           \ [SEVİYE 1 - KAMUYA AÇIK]
                /                                  \ - Web Sitesi, Basın Bültenleri
               /------------------------------------\ - Odak: Bütünlük (WAF, TLS)
```

---

## 2. Sıfırdan Başlayan Kristal Netliğinde Teori

NIST CSF 2.0 `ID.AM` (Asset Management) ve ISO/IEC 27001 standardı (Madde A.8.1), güvenliği yönetebilmek için varlıkların eksiksiz bir envanterde toplanmasını ve sınıflandırılmasını şart koşar.

### 2.1. Varlık Nedir ve Türleri Nelerdir?
Birçok acemi "varlık" denilince sadece fiziksel bir bilgisayar kasasını anlar. Oysa siber güvenlikte varlık beş temel kategoriye ayrılır:
1. **VERİ (Data):** En nihai hedeftir. Veritabanları, dosya sunucuları, yedek arşivleri, bulut depolama alanları (S3 bucket).
2. **UYGULAMA (Application):** Veriyi işleyen yazılımlar, API uç noktaları, ERP sistemleri, mikroservisler, web siteleri.
3. **KİMLİK (Identity):** En kritik saldırı vektörüdür. Kullanıcı hesapları, etki alanı yöneticileri (Domain Admins), servis hesapları (Service Accounts), API tokenları ve SSH özel anahtarları.
4. **CİHAZ / DONANIM (Hardware/Device):** Sunucular, dizüstü bilgisayarlar, yönlendiriciler, güvenlik duvarları, IoT cihazları.
5. **AĞ ALTYAPISI (Network):** VLAN'lar, alt ağlar (subnets), VPN tünelleri ve DMZ bölgeleri.

### 2.2. Dört Seviyeli Veri Sınıflandırma Hiyerarşisi
Kurumdaki tüm verilere aynı koruma tedbirini uygulayamazsın. Halka açık basın bültenini şifrelemeye çalışmak bütçe israfıdır; müşteri kimlik numarasını şifrelemeden saklamak ise suçtur. Bu nedenle veriler dört sınıfa ayrılır:

* **1. Seviye: KAMUYA AÇIK (Public)**
  * *Tanım:* Herkesin erişimine açık, ifşa olması durumunda kuruma hiçbir zarar vermeyecek bilgiler (Ürün katalogları, kurumsal web sitesi metinleri).
  * *Güvenlik Odağı:* Gizlilik gereksinimi sıfırdır; ancak **Bütünlük (Integrity)** ve **Erişilebilirlik (Availability)** kritiktir. Sitenin tahrif edilmemesi (Defacement) ve DDoS ile çökertilmemesi için WAF ve CDN kullanılır.
* **2. Seviye: DAHİLİ / İÇ KULLANIM (Internal)**
  * *Tanım:* Yalnızca şirket çalışanlarının ve sözleşmeli personelin bilmesi gereken operasyonel veriler (İç telefon rehberi, yemekhane menüsü, iç politika dokümanları).
  * *Güvenlik Odağı:* Kurum dışına çıkmaması istenir ancak ifşası durumunda hayati bir tehlike oluşturmaz.
* **3. Seviye: GİZLİ (Confidential)**
  * *Tanım:* Yetkisiz kişilerin eline geçtiğinde şirkete ciddi mali, operasyonel veya rekabet kaybı yaşatacak hassas veriler (Ar-Ge kaynak kodları, finansal tablolar, tedarikçi sözleşmeleri, Active Directory şifre karmaları).
  * *Güvenlik Odağı:* Kesinlikle şifrelenmeli (At-Rest ve In-Transit), Rol Bazlı Erişim Kontrolü (RBAC) ile kısıtlanmalı ve DLP sistemleriyle izlenmelidir.
* **4. Seviye: ÇOK GİZLİ / SIR (Restricted / Top Secret / Crown Jewels)**
  * *Tanım:* Kurumun en kritik hazinesidir. İfşa olması durumunda kurumun iflasına, ağır yasal cezalara (KVKK, BDDK, GDPR, PCI-DSS) veya adli soruşturmalara yol açacak veriler (Kredi kartı numaraları, biyometrik veriler, sağlık kayıtları, yönetici anahtarları).
  * *Güvenlik Odağı:* FIDO2/MFA zorunluluğu, Donanım Güvenlik Modülü (HSM), ayrıcalıklı erişim yönetimi (PAM), izole ağ segmentasyonu ve değiştirilemez çevrimdışı (WORM) yedekleme.

### 2.3. Varlık Sahipliği (Asset Ownership) İlkeleri
Bir envanter tablosunda en kritik sütun **"Sahip" (Asset Owner)** sütunudur.
* Varlık sahibi genellikle bir teknik sistem yöneticisi değil, o varlığın iş süreçlerindeki sorumlusudur (Örn: Müşteri veritabanının sahibi IT teknisyeni değil, Veri Yönetişimi Direktörüdür).
* Varlık Sahibi ne yapar?
  1. Varlığın veri sınıfını ve kritiklik seviyesini belirler.
  2. Varlığa kimlerin erişebileceğini (Access Matrix) onaylar.
  3. Yılda en az bir kez erişim yetkilerini gözden geçirir (Access Review).
  4. Varlık ömrünü tamamladığında güvenli imha (Decommissioning) sürecini başlatır.

---

## 3. İki Yönlü Bakış: Saldırganın Gözü (Offensive) vs Savunmacının Kalkanı (Defensive)

### Saldırganın Gözü (Offensive Angle)
Bir sızma testi uzmanı (Red Team) veya siber saldırgan, hedef ağa adım attığında doğrudan güvenlik operasyon merkezinin (SOC) gözünün üzerinde olduğu ana sunuculara saldırmaz:
1. **Gölge BT (Shadow IT) Keşfi:** Saldırgan, pasif DNS kayıtlarını, sertifika şeffaflık (Certificate Transparency) günlüklerini ve Shodan taramalarını inceler. Şirketin unuttuğu `test-api-2022.firma.com` veya `staging-db.firma.com` gibi sahipsiz sunucuları tespit eder. Bu sunucularda yama yapılmamış zafiyetler (RCE) bulunur.
2. **Kimlik Avcılığı (Identity as an Asset):** Saldırgan için en değerli varlık sunucu kasası değil, bellekteki Kerberos biletleri ve Domain Admin hash'leridir. `AST-003` gibi bir Domain Controller ele geçirildiğinde, tüm kurum ağının anahtarı saldırganın eline geçer.
3. **Çifte Şantajda (Double Extortion) Veri Sınıfı Hedeflemesi:** Modern fidye yazılımı aktörleri rastgele dosya şifrelemez. Önce ağda sessizce gezerek `COK_GIZLI_SIR` sınıfındaki veritabanlarını bulur ve dışarı sızdırır (Exfiltration). Fidyeyi ödemezsen bu verileri Dark Web'de yayınlamakla tehdit eder; çünkü kurumun KVKK/GDPR cezasından korktuğunu çok iyi bilir!

### Savunmacının Kalkanı (Defensive Angle)
Mavi Takım (Blue Team) olarak savunmayı varlık temelli kurarız:
1. **Dinamik ve Sürekli Keşif (Continuous Asset Discovery):** Yılda bir kez manuel Excel doldurma devri kapanmıştır. Ağdaki her yeni IP'yi DHCP loglarından, Active Directory katılımından ve bulut API'lerinden (AWS/Azure) otomatik yakalayan CMDB motorları kullanırız.
2. **Hassas Veri Keşif ve Etiketleme (Data Discovery & DLP):** Dosya sunucuları ve e-postalar düzenli olarak regex ve yapay zeka ajanlarıyla taranır. İçinde 16 haneli kredi kartı veya 11 haneli T.C. Kimlik No geçen her dosya otomatik olarak `COK_GIZLI_SIR` etiketiyle mühürlenir.
3. **Ağ Segmentasyonu ve DMZ Kuralı:** Kamuya açık uygulamalar (`AST-002`) izole DMZ bölgesinde tutulurken, müşteri veritabanları (`AST-001`) internete tamamen kapalı, yalnızca uygulama sunucularının belirli portlardan erişebildiği izole iç ağlarda (Micro-segmentation) muhafaza edilir.

---

## 4. Hocayla Birlikte Canlı Laboratuvar (Gerçek Kod & Canlı Sistem)

Bugün geliştirdiğimiz `asset_classifier.py` motoru, bir kurumun envanterini doğrular, sahipsiz sistemleri cezalandırır, sınıflandırma uyumsuzluklarını ifşa eder ve donanım fiyatı ile iş riski arasındaki devasa uçurumu matematiksel olarak hesaplar.

### Canlı Betiğimizin Kod Mimarisi ve Kritik Bölümleri
Betiğimizin her satırı öğretici açıklamalarla donatılmıştır. Aşağıda sahipsizlik kontrolü ve şifreleme uyumluluğunun denetlendiği kritik kod bloğu yer almaktadır:

```python
# uygulama/asset_classifier.py dosyasından kritik bölüm:
# 1. Sahipsiz Varlık (Orphan Asset / Gölge BT) Denetimi:
sahip = varlik.get("sahip")
if not sahip or not isinstance(sahip, str) or len(sahip.strip()) < 3:
    # Sahibi olmayan bir varlık kural dışıdır; doğrudan NistCsf / ISO 27001 ihlalidir
    hatalar.append(f"Sahipsiz Varlık Hatası (Orphan Asset): '{v_id}' için atanmış sorumlu bir 'sahip' bulunamadı!")

# 2. Hassas Veri Taşıyan Varlıklarda Şifreleme (Encryption) Zorunluluğu:
if v_sinif in {"COK_GIZLI_SIR", "GIZLI"}:
    sifreleme_var_mi = any(
        "aes" in c or "şifre" in c or "sifre" in c or "encrypt" in c or 
        "tls" in c or "bitlocker" in c or "luks" in c
        for c in mevcut_kontroller
    )
    if not sifreleme_var_mi:
        guvenlik_uyarilari.append({
            "varlik_id": v_id,
            "seviye": "KRİTİK AÇIK",
            "mesaj": f"Varlık '{v_sinif}' sınıfında hassas veri taşıyor ancak şifreleme kontrolü tanımlanmamış!"
        })
```

### Canlı Terminal Yürütmesi
Aracımızı 5 gerçekçi kurumsal varlığı içeren `varlik_envanteri.json` üzerinde çalıştırdığımızda elde ettiğimiz denetim tablosu:

```text
========================================================================================================================
  KURUMSAL VARLIK ENVANTERİ VE VERİ SINIFLANDIRMA DENETİMİ: Anadolu Finansal Teknolojiler A.Ş.
  Gün Kimliği: G005 | Toplam Varlık: 5
========================================================================================================================
ID        | TÜR       | SINIF          | KRİTİKLİK  | DONANIM ($)  | İŞ ETKİSİ ($)  | ORAN   | VARLIK ADI
------------------------------------------------------------------------------------------------------------------------
AST-001   | VERI      | COK_GIZLI_SIR  | KRITIK     | $2,500       | $15,000,000    | 6000.0x | Müşteri Kredi Kartı ve Finansal Hesap Veritabanı (PostgreSQL Prod)
AST-002   | UYGULAMA  | KAMUYA_ACIK    | DUSUK      | $12,000      | $50,000        | 4.2x   | Dış Web Portalı ve Kurumsal Tanıtım Sunucusu (Nginx Web Cluster)
AST-003   | KIMLIK    | GIZLI          | KRITIK     | $4,000       | $25,000,000    | 6250.0x | Merkezi Active Directory Etki Alanı Yöneticisi (Domain Controller DC-01)
AST-004   | UYGULAMA  | GIZLI          | YUKSEK     | $6,000       | $8,000,000     | 1333.3x | Ar-Ge Kaynak Kod Deposu ve Dağıtım Sunucusu (GitLab Enterprise)
AST-005   | CIHAZ     | DAHILI         | KRITIK     | $45,000      | $10,000,000    | 222.2x | Merkezi Omurga Yönlendiricisi ve Yeni Nesil Güvenlik Duvarı (Core NGFW)
========================================================================================================================
  FINANSAL PARADOKS VE CROWN JEWELS ANALİZİ:
  * Toplam Satın Alma / Donanım Bedeli: $69,500.00
  * Olası İhlal Durumunda Toplam İş Etkisi: $58,050,000.00
  * SONUÇ: Kritiklik donanım fiyatıyla ölçülemez! $2,500'lık eski bir DB sunucusu $15,000,000'lık risk barındırır.
------------------------------------------------------------------------------------------------------------------------
  [+] GÜVENLİK DENETİMİ BAŞARILI: Veri sınıfları ve kontroller arasında çelişki bulunamadı.
========================================================================================================================
```

Tablodaki **ORAN** sütununa dikkat et:
* `AST-001` (Veritabanı) donanım fiyatının **6.000 katı** risk taşır!
* `AST-003` (Active Directory) donanım fiyatının **6.250 katı** risk taşır!
* `AST-005` (Pahalı Güvenlik Duvarı) donanım fiyatının sadece **222 katı** risk taşır.

---

## 5. Hocanın "Ölümcül Hatalar" Notu

Evlat, sahada bir denetim veya mimari tasarım yaparken şu 5 hataya düşenleri uyar:

1. **Donanım Faturasını Güvenlik Önceliği Sanmak:**
   Pahalı cihaza odaklanıp veritabanını unutan ekipler, ilk fidye yazılımı saldırısında şirketin iflas etmesine neden olurlar. Güvenlik bütçesi donanıma değil, verinin kritiklik indeksine göre dağıtılır.
2. **Sahipsiz Varlık (Orphan Asset) Bırakmak:**
   Envanterde "Sahibi: IT Ekibi" gibi genel ve soyut ifadeler kabul edilemez. Her varlığın adı, soyadı ve unvanı belli olan gerçek bir sahibi olmalıdır. Sahipsiz sistem, yamasız sistemdir.
3. **Aşırı Sınıflandırma (Over-Classification Felci):**
   Şirketteki her e-postayı ve her dokümanı "ÇOK GİZLİ" diye etiketlersen, çalışanlar iş yapamaz hale gelir. Bürokrasiyi aşmak için verileri kişisel Gmail hesaplarına veya USB disklere kopyalamaya başlarlar. Sınıflandırma dengeli ve uygulanabilir olmalıdır.
4. **Kimlikleri (Identities) Varlık Olarak Görmemek:**
   Birçok kurum sadece sunucuları ve dizüstü bilgisayarları envantere yazar; Domain Admin hesaplarını, bulut IAM rollerini ve servis hesaplarını unutur. Oysa saldırganlar sistemleri hacklemez, kimliklerle içeri girerler.
5. **Envanteri Yılda Bir Güncellenen Statik Bir Excel Sanmak:**
   Oluşturulduğu gün eskiyen bir Excel tablosu envanter değildir. Sanal sunucuların dakikalar içinde açılıp kapandığı bulut çağında envanter; API'lerle, tarayıcılarla ve CMDB araçlarıyla 7/24 canlı güncellenmelidir.

---

## 6. Laboratuvar Görevi ve Beklenen Çıktılar

### Görev Tanımı
Hayalî bir kurum için 5 farklı varlık türünü (Veri, Uygulama, Kimlik, Cihaz) içeren envanteri JSON formatında tanımla; her varlığa sahip, veri sınıfı ve kritiklik derecesi ata; `asset_classifier.py` ile çalıştırarak doğrula ve negatif kontrol senaryolarını test et.

### Girdi Verisi (`ornek_veri/varlik_envanteri.json`)
* `AST-001` (VERI): Sahip: Dr. Selin Kaya | Sınıf: COK_GIZLI_SIR | Kritiklik: KRITIK | Donanım: $2,500 | Risk: $15,000,000
* `AST-002` (UYGULAMA): Sahip: Kerem Yılmaz | Sınıf: KAMUYA_ACIK | Kritiklik: DUSUK | Donanım: $12,000 | Risk: $50,000
* `AST-003` (KIMLIK): Sahip: Burak Demir | Sınıf: GIZLI | Kritiklik: KRITIK | Donanım: $4,000 | Risk: $25,000,000
* `AST-004` (UYGULAMA): Sahip: Zeynep Can | Sınıf: GIZLI | Kritiklik: YUKSEK | Donanım: $6,000 | Risk: $8,000,000
* `AST-005` (CIHAZ): Sahip: Caner Aydın | Sınıf: DAHILI | Kritiklik: KRITIK | Donanım: $45,000 | Risk: $10,000,000

### Pozitif ve Negatif Kontroller
1. **Pozitif Kontrol:** 5 varlık eksiksiz doğrulandığında toplam donanım maliyeti $69,500, toplam iş etki değeri $58,050,000 olarak hesaplanır, sıfır hata ile tablo basılır.
2. **Negatif Kontrol 1 (Sahipsiz Varlık):** Bir varlığın `sahip` alanı boş bırakıldığında motor `AssetValidationError` ("Sahipsiz Varlık Hatası") fırlatarak çöker.
3. **Negatif Kontrol 2 (Geçersiz Veri Sınıfı):** Standart dışı bir sınıf girildiğinde sistem işlemi reddeder.
4. **Negatif Kontrol 3 (Mükerrer Kimlik):** İki varlığa aynı `varlik_id` verilmesi engellenir.
5. **Negatif Kontrol 4 (Korumasız Hassas Veri):** `COK_GIZLI_SIR` veride şifreleme kontrolü tanımlanmamışsa analiste `KRİTİK AÇIK` uyarısı üretilir.

---

## 7. Hocanın Soru Odası (Kapsamlı Soru-Cevap)

Müfredatımızın `SORU BANKASI` gereksinimlerine göre 4 katı alt başlık kuralıyla cevaplanmıştır:

### Soru 1: Varlık envanteri ve veri sınıflandırması: Temel mekanizmayı ve güvenlik önemini açıkla.

#### 1. Yanıt
Bir varlığın cihaz, uygulama, kimlik veya veri olması ona farklı koruma gereksinimleri getirir; kritiklik yalnızca parasal donanım değerine bağlı değildir. Varlık envanteri, kurumun sahip olduğu tüm dijital ve fiziksel kaynakların sahipleriyle birlikte kayıt altına alınmasıdır; veri sınıflandırması ise bu kaynakların taşıdığı bilginin gizlilik, bütünlük ve yasal etki derecesine göre derecelendirilerek uygun savunma kontrolleriyle (şifreleme, erişim yetkisi, segmentasyon) eşleştirilmesidir.

#### 2. Teknik Gerekçe
Sahip olduğun şeyi bilmeden koruyamazsın (NIST CSF ID.AM). Farklı varlık türleri farklı saldırı vektörlerine maruz kalır: Bir cihaz fiziksel hırsızlığa ve port taramasına maruz kalırken; bir kimlik kimlik avına (phishing) ve parola püskürtmeye (password spraying); bir web uygulaması SQL Injection'a; bir veri tabanı ise yetkisiz dışarı sızdırmaya (exfiltration) açıktır. Dolayısıyla her varlığa türüne ve veri sınıfına özel kontrol (cihaza BitLocker, kimliğe MFA/PAM, veriye AES-256) uygulanmalıdır.

#### 3. Yaygın Hata
Güvenlik önceliğini cihazın satın alma faturasına göre belirlemek. $45.000'lık bir güvenlik duvarını $2.500'lık bir müşteri veritabanından daha değerli sanarak bütçeyi ve koruma odak noktasını yanlış yönlendirmek.

#### 4. Standart ve Kaynak
* NIST CSF 2.0: ID.AM (Asset Management) ve PR.DS (Data Security).
* ISO/IEC 27001:2022 Ek A Madde 8.1 (Kullanıcı Uç Nokta Cihazları) ve Madde 5.12 (Bilgilerin Sınıflandırılması).

---

### Soru 2: Varlık envanteri ve veri sınıflandırması: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

#### 1. Yanıt
Laboratuvarımızın girdisi, 5 farklı varlık türünü içeren `varlik_envanteri.json` dosyasıdır. İşlem, `asset_classifier.py` motorunun varlık kimliklerini, sahiplik alanlarını, veri sınıflarını ve kontrollerini doğrulaması; donanım maliyeti ile iş etki değeri arasındaki çarpanı (Crown Jewels Index) hesaplaması ve güvenlik uyumsuzluklarını denetlemesidir. Beklenen sonuç, 5 varlığın $69.500 donanım ve $58.050.000 iş riski ile hatasız doğrulanmasıdır. Negatif kontrol ise bir varlığın `sahip` bilgisi silindiğinde (Orphan Asset) veya şifresiz gizli veri tespit edildiğinde sistemin hata fırlatmasıdır.

#### 2. Teknik Gerekçe
Siber güvenlik denetim araçları, belirsizliği ve insan hatasını ortadan kaldırmalıdır. Sahipsiz bir varlığın (Shadow IT) varlığı, o varlığın yama yönetimi ve log takibi dışında kalması anlamına geldiğinden, envanter doğrulayıcının eksik sahiplik durumunda işlemi derhal durdurması (`AssetValidationError`) kurumsal bir güvenlik zorunluluğudur.

#### 3. Yaygın Hata
Laboratuvar ortamında yalnızca tüm alanları dolu "mükemmel" verileri test etmek; sahipsiz varlık, mükerrer ID veya sınıflandırma-kontrol uyumsuzluğu gibi sınır durumları denetlememek.

#### 4. Standart ve Kaynak
* CIS Controls v8: Control 1 (Inventory and Control of Enterprise Assets) ve Control 3 (Data Protection).
* NIST SP 800-137: Information Security Continuous Monitoring (ISCM).

---

### Soru 3: 'Varlık envanteri ve veri sınıflandırması' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Yanıt
Risk; sahipsiz varlıkların (Gölge BT) ağda unutulması, hassas verilerin sınıflandırılmayıp şifresiz açık paylaşımlarda saklanması veya kritik varlıkların yanlışlıkla DMZ gibi güvensiz ağlara yerleştirilmesiyle oluşur. Risk; periyodik envanter taramaları, otomatik veri keşif araçları (DLP) ve ağ segmentasyon denetimleriyle tespit edilir. Önleme ise zorunlu varlık sahipliği ataması, en az yetki prensibi (Least Privilege), veri minimizasyonu, şifreleme ve ağ mikro-segmentasyonu ile sağlanır.

#### 2. Teknik Gerekçe
Saldırganlar kuruma girdiklerinde genellikle en iyi korunan kapılardan değil, unutulmuş ve güncellenmeyen sahipsiz test sunucularından giriş yaparlar. Ayrıca sınıflandırılmamış veriler şifrelenmediği için saldırganın bellek veya ağ dinleme yoluyla veriyi düz metin (plaintext) olarak ele geçirmesi mümkündür. DLP araçları ve ağ tarayıcıları düzenli olarak sınıflandırılmamış varlıkları sinyal olarak yakalamalı; IAM ve şifreleme kontrolleri yetkisiz erişimi engellemelidir.

#### 3. Yaygın Hata
Veri sınıflandırmayı çalışanların inisiyatifine bırakmak veya envanter çıkarmayı bir kerelik statik bir Excel doldurma görevi olarak görmek.

#### 4. Standart ve Kaynak
* NIST SP 800-60 Vol. 1 Rev. 1: Guide for Mapping Types of Information and Information Systems to Security Categories.
* FIPS PUB 199: Standards for Security Categorization of Federal Information and Information Systems.
