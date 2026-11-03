<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 006: Tehdit Modelleme Başlangıcı — Varlık, Güven Sınırı, Saldırı Yüzeyi ve Kontrol İlişkisi

---

## 1. Hocanın Giriş Sohbeti & Zihinsel Model (Mental Model)

Evlat, masamıza hoş geldin. Dün varlıklarımızı envantere aldık, onları sınıflandırdık ve tahtın mücevherlerini (Crown Jewels) belirledik. Peki şimdi ne yapacağız?
Birçok acemi yazılımcı veya güvenlikçi şöyle düşünür: *"Hocam, kodu yazalım, sunucuya atalım, önüne bir firewall koyarız, sonra da otomatik bir zafiyet tarama aracı (vulnerability scanner) çalıştırır, ne çıkarsa bakarız!"*

İşte bu, evini camdan inşa edip sonra ön kapısına çelik kilit takmaya benzer!
Siber güvenlik kod yazıldıktan veya sunucu kurulduktan sonra sonradan eklenen bir cila değildir. Güvenlik, **daha ilk mimari taslak çizilirken** sisteme nakşedilir. İşte buna **Tehdit Modelleme (Threat Modeling)** diyoruz.

Tehdit modellemenin babası sayılan Adam Shostack'in dünyaya öğrettiği 4 altın soru vardır:
1. **Ne inşa ediyoruz?** *(Sistemin mimarisi, veri akışları ve bileşenleri neler?)*
2. **Ne ters gidebilir?** *(Saldırgan nereden vurabilir, hangi tehditler var?)*
3. **Buna karşı ne yapacağız?** *(Hangi kontrolleri, şifrelemeleri, filtreleri koyacağız?)*
4. **Yeterince iyi yaptık mı?** *(Yaptığımız savunmayı test edip doğruladık mı?)*

Ve bugünün en can alıcı zihinsel prensibi şudur:
> **Tehdit, gerçekleşmiş bir olay (Incident) değildir!**  
> Tehdit; bir zafiyeti kullanarak sisteme zarar verme potansiyeline sahip her türlü tehlikedir. Bir fırtına tehdittir; ama çatıyı sağlam yaparsan o fırtına bir felakete (olaya) dönüşmez. Tehdit modelleme, tehditleri henüz birer güvenlik ihlaline dönüşmeden mimari masasında imha etme sanatıdır.

Bugün bir diğer hayati kavramı öğreneceksin: **Güven Sınırı (Trust Boundary)**.
Havalimanlarını düşün: Bilet kontrolünden geçmeden önceki alan bir güven bölgesidir; pasaport kontrolünden geçtikten sonraki dış hatlar bekleme salonu farklı bir güven bölgesidir; uçağın içi ise en üst güven bölgesidir. Bir yolcu (veri), bir alandan diğerine geçerken mutlaka bir polis/gümrük noktasından (kontrol) geçmek zorundadır.
Bir yazılımda da kullanıcı klavyesinden çıkan veri işletim sistemi belleğine geçerken; bellekten diske yazılırken; veya yerel makineden internetteki bulut sunucusuna akarken **Güven Sınırlarını** aşar. Eğer bir veri akışı güven sınırını kontrolsüz, şifresiz ve doğrulamasız geçiyorsa; orası bir saldırgan için açık kapıdır!

```
 [DIŞ VARLIK: E1]
 (Kullanıcı / İnsan)
         |
         | [DF1: Not Metni]
         | (Girdi Doğrulama & Sanitizasyon)
 ~ ~ ~ ~ v ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
 [ GÜVEN SINIRI: TB1 - Kullanıcı / İşletim Sistemi Oturum Sınırı ]
 ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
         |
         v
 +-----------------------------------------------------------------------------+
 | [SÜREÇ: P1] Not Defteri Masaüstü Süreci (Bellek / Execution Memory)         |
 | - Kullanıcı Arayüzü Olay Yönetimi (UI Event Loop)                           |
 | - Kriptografik Şifreleme & Çözme (AES-256-GCM / PBKDF2)                     |
 +----------------------+------------------------------+-----------------------+
                        |                              |
 ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~  v  ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ v ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
 [ GÜVEN SINIRI: TB2 - Disk Depolama Sınırı ]   [ GÜVEN SINIRI: TB3 - İnternet/Bulut Sınırı ]
 ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
                        |                              |
    [DF2/DF3: Şifreli Kalıcı Depolama]           [DF4: Sıfır Bilgi E2EE Senkronizasyon]
    - At-Rest AES-256-GCM                       - TLS 1.3 Taşıma Koruması
    - GCM Kimlik Doğrulama Etiketi (Auth Tag)   - Certificate Pinning & JWT
                        |                              |
                        v                              v
 [(VERİ DEPOSU: DS1)]                          [UZAK SÜREÇ: P2]
 Şifreli Not Kasası (SQLite Dosyası)           Bulut Senkronizasyon Servisi (AWS API)
```

---

## 2. Sıfırdan Başlayan Kristal Netliğinde Teori

### 2.1. Veri Akış Diyagramının (DFD - Data Flow Diagram) 4 Temel Elemanı
Bir mimariyi tehdit modellemesine hazırlamak için onu DFD seviyesinde parçalara ayırırız:
1. **Dış Varlıklar (External Entities - Dikdörtgen):** Sistemin sınırları dışındaki aktörler (İnsan kullanıcı, harici bir ödeme servisi API'si).
2. **Süreçler (Processes - Daire / Yuvarlak Köşeli Dikdörtgen):** Veriyi alan, işleyen, değiştiren veya yönlendiren kod parçaları (Web sunucusu, masaüstü uygulaması, arka plan worker'ı).
3. **Veri Depoları (Data Stores - Çift Çizgi / Silindir):** Verinin kalıcı veya geçici olarak bekletildiği yerler (SQLite veritabanı, Redis önbelleği, log dosyası).
4. **Veri Akışları (Data Flows - Oklar):** Bilginin bir bileşenden diğerine hangi protokol ve biçimde aktığını gösteren hatlar.
5. **Güven Sınırları (Trust Boundaries - Kesikli Çizgiler):** Farklı yetki, ayrıcalık veya erişim seviyelerine sahip bölgeleri ayıran hayati çizgiler.

### 2.2. Microsoft STRIDE Tehdit Çerçevesi
Siber güvenlik dünyasında tehditleri sınıflandırmak için en çok kullanılan standart **STRIDE** modelidir. STRIDE, CIA üçlüsünün ve yetkilendirmenin ters yüz edilmiş halidir:

| STRIDE Harfi | Tehdit Adı (TR/EN) | Açıklama | Karşı Güvenlik Hedefi |
| :---: | :--- | :--- | :--- |
| **S** | **Spoofing** (Kimlik Sahteciliği) | Saldırganın yetkili bir kullanıcı veya meşru bir sunucu gibi davranması. | **Kimlik Doğrulama** (Authentication - MFA, TLS) |
| **T** | **Tampering** (Veri Tahrifatı) | Veritabanındaki veya iletimdeki verinin yetkisizce değiştirilmesi. | **Bütünlük** (Integrity - Hash, HMAC, GCM Auth Tag) |
| **R** | **Repudiation** (İnkar Edilebilirlik) | Bir kullanıcının yaptığı kritik işlemi "ben yapmadım" diyerek reddetmesi. | **İnkar Edilemezlik** (Non-Repudiation - Dijital İmza, Audit Log) |
| **I** | **Information Disclosure** (Bilgi İfşası) | Gizli verinin üçüncü şahıslar tarafından okunması veya sızdırılması. | **Gizlilik** (Confidentiality - AES-256 Şifreleme) |
| **D** | **Denial of Service** (Hizmet Engelleme) | Sistemin kaynaklarının tüketilerek meşru kullanıcılara hizmet veremez hale getirilmesi. | **Erişilebilirlik** (Availability - Rate Limiting, DDoS Koruması) |
| **E** | **Elevation of Privilege** (Yetki Yükseltme) | Düşük yetkili bir kullanıcının yönetici (Admin/Root) yetkilerine sıçraması. | **Yetkilendirme** (Authorization - Least Privilege, RBAC) |

### 2.3. Saldırı Yüzeyi (Attack Surface) Nedir?
Saldırı yüzeyi; bir saldırganın sisteme veri sokabileceği, sistemden veri çekebileceği veya sisteme komut yürütebileceği **tüm giriş ve çıkış noktalarının toplamıdır**.
* Bir uygulamanın ne kadar çok açık portu, ne kadar çok parametre alan API uç noktası ve ne kadar çok güven sınırı geçişi varsa, saldırı yüzeyi o kadar geniştir.
* Güvenli mimarinin hedefi saldırı yüzeyini küçültmektir (Attack Surface Reduction - ASR).

---

## 3. İki Yönlü Bakış: Saldırganın Gözü (Offensive) vs Savunmacının Kalkanı (Defensive)

### Saldırganın Gözü (Offensive Angle)
Bir tersine mühendis (Reverse Engineer) veya istismar geliştirici (Exploit Developer) yerel bir uygulamayı hedeflerken kaynak koduna bakmadan önce DFD'sini kafasında çizer:
1. **Güven Sınırı İhmallerini Aramak (Unvalidated Trust Boundaries):** Geliştirici genellikle `TB2` sınırını (Disk Depolama) güvenli sanır: *"Zaten dosya kullanıcının kendi bilgisayarında, oraya kim müdahale edebilir ki?"* der. Saldırgan, kullanıcının bilgisayarına bıraktığı düşük yetkili bir zararlı yazılımla o SQLite dosyasındaki şifresiz alanları tahrif eder (Tampering) veya içine özel biçimlendirilmiş zararlı baytlar enjekte eder. Uygulama bir sonraki açılışında bu dosyayı güvenle okumaya çalıştığında bellek taşması (Buffer Overflow) tetiklenir ve saldırgan sistemde kod yürütür!
2. **Ağ Dinlemesi ve Sahte Sunucu (Spoofing & Information Disclosure):** `TB3` sınırında eğer uygulama TLS Sertifika Sabitlemesi (Certificate Pinning) yapmıyorsa, saldırgan yerel ağda (Wi-Fi) sahte bir kök sertifika enjekte ederek araya girer (Man-in-the-Middle) ve not senkronizasyon paketlerini deşifre eder.

### Savunmacının Kalkanı (Defensive Angle)
Biz savunmacılar olarak her güven sınırında **"Sıfır Güven" (Zero Trust)** ilkesiyle hareket ederiz:
1. **Girişte Doğrulama (TB1):** Kullanıcıdan gelen her girdi potansiyel bir saldırıdır. Boyut sınırlaması (10 MB), karakter kaçırma (Sanitization) ve tip kontrolü zorunludur.
2. **Kalıcı Depolamada Doğrulanmış Kriptografi (TB2):** Notlar diske yazılırken sadece şifrelenmekle (AES-256) kalmaz; **AES-GCM (Galois/Counter Mode)** kullanılarak bir Kimlik Doğrulama Etiketi (Authentication Tag) üretilir. Dosyadaki tek bir bit bile dışarıdan değiştirilirse GCM çözme işlemi başarısız olur ve tahrifat anında engellenir.
3. **Ağ İletiminde Sıfır Bilgi ve Sabitleme (TB3):** İstemci ile bulut sunucusu arasındaki iletişim TLS 1.3 ile şifrelenir; sunucu sertifikası koda gömülerek (Certificate Pinning) sahte sertifikalar engellenir ve **Sıfır Bilgi (Zero-Knowledge)** mimarisiyle sunucunun dahi notların içeriğini okuyamayacağı uçtan uca şifreleme sağlanır.

---

## 4. Hocayla Birlikte Canlı Laboratuvar (Gerçek Kod & Canlı Sistem)

Bugün geliştirdiğimiz `threat_modeler.py` motoru; yerel bir not uygulamasının (`KriptoNot`) Veri Akış Diyagramını (DFD) okur, güven sınırlarını denetler, açıkta kalan STRIDE tehditlerini tespit eder ve ASCII akış şemasını üretir.

### Canlı Betiğimizin Kod Mimarisi ve Kritik Doğrulama Bloğu
Aşağıdaki kod parçası, yüksek riskli güven sınırlarını geçen veri akışlarında kriptografik koruma olup olmadığını matematiksel olarak denetleyen mimari kuralı göstermektedir:

```python
# uygulama/threat_modeler.py dosyasından kritik bölüm:
# Yüksek riskli sınır geçişlerinde (Disk ve Ağ) şifreleme denetimi:

for akis in veri_akislari:
    sinir_id = akis.get("gecilen_sinir")
    sinir_obj = guven_sinirlari.get(sinir_id, {})
    risk_seviyesi = sinir_obj.get("risk_seviyesi", "DUSUK")

    kontroller = [str(k).lower() for k in akis.get("kontroller", [])]

    # Disk (TB2) veya İnternet (TB3) gibi kritik sınırlardan geçen veride
    # AES, TLS veya GCM gibi kriptografik kontroller zorunludur!
    if risk_seviyesi in {"YUKSEK", "KRITIK"}:
        sifreleme_var_mi = any(
            "aes" in k or "tls" in k or "şifre" in k or "sifre" in k or 
            "encrypt" in k or "gcm" in k
            for k in kontroller
        )
        if not sifreleme_var_mi:
            # Sınırı korumasız geçen akış bir mimari güvenlik açığıdır
            guvenlik_bulgulari.append({
                "seviye": "KRİTİK MİMARİ KUSUR",
                "id": akis.get("id"),
                "mesaj": f"'{akis.get('id')}' akışı '{sinir_obj.get('ad')}' ({risk_seviyesi}) sınırını geçiyor ancak kriptografik koruma tanımlanmamış!"
            })
```

### Canlı Terminal Yürütmesi
Aracımızı `not_uygulamasi_dfd.json` üzerinde çalıştırdığımızda elde ettiğimiz canlı DFD çıktısı:

```text
========================================================================================================
  VERİ AKIŞ DİYAGRAMI (DFD) VE GÜVEN SINIRI ŞEMASI: KriptoNot Yerel Not ve Senkronizasyon Uygulaması
  Gün: G006 | Bileşen: 4 | Sınır: 3 | Akış: 4
========================================================================================================

  [DIŞ VARLIK: E1]                 === GÜVEN SINIRI: TB1 (Kullanıcı Girdi Sınırı) ===
  (Kullanıcı / İnsan)
          |
          |  [DF1: Not Girişi / Girdi Doğrulama & Sanitizasyon]
          v
  +--------------------------------------------------------------------------------+
  | [SÜREÇ: P1] Not Defteri İstemci Süreci (Masaüstü Uygulaması)                   |
  | - Kullanıcı Arayüzü Yönetimi                                                   |
  | - Kriptografik Şifreleme / Çözme (AES-256-GCM)                                 |
  +-----------------------+--------------------------------+-----------------------+
                          |                                |
   === GÜVEN SINIRI: TB2 (Disk/Depolama) ===       === GÜVEN SINIRI: TB3 (İnternet/Bulut) ===
                          |                                |
     [DF2/DF3: Şifreli Okuma/Yazma]                 [DF4: Sıfır Bilgi TLS 1.3 Sync]
     - AES-256-GCM + Auth Tag                      - Certificate Pinning + JWT
                          |                                |
                          v                                v
  [(VERİ DEPOSU: DS1)]                             [UZAK SÜREÇ: P2]
  Şifreli Not Kasası (SQLite Dosyası)              Bulut Senkronizasyon Sunucusu (API)

--------------------------------------------------------------------------------------------------------
  STRIDE TEHDİT KAPSAMI VE DURUMU:
    * SPOOFING                : 1 Tehdit Tanımlı ve Engellendi
    * TAMPERING               : 1 Tehdit Tanımlı ve Engellendi
    * REPUDIATION             : Tehdit Tanımlanmamış
    * INFORMATION_DISCLOSURE  : 2 Tehdit Tanımlı ve Engellendi
    * DENIAL_OF_SERVICE       : 1 Tehdit Tanımlı ve Engellendi
    * ELEVATION_OF_PRIVILEGE  : Tehdit Tanımlanmamış
--------------------------------------------------------------------------------------------------------
  [+] MİMARİ DOĞRULAMA BAŞARILI: Güven sınırlarını geçen tüm akışlar kriptografik olarak korunmuştur.
      Açıkta kalan (sahipsiz/mitigasyonsuz) hiçbir STRIDE tehdidi tespit edilmedi.
========================================================================================================
```

---

## 5. Hocanın "Ölümcül Hatalar" Notu

Evlat, tehdit modelleme yaparken şu 5 ölümcül yanılgıya asla düşme:

1. **"Tehdit" ile "Olay"ı Birbirine Karıştırmak:**
   Her tehdit bir olay değildir; her tehdit gerçekleşecek diye bir kural da yoktur. Tehdit potansiyeldir, olay ise gerçeğe dönüşmüş halidir. Tehdit modellemenin amacı panik yapmak değil, mimariyi sakin bir mühendislik aklıyla zırhlandırmaktır.
2. **Yerel Dosya Sistemini "Zaten Güvenli" Sanmak:**
   "Kullanıcının kendi diski, orayı şifrelemeye ne gerek var?" diyen tüm yerel not defteri ve parola yöneticisi uygulamaları tarihin çöplüğüne karıştı. Bilgisayara giren basit bir casus yazılım (Spyware) düz metin notları 1 saniyede çalar.
3. **Mimariyi Çizmeden Güvenlik Aracı Satın Almak:**
   Sistemin veri akışlarını ve güven sınırlarını haritalandırmadan kurulan firewall'lar ve EDR'lar kör nöbetçiler gibidir; arka kapının açık olduğunu göremezler.
4. **Tehdit Tanımlayıp Karşısına Kontrol Koymamak (Unmitigated Threats):**
   Tehdit modelleme dokümanına "Saldırgan sahte sertifika ile araya girebilir" yazıp karşısına hiçbir kontrol (Mitigation) tanımlamadan projeyi canlıya almak, bilerek açık kapı bırakmaktır.
5. **Tehdit Modellemesini Bir Seferlik Kâğıt İşi Sanmak:**
   Yazılıma her yeni özellik (Feature), her yeni API ve her yeni entegrasyon eklendiğinde DFD güncellenmeli ve tehdit modeli yeniden işletilmelidir.

---

## 6. Laboratuvar Görevi ve Beklenen Çıktılar

### Görev Tanımı
Yerel bir not defteri uygulaması (`KriptoNot`) için 4 bileşen (Kullanıcı, Masaüstü Süreci, SQLite Veri Deposu, Bulut API), 3 güven sınırı (Kullanıcı Sınırı, Disk Sınırı, Ağ Sınırı) ve 4 veri akışı içeren Veri Akış Diyagramını (DFD) JSON olarak modelle; `threat_modeler.py` ile çalıştırarak mimariyi doğrula ve negatif kontrol senaryolarını test et.

### Girdi Verisi (`ornek_veri/not_uygulamasi_dfd.json`)
* **Bileşenler:** E1 (Dış Varlık), P1 (Süreç), DS1 (Veri Deposu), P2 (Uzak Süreç).
* **Güven Sınırları:** TB1 (Kullanıcı Girdi Sınırı), TB2 (Disk/Kalıcı Depolama Sınırı), TB3 (İnternet/Ağ Sınırı).
* **Akışlar:** DF1 (Girdi), DF2 (Şifreli Yazma), DF3 (Şifreli Okuma), DF4 (Bulut Senkronizasyonu).
* **STRIDE Tehditleri:** 5 tanımlı tehdit (Spoofing, Tampering, Information Disclosure, Denial of Service).

### Pozitif ve Negatif Kontroller
1. **Pozitif Kontrol:** Model eksiksiz doğrulandığında 4 bileşen, 3 sınır, 4 akış hatasız eşleşir; mimari açık sayısı 0 çıkar.
2. **Negatif Kontrol 1 (Hayalet Kaynak):** Akışın kaynağı tanımlı olmayan bir bileşen yapıldığında `ThreatModelValidationError` fırlatılır.
3. **Negatif Kontrol 2 (Tanımsız Güven Sınırı):** Akış tanımlanmamış bir sınır iddia ettiğinde sistem işlemi durdurur.
4. **Negatif Kontrol 3 (Korumasız Sınır Geçişi):** İnternet akışından (DF4) TLS kaldırıldığında motor `KRİTİK MİMARİ KUSUR` alarmı üretir.
5. **Negatif Kontrol 4 (Açık Tehdit):** Bir tehdidin kontrolü boş bırakıldığında motor `AÇIK TEHDİT (UNMITIGATED)` bulgusu raporlar.

---

## 7. Hocanın Soru Odası (Kapsamlı Soru-Cevap)

Müfredatımızın `SORU BANKASI` gereksinimlerine göre 4 katı alt başlık kuralıyla cevaplanmıştır:

### Soru 1: Tehdit modelleme başlangıcı: Temel mekanizmayı ve güvenlik önemini açıkla.

#### 1. Yanıt
Tehdit modeli; varlık (asset), güven sınırı (trust boundary), saldırı yüzeyi (attack surface) ve kontrol (mitigation) arasındaki nedensel ilişkiyi kuran yapısal bir analiz yöntemidir. En kritik ilkesi şudur: **Her tehdit gerçekleşmiş bir olay değildir.** Tehdit modelleme, sistemin mimarisini Veri Akış Diyagramları (DFD) ile haritalandırarak ve STRIDE metodolojisini kullanarak potansiyel tehlikeleri henüz birer güvenlik ihlaline (incident) dönüşmeden tasarım aşamasında tespit edip bertaraf etmeyi sağlar.

#### 2. Teknik Gerekçe
Yazılım ve sistem mimarisinde bileşenler tek başına güvenli görünse bile, farklı ayrıcalık seviyeleri arasındaki güven sınırlarını (örneğin kullanıcı girdisi ile uygulama belleği veya yerel makine ile internet hattı) aşarken zafiyetler doğar. Tehdit modeli olmadan geliştirilen sistemlerde savunma reaktif kalır; zafiyetler ancak saldırganlar tarafından istismar edildiğinde fark edilir. Tehdit modelleme, saldırı yüzeyini en aza indirerek proaktif güvenliği mimari düzeyde temin eder.

#### 3. Yaygın Hata
Tehdit modellemesini yalnızca sızma testi (penetration test) aşamasında veya sistem canlıya alındıktan sonra hatırlamak; güven sınırlarını belirlemeden sadece güvenlik duvarı veya antivirüs gibi genel geçer ürünlere güvenmek.

#### 4. Standart ve Kaynak
* NIST SP 800-154: Guide to Data-Centric System Threat Modeling.
* OWASP Threat Modeling Project & Microsoft Threat Modeling Process (STRIDE).

---

### Soru 2: Tehdit modelleme başlangıcı: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

#### 1. Yanıt
Laboratuvarımızın girdisi, yerel bir not uygulamasına (`KriptoNot`) ait bileşenleri, güven sınırlarını, veri akışlarını ve STRIDE tehditlerini içeren `not_uygulamasi_dfd.json` veri dosyasıdır. İşlem, `threat_modeler.py` motorunun bileşen ve akış bütünlüğünü doğrulaması, güven sınırlarını geçen akışların kriptografik kontrollerini denetlemesi ve açıkta kalan tehditleri sorgulamasıdır. Beklenen sonuç, 4 bileşen ve 3 sınırın 0 mimari kusurla doğrulanması ve ASCII DFD şemasının basılmasıdır. Negatif kontrol ise akışlardan birinin kaynağı hayalet bir bileşen yapıldığında veya kritik sınır geçişinde şifreleme kaldırıldığında sistemin hata üretmesidir.

#### 2. Teknik Gerekçe
Bir tehdit modelleme aracının teknik geçerliliği, mimarideki kopuklukları (var olmayan bileşene giden akışlar) ve sahte güvenlik iddialarını (internet sınırını düz metin geçen akışlar) matematiksel olarak yakalayabilmesine bağlıdır. Güven sınırını korumasız geçen bir veri akışı sessizce onaylanırsa modelleme amacını yitirir; bu nedenle negatif kontroller mimari güvenliğin temel sigortasıdır.

#### 3. Yaygın Hata
Laboratuvarda yalnızca ideal ve eksiksiz modelleri çalıştırmak; sınır ihlallerini, tanımsız ID'leri ve mitigasyonsuz bırakılan açık tehdit senaryolarını test etmemek.

#### 4. Standart ve Kaynak
* ISO/IEC 27034: Application Security — Application Security Risk Management.
* NIST CSF 2.0: ID.RA (Risk Assessment) ve PR.DS (Data Security).

---

### Soru 3: 'Tehdit modelleme başlangıcı' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Yanıt
Risk; sistem mimarisindeki güven sınırlarının belirsiz bırakılması, veri akışlarının doğrulamasız/şifresiz geçiş yapması veya tehditlerin tespit edilip karşısına hafifletici kontrol konulmamasıyla oluşur. Risk, Veri Akış Diyagramı (DFD) üzerindeki güven sınırı kesişim noktalarının incelenmesi ve STRIDE matrisindeki boşlukların analizi ile tespit edilir. Önleme ise girdi doğrulaması (Input Sanitization), güçlü kriptografi (AES-256-GCM, TLS 1.3), sertifika sabitleme ve en az yetki mimarisi ile sağlanır.

#### 2. Teknik Gerekçe
Saldırganlar sistemin en güçlü zırhına değil, iki bileşen arasındaki güven sınırının denetimsiz kaldığı noktalara (örneğin yerel SQLite veritabanına yazılan verinin tahrif edilmesi veya ağdan gelen paketin doğrulanmaması) saldırırlar. Bir güven sınırında kimlik doğrulama veya bütünlük denetimi yoksa, tehdit doğrudan istismara (Exploit) ve veri sızıntısına dönüşür. Kontroller (HMAC, GCM Auth Tag, TLS) sınır geçişlerini koruma altına alarak riski kabul edilebilir seviyeye indirir.

#### 3. Yaygın Hata
Yerel diskte saklanan veriyi "zaten kullanıcının kendi bilgisayarında" varsayımıyla şifrelemeden saklamak; yerel depolama sınırını (TB2) güvenli bölge sanmak.

#### 4. Standart ve Kaynak
* Microsoft Security Development Lifecycle (SDL) — Threat Modeling Guidelines.
* OWASP Top 10: A04:2021 — Insecure Design (Güvensiz Tasarım).
