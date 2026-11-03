<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 001: Siber Güvenlik Nedir ve Neyi Korur?
## Varlık, Tehdit, Zafiyet, Risk ve CIA Üçlüsünün Mekanik Anatomisi

---

### 1. Hocanın Giriş Sohbeti & Zihinsel Model (Mental Model)

Hoş geldin evlat. Masamıza otur, çayını veya kahveni al. Bugün seninle 365 günlük uzun, zorlu ama hayatını değiştirecek bir yolculuğun tam ilk adımındayız. 

Karşımda sıfır bilgiyle oturuyor olabilirsin; IP nedir, RAM nedir, sunucu nedir henüz tam oturtamamış olabilirsin. Hiç önemli değil. Bu yolculukta senden tek bir şey istiyorum: **Ezber yapmayı bırak ve mekanizmayı zihninde canlandır.**

Sana ilk sorum şu: **Biz siber güvenlikçiler gerçekte neyi koruyoruz?**
Bilgisayarları mı? Yanıp sönen yeşil yazıları mı? Kabloları mı?
Hayır. Biz **DEĞERİ (VARLIĞI)** koruyoruz.

Şimdi gözlerini kapat ve şu zihinsel modeli zihnine kazı:
Bir şehir düşün. Şehrin ortasında büyük bir devlet hastanesi var. Bu hastanede üç kritik durum yaşanabilir:
1. **Senaryo A:** Başhekimin odasındaki hasta ameliyat ve kanser teşhis dosyalarını birisi gizlice cep telefonuyla fotoğraflayıp internete sızdırıyor. Hasta hayatta, ameliyat devam ediyor ama mahremiyet yerle bir oldu. İşte bu **Gizlilik (Confidentiality)** felaketidir.
2. **Senaryo B:** Birisi yoğun bakımdaki hastanın ilaç veritabanına giriyor. Hastanın alması gereken 5 mg insülin değerini 500 mg yapıyor. Sistem çalışıyor, ekran açık, kimse bir şey sızdırmadı ama veri **bozuldu**. Hasta ölür! İşte bu **Bütünlük (Integrity)** felaketidir.
3. **Senaryo C:** Hastanenin elektrikleri kesildi, jeneratör devreye girmedi ve ameliyathanedeki cihazlar kapandı; doktor hastaya müdahale edemiyor. Dosyalar sağlam, kimse görmedi ama **sistem ortada yok**. İşte bu **Erişilebilirlik (Availability)** felaketidir.

Gördün mü? Siber güvenlik, havalı hacker filmlerindeki gibi sadece şifre kırmak değildir. Siber güvenlik; dijital dünyada **Gizlilik, Bütünlük ve Erişilebilirlik** sacayağını dengede tutma sanatıdır. Biri çökerse hepsi çöker.

---

### 2. Sıfırdan Başlayan Kristal Netliğinde Teori (0'dan Uzmanlığa Derinlik)

Konuyu en temel yapıtaşlarına, atomlarına ayıralım.

```
                      +-----------------------------+
                      |         VARLIK (Asset)      |
                      |   (Veri, Donanım, İtibar)   |
                      +--------------+--------------+
                                     |
               +---------------------+---------------------+
               |                                           |
               v                                           v
    +----------------------+                    +----------------------+
    |    TEHDİT (Threat)   |                    |  ZAFİYET (Vuln)      |
    |  (Hacker, Deprem,    |                    |  (Zayıf parola,      |
    |   Kötü Amaçlı Yaz.)  |                    |   Açık port, Yama)   |
    +----------+-----------+                    +----------+-----------+
               |                                           |
               +---------------------+---------------------+
                                     |
                                     v
                          +---------------------+
                          |     RİSK (Risk)     |
                          | (Zarar Görme Olas.) |
                          +---------------------+
```

#### A. Temel Terminoloji Matrisi
1. **Varlık (Asset):** Korunmaya değer olan her şeydir. Okulun not kütüğü, bankanın müşteri hesap bakiyesi, şirketin kaynak kodları, sunucunun işlemci gücü birer varlıktır.
2. **Tehdit (Threat):** Bir varlığa zarar verme potansiyeli olan her türlü aktör veya olaydır. Bir APT grubu (devlet destekli hacker), fidye yazılımı (ransomware), sistem odasını basan su veya sinirli bir eski çalışan tehdittir.
3. **Zafiyet (Vulnerability):** Sistemdeki bir zayıflık, tasarım hatası veya eksikliktir. Örn: Veritabanına `root / 123456` parolası verilmesi, sistemin yamasız bırakılması veya dosya izinlerinin herkese açık olması (`chmod 777`).
4. **Risk (Risk):** Tehdidin var olan bir zafiyeti kullanarak varlığa zarar verme olasılığı ve bu zararın büyüklüğüdür:
   $$\text{Risk} = \text{Tehdit} \times \text{Zafiyet} \times \text{Varlık Değeri}$$
   *Hocanın Notu:* Varlık yoksa risk yoktur. Zafiyet yoksa tehdit kapıda beklese de risk minimize olur.

#### B. CIA Üçlüsü (The CIA Triad)
Siber güvenliğin Anayasası 3 maddeden oluşur:

* **Gizlilik (Confidentiality):** Bilgiye sadece ve sadece yetkisi olan kişilerin erişebilmesidir.
  * *Teknik Mekanizma:* Simetrik/Asimetrik Şifreleme (AES-256, RSA), Rol Tabanlı Erişim Kontrolü (RBAC), Çok Faktörlü Kimlik Doğrulama (MFA).
* **Bütünlük (Integrity):** Bilginin yetkisiz kişilerce değiştirilmediğinin, silinmediğinin veya tahrif edilmediğinin garanti edilmesidir.
  * *Teknik Mekanizma:* Kriptografik Özet Fonksiyonları (Cryptographic Hash Functions: SHA-256, BLAKE2), Dijital İmzalar, Blokzincir, HMAC.
* **Erişilebilirlik (Availability):** Yetkili kullanıcıların ihtiyaç duydukları anda veriye ve sisteme kesintisiz ulaşabilmesidir.
  * *Teknik Mekanizma:* Yedeklilik (Redundancy, RAID), Yük Dengeleyiciler (Load Balancers), DDoS Koruması, Felaket Kurtarma Merkezleri (DRC).

---

### 3. İki Yönlü Bakış: Saldırganın Gözü (Offensive) vs Savunmacının Kalkanı (Defensive)

Bir siber güvenlik uzmanı tek gözle bakamaz. Bir gözünle saldırganın neyi hedeflediğini göreceksin, diğer gözünle kalkanı nereye koyacağını bileceksin.

| Güvenlik Boyutu | Saldırgan Ne Yapar? (Offensive) | Savunmacı Nasıl Korur? (Defensive) |
| :--- | :--- | :--- |
| **Gizlilik** | Trafiği koklar (Sniffing/Wireshark), kimlik bilgilerini çalar (Credential Dumping), yetkisiz IDOR açığı ile diğer öğrencilerin notlarını çeker. | Veriyi uçtan uca şifreler (TLS 1.3, AES), En Düşük Yetki İlkesini (Principle of Least Privilege) uygular, katı erişim kontrolleri (RBAC/ACL) koyar. |
| **Bütünlük** | Araya girer (MitM), not dosyasındaki 45 sayısını 95 yapar, log dosyalarını siler veya hash değerlerini manipüle etmeye çalışır. | Veritabanı ve dosya değişikliklerini kriptografik hash (SHA-256) ile imzalar, WORM (Write Once Read Many) log sunucuları kullanır. |
| **Erişilebilirlik** | Sunucuya SYN-Flood DDoS atar, dosya sistemini fidye yazılımıyla şifreleyip servisi durdurur, sunucu odasının elektriğini keser. | Bant genişliği filtreleme, Cloudflare/DDoS koruması, coğrafi yedekli sunucular, otomatik yük devretme (Failover) ve düzenli çevrimdışı yedekler alır. |

---

### 4. Hocayla Birlikte Canlı Laboratuvar (Adım Adım Gerçek Kod ve Komutlar)

Şimdi lafı bırakıp terminale geçiyoruz. Bugün bir okul sisteminin not kütüğünü (`okul_not_sistemi.txt`) laboratuvar masasına yatırıyoruz.

#### Adım 1: Örnek Verimizi İnceleyelim
Veri kütüğümüz `portfolio/hafta_01/gun_001/ornek_veri/okul_not_sistemi.txt` dosyasında duruyor. İçeriğe bakalım:
```text
OGRENCI_NO|AD_SOYAD|DERS|VIZE|FINAL|DURUM
101|Ali Yılmaz|Siber Güvenliğe Giriş|45|55|Kaldı
102|Ayşe Kaya|Ağ Temelleri|85|90|Geçti
103|Mehmet Demir|İşletim Sistemleri|70|75|Geçti
```

#### Adım 2: Terminalde SHA-256 Özeti Hesaplama (Bütünlük Temeli)
Öğrencinin not kütüğünün parmak izini Windows PowerShell terminalinde şu yerel komutla çıkar:
```powershell
Get-FileHash -Algorithm SHA256 .\portfolio\hafta_01\gun_001\ornek_veri\okul_not_sistemi.txt
```
*Gözlem:* Ekrana 64 karakterlik onaltılık (hexadecimal) bir özet dökülür. Dosyada tek bir harf veya boşluk değiştiğinde bu özet tamamen değişir!

#### Adım 3: Geliştirdiğimiz Laboratuvar Kodunu Çalıştırma
Uygulama klasörümüzdeki [`cia_triad_lab.py`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_001/uygulama/cia_triad_lab.py) dosyasını çalıştıralım:

```bash
python portfolio/hafta_01/gun_001/uygulama/cia_triad_lab.py --audit
```

**Ekranda Göreceğin Canlı Sonuç:**
1. **Gizlilik Testi:** Öğretmen tüm kayıtları okurken, öğrenci 101 yalnızca kendi satırını görebildi. Misafir kullanıcı erişmeye çalıştığında sistem `ConfidentialityViolationError` fırlattı ve işlemi engelledi!
2. **Bütünlük Testi:** Ali'nin 45 olan vizesi arka planda simüle edilerek 95 yapıldı. Sistem anında SHA-256 çığ etkisini tespit etti, `IntegrityViolationError` üretti ve tahrifatı engelledi!
3. **Erişilebilirlik Testi:** Sistem kaynağı kilitlendiğinde, erişim talepleri `AvailabilityViolationError` ile düştü ve servis kesintisi raporlandı.

---

### 5. Hocanın "Ölümcül Hatalar ve Mülakat Tuzakları" Notu

Evlat, bu bölümü mülakatlara girmeden önce defalarca oku:

> [!WARNING]
> **Ölümcül Hata 1: "Veriyi şifreledim, artık tamamen güvendeyim!"**
> Bu, sektöre yeni girenlerin en büyük yanılgısıdır. Veriyi 256-bit AES ile şifrelemiş olabilirsin (Mükemmel Gizlilik). Ama saldırgan şifreli dosyanın üzerine rastgele baytlar yazarsa veya dosyayı silerse veriyi kaybedersin! Bütünlük ve Erişilebilirlik sıfırlanır. Tek bir güvenlik önlemi asla tek başına yeterli değildir.

> [!NOTE]
> **Mülakat Sorusu: "CIA üçlüsü bileşenleri arasında bir çelişki/takas (trade-off) var mıdır?"**
> **Doğru Yanıt:** Evet! Güvenlik ve kullanılabilirlik sürekli bir gerilim halindedir. Gizliliği artırmak için 5 aşamalı MFA, 32 karakterlik karmaşık parola ve 3 katmanlı VPN koyarsanız; acil bir durumda sistem yöneticisi veya doktor sisteme hızlıca erişemez (Erişilebilirlik darbe alır). Tersine, herkes hızlıca erişsin diye parolaları kaldırırsanız Gizlilik yok olur. Bir güvenlik mimarının işi bu üçlü arasındaki optimum dengeyi kurmaktır.

---

### 6. Günün Pratik Görevi (Challenge & Walkthrough)

**Senaryo Görevi (Excel Müfredatından):**
Hayalî bir okul sistemi için üç güvenlik hedefini ve ölçülebilir teknik kriterlerini belirle:
1. **Hedef 1 (Gizlilik):** Not kütüğüne yalnızca atanan dersin öğretmeni tam erişebilir; öğrenci yalnızca kendi numarasını sorgulayabilir; misafir/anonim kullanıcılar API'den 403 Forbidden alır.
2. **Hedef 2 (Bütünlük):** Not kütüğü her günün sonunda SHA-256 özeti alınarak zaman damgalı güvenli bir deftere yazılır. Sabah alınan hash ile akşamki hash uyuşmuyorsa ve onaylı bir öğretmen değişikliği yoksa sistem alarm verir.
3. **Hedef 3 (Erişilebilirlik):** Vize/Final haftasında eşzamanlı 5000 öğrenci girişi olduğunda sistem yanıt süresi 2000 ms'yi aşamaz; ana sunucu çökerse 30 saniye içinde yedek düğüm (failover node) devreye girer.

---

### 7. Hocanın Soru Odası (Excel Soru Bankası Detaylı Yanıtları)

#### Soru 1 (G001-SC1): Siber güvenlik nedir ve neyi korur? Temel mekanizmayı ve güvenlik önemini açıkla.
- **1. Yanıt:** Siber güvenlik; elektronik bilgi sistemlerinin, ağ altyapılarının, donanım ve yazılımların yetkisiz erişim, tahrifat, ifşa, kesinti ve imhadan korunması bilimidir. Siber güvenliğin nihai hedefi cihazların kendisinden ziyade, bu cihazlar üzerinde işlenen ve saklanan **bilgi varlıklarının değerini** korumaktır.
- **2. Teknik Gerekçe:** Güvenlik mekanizması 4 aşamalı bir yaşam döngüsüdür: Varlık tespiti, tehdit modelleme, zafiyet yönetimi ve CIA kontrollerinin (RBAC, SHA-256, yedeklilik) uygulanması.
- **3. Yaygın Hata:** Siber güvenliği sadece "hacker araçları kullanmak" veya "virüs programı kurmak" sanmak. Güvenlik bir ürün değil; insan, süreç ve teknolojiyi kapsayan sürekli bir denetim sürecidir.
- **4. Standart ve Kaynak:** NIST CSF 2.0 (Govern / Identify Fonksiyonları) | ISO/IEC 27001:2022 Madde 4.4 ve 8.1.

#### Soru 2 (G001-SC2): Siber güvenlik nedir ve neyi korur? Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?
- **1. Yanıt:** Gün 001 laboratuvarı, siber güvenliğin 3 temel direğini (`cia_triad_lab.py`) bağımsız, ölçülebilir ve sentetik teknik kontrollerle doğrular.
- **2. Teknik Gerekçe:** Girdi: `okul_not_sistemi.txt` ve referans SHA-256 hash değeri. İşlem: RBAC ile okuma yetkilendirmesi, kriptografik SHA-256 bütünlük doğrulaması ve sistem servis kilidi durum sorgusu. Beklenen Sonuç: Yetkili öğretmenin tam kütüğü okuması, öğrencinin sadece kendi notunu görmesi, sağlam dosyanın hash testinden geçmesi.
- **3. Yaygın Hata (Negatif Kontrol):** Bir güvenlik mekanizmasını test ederken yalnızca başarılı senaryoları denemek. Negatif kontrollerimiz: Yetkisiz misafirin `ConfidentialityViolationError` ile engellenmesi, Ali'nin notu değiştirildiğinde `IntegrityViolationError` üretilmesi ve kilitli sistemde `AvailabilityViolationError` fırlatılmasıdır.
- **4. Standart ve Kaynak:** NIST SP 800-53 Rev. 5 (AC-3 Access Enforcement, SI-7 Information Integrity).

#### Soru 3 (G001-SC3): 'Siber güvenlik nedir ve neyi korur?' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?
- **1. Yanıt:** Risk; bir varlığın zafiyet barındırması ve bu zafiyeti istismar edebilecek tehdit aktörünün varlığı ile oluşur. Formülü: $\text{Risk} = \text{Tehdit} \times \text{Zafiyet} \times \text{Varlık Değeri}$.
- **2. Teknik Gerekçe:** Not kütüğü sunucusunda kimlik doğrulamasız dosya okuma açığı (zafiyet) varken notunu yükseltmek isteyen bir öğrenci (tehdit) mevcutsa yüksek risk doğar. FIM ajanları ve zafiyet taramalarıyla tespit edilir; En Düşük Yetki İlkesi, kriptografik özetler ve DoS kalkanlarıyla önlenir.
- **3. Yaygın Hata:** "Veriyi AES ile şifreledim, o halde tamamen güvendeyim" yanılgısı. Güçlü şifreleme sistemin kullanılabilir olduğunu veya verinin silinmeyeceğini tek başına garanti etmez.
- **4. Standart ve Kaynak:** ISO/IEC 27005:2022 (Bilgi Güvenliği Risk Yönetimi) | NIST SP 800-30 Rev. 1.
