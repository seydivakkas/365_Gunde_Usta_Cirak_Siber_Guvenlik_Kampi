<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 001: Soru ve Cevap Odası
## Siber Güvenlik Nedir ve Neyi Korur? — CIA Üçlüsü ve Temel İlkeler

---

### Soru 1 (G001-SC1): Siber güvenlik nedir ve neyi korur? Temel mekanizmayı ve güvenlik önemini açıkla.

- **1. Yanıt:** Siber güvenlik; elektronik bilgi sistemlerinin, ağ altyapılarının, donanım ve yazılımların yetkisiz erişim, tahrifat, ifşa, kesinti ve imhadan korunması bilimidir. Siber güvenliğin nihai hedefi cihazların kendisinden ziyade, bu cihazlar üzerinde işlenen ve saklanan **bilgi varlıklarının değerini** korumaktır.
- **2. Teknik Gerekçe:** Güvenlik mekanizması 4 aşamalı bir yaşam döngüsüdür:
  1. *Varlık Tespiti (Asset Inventory):* Korunacak verilerin (okul not kütüğü, müşteri kimlikleri, ticari sırlar) sınıflandırılması.
  2. *Tehdit Modelleme (Threat Modeling):* Varlığa kimin, hangi motivasyonla ve hangi saldırı vektörüyle yönelebileceğinin analizi.
  3. *Zafiyet Yönetimi (Vulnerability Management):* Sistemdeki yapılandırma, kod veya yama eksikliklerinin tespiti.
  4. *Kontrol Uygulama (Security Controls):* Gizlilik için RBAC/şifreleme, bütünlük için SHA-256/imzalama, erişilebilirlik için yedeklilik/DoS kalkanlarının devreye alınması.
- **3. Yaygın Hata:** Siber güvenliği sadece "hacker araçları kullanmak" veya "virüs programı kurmak" sanmak. Güvenlik bir ürün değil; insan, süreç ve teknolojiyi kapsayan sürekli bir denetim sürecidir.
- **4. Standart ve Kaynak:** NIST CSF 2.0 (Govern / Identify Fonksiyonları) | ISO/IEC 27001:2022 Madde 4.4 ve 8.1.

---

### Soru 2 (G001-SC2): Siber güvenlik nedir ve neyi korur? Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

- **1. Yanıt:** Gün 001 laboratuvarı, siber güvenliğin 3 temel direğini ([`cia_triad_lab.py`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_001/uygulama/cia_triad_lab.py)) bağımsız, ölçülebilir ve sentetik teknik kontrollerle doğrular.
- **2. Teknik Gerekçe:**
  - *Girdi:* [`okul_not_sistemi.txt`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_001/ornek_veri/okul_not_sistemi.txt) sentetik not kütüğü ve referans SHA-256 hash değeri (`2e5462450ae63eab2d21a315636aa3e9a9a82ed85406ec624bc4cff195dc4c2f`).
  - *İşlem:* Rol Tabanlı Erişim Kontrolü (RBAC) ile okuma, bayt akışı üzerinden SHA-256 kriptografik bütünlük doğrulaması ve sistem servis kilidi durum sorgusu.
  - *Beklenen Sonuç:* Öğretmenin tüm kütüğü okuyabilmesi, öğrencinin yalnızca kendi notunu görmesi, değişmeyen dosyanın hash kontrolünden başarıyla geçmesi.
- **3. Yaygın Hata (Negatif Kontrol):** Bir güvenlik mekanizmasını test ederken yalnızca başarılı (pozitif) senaryoları denemek, başarısızlık durumlarını sınamamak. Negatif kontrollerimiz: Yetkisiz misafirin `ConfidentialityViolationError` ile engellenmesi, Ali'nin notu 45'ten 95'e çıkarıldığında SHA-256 çığ etkisinin `IntegrityViolationError` üretmesi ve kilitli sistemde `AvailabilityViolationError` fırlatılmasıdır.
- **4. Standart ve Kaynak:** NIST SP 800-53 Rev. 5 (AC-3 Access Enforcement, SI-7 Software, Firmware, and Information Integrity).

---

### Soru 3 (G001-SC3): 'Siber güvenlik nedir ve neyi korur?' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

- **1. Yanıt:** Risk; bir varlığın zafiyet barındırması ve bu zafiyeti istismar edebilecek tehdit aktörünün varlığı ile oluşur. Formülü: $\text{Risk} = \text{Tehdit} \times \text{Zafiyet} \times \text{Varlık Değeri}$.
- **2. Teknik Gerekçe:**
  - *Oluşumu:* Not kütüğünün barındığı sunucuda kimlik doğrulamasız dosya okuma açığı (zafiyet) varsa ve notunu yükseltmek isteyen bir öğrenci (tehdit) mevcutsa yüksek risk doğar.
  - *Tespiti:* Güvenlik denetimleri (audit), zafiyet taramaları, Dosya Bütünlük İzleme (FIM) ajanları ve SIEM erişim logları ile tespit edilir.
  - *Önlenmesi:* Gizlilik için En Düşük Yetki İlkesi (Principle of Least Privilege), bütünlük için dijital imzalar/kriptografik özetler, erişilebilirlik için yedekli altyapı kontrolleri uygulanır.
- **3. Yaygın Hata:** "Veriyi AES ile şifreledim, o halde tamamen güvendeyim" yanılgısı. Güçlü şifreleme sistemin erişilebilir olduğunu veya şifreli verinin tahrif edilip silinmeyeceğini garanti etmez.
- **4. Standart ve Kaynak:** ISO/IEC 27005:2022 (Bilgi Güvenliği Risk Yönetimi) | NIST SP 800-30 Rev. 1 (Risk Değerlendirme Rehberi).
