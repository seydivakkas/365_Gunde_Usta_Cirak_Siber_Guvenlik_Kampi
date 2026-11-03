<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 004: Soru-Cevap ve Kavram Doğrulama

Bu belge, NIST CSF 2.0 işlevlerine ilişkin `SORU BANKASI` kayıtlarını ve teknik doğrulama standartlarını içerir. Her soru katı 4 bölümlü formatta cevaplanmıştır.

---

### G004-SC1: NIST CSF 2.0 işlevleri: Temel mekanizmayı ve güvenlik önemini açıkla.

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

### G004-SC2: NIST CSF 2.0 işlevleri: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

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

### G004-SC3: 'NIST CSF 2.0 işlevleri' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Yanıt
Risk; kurumsal yönetişimin (Govern) eksikliği, varlıkların sahipsiz kalması (Identify), tedarikçilerin denetlenmemesi veya koruma duvarlarına aşırı güvenilip tespit (Detect) ve kurtarma (Recover) süreçlerinin terk edilmesiyle oluşur. Risk, periyodik NIST CSF olgunluk matrisi denetimleriyle, açığı olan alt kategorilerin (Gap Analysis) tespitiyle ve sızma testleriyle keşfedilir. Önleme ise 6 işlevi dengeli bir biçimde hayata geçiren kontrollerle (MFA, EDR/SIEM, SOAR, hava aralıklı yedekler ve kurumsal politikalar) sağlanır.

#### 2. Teknik Gerekçe
Risk formülü $Risk = Tehdit \times Zafiyet \times Etki$ dengesine dayanır. Bir kurumda `GV.SC` (Tedarik Zinciri Risk Yönetimi) yoksa, üçüncü taraf bir yazılım güncellemesi (örn: SolarWinds) tüm kurum ağını zafiyete boğar. Kurumda `DE.CM` (Sürekli İzleme) yoksa, saldırganın ağdaki dwell time'ı (barınma süresi) aylar sürer ve veriler dışarı sızdırılır. Risk tespiti, telemetrilerin MITRE ATT&CK matrisiyle eşleştirilmesi ve kontrol listesi boşluklarının analizi ile gerçekleşir.

#### 3. Yaygın Hata
Risk yönetimini sadece yıllık yapılan sızma testi (penetration test) raporundan ibaret görmek. Sızma testi anlık bir fotoğraftır; NIST CSF ise yaşayan bir kurumsal savunma kalkanıdır.

#### 4. Standart ve Kaynak
* NIST SP 800-30 Rev. 1: Guide for Conducting Risk Assessments.
* NIST SP 800-37 Rev. 2: Risk Management Framework for Information Systems and Organizations.
