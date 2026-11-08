# Gün 153: Mini Proje 21 — Uç Nokta Risk Panosu ve Güvenlik Duruşu Yönetimi (Endpoint Posture Management)

## Usta-Çırak / Hoca Dersi Notu

Evlat! Hafta 22 boyunca uç nokta güvenliğinin en kritik katmanlarını tek tek inceledik:
1. **EDR ve Telemetri (Gün 148):** Uç noktadaki süreçleri, ağ bağlantılarını ve davranışsal tehditleri izledik.
2. **Uygulama İzinleri ve Sandbox (Gün 149):** Seccomp, Linux Capabilities, Windows AppContainer ve AppLocker ile süreçleri hapsettik.
3. **Disk Şifreleme ve TPM (Gün 150):** BitLocker, LUKS2 ve TPM 2.0 PCR zinciri ile fiziksel ve önyükleme saldırılarına set çektik.
4. **Yedek Doğrulama ve Kurtarma (Gün 151):** 3-2-1-1-0 kuralı, WORM/Değiştirilemez depolama ve sessiz bozulma denetimi yaptık.
5. **Güvenli Yapılandırma Sapması (Gün 152):** CIS Benchmarks ve DISA STIG kurallarıyla referans durumdan uzaklaşmayı yakaladık.

Bugün, bu beş devasa savunma hattını tek bir komuta merkezinde birleştirdiğimiz **Mini Proje 21: Uç Nokta Risk Panosu ve Güvenlik Duruşu Yönetimi (Endpoint Security Posture Management - ESPM / CAASM)** günümüzdür.

Gel çırağım; binlerce istemci ve sunucudan oluşan bir kurumda CISO'nun, SOC Liderinin veya Sistem Yöneticisinin önüne konacak o "kristal netliğindeki" risk panosunu nasıl tasarladığımızı inceleyelim.

---

### 1. Neden Tek Bir EDR veya Antivirüs Konsolu Yeterli Değildir?

Sektöre yeni giren acemiler sanır ki kuruma CrowdStrike veya Microsoft Defender for Endpoint kurunca tüm uç nokta güvenliği çözülür. Bu ölümcül bir yanılgıdır!

Bir uç noktanın savunmasını tek bir boyutta değerlendiremezsin:
* **Kör Nokta 1 (Fiziksel Güvenlik):** EDR'ın harika çalışıyor olabilir ama bir yönetici dizüstü bilgisayarını takside unuttuysa ve diski şifrelenmemişse (`BitLocker=False`), saldırgan diski söküp 5 dakikada tüm gizli verileri kopyalar. EDR hiçbir şey yapamaz!
* **Kör Nokta 2 (Fidye Yazılımı ve Kurtarma):** EDR'ı atlatmayı başaran 0-day bir fidye yazılımı sistemi şifrelediğinde, eğer son yedek 30 gün önce alınmışsa ve yedek deposu değiştirilebilir (mutable) olduğu için silinmişse kurum batar.
* **Kör Nokta 3 (Kimlik ve Yetki Hijyeni):** Bir yazılımcı kendi hesabını yerel `Administrators` grubuna eklemiş ve UAC'yi kapatmışsa, EDR en ufak bir zararlı dosyayı yakalayana kadar saldırgan çekirdek seviyesine ulaşır.
* **Kör Nokta 4 (Zafiyet ve Yama):** Sistem üzerinde 90 gündür kapatılmamış kritik bir RCE açığı (örn. Log4Shell, EternalBlue) duruyorsa, o makine her an ağ üzerinden düşürülebilir.

İşte bu yüzden gerçek dünya güvenliği **Çok Vektörlü Güvenlik Duruşu (Multi-Vector Posture)** gerektirir.

---

### 2. Çok Vektörlü Risk Skorlama Matematiği (Weighted Risk Fusion)

Bir uç noktanın riskini değerlendirirken 6 temel güvenlik vektörünü ağırlıklı olarak birleştirdik:

$$\text{Base Risk Score} = \sum_{i=1}^{6} (P_i \times W_i)$$

Burada:
1. **EDR & Telemetri Vektörü ($W_1 = 0.25$):** Ajanın kurulu olması, servisin çalışması, kurcalama koruması (Tamper Protection) ve imza güncelliği.
2. **CIS Sıkılaştırma ve Sapma Vektörü ($W_2 = 0.20$):** CIS uyumluluk yüzdesi, yetkisiz yerel yöneticiler ve çekirdek savunması (UAC / ASLR).
3. **Disk Şifreleme ve TPM Vektörü ($W_3 = 0.15$):** Disk şifreleme durumu, TPM 2.0 donanım kökü, PCR bağlama ve kurtarma anahtarı yedekliliği (escrow).
4. **Yedekleme ve Kurtarma Vektörü ($W_4 = 0.15$):** Son yedekleme zamanı ($<24$ saat), WORM/Değiştirilemez depolama ve geri yükleme tatbikatı doğrulaması.
5. **Zafiyet ve Yama Durumu ($W_5 = 0.15$):** Kritik/Yüksek CVE sayıları ve işletim sistemi yama gecikme gün sayısı ($>30$ gün, $>60$ gün).
6. **Uygulama Denetimi ve Beyaz Liste ($W_6 = 0.10$):** AppLocker/WDAC modu (Enforce, Audit, Disabled) ve tespit edilen onaysız ikili dosyalar.

#### Kritik Varlık Çarpanı (Critical Asset Multiplier):
Eğer bir cihaz Etki Alanı Denetleyicisi (Domain Controller), Temel Veritabanı veya Yönetici Bilgisayarı ise (`is_critical_asset = True`), üzerindeki zafiyetlerin kurum geneline yayılma ve iş durdurma etkisi katbekat yüksektir. Bu sebeple baz risk skoruna **%15 çarpan** uygulanır:

$$\text{Final Risk Score} = \min(100.0, \text{Base Risk Score} \times 1.15)$$

---

### 3. Risk Seviyesi Bantları (Risk Bands)

Hesaplanan 0.0 - 100.0 puanlık risk skoru 4 kurumsal banda ayrılır:

| Risk Skoru | Risk Bandı | Duruş Puanı | SOC / Operasyonel Aksiyon |
| :---: | :---: | :---: | :--- |
| **0.0 – 19.9** | **DÜŞÜK (LOW)** | 80.1 – 100.0 | **Sağlam Durum:** Rutin periyodik denetim devam eder. |
| **20.0 – 44.9** | **ORTA (MEDIUM)** | 55.1 – 80.0 | **İzleme & İyileştirme:** Sıradaki bakım döngüsünde eksikler giderilir. |
| **45.0 – 69.9** | **YÜKSEK (HIGH)** | 30.1 – 55.0 | **Acil Müdahale:** 24 saat içinde otomatik/manuel düzeltme uygulanır. |
| **70.0 – 100.0** | **KRİTİK (CRITICAL)** | 0.0 – 30.0 | **Derhal İzolasyon:** Cihaz ağdan izole edilir, acil olay müdahale başlatılır. |

---

### 4. Filo Toplulaştırma (Fleet Aggregation) ve Yönetici Görünümü

Bir güvenlik yöneticisi binlerce makineyi tek tek inceleyemez. Ona büyük resmi gösterecek şu metrikler gerekir:
* **Filo Ortalama Risk & Duruş Skoru:** Genel durum iyiye mi gidiyor, kötüye mi?
* **Departman Bazlı Isı Haritası (Heatmap):** En yüksek risk hangi departmanda? (Örn. Dış Yükleniciler veya Finans).
* **En Riskli İlk 5 Uç Nokta (Top 5 Riskiest Hosts):** Saldırganların en kolay sızabileceği zayıf halkalar.
* **Sistemik Zayıflıklar (Systemic Weaknesses):** Kurum genelinde kronikleşmiş ortak problemler (örn. "Yedek depolama birimi WORM değil", "BitLocker açık değil").

Geliştirdiğimiz CLI ve motor, bu çıktıları hem makinelerin işleyebileceği `fleet_risk_dashboard.json` formatında hem de C-Level yöneticilerin okuyabileceği zengin ASCII tablolarında üretir.

---

### 5. Riskten Aksiyona: Otomatik İyileştirme (Auto-Remediation)

Yalnızca risk ölçüp raporlamak "sorunu izlemekten" ibarettir. Gerçek mühendislik, tespit edilen riskleri otomatik olarak ortadan kaldırmaktır.

Motorumuz, `HIGH` ve `CRITICAL` seviyesindeki uç noktaları filtreler ve her birinin spesifik zafiyetine göre doğrudan çalıştırılabilir **PowerShell iyileştirme betikleri** (`top_priority_remediation.ps1`) üretir:
* EDR servisi durmuşsa -> `Start-Service -Name 'Sense'` ve `Set-Service StartupType Automatic`.
* BitLocker şifresiz ise -> `Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -TpmProtector`.
* UAC kapalıysa -> Kayıt defterinde `EnableLUA=1` zorlaması.

---

### 6. Ustanın Altın Öğüdü

Evlat! Siber güvenlikte "göremediğin şeyi koruyamazsın; ölçemediğin şeyi yönetemezsin." 
Bir uç noktanın güvenliği asla tek bir parametreye emanet edilemez. Savunma derinliği (Defense-in-Depth), tüm güvenlik katmanlarının bir ahenk içinde izlenmesi ve sapma görüldüğü an otomatik olarak onarılmasıyla mümkündür. Bu mini proje, kurumsal bir SOC'un uç nokta duruş yönetimi vizyonunun somutlaşmış halidir!
