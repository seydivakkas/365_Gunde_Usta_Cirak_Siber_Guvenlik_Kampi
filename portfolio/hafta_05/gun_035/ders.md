# GÜN 35: MİNİ PROJE 4: SİSTEM DURUM KONTROLÜ (MP-04)
## Usta-Çırak / Hoca Dersi Notları (Hafta 05 Kapanış Projesi)

---

### Lisans Bildirimi
```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve eğitim amaçlıdır.
Kopyalanamaz, dağıtılamaz, ticari amaçla kullanılamaz.
```

---

### 1. Giriş ve Temel Pedagojik Yaklaşım: Çırağa Öğüt
Evlat, koskoca bir haftayı (Hafta 05) geride bıraktık. Aşama 02'nin (Sistem ve Ağ Güvenliği Temelleri) en kritik omurgasını ilmek ilmek ördün:
- Gün 29'da Windows Event Viewer ve olay kimliklerini (Event ID 4624, 4625, 4688, 7045),
- Gün 30'da Linux systemd-journald mimarisini, journalctl filtrelerini ve log rotasyonunu,
- Gün 31'de Process Explorer'ı, PPID-PID ebeveyn-çocuk hiyerarşisini ve döngü denetimini,
- Gün 32'de Başlangıç noktalarını (Run keys), SCM servislerini ve Tırnaksız Servis Yolu zafiyetini,
- Gün 33'te Kriptografik özetleri (SHA-256), Çığ Etkisini (Avalanche Effect) ve FIM taban çizgisini,
- Gün 34'te Dosya uzantısı yanılsamasını, sihirli baytları (Magic Bytes) ve MIME analizini çalıştın.

Şimdi bugün **Mini Proje 4 (MP-04)** günüdür. Bugün tekil parçaları birleştirecek, bir şirketin bilgi güvenliği operasyon merkezinde (SOC) ya da sistem denetiminde kullanılabilecek tam teşekküllü bir **Sistem Durum Kontrolü ve Sağlık Denetleyicisi (System Posture Auditor)** inşa edeceksin.

Ve bugün kulağına şu altın kuralı küpe edeceksin:
> **"Sistem durum taraması yalnızca gözlemlerden anlamlı özet üretmeli ve yönetimsel ayrıcalık gerektirmemelidir."**

---

### 2. Salt-Okunur Gözlemci Modeli (Read-Only Observer Pattern)

Birçok acemi güvenlikçi, sistem denetimi yaparken hedef makinede yüksek ayrıcalıklar (`Administrator` / `root`) ister, sistem dosyalarını kurcalar ve arkasında kalıcı izler bırakır. Bu durum adli bilişim (DFIR) ve sistem kararlılığı açısından affedilemez bir hatadır:
1. **Adli Delillerin Kirlenmesi (Locard Değişim Prensibi):** Hedef sisteme dokunan her araç, dosya erişim tarihlerini (MACB), geçici kayıtları ve bellek alanlarını değiştirir. Denetim aracı kesinlikle **Salt-Okunur (Read-Only)** çalışmalı, sistemde hiçbir değişiklik yapmamalıdır.
2. **En Az Ayrıcalık (Least Privilege):** Bir sistem sağlık tarayıcısı, çekirdek düzeyinde sürücü yüklememeli veya `SYSTEM` hesabı talep etmemelidir. Yalnızca standart kullanıcı yetkisiyle işletim sisteminin dışarıya sunduğu telemetriyi (WMI, ProcFS, API çıktıları) toplayıp anlamlandırmalıdır.
3. **Sıfır Yan Etki (Zero Side-Effects):** Tarayıcı kilitlenirse veya çökerse, hedef üretim sunucusuna hiçbir zarar vermemelidir.

---

### 3. Konsolide Denetim Alanları (Dörtlü Savunma Hattı)

Mini Proje 4 kapsamında geliştirdiğimiz `SystemPostureAuditor`, bir hedef makinenin güvenlik duruşunu 4 ana alanda eş zamanlı inceler:

#### A. Süreç Ağacı ve Yürütme Hiyerarşisi (Process Posture)
- **Ebeveyn-Çocuk İlişkisi (Parent-Child Chain):** Meşru ofis yazılımlarının (`winword.exe`, `excel.exe`) bir kabuk motorunu (`powershell.exe`, `cmd.exe`) tetiklemesi doğrudan makro tabanlı oltalama saldırısı (Malicious Document) göstergesidir.
- **Süreç Taklidi (Masquerading):** Geçici dizinlerden (`C:\Windows\Temp\`) çalışan veya meşru sistem isimlerini taklit eden (`svch0st.exe`) ikililerin yakalanması.

#### B. Servis ve Başlangıç Güvenliği (Service Posture)
- **Savunma Tahrifatı (Impair Defenses):** `MpsSvc` (Güvenlik Duvarı) veya `WinDefend` (Defender) servislerinin durdurulmuş ya da devre dışı bırakılmış olması.
- **Tırnaksız Servis Yolu (Unquoted Service Path - T1574.009):** Boşluk içeren ve tırnaksız bırakılan servis ikili yolları üzerinden yerel yetki yükseltme (LPE) riskinin tespiti.

#### C. Dosya Bütünlüğü ve Taban Çizgisi (Integrity Posture)
- **Konfigürasyon Tahrifatı:** `hosts` veya `security_policy.cfg` gibi kritik sistem dosyalarının SHA-256 özetlerinin taban çizgisiyle (Golden Baseline) uyuşmaması (`INTEGRITY_VIOLATION`).
- **Kayıp Sistem Dosyaları:** Taban çizgisinde yer alan zorunlu bileşenlerin silinmiş olması (`BASELINE_DISRUPTION`).

#### D. Sihirli Bayt ve Dosya Türü Uyumluluğu (Signature Posture)
- **Uzantı Aldatmacası (Extension Spoofing):** `.pdf` uzantılı bir dosyanın başlığında `4D 5A` (MZ PE executable) baytlarının bulunması (T1036.008).
- **Çift Uzantı Hilesi (Double Extension):** `.pdf.exe` gibi kullanıcıyı kandırmaya yönelik yürütülebilir dosyalar.

---

### 4. Sağlık Puanı (Health Score) Matematiği

Analiz motoru, tespit edilen her bulguyu ciddiyet derecesine göre ağırlıklandırarak 100 taban puanından düşüş yapar:
- **CRITICAL:** -25 puan (Sistem ele geçirilmiş veya savunma tamamen kapatılmış)
- **HIGH:** -15 puan (Yetki yükseltme veya çift uzantı gibi ciddi saldırı vektörü)
- **MEDIUM:** -8 puan (Yapılandırma zafiyeti veya imzasız yazılım)
- **LOW:** -3 puan (Küçük metadata uyumsuzluğu)

**Duruş Skalası:**
- `90 - 100`: **HEALTHY_BASELINE** (Temiz ve Güvenli)
- `70 - 89`: **ELEVATED_RISK** (Yükseltilmiş Risk)
- `40 - 69`: **CRITICAL_ATTENTION_REQUIRED** (Acil Müdahale Gerekli)
- `0 - 39`: **COMPROMISED_ENVIRONMENT** (Ortam Ele Geçirilmiş / Ağır Tehdit)

---

### 5. Haftalık Sorular (W05) ve Profesyonel Mühendislik İlkeleri

Mini projelerde bir siber güvenlik mühendisi şu prensiplerle hareket eder:
1. **W05-SC1 (Sorun Giderme Adımları):** Eğer denetim çıktısı beklendiği gibi görünmüyorsa:
   - *Adım 1:* Ön koşulları ve izinli ortamı doğrula.
   - *Adım 2:* Ham girdiyi ve hata izini (traceback) izole et.
   - *Adım 3:* Kontrollü negatif testle hatayı yeniden üret ve düzeltmeyi kaynaklı kaydet.
2. **W05-SC2 (İzin ve Veri Koşulları):** Aracı üçüncü bir taraf sistemde çalıştırmadan önce:
   - Yazılı yetki belgesi (RoE - Rules of Engagement) ve kapsam sınırı alınmalıdır.
   - Veri minimizasyonu gözetilmeli; kişisel veriler (PII) toplanmamalıdır.
   - Test zamanı, hız sınırı ve acil durdurma koşulu önceden kararlaştırılmalıdır.
3. **W05-SC3 (PASS Kararı İçin 3 Somut Kanıt):**
   - Çalışan gerçek komut ve konsol çıktısı (`komut_ve_cikis.txt`),
   - Olumlu/olumsuz test sonuçlarının eksiksiz yeşil dökümü (`test_sonuclari.txt`),
   - Kaynaklı, dürüst ve anonimleştirilmiş teknik rapor (`rapor.md`).

---

### Resmî Kaynaklar
- Microsoft Learn: [Windows Security Documentation](https://learn.microsoft.com/en-us/windows/security/)
- CIS Benchmarks: [CIS Microsoft Windows Desktop and Server Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- MITRE ATT&CK: [Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
