# GÜN 32: BAŞLANGIÇ UYGULAMALARI VE HİZMET YÖNETİMİ — SORU-CEVAP BANKASI

---

### Lisans Bildirimi
```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu soru-cevap ve eğitim içeriği yalnızca görüntüleme ve eğitim amaçlıdır.
Kopyalanamaz, çoğaltılamaz, ticari amaçla kullanılamaz.
```

---

## SORU 1 (G032-SC1)

### Temel Kavram ve Güvenlik Mekanizması
İşletim sistemi başlangıç uygulamaları (startup applications) ve arka plan servisleri (services/daemons), sistem önyüklemesi (boot) veya kullanıcı oturumu açılması (logon) anında insan müdahalesine gerek kalmaksızın otomatik olarak yürütülen kod bloklarıdır. 

Windows ortamında bu işleyiş; Kayıt Defteri (Registry `Run`/`RunOnce` anahtarları), Başlangıç Klasörü (`shell:startup`), Zamanlanmış Görevler (`Task Scheduler`) ve Hizmet Denetim Yöneticisi (`services.exe` - SCM) üzerinden kontrol edilir. Linux ortamında ise `systemd` birim dosyaları (`/etc/systemd/system/`), `cron` zamanlayıcıları ve kabuk profil betikleri (`/etc/profile.d/`, `~/.bashrc`) bu görevi üstlenir.

Güvenlik mekanizması açısından her başlangıç girdisi işletim sisteminin **saldırı yüzeyini (attack surface)** doğrudan genişletir. Çünkü otomatik başlayan her yazılım bellek, CPU, ağ soketleri ve en önemlisi belirli bir kullanıcı/hizmet güvenlik bağlamı (security context) tüketir. Saldırganlar için kalıcılık (persistence) elde etmenin en kestirme yolu bu başlangıç noktalarından birine kanca atmaktır. Buna karşılık, bilgisiz sistem yöneticilerinin internetten gördükleri tavsiyelerle temel işletim sistemi servislerini (Örn: `EventLog`, `RPCSS`, `WinDefend`) "performans artırma" amacıyla kapatması ise bağımlılık zincirini koparır ve savunma mekanizmalarını körleştirir.

---

### Soru ve Didaktik Çözüm
**Soru:**
Başlangıç uygulamaları ve hizmet yönetimi: Temel mekanizmayı ve güvenlik önemini açıklayınız.

**Didaktik Çözüm:**
Otomatik başlayan uygulamalar ve servisler sistem saldırı yüzeyini doğrudan büyütür; fakat gerekli hizmetler gelişigüzel kapatılmamalıdır.
1. **Saldırı Yüzeyinin Büyümesi:** Otomatik başlatılan her üçüncü taraf yazılım, potansiyel kod yürütme zafiyetlerini (Örn: unquoted service path, DLL hijacking, zayıf dosya izinleri) ve sistem üzerinde yetkisiz kalıcılığı beraberinde getirir.
2. **Gelişigüzel Hizmet Kapatmanın Tehlikesi:** Windows servisleri izole değildir; aralarında derin bağımlılıklar (dependencies) vardır. Örneğin `RPCSS` veya `EventLog` kapatıldığında kimlik doğrulama, COM etkileşimleri ve güvenlik loglaması durur. Dolayısıyla hizmet kapatma işlemi gelişigüzel değil, kurumsal sıkılaştırma (hardening) kılavuzlarına (CIS Benchmarks, DISA STIG) göre kontrollü yapılmalıdır.

---

### Savunma ve Tespit Kılavuzu
- **Tespit Mekanizması:**
  - Sysinternals `Autoruns` aracı ile tüm otomatik başlangıç noktalarını dijital imza ve VirusTotal entegrasyonu ile tarayın.
  - PowerShell ile çalışan servislerin başlangıç türlerini ve ikili dosya yollarını listeleyin:
    ```powershell
    Get-CimInstance -ClassName Win32_Service | Select-Object Name, State, StartMode, PathName, StartName
    ```
- **Savunma Kontrolü:**
  - Güvenlik kritik servislerin (`WinDefend`, `MpsSvc`, `EventLog`) durumunu GPO (Group Policy Object) veya Intune üzerinden zorunlu kılın (Enforce Automatic).
  - Standart kullanıcıların `HKLM\...\Run` ve servis kayıt dizinlerine yazma haklarını kısıtlayın.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
*Usta der ki:* "Çırak, bir makineye ilk bağlandığında hemen Task Manager'a bakıp 'aaa şu servis çok RAM yiyor, durduralım' deme. Önce o servisin 'Dependencies' (Bağımlılıklar) sekmesini aç. Kapatacağın tek bir servis, şirketin Active Directory kimlik doğrulamasını veya EDR log iletimini patlatabilir. Otomatik başlayan şeyleri azaltmak esastır, ama bilerek ve ölçerek azaltmak şarttır."

---

## SORU 2 (G032-SC2)

### Temel Kavram ve Güvenlik Mekanizması
Bir güvenlik analistinin başlangıç uygulamalarını ve servisleri denetlerken geliştirdiği araçlar; tamamen izole, tekrarlanabilir ve bağımsız test girdilerine dayanmalıdır. Bu tür bir analiz aracının mimarisi; sistemdeki başlangıç girdilerini (Registry Run, Services, Scheduled Tasks) okumalı, sözleşme kurallarını doğrulamalı, tırnaksız servis yolları veya şüpheli dizinler gibi zafiyetleri tespit etmeli ve bozuk/hatalı veri yapıları karşısında çökmeksizin negatif kontrolleri başarıyla işletmelidir.

---

### Soru ve Didaktik Çözüm
**Soru:**
Başlangıç uygulamaları ve hizmet yönetimi: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

**Didaktik Çözüm:**
Bağımsız laboratuvar çalışmasının 4 temel bileşeni şunlardır:
1. **Girdi (Input):** Kendi test ortamımızda oluşturulan, hem meşru sistem servislerini (`WinDefend`, `EventLog`, `sshd`) hem de zafiyetli/zararlı başlangıç girdilerini (`VulnBackupService`, `svch0st_service`, `%Temp%` tabanlı `EdgeUpdateHelper`) içeren yapılandırılmış JSON envanter veri seti (`sample_startup_service_inventory.json`). Önceki günlerin kod veya veri mirası kesinlikle kullanılmaz.
2. **İşlem (Process):** `StartupServiceAuditor` motoru tarafından verilerin taranması; şema doğrulaması, tırnaksız yol analizi (`detect_unquoted_service_paths`), şüpheli konum tespiti (`detect_suspicious_binary_paths`), isim sahteciliği (`detect_name_masquerading`), güvenlik servisi tahrifatı (`detect_security_service_tampering`) ve risk puanlaması.
3. **Beklenen Sonuç (Expected Output):** Zafiyetli kayıtların doğru sınıflandırılması (örneğin `VulnBackupService` için `UNQUOTED_SERVICE_PATH` - HIGH, `svch0st` için `MASQUERADING` - CRITICAL), sistem risk puanının (100/100, CRITICAL_THREAT) üretilmesi ve anlaşılır bir ASCII denetim raporunun oluşturulması.
4. **Negatif Kontrol (Negative Control):** Bozuk şemalı kayıtlar (eksik isim, eksik yol, sözlük olmayan nesneler, geçersiz servis tipleri içeren `corrupted_startup_service_test.json`), var olmayan dosya yolları ve liste formatında olmayan JSON verilerinin sisteme verilmesi; uygulamanın çökmeksizin hataları yakalayıp `corrupted_records` günlüğüne işlemesi ve 14/14 testin başarıyla PASS vermesi.

---

### Savunma ve Tespit Kılavuzu
- **Test ve Doğrulama Adımları:**
  - Birim testleri çalıştırarak hem olumlu tespiti hem de negatif veri reddini doğrulayın:
    ```bash
    python -m unittest portfolio/hafta_05/gun_032/tests/test_startup_service_auditor.py -v
    ```
  - Denetleyiciyi doğrudan çalıştırarak gerçek terminal çıktısını inceleyin:
    ```bash
    python portfolio/hafta_05/gun_032/uygulama/startup_service_auditor.py
    ```

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
*Usta der ki:* "Kodunun kalitesi yalnızca tertemiz veriyi işlerken değil, önüne çöp veri, eksik şema veya saldırganın kasıtlı bozduğu bozuk bir dosya geldiğinde nasıl davrandığıyla ölçülür. `validate_entry` fonksiyonu senin kapındaki nöbetçidir. Nöbetçi uyursa tüm sistem çöker."

---

## SORU 3 (G032-SC3)

### Temel Kavram ve Güvenlik Mekanizması
Başlangıç ve hizmet mimarisinde risk üç ana kaynaktan doğar:
1. **Gereksiz İzinler ve En Az Ayrıcalık İhlali:** Servislerin gereksiz yere `LocalSystem` (SYSTEM) yetkisiyle koşturulması ve ikili dosya dizinlerinin standart kullanıcılara yazma izniyle (`Everyone: Full Control`) bırakılması.
2. **Yanlış Servis Yapılandırması (Misconfiguration):** Tırnaksız servis yolları (Unquoted Service Paths) sebebiyle Windows'un dosya arama mekanizmasının istismar edilmesi.
3. **Güvenlik Körlüğü ve Taban Çizgisi Yokluğu:** Hangi servislerin meşru, hangilerinin sonradan yetkisizce eklendiğini gösteren bir envanter ve fark (diff) mekanizmasının bulunmaması.

---

### Soru ve Didaktik Çözüm
**Soru:**
'Başlangıç uygulamaları ve hizmet yönetimi' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

**Didaktik Çözüm:**
1. **Risk Nasıl Oluşur?:**
   - **Gereksiz İzin:** Bir yedekleme veya yönetim servisi `SYSTEM` hesabı altında çalışırken ikili dosya yolu `C:\Program Files\App\agent.exe` şeklinde tırnaksız bırakılır. Standart kullanıcı `C:\Program.exe` dosyasını yazabilirse makine yeniden başladığında kod SYSTEM olarak çalışır ve yetki yükselir.
   - **Yanlış Servis:** Zararlı yazılımlar kullanıcı dizinlerine (`%APPDATA%`, `%TEMP%`) yerleşip Registry Run anahtarı ekleyerek veya meşru servis isimlerini taklit ederek (`svch0st`) kalıcılık sağlar.
   - **Savunma Tahrifatı:** Saldırgan Defender veya Güvenlik Duvarı servisini devre dışı bırakır.
2. **Nasıl Tespit Edilir?:**
   - **Servis ve Başlangıç Envanteri:** Periyodik olarak sistemdeki başlangıç kayıtlarının ve servislerin anlık dökümü alınır.
   - **Fark Raporu (Differential Analysis):** Bilinen temiz altın imaj (gold image/baseline) ile mevcut durum karşılaştırılır; yeni eklenen imzasız veya standart dışı dizindeki ikililer alarm üretir.
3. **Hangi Kontrolle Önlenir?:**
   - **En Az Ayrıcalık (Least Privilege):** Servisler zorunlu olmadıkça `SYSTEM` değil `LocalService` veya sanal hesaplarla çalıştırılır.
   - **Geri Alınabilir Yapılandırma ve Tırnaklama:** Bütün servis yolları çift tırnak içine alınır. Servis izinleri (ACL) yalnızca TrustedInstaller ve Administrators gruplarına yazma yetkisi verecek şekilde kilitlenir.

---

### Savunma ve Tespit Kılavuzu
- **Tespit Sorgusu (Unquoted Service Paths Taraması):**
  ```cmd
  wmic service get name,displayname,pathname,startmode | findstr /i /v "c:\windows\\" | findstr /i /v """
  ```
- **Önleme Komutu (Tırnaklama İyileştirmesi):**
  ```cmd
  sc.exe config "VulnBackupService" binPath= "\"C:\Program Files\Vulnerable Backup Solution\BackupAgent.exe\" -daemon"
  ```
- **Kritik Servis Koruma Kontrolü:**
  Kayıt defterindeki `HKLM\SYSTEM\CurrentControlSet\Services\` altındaki izinler kısıtlanarak standart kullanıcıların veya kötü niyetli scriptlerin `Start` anahtarını `4` (Disabled) yapması engellenir.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
*Usta der ki:* "Saldırganlar içeri girdiklerinde ilk yaptıkları şey izlerini kalıcı kılmaktır. Bir adli bilişim incelemesinde ilk bakacağın üç yer: Kayıt Defteri Run anahtarları, Windows Servisleri ve Zamanlanmış Görevlerdir. Bu üç noktayı korumayı ve denetlemeyi bilen bir mavi takım uzmanı, saldırganın belini daha ilk dakikada kırar."
