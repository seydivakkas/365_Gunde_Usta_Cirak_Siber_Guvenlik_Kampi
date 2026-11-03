# GÜN 018: SORU-CEVAP VE SENARYO ANALİZLERİ
# Süreç, İş Parçacığı ve Hizmet Güvenlik Değerlendirmesi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).  
> Bu dosya ve içerikler yalnızca görüntüleme ve eğitim amaçlıdır. Ticari/gayriticari kopyalanamaz, çoğaltılamaz, dağıtılamaz.

---

## SORU 1: [G018-SC1] Temel Mekanizma ve Güvenlik Önemi

### Soru ve Bağlam
*Süreç, thread ve hizmet kavramları: Temel mekanizmayı ve güvenlik önemini açıkla.*  
İşletim sistemi düzeyinde süreç (Process), iş parçacığı (Thread) ve hizmet (Service/Daemon) kavramlarının mimari ayrımı nedir? Bu bileşenlerin bellek paylaşımı ve oturum izolasyon sınırları siber savunmada neden kritiktir?

### Teknik Açıklama ve Mekanizma
1. **Süreç (Process):** Kendi bağımsız sanal adres alanına (VAS), Sayfa Tablosu Dizinine (CR3), Güvenlik Belirtecine (Token/UID) ve kaynak tanıtıcılarına (Handle) sahip olan ana yürütme kapsayıcısıdır. İki süreç donanımsal olarak birbirinden izoledir; Süreç A, Süreç B'nin belleğine doğrudan erişemez.
2. **İş Parçacığı (Thread):** Süreç içinde CPU çekirdeklerinde aynı anda çalışan yürütme hatlarıdır. Bir süreçteki tüm iş parçacıkları aynı bellek alanını (Heap, Data, BSS) ve açık dosya tanıtıcılarını ortaklaşa paylaşır; yalnızca kendi yığıtları (Stack) ve CPU yazmaç durumları izoledir.
3. **Hizmet (Service):** Kullanıcı oturum açmadan önce sistem başladığında devreye giren, kullanıcı arayüzü (GUI) barındırmayan ve genellikle yüksek yetkili hesaplarla (`SYSTEM`, `LocalService`) arka planda çalışan özel süreçlerdir. Windows'ta oturum açan kullanıcıların saldırılarına karşı **Session 0 İzolasyonu** ile korunurlar.

Güvenlik önemi; iş parçacıkları arasında kilit mekanizması (Mutex) işletilmediğinde yarış durumları (Race Condition) oluşması, süreçler arası izolasyonun enjeksiyon teknikleriyle (Process Injection) aşılabilmesi ve arka plan hizmetlerinin yanlış yapılandırmalarla (Unquoted Service Path) yetki yükseltme kapısı açmasında yatar.

### Güvenlik Etkisi ve Saldırı / Savunma Senaryosu
- **Saldırı Senaryosu (Process Injection ve Mimikatz):** Saldırgan düşük yetkili bir kullanıcı sürecini ele geçirir. Eğer kullanıcı yönetici haklarına sahipse, `VirtualAllocEx` ve `WriteProcessMemory` API'lerini kullanarak `lsass.exe` sürecinin bellek alanına kod enjekte eder ve açık metin parolaları çeker.
- **Savunma Senaryosu:** 
  - Windows Protected Process Light (PPL) etkinleştirilerek `lsass.exe` gibi kritik süreçlerin belleğine yönetici olsa dahi üçüncü parti süreçlerin enjeksiyon yapması engellenir.
  - İş parçacıkları arasında paylaşılan kritik değişkenler Mutex kilitleri ile korunarak TOCTOU zaafiyetleri önlenir.

### Uygulama, Doğrulama ve Çıkarılan Ders
- **Uygulama:** `ProcessThreadServiceSecurityAuditor` modülü, süreçlerin bellek sınırlarını ve Session 0 hizmet izolasyonunu denetler.
- **Doğrulama:** `test_02_canli_envanter_kullanici_surecleri_en_az_iki_surec` ve `test_03_canli_envanter_sistem_hizmeti_session_zero` testleri ile yerel ortamda izolasyon sınırları doğrulanmıştır.
- **Çıkarılan Ders:** Bir sürecin sınırları sadece işletim sistemi güvenlik politikalarına bağlıdır; doğru kilit ve erişim kontrolü uygulanmadığında en ufak iş parçacığı sızıntısı tüm süreci çökertebilir.

---

## SORU 2: [G018-SC2] Bağımsız Laboratuvar ve Test Mimarisi

### Soru ve Bağlam
*Süreç, thread ve hizmet kavramları: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?*  
Windows üzerinde iki kullanıcı sürecini ve bir hizmeti ad ve PID bilgileriyle belgeleyen, iş parçacığı yarış durumunu simüle eden bağımsız laboratuvar mimarisi nasıl kurulur?

### Teknik Açıklama ve Mekanizma
Laboratuvarımız `process_thread_service_security_auditor.py` modülü ile bağımsız olarak icra edilir:
1. **Kontrollü Girdi (Input):**
   - Canlı sistem için yerel işletim sistemi süreç ve hizmet tabloları (`tasklist`, `sc query`, `os.getpid()`).
   - Simülasyon için `ornek_veri/process_thread_service_inventory.json` veri seti (tırnaksız yollar, yazılabilir klasörler).
   - İş parçacığı deneyi için iki eşzamanlı `threading.Thread` iş parçacığı ve paylaşılan sayaç değişkeni.
2. **Laboratuvar İşlemi (Process):**
   - Canlı sistem sorgusu: Mevcut Python süreci (PID) ve sistemdeki diğer bir kullanıcı/sistem süreci ile Session 0'da koşan bir hizmet ad ve PID ile tespit edilir.
   - `detect_unquoted_service_path()` ile hizmet yolunun boşluk ve tırnak kontrolü yapılır.
   - `simulate_thread_memory_sharing()` ile kilitli (`use_mutex=True`) ve kilitsiz (`use_mutex=False`) bellek yarış durumu koşturulur.
3. **Beklenen Sonuç (Expected Output):**
   - En az iki kullanıcı süreci (örneğin PID 48532 python.exe ve PID 4 System) ve en az bir sistem hizmetinin (örneğin ADPSvc, Session 0) envanterlenmesi.
   - Kilitli senaryoda iki iş parçacığının sayacı hatasız senkronize etmesi ve `GÜVENLİ` sonucunun alınması.
4. **Negatif Kontrol (Negative Control):**
   - `C:\Program Files\App\sub\engine.exe` gibi tırnaksız ve boşluklu bir yol verildiğinde, denetleyicinin `zafiyet_var_mi = True` ve `risk_seviyesi = YUKSEK` üretmesi; Windows'un arayacağı aday tuzak dosyaları (`C:\Program.exe`, `C:\Program Files\App.exe`) tam liste olarak çıkarması.
   - Yazılabilir klasör izni olan servisin `KRİTİK` risk olarak işaretlenmesi.

### Güvenlik Etkisi ve Saldırı / Savunma Senaryosu
- **Unquoted Path İstismarı:** Saldırgan sistemde `C:\Program.exe` adlı zararlı bir ikili dosya oluşturur. Sistem yeniden başladığında SCM, boşluk ayracından dolayı `C:\Program Files\App\engine.exe` yerine doğrudan `C:\Program.exe` dosyasını `SYSTEM` yetkisiyle çalıştırır ve saldırgana tam kontrol verir.
- **Savunma:** Kayıt Defteri'ndeki tüm `ImagePath` değerleri çift tırnak içine alınır (`"C:\Program Files\..."`) ve `C:\` kök dizinine standart kullanıcı yazma izinleri kapatılır.

### Uygulama, Doğrulama ve Çıkarılan Ders
- **Uygulama:** `detect_unquoted_service_path` ve `audit_service_security` metotları bu istismar zincirini otomatik olarak denetler.
- **Doğrulama:** `test_06_unquoted_path_tespiti_pozitif_zafiyet`, `test_09_unquoted_path_olasi_tuzak_yol_uretme` ve `test_12_is_parcacigi_kilitli_senkronizasyon_guvenli_sonuc` testleri ile %100 başarı sağlanmıştır.
- **Çıkarılan Ders:** Bir sistem yolundaki basit bir çift tırnak eksikliği, sıradan bir kullanıcıyı saniyeler içinde alan adı veya yerel sistem yöneticisi yapabilir.

---

## SORU 3: [G018-SC3] Risk Oluşumu, Tespit ve Savunma Kontrolleri

### Soru ve Bağlam
*'Süreç, thread ve hizmet kavramları' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?*  
Arka plan servislerinin yapılandırma hataları ve süreç içi senkronizasyon eksiklikleri kurumsal sistemlerde nasıl sömürülür, bu riskler denetçiler tarafından nasıl yakalanır ve CIS/NIST kontrolleriyle nasıl kapatılır?

### Teknik Açıklama ve Mekanizma
1. **Risk Oluşumu:**
   - **Gevşek Dosya Sistemi ve Servis İzinleri:** Yazılım geliştiricilerin servis klasörüne `Everyone` veya `Authenticated Users: Full Control` vermesi.
   - **Tırnaksız Servis Yolları (T1574.009):** Kurulum betiklerinin kayıt defterine `ImagePath` yazarken çift tırnak eklememesi.
   - **Hizmet Hesabı Savurganlığı:** Her servisin gereksiz yere `NT AUTHORITY\SYSTEM` olarak çalıştırılması.
2. **Tespit Mekanizmaları:**
   - **WMI ve PowerShell Taramaları:** `Get-CimInstance Win32_Service` ile tırnaksız ve boşluklu yolların taranması.
   - **Erişim Denetimi Analizi:** `icacls` veya `AccessChk` (Sysinternals) ile servis klasörlerinin standart kullanıcılar tarafından yazılabilir olup olmadığının denetlenmesi.
3. **Savunma ve Önleme Kontrolleri:**
   - **CIS Benchmark Kuralı (Quoted Paths):** Grup İlkeleri (GPO) ve uç nokta yönetim araçları (SCCM/Intune) ile tüm servis yollarının çift tırnak içine alınmasının zorunlu kılınması.
   - **En Az Ayrıcalık (Least Privilege):** Servislerin SYSTEM yerine kısıtlı `LocalService` veya `Group Managed Service Accounts (gMSA)` hesaplarıyla çalıştırılması.
   - **Sıkı Klasör İzinleri:** `C:\Program Files` ve altındaki tüm servis dizinlerinde standart kullanıcıların yalnızca `Okuma ve Yürütme (Read & Execute)` hakkına sahip olmasının sağlanması.

### Güvenlik Etkisi ve Saldırı / Savunma Senaryosu
- **Senaryo:** Kurumsal yedekleme yazılımı `C:\Program Files\Backup Tool\backup.exe` yoluna kurulmuş ancak tırnak içine alınmamıştır. Ayrıca `Backup Tool` klasörü tüm kullanıcılara yazılabilir bırakılmıştır. Bir saldırgan `backup.exe` dosyasını kendi ters kabuk (reverse shell) yazılımıyla değiştirir ve servisi yeniden başlatarak kurum sunucusunda SYSTEM yetkisi elde eder.
- **Önleme:** `ProcessThreadServiceSecurityAuditor` aracımızın `RULE-SVC-001` ve `RULE-SVC-002` kuralları, hem tırnak eksikliğini hem de yazılabilir klasör zafiyetini aynı anda raporlayarak saldırı gerçekleşmeden önce güvenlik açığını kapatır.

### Uygulama, Doğrulama ve Çıkarılan Ders
- **Uygulama:** `audit_service_security` metodu tüm bu zafiyet vektörlerini tek bir raporlama çıktısında birleştirir.
- **Doğrulama:** `test_10_hizmet_denetimi_kritik_yazilabilir_klasor_tespiti` ile zayıf klasör izinleri test edilmiştir.
- **Çıkarılan Ders:** Bir hizmeti yüksek yetkiyle koşturmak büyük bir sorumluluktur. Servis ikili dosyasının yolu ve klasör izinleri kilitlenmediği takdirde, hizmet sistemin savunması değil saldırganın köprüsü haline gelir.
