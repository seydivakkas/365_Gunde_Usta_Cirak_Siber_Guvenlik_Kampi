# GÜN 017: SORU-CEVAP VE SENARYO ANALİZLERİ
# İşletim Sistemi Çekirdeği ve Kullanıcı Modu Güvenlik Değerlendirmesi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).  
> Bu dosya ve içerikler yalnızca görüntüleme ve eğitim amaçlıdır. Ticari/gayriticari kopyalanamaz, çoğaltılamaz, dağıtılamaz.

---

## SORU 1: [G017-SC1] Temel Mekanizma ve Güvenlik Önemi

### Soru ve Bağlam
*İşletim sistemi çekirdeği ve kullanıcı modu: Temel mekanizmayı ve güvenlik önemini açıkla.*  
Çekirdek yetkisi (Kernel Mode / Ring 0) ile kullanıcı süreçleri (User Mode / Ring 3) arasındaki mimari koruma mekanizması nedir? Bir programın yönetici (Administrator/root) olması neden mutlak güvenlik veya doğrudan çekirdek yetkisi anlamına gelmez?

### Teknik Açıklama ve Mekanizma
Modern işlemcilerde güvenlik, CPU seviyesindeki **Ayrıcalık Halkaları (Privilege Rings)** ve sanal bellek adres ayrımı ile sağlanır:
1. **Kullanıcı Modu (Ring 3):** Standart kullanıcı süreçleri ve yönetici kabukları burada çalışır. x86_64 mimarisinde adres alanı `0x0000000000000000` ile `0x00007FFFFFFFFFFF` (Kullanıcı Alanı) arasındadır. İşlemcinin fiziksel kontrol komutları (`HLT`, `CLI`, `STI`, `MOV CR3`) bu halkada yasaktır.
2. **Çekirdek Modu (Ring 0):** İşletim sistemi çekirdeği (`ntoskrnl.exe`, `vmlinuz`) ve aygıt sürücüleri burada çalışır. Adres alanı `0xFFFF800000000000` üzerindedir. Tüm fiziksel belleğe ve donanım kayıtçılarına doğrudan erişim hakkı vardır.

**Yönetici Yanılgısı:** Bir programın Windows'ta "Yönetici" veya Linux'ta "root" olması, onun çekirdeğe geçtiği anlamına gelmez. Yönetici süreci de **Ring 3'te** çalışır. Aradaki fark, işletim sistemi güvenlik politikalarının yöneticiye daha fazla kullanıcı nesnesine erişim (örn: diğer süreçlerin belleğini okuma yetkisi olan `SeDebugPrivilege` veya sürücü yükleme yetkisi) tanımasıdır. Ancak donanım seviyesinde CPU kuralları hâlâ geçerlidir; yönetici süreci doğrudan çekirdek adresine yazmaya çalışırsa CPU yine `Access Violation / GP Fault` üreterek programı sonlandırır.

### Güvenlik Etkisi ve Saldırı / Savunma Senaryosu
- **Saldırı Senaryosu (EDR Katili Zararlı Yazılım):** Bir fidye yazılımı yönetici yetkisi elde etse bile Ring 3'te çalıştığı için, Ring 0'da ve Erken Başlatılan Kötü Amaçlı Yazılımdan Koruma (ELAM) güvencesinde çalışan kurumsal EDR/Antivirüs sürücüsünü kapatamaz. Bu engeli aşmak için saldırgan, çekirdek moduna geçmek zorundadır. Bunu da sistemdeki bir çekirdek açığını kullanarak veya geçerli imzalı savunmasız bir sürücüyü (BYOVD) yükleyerek gerçekleştirir.
- **Savunma Senaryosu:** İşletim sisteminde Çekirdek İzolasyonu (Core Isolation / HVCI), Sürücü İmza Zorunluluğu (DSE) ve Microsoft Savunmasız Sürücü Engelleme Listesi aktif edilerek yönetici haklarına sahip saldırganın bile çekirdek seviyesine sızması donanımsal olarak engellenir.

### Uygulama, Doğrulama ve Çıkarılan Ders
- **Uygulama:** `KernelUserModeBoundaryAnalyzer` sınıfının `get_current_process_privilege_context()` metodu, mevcut sürecin yönetici olup olmadığını sorgularken aynı zamanda çalışma halkasının kesinlikle `Ring 3 (User Mode)` olduğunu canlı olarak kanıtlar.
- **Doğrulama:** `test_02_canli_surec_baglami_sorgulama` ile yerel süreç bağlamı ve Ring 3 izolasyonu doğrulanmıştır.
- **Çıkarılan Ders:** Yönetici yetkisi mutlak güç değildir; güvenlik mimarisi çekirdek ile kullanıcı modunu birbirinden ayırdığı sürece sistem bütünlüğü savunulabilir durumdadır.

---

## SORU 2: [G017-SC2] Bağımsız Laboratuvar ve Test Mimarisi

### Soru ve Bağlam
*İşletim sistemi çekirdeği ve kullanıcı modu: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?*  
İki farklı yetki seviyesinin (Ring 0 vs. Ring 3) izinlerini açıklayan tabloyu oluşturan ve sistem çağrısı işaretçi doğrulaması yapan bağımsız laboratuvar mimarisi nasıl kurulur?

### Teknik Açıklama ve Mekanizma
Laboratuvarımız `kernel_user_mode_boundary_analyzer.py` modülü üzerinden 4 temel aşamada kurgulanmıştır:
1. **Kontrollü Girdi (Input):**
   - Ring 0 (Çekirdek), Ring 3 Yönetici ve Ring 3 Standart kullanıcı izin ve adres sınırlarını içeren `ornek_veri/kernel_user_privilege_matrix.json`.
   - Çekirdeğe sistem çağrısı (syscall) ile iletilen 3 farklı bellek göstericisi:
     - Geçerli kullanıcı göstericisi (`0x00007ffd12340000`)
     - Çekirdek alanını işaret eden sahte gösterici (`0xfffff80012340000`)
     - Sıfır sayfası / NULL gösterici (`0x0000000000000000`)
2. **Laboratuvar İşlemi (Process):**
   - Yetki matrisinin yüklenmesi ve katmanlar arası izin farklarının karşılaştırılması.
   - `validate_syscall_pointer()` fonksiyonu ile Windows çekirdeğindeki `ProbeForRead` / `ProbeForWrite` ve donanımsal SMEP/SMAP kontrol mantığının simüle edilmesi.
   - Adres formatı, NULL pointer, 64-bit tamsayı taşması ve kullanıcı/çekirdek adres sınırı kontrolü.
3. **Beklenen Sonuç (Expected Output):**
   - Kullanıcı alanında kalan geçerli göstericinin `GECERLI_KULLANICI_ISARETCISI` olarak onaylanması (`guvenli_mi = True`).
   - Yetki tablosunda Ring 0'ın tam fiziksel erişime sahip olduğunun, Ring 3'ün ise donanım komutlarından men edildiğinin ortaya konulması.
4. **Negatif Kontrol (Negative Control):**
   - Çekirdek alanına (`0xfffff800...`) işaret eden adres verildiğinde denetleyicinin işlemi anında reddederek `ENGEL_CEKIRDEK_ALANI_IHLALI` üretmesi ve `guvenli_mi = False` döndürmesi.
   - NULL gösterici (0x0) verildiğinde `ENGEL_NULL_POINTER` ile çekirdek çökmesinin (BSOD) önlendiğinin ispatlanması.

### Güvenlik Etkisi ve Saldırı / Savunma Senaryosu
- **İstismar Analizi:** Bir saldırgan çekirdek sürücüsüne gönderdiği sistem çağrısında çıktı tamponu adresi olarak çekirdeğin güvenlik tablosunu veya EPROCESS yapısını verirse ve çekirdek bunu doğrulamadan açarsa, kullanıcı modu çekirdek belleğini keyfi olarak ezer (Write-What-Where).
- **Savunma:** `ProbeForRead/Write` kontrolleri ve SMEP/SMAP donanım kalkanları sayesinde bu istismar teşebbüsü henüz parametre doğrulama aşamasında kesilir.

### Uygulama, Doğrulama ve Çıkarılan Ders
- **Uygulama:** `validate_syscall_pointer` metodu bu kontrolleri matematiksel ve mimari sınırlarla icra eder.
- **Doğrulama:** `test_05_syscall_gecerli_kullanici_isaretcisi`, `test_06_syscall_null_pointer_engeli_negatif_kontrol` ve `test_07_syscall_cekirdek_alani_ihlali_negatif_kontrol` testleri 14/14 başarıyla doğrulanmıştır.
- **Çıkarılan Ders:** Çekirdek modu, kullanıcı modundan gelen hiçbir veriye ve göstericiye güvenemez. Her girdi sınır çizgisinde katı şekilde doğrulanmalıdır.

---

## SORU 3: [G017-SC3] Risk Oluşumu, Tespit ve Savunma Kontrolleri

### Soru ve Bağlam
*'İşletim sistemi çekirdeği ve kullanıcı modu' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?*  
Kullanıcı modundan çekirdek moduna geçişte kurumsal riskler (özellikle BYOVD) nasıl doğar, güvenlik operasyonlarında nasıl tespit edilir ve Microsoft/NIST standartlarıyla nasıl önlenir?

### Teknik Açıklama ve Mekanizma
1. **Risk Oluşumu:**
   - **Aşırı Ayrıcalıklı Kullanıcılar:** Son kullanıcı hesaplarına yerel yönetici hakkı verilmesi.
   - **Savunmasız Sürücülerin İstismarı (BYOVD):** Yönetici hakkı alan saldırganın, geçerli Microsoft imzasına sahip ancak bilinen zafiyetleri olan eski donanım sürücülerini (`RTCore64.sys`, `gdrv.sys`) sisteme yüklemesi.
   - **Güvenlik Çözümlerinin Kör Edilmesi:** Çekirdeğe sızan saldırganın EDR kanca (hook) ve kayıtçılarını devre dışı bırakması.
2. **Tespit Mekanizmaları:**
   - **Sürücü Yükleme Olay Günlükleri:** Windows Olay Günlüğü `Event ID 7045` (Yeni bir servis yüklendi) ve Sysmon `Event ID 6` (Sürücü yüklendi - Driver Loaded) günlüklerinin SIEM üzerinde izlenmesi.
   - **Hash ve Sertifika Taraması:** Yüklenen sürücülerin SHA-256 özetlerinin Microsoft Savunmasız Sürücü Engelleme Listesi ve VirusTotal ile karşılaştırılması.
3. **Savunma ve Önleme Kontrolleri:**
   - **En Az Ayrıcalık (Least Privilege):** Kullanıcılardan yerel yönetici haklarının alınması (yönetici olmayan kullanıcı sürücü yükleyemez).
   - **HVCI (Hipervizör Korumalı Kod Bütünlüğü):** Çekirdek kod sayfalarının dinamik olarak değiştirilmesinin donanımsal olarak engellenmesi.
   - **Microsoft Önerilen Savunmasız Sürücü Engelleme Listesi:** Windows Defender Uygulama Denetimi (WDAC) ilkeleriyle bilinen BYOVD sürücülerinin sisteme yüklenmesinin tamamen engellenmesi.

### Güvenlik Etkisi ve Saldırı / Savunma Senaryosu
- **Senaryo:** BlackCat/ALPHV fidye yazılımı aktörleri, MSI'ın eski `RTCore64.sys` sürücüsünü sisteme yükleyerek çekirdek modunda fiziksel bellek okuma/yazma yetkisi elde etmiş ve antivirüs süreçlerini bellekten sonlandırmıştır.
- **Önleme:** Eğer sistemde Microsoft Sürücü Engelleme Listesi açık olsaydı, `KernelUserModeBoundaryAnalyzer` aracımızın `RULE-KERN-002` kuralında doğruladığı gibi sürücü yükleme isteği işletim sistemi çekirdeği tarafından derhal reddedilecekti.

### Uygulama, Doğrulama ve Çıkarılan Ders
- **Uygulama:** `audit_byovd_drivers` ve `audit_kernel_security_baseline` fonksiyonları, tehlikeli sürücüleri ve devre dışı bırakılmış çekirdek savunmalarını anında raporlar.
- **Doğrulama:** `test_10_byovd_surucu_denetimi_tehdit_tespiti` ve `test_12_cekirdek_taban_cizgisi_ihlal_yakalama` ile senaryo başarıyla test edilmiştir.
- **Çıkarılan Ders:** Çekirdek güvenliği yalnızca imza kontrolüne bırakılamaz. Geçmişte imzalanmış zafiyetli sürücüler engellenmedikçe çekirdek kapısı saldırganlara sonuna kadar açıktır.
