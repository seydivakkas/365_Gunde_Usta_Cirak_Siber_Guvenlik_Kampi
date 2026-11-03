# GÜN 016: SORU-CEVAP VE SENARYO ANALİZLERİ
# CPU, RAM ve Depolama Ayrımı Güvenlik Değerlendirmesi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).  
> Bu dosya ve içerikler yalnızca görüntüleme ve eğitim amaçlıdır. Ticari/gayriticari kopyalanamaz, çoğaltılamaz, dağıtılamaz.

---

## SORU 1: [G016-SC1] Temel Mekanizma ve Güvenlik Önemi

### Soru ve Bağlam
*CPU, RAM ve depolama ayrımı: Temel mekanizmayı ve güvenlik önemini açıkla.*  
Modern bilgi işlem mimarisinde CPU, RAM ve kalıcı depolama birimleri arasındaki fiziksel ve mantıksal ayrım nedir? Bu ayrımın veri gizliliği, bellek izolasyonu ve adli bilişim açısından taşıdığı kritik güvenlik önemi nasıldır?

### Teknik Açıklama ve Mekanizma
1. **CPU Katmanı:** Komut yürütme merkezidir. Anlık işlemler yazmaçlar (Registers) ve L1/L2/L3 önbellekler üzerinde nanometre ve nanosaniye ölçeğinde icra edilir. Donanımsal yetki halkaları (Ring 0 / Ring 3) işlemcinin hangi komutları çalıştırabileceğini sınırlar.
2. **RAM Katmanı (Uçucu Hafıza):** Süreçlerin kod, veri, yığıt (stack) ve öbek (heap) alanlarını barındıran dinamik çalışma sahasıdır. İşletim sistemi sanal bellek yöneticisi (MMU) her sürece izole edilmiş sanal adres alanı tahsis eder. Elektrik kesildiğinde verinin kaybolduğu varsayılır.
3. **Depolama Katmanı (Kalıcı Hafıza):** Dosya sistemleri (NTFS, ext4), takas alanları (swap/pagefile) ve hazırda bekletme dosyalarını saklayan manyetik veya katı hal (SSD) birimleridir. Elektrik kesilse dahi veriler fiziki olarak korunur.

Güvenlik önemi; verinin bir katmandan diğerine akarken (örneğin RAM'den `pagefile.sys`'ye yazılması veya diskten bir dosya silinirken yalnızca inode/göstericinin silinmesi) **uçuculuk varsayımlarının kırılması** ve kalıntı sızıntısı (data remanence) oluşması gerçeğinde yatar.

### Güvenlik Etkisi ve Saldırı / Savunma Senaryosu
- **Saldırı Senaryosu (LSASS ve Pagefile Sızıntısı):** Bir saldırgan yerel sistemde yönetici hakkı elde edemese bile, makine kapatıldığında sabit diski fiziksel olarak çıkarıp başka bir bilgisayara bağlar (veya Linux live USB ile başlatır). BitLocker veya tam disk şifreleme yoksa, `C:\pagefile.sys` dosyasını tarayarak RAM'den diske takas edilmiş açık metin parolaları, API anahtarlarını ve oturum belirteçlerini elde eder.
- **Savunma Senaryosu:** 
  - Kritik kimlik doğrulama süreçlerinde `VirtualLock()` / `mlock()` çağrılarak hassas bellek sayfalarının diske takas edilmesi donanımsal olarak engellenir.
  - Kurumsal işletim sistemlerinde `ClearPageFileAtShutdown = 1` politikası etkinleştirilerek kapanış esnasında takas alanının sıfırlarla ezilmesi sağlanır.
  - Tam disk şifreleme (FDE - BitLocker XTS-AES-256 / LUKS) zorunlu kılınarak fiziksel medya hırsızlıklarına karşı koruma sağlanır.

### Uygulama, Doğrulama ve Çıkarılan Ders
- **Uygulama:** `SystemHardwareBoundaryAuditor` modülü, sistemin canlı donanım envanterini toplar ve CIS Benchmark taban çizgisine göre `RULE-STORAGE-002` kuralı ile sayfalama dosyasının temizlenme durumunu denetler.
- **Doğrulama:** `test_02_canli_donanim_envanteri_cpu_katmani`, `test_03_canli_donanim_envanteri_ram_katmani` ve `test_04_canli_donanim_envanteri_depolama_katmani` ile canlı sistem metrikleri ve izolasyon sınırları doğrulanmıştır.
- **Çıkarılan Ders:** Bir verinin gizliliği, bulunduğu en zayıf donanım katmanının güvenliği kadardır. RAM'de güvenle işlenen bir veri, disk takasına düştüğü anda kalıcı bir tehdit yüzeyi oluşturur.

---

## SORU 2: [G016-SC2] Bağımsız Laboratuvar ve Test Mimarisi

### Soru ve Bağlam
*CPU, RAM ve depolama ayrımı: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?*  
Örnek uygulama bağlamında; Görev Yöneticisi veya otomatize Python araçlarıyla CPU, RAM ve depolama ayrımını ve bellek yaşam döngüsünü bağımsız olarak test eden bir laboratuvar kurgusu nasıl oluşturulur?

### Teknik Açıklama ve Mekanizma
Laboratuvarımız harici bir araca ihtiyaç duymaksızın doğrudan `system_hardware_boundary_auditor.py` modülü ile yürütülür:
1. **Kontrollü Girdi (Input):**
   - Canlı sistem için işletim sistemi çekirdek ve donanım göstergeleri (`platform`, `os.cpu_count()`, `shutil.disk_usage()`).
   - Simülasyon için `ornek_veri/hardware_boundary_sample.json` ve `hardware_security_baseline.json` veri setleri.
   - Yaşam döngüsü deneyi için hassas parola bayt dizisi (`b"SuperGizliKurumsalParola2026!"`).
2. **Laboratuvar İşlemi (Process):**
   - Donanım envanterinin çıkarılması ve katman bazlı risk profillemesi.
   - Bellek yaşam döngüsü simülasyonu: `bytearray` tahsisi, verinin yerleştirilmesi ve serbest bırakılma anında iki farklı yöntemin uygulanması (`use_secure_zero=True` vs. `use_secure_zero=False`).
   - Taban çizgisi kuralları (ASLR, DEP, FDE, Pagefile wipe) ile sistem konfigürasyonunun karşılaştırılması.
3. **Beklenen Sonuç (Expected Output):**
   - Güvenli sıfırlama (`SecureZeroMemory`) yapıldığında bellek bloğunun tamamen `0x00` baytları ile ezilmesi ve kalıntı riskinin `YOK` olarak raporlanması.
   - Örnek donanım verisindeki sayfalama kapanış temizliği eksikliği nedeniyle `RULE-STORAGE-002` ihlalinin yakalanması.
4. **Negatif Kontrol (Negative Control):**
   - Basit bırakma (`plain_free`) uygulandığında, tampon içeriğinin serbest bırakılmasına rağmen verinin bellekte aynen korunduğunun (`kalinti_verisi_hex == tahsis_verisi_hex`) ve kalıntı riskinin `KRITIK` seviyede tetiklendiğinin ispatlanması.

### Güvenlik Etkisi ve Saldırı / Savunma Senaryosu
- **Adli Bilişim ve İstismar Simülasyonu:** Negatif kontrol testi, yazılımcıların `free()` çağrısı yaptıktan sonra belleğin otomatik temizlendiğine dair yanılgısını teknik olarak çürütür. Bir saldırgan bellek ayırıcının (memory allocator) yeniden tahsis etmediği bu blokları `Use-After-Free` veya doğrudan `/proc/$PID/mem` okuması ile ele geçirebilir.
- **Savunma:** Değiştirilebilir tampon üzerinde döngüsel `0x00` yazımı veya `ctypes.memset` ile sıfırlama uygulanarak adli bilişimsel iz bırakılmaması garanti edilir.

### Uygulama, Doğrulama ve Çıkarılan Ders
- **Uygulama:** `simulate_memory_lifecycle(secret_bytes, use_secure_zero)` fonksiyonu iki yaklaşımı karşılaştırmalı olarak yürütür.
- **Doğrulama:** `test_12_bellek_yasam_dongusu_guvenli_sifirlama_simulasyonu` ve `test_13_bellek_yasam_dongusu_guvensiz_birakma_kalinti_simulasyonu` testleri pozitif ve negatif kontrolleri %100 doğrulukla sınamıştır.
- **Çıkarılan Ders:** Yazılım seviyesinde yapılan bellek tahsisleri fiziksel donanım katmanlarını doğrudan etkiler. Güvenli kodlama prensipleri işletilmediğinde işletim sistemi veriyi temizlemez.

---

## SORU 3: [G016-SC3] Risk Oluşumu, Tespit ve Savunma Kontrolleri

### Soru ve Bağlam
*'CPU, RAM ve depolama ayrımı' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?*  
Donanım mimarisi ve bellek katmanları arasındaki veri akışında kurumsal riskler nasıl filizlenir, bu riskler güvenlik operasyon merkezleri (SOC) ve denetçiler tarafından nasıl tespit edilir ve hangi savunma kontrolleriyle bertaraf edilir?

### Teknik Açıklama ve Mekanizma
1. **Risk Oluşumu:**
   - **Gereksiz İzin ve Halka İhlali:** Kullanıcı kipi (Ring 3) uygulamalarına aşırı ayrıcalık verilmesi veya çekirdek (Ring 0) sürücülerinin imzasız yüklenmesi.
   - **Bellek Hijyeni Eksikliği:** Parola ve anahtarların RAM'de açık metin tutulması ve `mlock` ile korunmaması.
   - **Depolama Kalıntısı:** Geçici dosyaların (`.tmp`) doğrudan silinmesi yerine `shred` uygulanmaması ve `ClearPageFileAtShutdown` ayarının kapalı bırakılması.
2. **Tespit Mekanizmaları:**
   - **Statik ve Dinamik Denetim:** `SystemHardwareBoundaryAuditor` gibi araçlarla kayıt defteri (`HKLM`), grup ilkeleri (GPO) ve donanım koruma bayraklarının (ASLR, DEP) taranması.
   - **Adli Bilişim Taraması:** Çöken sistemlerin bellek dökümlerinde (`MEMORY.DMP`) veya disk slack/unallocated alanlarında açık metin anahtar taranması (`strings`, `volatility`).
3. **Savunma ve Önleme Kontrolleri:**
   - **En Az Ayrıcalık (Least Privilege):** Ring 3 süreçlerinin çekirdek bellek alanına doğrudan erişiminin SMEP (Supervisor Mode Execution Prevention) ve SMAP ile donanımsal olarak engellenmesi.
   - **NIST SP 800-88 Medya İmhası:** Depolama birimlerinde kriptografik silme ve standart ezme prosedürlerinin uygulanması.
   - **Zorunlu FDE:** Tüm uç noktalarda BitLocker / LUKS şifrelemesi ve TPM 2.0 çipi ile anahtar saklama.

### Güvenlik Etkisi ve Saldırı / Savunma Senaryosu
- **Senaryo:** Bir kurumda çalışan geliştirici, API anahtarını yerel diskte geçici bir dosyaya yazar ve işlem bitince standart dosya silme fonksiyonuyla dosyayı siler. Şirket dizüstü bilgisayarı elden çıkarıldığında, ikinci el alıcı `PhotoRec` aracıyla silinen dosyayı saniyeler içinde kurtararak kurumun bulut altyapısına sızar.
- **Önleme:** Kurum güvenlik politikalarında NIST SP 800-88 Clear/Purge prosedürleri zorunlu tutulmuş, geçici dosyalar RAM disk (`tmpfs`) üzerinde işlenmiş ve tam disk şifreleme uygulanmış olsaydı, kalıntı kurtarma girişimi tamamen başarısız olacaktı.

### Uygulama, Doğrulama ve Çıkarılan Ders
- **Uygulama:** `audit_hardware_security` ve `evaluate_data_remanence` fonksiyonları, depolama ve bellek nesnelerinde güvenli silme ve şifreleme eksikliklerini otomatik olarak yakalar.
- **Doğrulama:** `test_09_depolama_nesnesi_silinmeyen_kalinti_degerlendirmesi` ve `test_11_donanim_taban_cizgisi_denetimi_ihlal_tespiti` ile bu kurumsal riskler test edilmiştir.
- **Çıkarılan Ders:** Donanım sınırları iyi yönetilmediğinde depolama katmanı adeta kalıcı bir saldırı müzesine dönüşür. Güvenlik, verinin ilk oluşturulduğu CPU yazmacından diske yazıldığı son sektöre kadar kesintisiz işletilmelidir.
