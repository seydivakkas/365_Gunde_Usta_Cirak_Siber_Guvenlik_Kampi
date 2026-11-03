# GÜN 35: MİNİ PROJE 4: SİSTEM DURUM KONTROLÜ — SORU-CEVAP BANKASI

---

### Lisans Bildirimi
```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu soru-cevap ve eğitim içeriği yalnızca görüntüleme ve eğitim amaçlıdır.
Kopyalanamaz, çoğaltılamaz, ticari amaçla kullanılamaz.
```

---

## BÖLÜM 1: GÜNLÜK SORU-CEVAPLAR (G035)

---

### SORU 1 (G035-SC1)

#### Temel Kavram ve Güvenlik Mekanizması
Sistem durum kontrolü ve güvenlik duruşu (posture) değerlendirmesi, bir hedef makinenin mevcut çalışan süreçlerini, hizmet yapılandırmalarını, başlangıç noktalarını ve kritik dosya bütünlüklerini analiz ederek genel bir güvenlik sağlığı özeti üretme sürecidir.

Güvenlik mekanizması açısından en kritik ilke **Salt-Okunur Gözlemci Modeli (Read-Only Observer Pattern)** ve **En Az Ayrıcalık (Least Privilege)** ilkesidir. Bir güvenlik tarama veya denetim aracı, çalıştırıldığı hedef işletim sisteminde gereksiz yere yüksek yönetimsel ayrıcalıklar (`SYSTEM`, `root`) talep etmemelidir. Bunun iki hayati nedeni vardır: Birincisi, denetim aracının kendisinin bir saldırı yüzeyi veya istismar noktası haline gelmesini önlemek; ikincisi ise adli bilişim (DFIR) prensipleri gereğince hedef sistemde delil kirlenmesine (dosya zaman damgalarının değişmesi, geçici sistem dosyaları oluşturulması) yol açmamaktır. Denetim aracı yalnızca gözlemlerden anlamlı özet üretmeli, sıfır yan etki ile çalışmalıdır.

#### Soru ve Didaktik Çözüm
**Soru:**
Mini proje 4: sistem durum kontrolü: Temel mekanizmayı ve güvenlik önemini açıklayınız.

**Didaktik Çözüm:**
Sistem durum taraması yalnızca gözlemlerden anlamlı özet üretmeli ve ayrıcalık gerektirmemelidir.
1. **Gözlemlerden Anlamlı Özet:** Dağınık haldeki süreç PID'lerini, servis durumlarını ve dosya karmalarını bir araya getirerek yöneticinin ve analistin saniyeler içinde karar verebileceği konsolide bir risk puanı ve eylem planı oluşturmalıdır.
2. **Ayrıcalık Gerektirmeme (En Az Ayrıcalık):** Standart kullanıcı haklarıyla toplanabilecek telemetriyi çekmeli, hedef sistemin durumunu kalıcı olarak değiştirmemelidir (sıfır yan etki).

#### Savunma ve Tespit Kılavuzu
- **Tespit Mekanizması:**
  - Güvenlik taramalarını standart kullanıcı yetkisiyle veya izole hizmet hesaplarıyla çalıştırın.
  - WMI veya PowerShell CIM sorgularında yalnızca `Get-*` komutlarını kullanarak durumu gözlemleyin.
- **Savunma Kontrolü:**
  - Denetim araçlarının sistem üzerinde yazma yapmasını önlemek için yürütme ortamını salt-okunur sandbox veya kısıtlı oturum ilkeleriyle sınırlayın.

#### Usta-Çırak İpuçları ve Laboratuvar Notu
*Usta der ki:* "Bir doktora gittiğinde doktor seni muayene eder, nabzına bakar, röntgen çeker; hemen masada karnını kesip ameliyat yapmaz! Sistem durum kontrolü de böyledir. Önce gözlem yapacaksın, durumu netleştireceksin. Gözlem yaparken sistemi yaralayan denetçi, denetçi değil kazadır!"

---

### SORU 2 (G035-SC2)

#### Temel Kavram ve Güvenlik Mekanizması
Mini proje düzeyindeki bağımsız bir laboratuvar; girdi, işlem, beklenen çıktı ve negatif kontrol ekseninde kurgulanmalıdır. Laboratuvar önceki günlerin dosyalarına bağımlı olmaksızın kendi başına çalışabilmeli ve hem pozitif tehditleri hem de bozuk verileri simüle eden sentetik telemetri setleriyle doğrulanmalıdır.

#### Soru ve Didaktik Çözüm
**Soru:**
Mini proje 4: sistem durum kontrolü: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

**Didaktik Çözüm:**
Bağımsız laboratuvar çalışmasının 4 temel bileşeni şunlardır:
1. **Girdi (Input):** Kendi test ortamımızda üretilen, hem meşru işletim sistemi süreç/servis hiyerarşisini hem de Week 5 boyunca incelenen tüm saldırı vektörlerini (ofis uygulamasının kabuk başlatması, servis tahrifatı, unquoted path, FIM hash uyuşmazlığı, çift uzantı) içeren kapsamlı telemetri anlık görüntüsü (`system_telemetry_snapshot.json`). Önceki günlerden hiçbir dosya devralınmaz.
2. **İşlem (Process):** `SystemPostureAuditor` motoru tarafından 4 denetim modülünün (süreç, servis, FIM, sihirli bayt) sırayla koşturulması, her bir alandaki bulguların toplanması ve ağırlıklı formülle 100 üzerinden Sistem Sağlık Puanının hesaplanması.
3. **Beklenen Sonuç (Expected Output):** Tüm kritik ve yüksek tehditlerin yakalanması, sistem sağlık puanının `0 / 100` (COMPROMISED_ENVIRONMENT) olarak tescillenmesi ve önceliklendirilmiş ASCII Yönetici Durum Panosunun üretilmesi.
4. **Negatif Kontrol (Negative Control):** Eksik bölümlü, liste yerine metin içeren veya null nesneler barındıran `corrupted_telemetry_test_cases.json` dosyasının sisteme verilmesi; motorun çökmeksizin hataları `corrupted_records` günlüğüne işlemesi ve 14/14 testin başarıyla PASS vermesi.

#### Savunma ve Tespit Kılavuzu
- **Test ve Doğrulama Adımları:**
  - Birim testleri çalıştırarak konsolide motorun hatasızlığını doğrulayın:
    ```bash
    python -m unittest portfolio/hafta_05/gun_035/tests/test_system_posture_auditor.py -v
    ```
  - Yönetici panosunu doğrudan ekrana yazdırarak inceleyin:
    ```bash
    python portfolio/hafta_05/gun_035/uygulama/system_posture_auditor.py
    ```

#### Usta-Çırak İpuçları ve Laboratuvar Notu
*Usta der ki:* "Haftalık projeler senin öğrendiğin tüm parçaları bir senfoni orkestrası gibi birlikte çalabilme yeteneğindir. Her modül bir enstrümandır. Biri detone olursa bütün sistem gürültüye boğulur."

---

### SORU 3 (G035-SC3)

#### Temel Kavram ve Güvenlik Mekanizması
'Sistem durum kontrolü' bağlamında kurumsal güvenlik riski; sistem bileşenlerinin (süreçler, servisler, konfigürasyon dosyaları) zaman içinde yönetimsel ihmaller veya saldırgan müdahaleleriyle taban çizgisinden (Golden Baseline) sapması (Configuration Drift) ve bu sapmaların fark edilememesinden kaynaklanır.

#### Soru ve Didaktik Çözüm
**Soru:**
'Mini proje 4: sistem durum kontrolü' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

**Didaktik Çözüm:**
1. **Risk Nasıl Oluşur?:**
   - **Gereksiz İzin:** Bir servisin `SYSTEM` hesabı ile tırnaksız yoldan başlatılması; kullanıcılara yazılabilir geçici dizinlerden betik yürütme izni verilmesi.
   - **Yanlış Servis ve Savunma Zafiyeti:** Güvenlik duvarının (`MpsSvc`) kapatılması veya imzasız üçüncü taraf servislerin otomatik başlatılması.
   - **Bütünlük İhlali:** Saldırganın konfigürasyon dosyasını tahrif edip sisteme gizlice çift uzantılı bir arka kapı bırakması.
2. **Nasıl Tespit Edilir?:**
   - **Kullanıcı/İzin/Servis Envanteri ve Fark Raporu:** `SystemPostureAuditor` gibi otomatik durum tarayıcıları düzenli aralıklarla çalıştırılarak altın taban çizgisi (baseline) ile fiili durum arasındaki farklar (diff) raporlanır.
3. **Hangi Kontrolle Önlenir?:**
   - **En Az Ayrıcalık ve Geri Alınabilir Yapılandırma:** Servis izinleri kilitlenir, yollar çift tırnak içine alınır. Tahrif edilen konfigürasyonlar IaC / Git reposundaki onaylı sürümlerle anında ezilir (Self-healing).

#### Savunma ve Tespit Kılavuzu
- **Sıkılaştırma Eylemleri:**
  - Tüm servisleri gözden geçirin, `sc.exe config` ile tırnakları tamamlayın.
  - Windows Defender ve Güvenlik Duvarı'nı GPO ile kilitli tutun.
  - Dosya bütünlük izlemesini (FIM) SIEM'e bağlayarak eşik aşımlarında otomatik izolasyon uygulayın.

#### Usta-Çırak İpuçları ve Laboratuvar Notu
*Usta der ki:* "Saldırganlar sistemde tek bir açık bulduğunda orada durmazlar; hemen güvenlik duvarını kapatır, yetki yükseltir ve sahte bir isimle arka kapı açarlar. Durum denetleyicin işte bu zincirleme saldırıların tüm halkalarını tek bakışta yakalamalıdır."

---

## BÖLÜM 2: HAFTALIK MİNİ PROJE SORU-CEVAPLARI (W05)

---

### SORU 4 (W05-SC1)

#### Soru ve Didaktik Çözüm
**Soru:**
'Mini proje 4: sistem durum kontrolü' çıktısı beklendiği gibi görünmüyorsa sorun giderme için ilk üç adımın ne olmalıdır?

**Didaktik Çözüm:**
1. **Adım 1 — Ön Koşul ve İzinli Ortam Doğrulaması:** Hedef test ortamının, izinli telemetri girdi dosyasının (`system_telemetry_snapshot.json`) mevcut olduğunu, dosya erişim yetkilerinin doğru ayarlandığını ve bağımsız çalışma kuralının bozulmadığını kontrol et.
2. **Adım 2 — Ham Girdi ve Hata İzi (Traceback) İncelemesi:** Konsola düşen hata mesajını, sözlük anahtarlarını ve veri tiplerini ayrıştır; hatanın hangi alt modülden (süreç, servis, FIM, imza) kaynaklandığını izole et.
3. **Adım 3 — Yeniden Üretim ve Kontrollü Düzeltme:** İzole edilen hatayı bağımsız bir negatif test senaryosuna dönüştürerek hatayı kontrollü ortamda yeniden üret, düzeltmeyi kodla ve kaynaklı gerekçesiyle tescille.

---

### SORU 5 (W05-SC2)

#### Soru ve Didaktik Çözüm
**Soru:**
'Mini proje 4: sistem durum kontrolü' çalışmasını başka bir sistem üzerinde uygulamadan önce hangi izin ve veri koşullarını doğrulamalısın?

**Didaktik Çözüm:**
1. **Yazılı Yetki ve Kapsam Belgesi (Rules of Engagement - RoE):** Sistem sahibinden veya kurum yönetiminden açık, yazılı ve imzalı test izni alınmalıdır.
2. **Veri Minimizasyonu ve Gizlilik:** Tarama motoru yalnızca güvenlik durum parametrelerini toplamalı; kullanıcı parolaları, kişisel veriler (PII) veya ticari gizlilik içeren dosya içeriklerini asla okumamalı ve kaydetmemelidir.
3. **Test Zamanı, Hız Sınırı ve Acil Durdurma Koşulu:** Taramanın üretim sistemini yormayacak saatlerde yapılması, sistem kaynağını tüketmemesi ve beklenmeyen bir yük anında hemen durdurulabilecek acil kapatma (kill-switch) mekanizmasının bulunması şarttır.

---

### SORU 6 (W05-SC3)

#### Soru ve Didaktik Çözüm
**Soru:**
'Mini proje 4: sistem durum kontrolü' için PASS kararını verebilmek adına hangi üç somut kanıtı saklamalısın?

**Didaktik Çözüm:**
1. **Çalışan Gerçek Komut ve Çıktı Kanıtı:** Uygulamanın başarıyla icra edildiğini gösteren terminal logları (`kanit/gercek/komut_ve_cikis.txt` ve `sistem_durum_panosu_raporu.txt`).
2. **Olumlu ve Olumsuz Test Sonuçları:** Birim test çatısı tarafından üretilen, 14 testin tamamının hatasız yeşil geçtiğini ve negatif kontrollerin çalıştığını belgeleyen döküm (`kanit/gercek/test_sonuclari.txt` ve `negatif_kontrol_sonuclari.txt`).
3. **Sınırlı, Kaynaklı ve Anonim Teknik Rapor:** Bulguların teknik kök nedenlerini, MITRE ATT&CK eşleşmelerini ve savunma önerilerini içeren resmi teknik değerlendirme belgesi (`rapor.md`).
