# Hafta 05 — Gün 029: Soru & Cevap ve Senaryo Analizleri

> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> **Özel Lisans — Tüm Hakları Saklıdır**  
> *Bu eğitim materyali yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, dağıtılamaz, ticari olarak kullanılamaz.*

---

## Senaryo 1 (G029-SC1): Windows Olay Günlüğü Temel Mekanizması ve Bağlamsal Analiz

### Senaryo Analizi ve Kapsam
Windows işletim sistemlerinde olay günlüğü altyapısı (Windows Event Log), işletim sistemi bileşenlerinin, sürücülerin ve üçüncü taraf yazılımların çalışma anındaki aktivitelerini yapılandırılmış (structured) biçimde kaydetmesini sağlar. Her olay kaydı; kaynak (Provider), olay kimliği (EventID), önem düzeyi (Level), kayıt numarası (RecordId), zaman damgası (TimeCreated) ve olaya özel parametreleri (EventData) barındırır. Bu senaryonun kapsamı; olay günlüğü anatomisini açıklamak ve en kritik güvenlik ilkesi olan *"Tek bir olay kimliği bağlam olmadan saldırı kanıtı değildir"* kuralını adli açıdan kanıtlamaktır.

### Teknik Açıklama ve Güvenlik Mekanizması
1. **Olay Anatomisi:**
   - **ProviderName:** Olayı üreten sistem servisi (örn: `Service Control Manager`, `Microsoft-Windows-Security-Auditing`).
   - **EventID:** Olayın teknik türünü tanımlayan tamsayı kimlik.
   - **TimeCreated:** Olayın gerçekleştiği kesin UTC zaman damgası.
   - **RecordId:** Sıralı, silinip araya kayıt eklenemez sıra numarası.
2. **Bağlamsal Analiz Zorunluluğu (Contextual Evaluation):**
   - **Event ID 4625 (Başarısız Oturum Açma):** Tek başına ele alındığında bir saldırı kanıtı olamaz. Kullanıcının klavyesindeki yazım hatası veya Caps Lock durumu tek bir 4625 üretir. Ancak aynı kullanıcı veya farklı kullanıcılar için 5 dakika içinde yüzlerce 4625 gelmesi, kaba kuvvet (Brute Force - MITRE ATT&CK T1110) veya parola püskürtme (Password Spraying) saldırısını kanıtlar.
   - **Event ID 7045 (Yeni Servis Kurulumu):** Meşru bir yazılım kurulumunda `C:\Program Files\` dizinindeki bir ikili dosya için üretildiğinde olağan kabul edilirken; `C:\Windows\Temp\` veya `AppData\Local\Temp\` altındaki bir `.exe` dosyasını çalıştırdığında yüksek riskli kalıcılık (Persistence - T1543.003) alarmı oluşturur.

### Komutlar, Kanıtlar ve Laboratuvar Doğrulaması
- **Adli Olay ve Bağlam Analizi Çalıştırma:**
  ```bash
  python portfolio/hafta_05/gun_029/uygulama/windows_event_viewer_analyzer.py --events portfolio/hafta_05/gun_029/ornek_veri/sample_system_events.json --analyze
  ```
- **Kanıt Dosyası:** `kanit/gercek/sistem_olay_analiz_kaydi.txt` dosyasında doğrulanmıştır. Her olay tekil kimliğiyle değil, çalıştırılan dosya yolu, kullanıcı ayrıcalığı ve MITRE ATT&CK tekniği ile birlikte değerlendirilmiştir.
- **Birim Test Kanıtı:** `test_09_contextual_eval_event_4625_single_vs_spray` testi ile tekil 4625'in `SINGLE_LOGON_FAILURE` olarak değerlendirildiği tescillenmiştir.

### Savunma Kontrolleri ve Alınacak Dersler
- Mavi takım analistleri ve SOC operatörleri, tekil olay kimliklerine dayalı kural yazmak yerine zaman penceresi (time window), eşik değer (threshold) ve süreç üstverilerini kapsayan korelasyon kuralları geliştirmelidir.
- Loglar bağlamından koparılarak tek başına cezalandırıcı delil yapılamaz.

---

## Senaryo 2 (G029-SC2): Bağımsız Laboratuvar Doğrulaması: 3 Sistem Olayı ve Negatif Kontrol

### Senaryo Analizi ve Kapsam
Bu senaryoda bağımsız bir laboratuvar deneyi kurgulanmıştır: Kontrollü bir girdi olarak gizli veri içermeyen 3 adet sistem olayı (`sample_system_events.json`) alınmış; olayların tüm alanları (`record_id`, `provider_name`, `event_id`, `time_created`, `computer`, `user_name`, `event_data`) taranmış ve SHA-256 kriptografik bütünlük özetleri çıkarılmıştır. Ardından negatif kontrol amacıyla eksik sağlayıcı adı, bozuk tarih ve geçersiz kimlik içeren 4 adet bozuk olay (`corrupted_events_test.json`) sisteme verilmiş ve motorun bu hatalı girdileri istisnasız reddettiği doğrulanmıştır.

### Teknik Açıklama ve Güvenlik Mekanizması
1. **İncelenen 3 Sistem Olayı (System Channel):**
   - **Olay 1 (Event 6005):** `EventLog` sağlayıcısı, `104201` RecordId. "The Event log service was started." Sistem önyükleme anını mühürler.
   - **Olay 2 (Event 7045):** `Service Control Manager`, `104205` RecordId. `SysmonAgentService` kurulumu. Kalıcılık (Persistence - T1543.003) analizi.
   - **Olay 3 (Event 1074):** `USER32`, `104210` RecordId. `shutdown.exe` ile planlı yeniden başlatma. Sistem kullanılabilirliği ve adli kronoloji (T1529).
2. **Kriptografik Bütünlük Mühürlemesi:** Her bir olay kaydı için `hashlib.sha256(f"{record_id}:{event_id}:{time_created}:{raw_message}".encode())` formülüyle 64 karakterlik SHA-256 özeti üretilmiştir.
3. **Negatif Kontrol (Negative Control):**
   - Boş `provider_name` -> `MISSING_PROVIDER_NAME`
   - Sayısal olmayan `event_id` -> `INVALID_EVENT_ID`
   - Bozuk tarih dizesi -> `MALFORMED_TIMESTAMP`
   - Boş kanal/bilgisayar üstverisi -> `MISSING_MANDATORY_METADATA`

### Komutlar, Kanıtlar ve Laboratuvar Doğrulaması
1. **Sistem Olaylarının Ayrıştırılması:**
   `python windows_event_viewer_analyzer.py --events sample_system_events.json --analyze`
   *(Çıktı: `3 sistem olayı eksiksiz ayrıştırıldı, SHA-256 üretildi.`)*
2. **Negatif Kontrol Doğrulama:**
   `python windows_event_viewer_analyzer.py --test-corrupted corrupted_events_test.json`
   *(Çıktı: `Toplam Test Edilen Hatalı Olay: 4, Başarıyla Reddedilen: 4, Sonuç: TAM BAŞARILI (PASS).`)*
- **Kanıt Dosyaları:**
  - `kanit/gercek/sistem_olay_analiz_kaydi.txt` (3 olayın tüm alanları ve adli gerekçeleri).
  - `kanit/gercek/negatif_kontrol_sonuclari.txt` (4 bozuk kaydın reddedilme izi).
  - `kanit/gercek/test_sonuclari.txt` (14/14 birim test PASS).

### Savunma Kontrolleri ve Alınacak Dersler
- Adli olay kayıtları adli zincirde (chain of custody) sunulmadan önce biçimsel bütünlük testinden geçirilmeli ve hash özetleri çıkarılmalıdır.
- Bozuk veya zaman damgası tahrif edilmiş kayıtlar sahte delil üretme girişimlerine karşı filtrelenmelidir.

---

## Senaryo 3 (G029-SC3): Risk Oluşumu, Tespiti ve Önleyici Savunma Kontrolleri

### Senaryo Analizi ve Kapsam
Windows Event Viewer ve olay günlükleri bağlamında güvenlik riskleri; denetim politikalarının yetersiz bırakılması (CWE-778), sistemdeki yetkisiz servis kurulumları (T1543.003), saldırganların adli izleri silmek için günlükleri temizlemesi (Event 1102 / T1070.001) ve log enjeksiyonu (CWE-117) ile ortaya çıkar. Bu senaryo, bu risklerin nasıl oluştuğunu, fark analizi ve kural tabanlı motorla nasıl tespit edildiğini ve en az ayrıcalık ile merkezi SIEM mimarisiyle nasıl önlendiğini ortaya koyar.

### Teknik Açıklama ve Güvenlik Mekanizması
1. **Risk Nasıl Oluşur?**
   - **İz Silme (Log Cleared - Event 1102):** Yönetici veya ele geçirilmiş ayrıcalıklı bir hesap `wevtutil cl Security` çalıştırdığında denetim günlüğü sıfırlanır.
   - **Yetersiz Denetim (Audit Policy Gap):** Süreç oluşturma (Event 4688) ve PowerShell komut günlüğü kapalı bırakıldığında saldırganın aktiviteleri karanlıkta kalır.
   - **Gereksiz Ayrıcalıklar (CWE-250):** Sıradan servislere `LocalSystem` yetkisi verilmesi durumunda zafiyet anında tam sistem kontrolü kaybedilir.
2. **Nasıl Tespit Edilir?**
   - **Fark Raporu ve Anomali Tespiti:** Sistem olayları periyodik olarak baseline ile karşılaştırılır. Yeni eklenen servisler (`Event 7045`), olağan dışı kapatmalar (`Event 1074`) veya güvenlik günlüğü temizleme alarmları (`Event 1102`) anında tespit edilir.
   - `windows_event_viewer_analyzer.py` motoru, şüpheli ikili dosya yollarını (Temp dizinleri) analiz ederek otomatik `HIGH` risk etiketi atar.
3. **Hangi Kontrollerle Önlenir?**
   - **Merkezi Log İletimi (WEC / WEF / SIEM):** Yerel günlükler saniyeler içinde merkezi, salt-okunur ve kriptografik olarak korunan bir log havuzuna (SIEM) aktarılmalıdır. Yerel log silinse dahi merkezdeki kopya korunur.
   - **En Az Ayrıcalık (Least Privilege):** Olay günlüklerini temizleme yetkisi yalnızca özel güvenlik yöneticilerine ayrılmalı; servis hesaplarının bu yetkisi engellenmelidir.
   - **Sysmon ve Gelişmiş SACL:** Hassas kayıt anahtarlarına ve sistem dizinlerine Sistem Erişim Kontrol Listeleri (SACL) uygulanmalıdır.

### Komutlar, Kanıtlar ve Laboratuvar Doğrulaması
- **Adli İhlal Tespiti:** Geliştirilen motor, Event 1102 kaydını doğrudan `CRITICAL` ve `AUDIT_LOG_TAMPERING` olarak etiketler (`test_10_contextual_eval_event_1102_log_cleared`).
- **Şüpheli Yol Tespiti:** Temp dizininden kurulan bir servis için motor `SUSPICIOUS_SERVICE_INSTALLATION` kararı üretmiştir (`test_07`).

### Savunma Kontrolleri ve Alınacak Dersler
- "Gözlem yoksa savunma yoktur." Olay günlükleri kurumun dijital kara kutusudur; korunmalı, yedeklenmeli ve sürekli izlenmelidir.
- Otomatik log iletimi aktif edilmeden hiçbir Windows sunucusu üretime alınmamalıdır.
