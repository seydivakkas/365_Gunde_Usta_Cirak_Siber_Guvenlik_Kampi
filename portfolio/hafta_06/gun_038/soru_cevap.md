<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 038 — Soru & Cevap ve Didaktik İnceleme

## G038-SC1: Zaman Senkronizasyonu, Saat Kayması (Clock Skew) ve Güvenlik Mekanizmaları

### Temel Kavram ve Güvenlik Mekanizması
Dağıtık bilgi sistemlerinde saat senkronizasyonu (time synchronization), ağa bağlı tüm uç noktaların ortak bir evrensel referans zamanı (Coordinated Universal Time - UTC) temelinde mikro/milisaniyelik hassasiyetle hizalanması sürecidir. Bu süreç Network Time Protocol (NTPv4 - RFC 5905), Chrony veya Windows Time Service (w32time) gibi zaman servisleriyle yönetilir.

Saat kayması (Clock Skew / Offset), yerel donanım saatinin (Real Time Clock - RTC / Quartz kristali) sıcaklık, voltaj ve osilatör toleransları sebebiyle gerçek referans zamandan uzaklaşmasıdır.

Güvenlik mekanizmaları üzerindeki doğrudan etkileri:
1. **Kerberos ve Kimlik Doğrulama Koruması:** Kerberos kimlik doğrulama protokolü, bilet hırsızlığı ve yeniden oynatma (replay) saldırılarını engellemek için biletlere kısa ömürlü zaman damgaları (timestamp) ekler. İstemci ile KDC (Key Distribution Center) arasındaki saat farkı 5 dakikayı (300 saniye) aştığında kimlik doğrulama reddedilir (`KRB_AP_ERR_SKEW`).
2. **TLS/X.509 Sertifika Doğrulama Zinciri:** Her dijital sertifikanın `NotBefore` ve `NotAfter` geçerlilik pencereleri vardır. Yerel saatin yanlış olması; geçerli bir sertifikanın süresi dolmuş zannedilerek reddedilmesine (DoS) veya süresi dolmuş zafiyetli bir sertifikanın geçerli sayılarak ortadaki adam saldırılarına (MitM) zemin hazırlamasına neden olur.
3. **SIEM ve Olay Zaman Çizelgesi (Forensic Timeline):** Olay müdahalesinde (incident response) saldırganın hareketleri uç noktalardan toplanan logların zaman sırasına göre dizilmesiyle aydınlatılır. Zaman kayması durumunda neden-sonuç ilişkileri bozulur, adli deliller mahkemede şüpheli hale gelir.

### Soru ve Didaktik Çözüm
**Soru:** Zaman senkronizasyonu ve NTP mimarisinin temel çalışma prensibi nedir? Dağıtık kurumsal ağlarda meydana gelen saat kaymaları; kimlik doğrulama, olay analizi (SIEM/SOC) ve dijital sertifika kontrollerini nasıl etkiler?

**Didaktik Çözüm:**
NTP, istemci ile sunucu arasında gönderilen paketlerdeki dört hassas zaman damgası (T1 istemci çıkış, T2 sunucu alış, T3 sunucu çıkış, T4 istemci varış) üzerinden ağ gecikmesini ($\theta$) hesaplar ve bu gecikmeyi ayıklayarak net saat kaymasını ($\Delta$) bulur:
$$\Delta = \frac{(T_2 - T_1) + (T_3 - T_4)}{2}$$

Bu matematiksel model sayesinde ağ gecikmelerinden bağımsız olarak yerel saat disipline edilir. Saat kaymasının kritik güvenlik etkileri:
- **Kerberos Felci:** İstemci veya sunucunun NTP servisi durduğunda, donanım saati günde birkaç saniye kayar ve birkaç hafta içinde 5 dakikalık sınırı aşar. Bu durumda hiçbir Active Directory kullanıcısı oturum açamaz; dosya paylaşımları (SMB) ve etki alanı servisleri çöker.
- **SIEM Korelasyon İflası:** Örneğin bir saldırgan önce güvenlik duvarını aşmış, ardından veritabanına sızmış olsun. Veritabanı saati 30 saniye gerideyse, SOC analisti veritabanı sorgusunu güvenlik duvarı geçişinden önce gerçekleşmiş gibi görür. Saldırganın içeriye nasıl girdiği anlaşılamaz.
- **Sertifika Kırılması:** Sistem saati geride olan bir sunucu, CRL (Certificate Revocation List) veya OCSP (Online Certificate Status Protocol) yanıtlarındaki iptal edilmiş sertifikaları hala geçerli kabul edebilir.

### Savunma ve Tespit Kılavuzu
- **Tespit Komutları:**
  ```bash
  # Linux (chrony):
  chronyc tracking
  chronyc sources -v
  
  # Linux (systemd):
  timedatectl timesync-status
  
  # Windows:
  w32tm /query /status
  w32tm /query /peers
  ```
- **Savunma Stratejisi:**
  - Tüm sunucular ortak bir iç Stratum 2/3 havuzuna bağlanmalıdır.
  - Active Directory PDC Emulator, dış güvenilir zaman kaynaklarıyla (örn. `pool.ntp.org` veya GPS NTP cihazı) senkronize edilmelidir.
  - SIEM'e gönderilen tüm loglar yerel saat yerine daima **ISO 8601 UTC** formatında (`2026-10-27T11:45:00.000Z`) normalize edilmelidir.

### Usta-Çırak İpuçları ve Laboratuvar Notu
- *Usta Notu:* "Evlat, Active Directory yöneticisi sana 'Kimse domainde oturum açamıyor, tüm kullanıcılar şifre hatası alıyor ama şifreler doğru!' diyerek ağlayarak gelirse, yapacağın ilk iş Domain Controller ile istemcinin saatini karşılaştırmaktır. O 5 dakikalık Kerberos eşiği aşılmışsa dünya durur."
- *Laboratuvar İpucu:* Geliştirdiğimiz denetçi (`ntp_time_sync_auditor.py`), telemetride 345 saniyelik saat kayması tespit ettiğinde bunu doğrudan **CRITICAL** Kerberos çöküşü olarak etiketler.

---

## G038-SC2: İki Sistemli Zaman Karşılaştırma Laboratuvarı, Kontrollü Girdi ve Negatif Testler

### Temel Kavram ve Güvenlik Mekanizması
Kurumsal ortamlarda zaman senkronizasyonu asla tek bir sunucu üzerinden izole değerlendirilmez. Farklı ağ segmentlerindeki (örneğin Kurumsal Ağdaki `dc01` ile DMZ segmentindeki `app01`) makinelerin zaman durumları çapraz denetime (cross-host audit) tabi tutulmalıdır.

Güvenilir bir zaman denetim laboratuvarının mimari bileşenleri:
1. **Kontrollü Girdi (Controlled Input):** Sistem telemetrisi; her bir düğüm için hostname, saat dilimi (timezone), UTC zaman damgası, senkronizasyon bayrağı, Stratum seviyesi, offset (ms), jitter (ms) ve tanımlı üst sunucu listesini yapılandırılmış JSON şemasıyla almalıdır.
2. **Gözlenebilir Çıktı (Observable Output):** Sistem bazında detaylı bulgular, iki sistem arasındaki saat farkı ($\Delta_{\text{cross}}$), Stratum hiyerarşisi değerlendirmesi ve somut iyileştirme adımları Markdown/metin raporu olarak üretilmelidir.
3. **Olumlu ve Olumsuz Doğrulama:**
   - *Olumlu Test (Positive Control):* Sağlıklı `dc01` (Stratum 2, offset 2.1 ms, 4 üst sunucu) ile senkronizasyonunu kaybetmiş `app01` (Stratum 16, offset 345,000 ms, tek üst sunucu, monlist açık) arasındaki farklar doğru ayrıştırılmalı, sistemler arası 345 saniyelik uçurum tespit edilmelidir.
   - *Olumsuz Test (Negative Control):* Negatif Stratum (`-2`), sayısal olmayan saat kayması (`"bes_yuz"`), negatif jitter ve eksik alanlar denetçi tarafından anında reddedilmeli ve `NtpTelemetryValidationError` fırlatılmalıdır.
4. **Etik ve Operasyonel Sınırlar:** Canlı sunucularda aniden saat sıçratması (`ntpdate -b` veya `date -s`) yapılmamalıdır. Ani sıçramalar çalışan veritabanlarında kilitlenmelere ve cron işlerinde mükerrer çalışmalara yol açar; saat daima kademeli (slewing) düzeltilmelidir.

### Soru ve Didaktik Çözüm
**Soru:** Zaman senkronizasyonu ve NTP denetimi için iki bağımsız test sisteminin (Domain Controller vs DMZ Uygulama Sunucusu) saat, saat dilimi ve NTP durumunu karşılaştıran bir laboratuvarın girdisi, işlemi, beklenen çıktısı ve negatif kontrolleri nasıl modellenmelidir?

**Didaktik Çözüm:**
1. **Girdi:** `sample_ntp_telemetry.json` dosyası.
   - `dc01.corp.internal`: Windows Server, Europe/Istanbul (UTC+3), Stratum 2, offset 2.1 ms, 4 adet NTP havuzu tanımlı, NTS/Auth etkin.
   - `app01.dmz.internal`: Linux Ubuntu, UTC, Stratum 16, offset 345,000 ms (5.75 dakika geride), tek bir üst sunucu (`192.168.10.5`), monlist açık, NTS kapalı.
2. **İşlem:**
   - Şema doğrulaması (`validate_telemetry_schema`)
   - Bireysel saat kayması analizi (`audit_clock_skew_and_authentication`)
   - Stratum ve senkronizasyon kaybı analizi (`audit_stratum_and_synchronization`)
   - Üst sunucu tek hata noktası (SPOF) analizi (`audit_upstream_redundancy`)
   - Protokol güvenliği ve monlist analizi (`audit_protocol_security_and_dos`)
   - Sistemler arası zaman uyumsuzluğu karşılaştırması (`compare_multi_system_timeline`)
3. **Beklenen Çıktı:** 100 üzerinden 15 puan alan, 3 adet CRITICAL (`KRB_AP_ERR_SKEW`, Stratum 16 senkronizasyon kaybı, Çapraz sistem zaman uyumsuzluğu), 2 adet HIGH (SPOF tek sunucu, monlist DDoS) ve 1 adet MEDIUM bulgu üreten detaylı rapor.
4. **Negatif Kontroller:** `corrupted_ntp_telemetry_test_cases.json` dosyasındaki 4 bozuk senaryonun tamamının güvenle yakalanıp engellenmesi.

### Savunma ve Tespit Kılavuzu
- **Saat Dilimi Tuzakları:** Saat dilimi (timezone) sadece insan için bir görüntüleme katmanıdır (`Europe/Istanbul`, `America/New_York`). İşletim sistemi çekirdeği saati daima epoch'tan bu yana geçen mikrosaniyeler (UTC) olarak tutar. İki sunucunun saat dilimlerinin farklı olması bir hata değildir; ancak UTC zaman damgaları arasındaki fark 1 saniyeyi aşıyorsa bu bir siber güvenlik ve operasyonel arızadır.
- **Çapraz Doğrulama Komutu:**
  ```bash
  # Uzak sunucunun NTP offsetini sorgulama:
  ntpdate -q dc01.corp.internal
  chronyd -q 'server dc01.corp.internal iburst'
  ```

### Usta-Çırak İpuçları ve Laboratuvar Notu
- *Usta Notu:* "Çırak, 'Bu sunucu Amerika saatinde, şu sunucu Türkiye saatinde, o yüzden loglar uyuşmuyor' diyen acemi sistemciye kanma. Bir güvenlik uzmanı her zaman sistemin altındaki saf UTC zaman damgasına bakar. Yerel saat dilimi kullanıcı arayüzü süsüdür, çekirdeğin tek bildiği UTC'dir."
- *Laboratuvar İpucu:* Test paketimiz (`test_ntp_time_sync_auditor.py`) hem tekil saat kaymalarını hem de sistem çiftleri arasındaki farkı milisaniye hassasiyetinde test eder.

---

## G038-SC3: NTP Yapılandırma Riskleri, DDoS İstismarı (monlist) ve En Az Ayrıcalık Kuralı

### Temel Kavram ve Güvenlik Mekanizması
NTP protokolü doğası gereği UDP (port 123) üzerinden çalışır. UDP bağlantısız (connectionless) bir protokol olduğu için IP başlığındaki kaynak adres doğrulaması (handshake) yapılmaz. Bu durum iki temel saldırı sınıfına yol açar:

1. **NTP Yükseltme (Amplification) DDoS Saldırısı (monlist Zafiyeti):**
   - Eski NTP sunucularında açık olan `monlist` (Mode 6) komutu, sunucuya bağlanan son 600 istemcinin IP adreslerini listeler.
   - Saldırgan, kaynak IP adresini kurbanın IP adresi yaparak küçük bir UDP isteği atar (200 bayt).
   - NTP sunucusu kurbana 48.000 baytlık yüzlerce paket fırlatır (200x amplifikasyon).
   - Bu sunucular internette taranarak milyonlarca zombi yansıtıcı (reflector) olarak kullanılır.
2. **Yetersiz Üst Sunucu ve Marzullo Algoritması Çöküşü:**
   - NTP istemcileri doğru zamanı seçmek ve yalancı/hatalı sunucuları (false-tickers) elemek için Marzullo algoritmasını kullanır.
   - İstemciye yalnızca 1 veya 2 sunucu tanımlanırsa, bir saldırgan bu sunuculardan birini DNS Spoofing veya BGP Hijacking ile ele geçirdiğinde istemci hangi zamanın doğru olduğunu ayırt edemez. Bizans hata toleransı için **en az 3, tercihen 4 bağımsız kaynak** şarttır.
3. **Şifresiz UDP ve Ortadaki Adam (MitM) Zaman Saptırması:**
   - UDP 123 trafiği şifrelenmemişse ağdaki saldırgan zaman paketlerini tahrif ederek süresi geçmiş TLS sertifikalarını kabul ettirebilir veya log kayıtlarını geçmişe gömebilir.

### Soru ve Didaktik Çözüm
**Soru:** Zaman senkronizasyonu ve NTP servisleri bağlamında; gereksiz izinler, yanlış servisler ve hatalı bağlama yapılandırmaları ne tür riskler doğurur? Bu riskler kullanıcı, izin ve servis envanteriyle nasıl tespit edilir ve "En Az Ayrıcalık" ile "Geri Alınabilir Yapılandırma" ilkeleriyle nasıl engellenir?

**Didaktik Çözüm:**
1. **Risk Tespiti ve Envanter:**
   - **NTP Servis Envanteri:** Sistemde hangi zaman servisinin çalıştığının belirlenmesi:
     ```bash
     systemctl list-units --type=service | grep -E 'ntp|chrony|systemd-timesyncd'
     ```
     (Aynı anda iki zaman servisinin çalışması saat salınımına ve çökmeye yol açar).
   - **monlist Açıklık Taraması:**
     ```bash
     ntpdc -c monlist <hedef_ip>
     # Eğer yanıt dönüyorsa sistem DDoS amplifikatörüdür!
     ```
   - **Ağ İzinleri ve Dinleme Portu:**
     ```bash
     ss -ulnp | grep :123
     ```
     (NTP istemcisi olan bir makinenin dışarıdan gelen sorguları dinlemesine gerek yoktur).
2. **Savunma Stratejisi (En Az Ayrıcalık & Sertleştirme):**
   - **Chrony/NTP Konfigürasyonunun Sertleştirilmesi:**
     `/etc/chrony/chrony.conf` veya `/etc/ntp.conf` dosyasına şu kısıtlamalar eklenmelidir:
     ```text
     # Yalnızca yerel sorgulara izin ver, dışarıdan yönetim komutlarını yasakla:
     restrict default nomodify notrap nopeer noquery
     restrict 127.0.0.1
     restrict ::1
     disable monitor
     ```
   - **Yedekli Kaynak Tanımlama (En az 4 sunucu):**
     ```text
     server 0.tr.pool.ntp.org iburst
     server 1.tr.pool.ntp.org iburst
     server 2.tr.pool.ntp.org iburst
     server 3.tr.pool.ntp.org iburst
     ```
   - **Network Time Security (NTS) Entegrasyonu:** TLS üzerinden şifreli ve imzalı zaman doğrulaması:
     ```text
     server time.cloudflare.com iburst nts
     ```
   - **Geri Alınabilir Yapılandırma:** Konfigürasyon değişiklikleri yapılmadan önce `chrony.conf.bak.$(date +%F)` yedeği alınmalı ve `chronyc reload sources` ile kesintisiz devreye alınmalıdır.

### Savunma ve Tespit Kılavuzu
- **Sertleştirme Kontrol Listesi:**
  1. Sunucu dışarıya açık bir NTP sunucusu değilse, güvenlik duvarında UDP 123 gelen (inbound) trafiği tamamen engellenmeli; yalnızca giden (outbound) trafiğe izin verilmelidir.
  2. `disable monitor` direktifi ile `monlist` açıklarının önüne geçilmelidir.
  3. Domain Controller makinelerinde zaman kaynağı yetkili bir dış donanım/sunucuya kilitlenmelidir (`w32tm /config /manualpeerlist:... /syncfromflags:manual /reliable:yes`).
  4. Sanallaştırılmış ortamlarda (VMware/Hyper-V), konuk makinenin saat senkronizasyonu hem VM Entegrasyon Servislerinden hem de NTP'den aynı anda çekilmemelidir (Time Ping-Pong etkisi önlenmelidir).

### Usta-Çırak İpuçları ve Laboratuvar Notu
- *Usta Notu:* "Çırak, şirketinde çalışan bir sunucu hafta sonu internetteki bir hastaneye veya bankaya karşı 100 Gbps DDoS saldırısı yapmışsa ve sistem yöneticisi 'Biz kimseye saldırmadık' diyorsa, aç o sunucunun 123 portuna bak. `monlist` açık bırakılmışsa senin masum sunucun saldırganın elinde bir bazukaya dönüşmüştür."
- *Laboratuvar İpucu:* Geliştirdiğimiz denetçi, `monlist_enabled: true` gördüğü an bunu doğrudan **HIGH** seviyesinde DDoS Amplifikasyon riski olarak raporlar ve `disable monitor` reçetesini üretir.
