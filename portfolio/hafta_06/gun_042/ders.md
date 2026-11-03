# G042 — Aşama 2 Kalite Özeti ve Kapanışı: İşletim Sistemi Temelleri

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

---

## 1. Giriş ve Usta-Çırak Aşama Kapanış Sohbeti

> **Usta:**  
> *"Evlat, bugün arkana dönüp bir bakmanı istiyorum. Tam 14 gündür (Gün 29'dan Gün 42'ye kadar) siber güvenliğin en kritik, en vazgeçilmez temelini inşa ettin: **İşletim Sistemi Güvenliği**.  
> Çoğu acemi hemen port taramaya, exploit fırlatmaya veya web sitesi kırmaya heves eder. Ama o exploit'in hedefte neyi tetiklediğini, bellekte nasıl yerleştiğini, hangi süreç yetkisiyle çalıştığını ve hangi log dosyasında iz bıraktığını bilmeyen biri asla gerçek bir siber güvenlik uzmanı olamaz.  
> Sen bu 14 günde; Linux ve Windows sanal makinelerinin ağ sınırlarını çizdin (G029-G030), dosya izinlerinin ve umask matematiğinin inceliklerini öğrendin (G031), süreçleri ve sinyalleri yönettin (G032), kullanıcı ve grup yetkilerini sınırlandırdın (G033), systemd servislerini kum havuzuna aldın (G034), syslog ve auditd ile çekirdek seviyesinde loglama yaptın (G035), bellek ve swap güvenliğini sağladın (G036), diskleri ve dosya sistemlerini inceledin (G037), zaman senkronizasyonu ile log korelasyonunu garantiye aldın (G038), 3-2-1 kuralıyla yedekleme yaptın (G039), uzaktan yönetimi kilitledin (G040) ve dün 10 göstergeyle Windows ve Linux'u objektif olarak karşılaştırdın (G041).  
> Bugün ise Aşama 02'nin resmi **Kalite Kapısındayız (Quality Gate)**. 6 ana sütun üzerinden kör kontrol listesiyle yeni bir sanal makinenin tüm envanterini denetleyecek, salt-okunur delillerle Aşama 2 Kabul Kararını (STAGE_02_PASS) mühürleyeceğiz."*

---

## 2. Aşama 02'nin 6 Temel Kabul Sütunu

Aşama 2 boyunca edinilen tüm bilgi ve beceriler, bağımsız bir sistemin üretim ortamına çıkabilmesi için 6 sütun altında standartlaştırılmıştır:

```
               [AŞAMA 2 KABUL VE KALİTE SÜTUNLARI]
 1. Süreç Hijyeni (Process Hygiene)       -> Unprivileged Daemons & Sıfır Rogue Süreç
 2. Dosya İzinleri & Umask                -> 0027 Umask, /etc/shadow 0640, /etc/sudoers 0440
 3. Olay Günlükleme (Security Logging)    -> journald Kalıcı, auditd Aktif, SIEM TLS İletim
 4. Bütünlük Karmaları (Integrity Hashes) -> SHA-256 Taban Çizgisi & Değişiklik Tespiti
 5. Yedekleme Stratejisi (Backup 3-2-1)   -> 3 Kopya, 2 Ortam, 1 Dış Lokasyon, Test: PASS
 6. Servis Hardening (Service Isolation)  -> Miras Servis Yasağı, SSH Root & Parola Engeli
```

---

## 3. Sütunların Ayrıntılı Didaktik Değerlendirmesi

### Sütun 1: Süreç Hijyeni ve Yetki Dağılımı
- **Teorik Mekanizma:** İşletim sisteminde çalışan her süreç (process) bir kullanıcı kimliğine (UID/GID) ve yetki kümesine (Linux Capabilities / Windows Token Privileges) sahiptir. Bir ağ servisinin (örneğin web sunucusu veya DNS) `root` yetkisiyle çalışması, o serviste çıkacak tek bir bellek taşması zafiyetinde saldırgana doğrudan sistemin tam kontrolünü verir.
- **Kabul Standardı:** Arka plan servisleri ayrık kullanıcılarla (`systemd-network`, `syslog`, `chrony`, `www-data`) ve systemd kum havuzlama yönergeleriyle (`ProtectSystem=strict`, `PrivateTmp=true`, `NoNewPrivileges=true`) çalışmalıdır. Sistemde yetkisiz veya meşruiyeti belgelenmemiş arka kapı/ters kabuk süreçleri kesinlikle bulunmamalıdır.

### Sütun 2: Dosya İzinleri ve Umask Sağlamlığı
- **Teorik Mekanizma:** POSIX izin modeli ve umask maskesi, sistemde yeni oluşturulan dosyaların varsayılan erişim sınırlarını belirler. Umask'ın gevşek olması (`0022` yerine `0002` gibi), yerel kullanıcıların birbirlerinin verilerini okumasına veya değiştirmesine yol açar.
- **Kabul Standardı:** Sistem genelinde umask değeri en az `0027` (diğer kullanıcılar için sıfır izin) olmalıdır. Kritik dosyaların izinleri tavizsizdir:
  - `/etc/shadow`: `0640` (Sahip: root, Grup: shadow)
  - `/etc/passwd`: `0644` (Sahip: root, Grup: root)
  - `/etc/sudoers`: `0440` (Yalnızca root ve sudo grubu salt okunur)
  - `/etc/ssh/sshd_config`: `0600` (Yalnızca root okur/yazar)

### Sütun 3: Güvenlik Olay Günlükleme ve İzlenebilirlik
- **Teorik Mekanizma:** Bir sistemde saldırı gerçekleştikten sonra faili tespit etmenin, saldırı vektörünü anlamanın ve yasal delil oluşturmanın tek yolu adli günlüklerdir. Ancak saldırganlar girdikleri sistemde ilk iş olarak yerel logları temizler (`rm -rf /var/log/*`).
- **Kabul Standardı:** `systemd-journald` mutlaka kalıcı depolama modunda (`Storage=persistent`) yapılandırılmalı; `auditd` çekirdek denetim motoru aktif edilerek kritik sistem çağrıları (file write, execve) izlenmeli; ve en önemlisi tüm loglar ağ üzerinden şifreli (TLS) olarak harici bir SIEM sunucusuna anlık olarak kopyalanmalıdır.

### Sütun 4: Kritik Dosya ve Yapılandırma Bütünlük Karmaları
- **Teorik Mekanizma:** Saldırganlar sistemde kalıcılık sağlamak (persistence) için genellikle sistem ikililerini Truva Atı (Trojan) haline getirir (örneğin `/bin/login` veya `/usr/bin/sudo` dosyalarını değiştirerek sahte şifre kaydedici yerleştirmek).
- **Kabul Standardı:** Sistem kurulduğu an temiz referans dosyalarının kriptografik SHA-256 karmaları alınmalı ve salt-okunur bir taban çizgisi (baseline) oluşturulmalıdır. Günlük veya saatlik denetimlerle dosyaların karmaları karşılaştırılmalı; en ufak bir bit sapmasında kırmızı alarm üretilmelidir.

### Sütun 5: Yedekleme Stratejisi ve 3-2-1 Kuralı Doğrulaması
- **Teorik Mekanizma:** Ransomware (Fidye Yazılımı) saldırılarının nihai hedefi, kurbanın yedeklerini de şifreleyerek fidye ödemesini zorunlu kılmaktır. Test edilmemiş ve yerel diskte tutulan bir yedek, gerçek bir yedek değildir.
- **Kabul Standardı:** 3-2-1 Kuralı eksiksiz işletilmelidir:
  - En az 3 kopya (1 orijinal veri + 2 yedek).
  - En az 2 farklı depolama ortamı (Disk + Bulut / Manyetik Bant).
  - En az 1 dış lokasyon (Offsite / Air-gapped / Immutable depolama).
  - Periyodik geri yükleme tatbikatı yapılmalı ve son test durumu `PASS` olarak belgelenmelidir.

### Sütun 6: Servis Yönetimi ve Güvensiz Miras Servis Yasağı
- **Teorik Mekanizma:** Ağ üzerinde açık duran her gereksiz port, saldırgan için potansiyel bir giriş kapısıdır. Özellikle açık metin aktarım yapan miras servisler (Telnet, RSH, Rlogin, FTP, TFTP) kimlik bilgilerinin ağ dinleme (sniffing) ile çalınmasına zemin hazırlar.
- **Kabul Standardı:** Tüm miras güvensiz protokoller sistemden tamamen kaldırılmalıdır (`purged`). Uzaktan yönetim yalnızca sıkılaştırılmış SSH üzerinden yapılmalı; `PermitRootLogin no` ve `PasswordAuthentication no` kurallarıyla parola tabanlı oturum açma tamamen yasaklanarak Ed25519 açık anahtar doğrulaması şart koşulmalıdır.

---

## 4. Aşama 2 Kabul Kararı: STAGE_02_PASS

Geliştirdiğimiz `stage2_os_foundations_auditor.py` motoru; sentetik VM envanterini 6 sütunun her biri için ayrı ayrı denetlemiş ve şu sonuçları üretmiştir:
- Süreç Hijyeni: 100.0 / 100
- Dosya İzinleri ve Umask: 100.0 / 100
- Olay Günlükleme: 100.0 / 100
- Bütünlük Karmaları: 100.0 / 100
- Yedekleme (3-2-1): 100.0 / 100
- Servis Hardening: 100.0 / 100
- **AŞAMA 2 GENEL KALİTE SKORU:** **100.0 / 100.0 (PASS)**

---

## 5. Aşama 03'e Geçiş ve Usta-Çırak Nasihati

> **Usta Diyor ki:**  
> *"Tebrikler evlat! Aşama 02'yi alnının akıyla, sıfır eksikle ve tam puanla tamamladın.  
> Artık tek bir sunucunun nasıl nefes aldığını, nasıl çalıştığını ve nasıl korunduğunu biliyorsun.  
> Önümüzdeki hafta (Hafta 07) **Aşama 03: Ağ Temelleri ve Ağ Güvenliği** başlıyor. Artık tek bir kutunun içinden çıkıp, o kutuların birbiriyle konuştuğu kablolara, paketlere, TCP/IP bayraklarına, yönlendiricilere ve güvenlik duvarlarına ineceğiz.  
> İşletim sistemi zeminini unutma; çünkü ağdaki her paketin arkasında çalışan bir işletim sistemi süreci vardır!"*
