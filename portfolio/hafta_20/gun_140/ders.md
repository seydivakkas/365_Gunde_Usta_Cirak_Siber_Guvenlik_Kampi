<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 140: Mini Proje 19 — Bütünleşik Linux Sertleştirme ve Denetim Çerçevesi (Usta Dersi)

**Seviye:** Orta-İleri Düzey (Hafta 20 Kapanış Projesi)  
**Pedagojik Model:** Usta-Çırak / Hoca Dersi  
**Odak:** Linux Uç Nokta Güvenliğinde Katmanlı Savunma (Defense-in-Depth), CIS Linux Benchmark v2.0.0, Otomatik Denetim ve Sıkılaştırma

---

## 1. Ustanın Giriş Dersi: "Tek Bir Kilit Bir Kaleyi Koruyamaz"

> "Yaklaş çırak, Hafta 20'nin sonuna geldik. Bu hafta boyunca seninle Linux işletim sisteminin altı ayrı hayati organını tek tek ameliyat masasına yatırdık:
> 1. Sudo ile ayrıcalık devrini (Gün 134),
> 2. PAM ve oturum disiplinini (Gün 135),
> 3. Systemd servis izolasyonunu (Gün 136),
> 4. SSH anahtarlarının kriptografik gücünü (Gün 137),
> 5. Nftables/UFW ile ağ paket süzgecini (Gün 138),
> 6. Ve nihayet auditd/journald ile kurcalanamaz adli hafızayı (Gün 139).
>
> Bugün bu altı parçayı birleştirecek, kurumsal bir **Linux Sertleştirme ve Denetim Motoru** inşa edeceğiz. Unutma evlat: Güvenlik tek bir parametreden ibaret değildir. SSH'ını en güçlü eliptik eğrilerle (Ed25519) kilitlesen bile, `/etc/sudoers` dosyanda `ALL=(ALL) NOPASSWD: /bin/bash` unuttuysan sistemin kapısı ardına kadar açıktır. Ya da güvenlik duvarın kusursuz çalışsa ama çekirdeğinde rootkit yüklenmesini denetleyen audit kuralların yoksa, içeri bir kez sızan saldırgan seni karanlıkta bırakır.
>
> İşte bu yüzden bir güvenlik mühendisi, tek tek ağaçlara değil, bütün ormana bakar. Bu projede hedefimiz; bir sunucunun konfigürasyonunu saniyeler içinde analiz edip 100 üzerinden uyumluluk notunu çıkaran ve eksikleri tek bir Bash betiğiyle onaran profesyonel bir çerçeve kurmaktır."

---

## 2. Linux Sertleştirme Çerçevesinin 6 Temel Katmanı

Bir kurumsal Linux sunucusunun sertleştirilmesi (OS Hardening), CIS (Center for Internet Security) ve NIST standartlarında birbirini tamamlayan 6 savunma katmanından oluşur:

```
+-------------------------------------------------------------------------+
| KATMAN 1: GÜVENLİK DUVARI (Netfilter / nftables / UFW)                   |
| -> Varsayılan DROP politikası, Durumlu paket takibi (Conntrack),        |
|    Loopback anti-spoofing, Gereksiz/düz metin portların kapatılması     |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| KATMAN 2: UZAKTAN ERİŞİM VE KRİPTOGRAFİ (OpenSSH Daemon)                |
| -> PermitRootLogin no, PasswordAuthentication no, Ed25519 / RSA >= 3072 |
|    Dosya izinleri: 0600 (özel anahtarlar), 0700 (.ssh dizini)           |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| KATMAN 3: KİMLİK VE OTURUM DİSİPLİNİ (PAM / faillock / pwquality)       |
| -> minlen >= 14, dcredit/ucredit/ocredit/lcredit <= -1,                 |
|    deny <= 5, unlock_time >= 900s, TMOUT <= 900s                        |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| KATMAN 4: EN DÜŞÜK AYRICALIK VE YETKİ DEVRİ (Sudoers)                   |
| -> /etc/sudoers izin 0440, env_reset, secure_path,                      |
|    GTFOBins kabuk kaçış komutlarına NOPASSWD yasağı                     |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| KATMAN 5: SERVİS İZOLASYONU VE KUM HAVUZU (Systemd Sandboxing)          |
| -> Yasaklanmış servisler yok (telnet, vsftpd, cups),                    |
|    NoNewPrivileges=yes, ProtectSystem=strict, PrivateTmp=yes            |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| KATMAN 6: ADLİ BÜTÜNLÜK VE DENETİM (Kernel Auditd & Journald FSS)       |
| -> -e 2 (immutable çekirdek kilidi), Kritik dosya saat/modül izleme,   |
|    systemd-journald Forward Secure Sealing (FSS) kriptografik mühürleme |
+-------------------------------------------------------------------------+
```

---

## 3. Katmanların Derinlemesine İncelenmesi

### 3.1. Katman 1: Güvenlik Duvarı (Ağ Süzgeci)
Sistemin dış dünya ile ilk temas noktasıdır. CIS 3.4 standardına göre:
- **Varsayılan Giriş ve Yönlendirme Politikası DROP:** İzin verilmeyen her paket sessizce düşürülmelidir.
- **Durumlu Bağlantı Filtresi (Conntrack):** `ct state established,related accept` kuralı ile yalnızca sunucunun başlattığı veya meşru kabul edilmiş oturumların yanıt paketlerine geçit verilir. `invalid` durumundaki tüm paketler anında imha edilir.
- **Açık Port Denetimi:** Telnet (23), FTP (21), TFTP (69) gibi şifresiz eski protokoller derhal kapatılmalıdır.

### 3.2. Katman 2: SSH ve Kriptografik Erişim Kontrolü
Sunucuya uzaktan yönetim kapısıdır. CIS 5.2 direktifleri:
- `PermitRootLogin no`: Saldırganın root hesabı üzerinden kaba kuvvet (brute-force) denemesi yapmasını baştan engeller. Yönetici önce kendi adıyla giriş yapmalı, ardından sudo kullanmalıdır.
- `PasswordAuthentication no`: Parola saldırılarını imkansız hale getirir; yalnızca asimetrik anahtarlara izin verilir.
- `Dosya İzinleri (0600)`: Özel anahtar dosyası (`id_ed25519`) yalnızca sahibi tarafından okunabilir olmalıdır. Başka kullanıcıların okuyabilmesi anahtarın ele geçirilmesi demektir.

### 3.3. Katman 3: PAM ve Oturum Yönetimi
Kimlik doğrulama omurgasıdır (Pluggable Authentication Modules).
- `pam_pwquality`: Parola entropisini garanti altına alır (en az 14 karakter, 4 farklı karakter kümesi).
- `pam_faillock`: Art arda 5 hatalı denemede hesabı 15 dakika (900 saniye) kilitler.
- `TMOUT=900`: Masasından kalkan yöneticinin açık kalan terminal oturumunu 15 dakika içinde otomatik olarak sonlandırarak fiziksel yetkisiz erişimi engeller.

### 3.4. Katman 4: Sudoers ve En Düşük Ayrıcalık Devri
- `/etc/sudoers` dosyasının izinleri `0440` olmalı ve yalnızca `visudo` ile düzenlenmelidir.
- `Defaults env_reset`: Saldırganın `LD_PRELOAD` veya `PYTHONPATH` gibi ortam değişkenlerini manipüle ederek paylaşımlı kütüphane enjeksiyonu yapmasını engeller.
- **GTFOBins Koruması:** `NOPASSWD: /bin/bash`, `NOPASSWD: vim` veya `NOPASSWD: find` gibi izinler, doğrudan `sudo -l` üzerinden saniyeler içinde yetki yükseltmeye (privilege escalation) olanak tanır; kesinlikle yasaklanmalıdır.

### 3.5. Katman 5: Systemd Kum Havuzu (Sandboxing)
Çalışan bir servisin (örneğin Nginx veya özel bir API) web zafiyeti (RCE/SQLi) üzerinden ele geçirilmesi durumunda işletim sistemini koruyan emniyet kemeridir:
- `NoNewPrivileges=yes`: Süreç içinden SUID bitine sahip ikililerin çalıştırılarak root yetkisine sıçranmasını imkansız kılar (`PR_SET_NO_NEW_PRIVS`).
- `ProtectSystem=strict`: `/usr`, `/boot` ve `/etc` dizinlerini servise salt-okunur (read-only) bağlar.
- `PrivateTmp=yes`: `/tmp` dizinini izole bir ad alanına (namespace) alarak süreçler arası dosya sızıntılarını önler.

### 3.6. Katman 6: Adli Bütünlük (Auditd & Journald FSS)
Saldırı anında ve sonrasında gerçeğin kaydedilmesini sağlar:
- `auditd -e 2`: Çekirdek denetim kurallarını dondurur. Root yetkisindeki saldırgan dahi kuralları silemez veya servisi durduramaz.
- `watched_files`: `/etc/shadow`, `/etc/passwd`, `/etc/sudoers` dosyalarına dokunan her süreç anında AUID ve PID bilgisiyle loglanır.
- `journald Seal=yes`: Forward Secure Sealing (FSS) sayesinde loglar geriye dönük tahrifata karşı kriptografik olarak mühürlenir.

---

## 4. Denetim Puanlama Algoritması (Scoring Engine)

Geliştirdiğimiz denetim motoru (`linux_hardening_audit_engine.py`), sistemi 6 bağımsız güvenlik alanına böler ve ağırlıklı puan hesaplar:

$$\text{Genel Uyumluluk Puanı} = \frac{1}{6} \sum_{i=1}^{6} \text{Domain Skor}_i$$

Her alan içinde icra edilen kontrollerin ağırlığı:
- **Kritik (CRITICAL) Zafiyet:** Sudoers 0777 izni, NOPASSWD /bin/bash, Root SSH açık, Firewall devre dışı, Audit -e 2 eksik. Bu kontrollerden biri dahi başarısız olursa sistem `NON-COMPLIANT` veya `AT_RISK` seviyesine düşer.
- **Yüksek (HIGH) Zafiyet:** Parola uzunluğu < 14, Conntrack kapalı, Özel anahtar izni > 0600.
- **Orta (MEDIUM) Zafiyet:** Oturum boşta kalma süresi yüksek, MaxAuthTries yüksek.

Sistem ancak **%90 ve üzerinde genel uyumluluk puanına** sahip olduğunda ve **hiçbir FAIL kontrolü bulunmadığında** `COMPLIANT (UYUMLU)` olarak nitelendirilir.

---

## 5. Çırağa Öğütler ve Saha Deneyimi

> "Çırak, sahada iki tip sistem yöneticisi görürsün:
> 1. Birincisi 'Sistem çalışıyor ya, kurcalamayalım' diyenlerdir. Bir gün fidye yazılımı (ransomware) veya veri sızıntısıyla uyandıklarında ne audit logu bulabilirler ne de saldırganın nereden girdiğini anlarlar.
> 2. İkincisi ise bu projede geliştirdiğimiz gibi otomatize denetim araçlarıyla her gece sunucularını tarayan, konfigürasyon sapmalarını (configuration drift) anında tespit edip otomatik düzelten profesyonellerdir.
>
> Sen ikinci yoldan yürüyeceksin. Her zaman kodunu test et, her zaman kanıtını topla ve mühürlü kayıtlardan asla ödün verme!"
