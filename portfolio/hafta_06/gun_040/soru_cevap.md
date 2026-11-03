# G040 — Güvenli Uzaktan Yönetim Başlangıcı: Soru ve Çözüm Analizleri

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

---

## [G040-SC1] Uzaktan Yönetim Protokollerinde Üçlü Güvenlik Sacayağı: Kimlik Doğrulama, Ağ Sınırı ve Kapsamlı Günlükleme

### Temel Kavram ve Güvenlik Mekanizması
Kurumsal BT ve siber güvenlik altyapılarında sunucu ve ağ cihazlarının uzaktan idare edilmesi kaçınılmaz bir operasyonel zorunluluktur. Ancak uzaktan yönetim arayüzleri (SSH, RDP, WinRM, Web GUI), saldırganlar için sisteme doğrudan kabuk (shell) veya konsol erişimi sağlayan en kritik saldırı yüzeyleridir (Attack Surface).

Bir uzaktan yönetim mimarisinin güvenliği, birbirini tamamlayan üç temel güvenlik mekanizmasının eksiksiz işletilmesine bağlıdır:
1. **Kimlik Doğrulama (Authentication & Authorization):** Statik parola kullanımının kesinlikle terk edilerek Ed25519 gibi modern açık/gizli anahtar çiftleri (Public Key Authentication), donanımsal belirteçler (FIDO2/WebAuthn) veya sertifika tabanlı SSH-CA mekanizmalarıyla güçlendirilmesi. Ayrıca uzaktan erişim oturumuna çok faktörlü kimlik doğrulama (MFA) zorunluluğunun getirilmesi.
2. **Ağ Sınırı ve İzolasyonu (Network Boundary & Segmentation):** Yönetim portlarının (TCP 22 SSH, TCP 3389 RDP vb.) hiçbir koşulda genel internete (0.0.0.0/0) doğrudan açılmaması. İdari erişimin bir Bastion Host (Atlama Sunucusu), IPsec/WireGuard VPN tünelleri veya Sıfır Güven Ağ Erişimi (ZTNA - Zero Trust Network Access) ağ geçitleri arkasında sınırlandırılması; kaynak IP filtreleme ve yönetim VLAN'ı (OOBM - Out-of-Band Management) mimarisine tabi tutulması.
3. **Kapsamlı ve Dışarıya Aktarılmış Günlükleme (Auditing & Centralized Logging):** Oturum açma girişimlerinin (başarılı ve başarısız), tünelleme hareketlerinin, çalıştırılan komutların ve oturum sürelerinin `auditd`, `sshd` `VERBOSE` logları veya Windows Güvenlik Olay Günlükleri (Event ID 4624, 4625, 4672) ile anlık olarak kaydedilmesi. Logların yerel diskte değiştirilmesini önlemek amacıyla anında bir SIEM/Syslog sunucusuna şifreli aktarılması.

---

### Soru ve Didaktik Çözüm
**Soru:**  
Bir kurumda Linux ve Windows sunucuların uzaktan yönetimi planlanmaktadır. Neden doğrudan internete açık portlarla parola tabanlı uzaktan erişim kabul edilemez bir mimari zaafiyettir? Kimlik doğrulama, ağ sınırı ve günlükleme adımlarının her birinde uygulanması gereken sıkılaştırma (hardening) kuralları nelerdir?

**Didaktik Çözüm:**  
- **İnternete Açık Servis Tehdidi:** Parola tabanlı SSH ve RDP doğrudan genel internete maruz bırakıldığında, dakikada yüzlerce botnet tarafından kaba kuvvet (brute-force) ve kimlik bilgisi doldurma (credential stuffing) saldırılarına maruz kalır. Üstelik protokol düzeyinde veya servis yazılımında (örneğin OpenSSH regreSSHion veya RDP BlueKeep) oluşabilecek bir Sıfır-Gün (0-day) uzaktan kod yürütme (RCE) açığında, hiçbir ek güvenlik katmanı olmadığı için saldırgan doğrudan hedef sistemin kök (root/SYSTEM) haklarına erişir.
- **Sıkılaştırma Kuralları:**
  1. *Kimlik Doğrulama Katmanı:* `/etc/ssh/sshd_config` içinde `PasswordAuthentication no`, `PermitRootLogin no`, `PubkeyAuthentication yes` yapılandırılır. RDP tarafında ise "Ağ Düzeyinde Kimlik Doğrulama" (NLA - Network Level Authentication) zorunlu kılınarak oturum açma penceresi dahi yüklenmeden önce Kerberos/NTLM el sıkışması istenir.
  2. *Ağ Sınırı Katmanı:* SSH ve RDP portları yalnızca şirket içi Yönetim VPN'inden (`10.50.0.0/24`) veya Bastion Host IP'sinden erişilebilir yapılır. `nftables`/`iptables` veya Windows Defender Güvenlik Duvarı ile `0.0.0.0/0` kuralı tamamen engellenir (`DROP`).
  3. *Günlükleme Katmanı:* SSH `LogLevel VERBOSE` seviyesine çekilir. Windows tarafında GPO ile "Gelişmiş Denetim İlkesi Yapılandırması" (Advanced Audit Policy) altındaki "Oturum Açma Olayları" ve "İşlem Oluşturma Olayları (Event ID 4688 ve Komut Satırı Günlükleme)" aktif edilir. Tüm loglar Syslog-ng veya Winlogbeat aracılığıyla SIEM havuzuna iletilir.

---

### Savunma ve Tespit Kılavuzu
- **Tespit Mekanizmaları:**
  - `ss -tlpn | grep -E ':(22|3389)'`: Dinleyen servislerin `0.0.0.0` (tüm arayüzler) yerine yalnızca belirli bir yerel yönetim IP'sine mi bağlı olduğunu periyodik olarak kontrol edin.
  - Fail2ban veya CrowdSec gibi saldırı tespit/önleme ajanları çalıştırarak belirli sayıda hatalı oturum açma girişiminde bulunan kaynak IP'leri otomatik olarak güvenlik duvarında bloklayın.
  - `/var/log/auth.log` veya `journalctl -u ssh`: `Failed password for ...` ve `Accepted publickey for ...` desenlerini SIEM üzerinde korelasyona tabi tutun. Sıra dışı saatlerde gelen ve coğrafi IP uyuşmazlığı gösteren erişimleri anlık uyarıya dönüştürün.
- **Savunma Stratejisi (Defense-in-Depth):**
  - Uzaktan erişim servislerini doğrudan uç makinelere dağıtmak yerine tekil, yalıtılmış ve oturum kaydı alan (session recording - örn. Apache Guacamole, Teleport veya CyberArk) ara denetçiler üzerinden geçirin.
  - SSH üzerinde X11 Forwarding, Agent Forwarding ve gereksiz TCP tünelleme izinlerini (`AllowAgentForwarding no`, `AllowTcpForwarding no`, `X11Forwarding no`) kısıtlayarak zıplama noktalarının pivot amacıyla suistimal edilmesini engelleyin.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, bir güvenlik denetçisi olarak bir şirketin ağında 22 ya da 3389 portunu dış dünyaya açık gördüğün an, orası 'girilmek üzere olan bir kaledir'. 'Benim parolam 30 karakter, kıramazlar' diyene güvenme. Servisin kendisinde bellek taşması (memory corruption) çıkar, kimlik doğrulamayı bypass ederler. Güvenlik, tek bir kaleye güvenmek değil, kapıları katman katman kilitlemektir. Önce VPN tünelini aşacak, sonra Bastion üzerinde donanımsal anahtarıyla doğrulanacak, en son hedef makinede salt okunur kısıtlı kullanıcıyla işini görüp sudo ile komut çalıştıracak; o komut da merkezi SIEM ekranına düşecek."*

---

## [G040-SC2] Uzaktan Erişim Yetkilendirme Matrisi ve Programatik Denetim Mimarisi

### Temel Kavram ve Güvenlik Mekanizması
Kurumsal ağlarda onlarca farklı sunucu rolü (veritabanı, etki alanı denetleyicisi, web sunucusu, geliştirme ortamı) bulunur. Hangi sistem yöneticisinin veya destek uzmanının hangi sunucuya, hangi protokol aracılığıyla, hangi ağ segmentinden ve hangi güvenlik koşulları altında erişebileceğini belirleyen resmi dokümana **"Uzaktan Erişim Matrisi" (Remote Access Authorization Matrix)** denir.

Güvenli bir matris modelinde şu unsurlar açıkça tanımlanır:
- Servis Adı ve Protokol Tipi (SSH, RDP, HTTPS API).
- Standart / Özel Port Numarası.
- İzin Verilen Kaynak Ağ Segmenti (CIDR / Bastion IP).
- Kimlik Doğrulama Yöntemi (Public Key, MFA, Kerberos).
- Oturum Kayıt ve Günlükleme Politikası (Session Recording / Central Syslog).
- İzin Durumu ve İş Gerekçesi (Business Justification).

Bu matrisin statik bir Excel tablosunda kalması yetersizdir; CI/CD ve güvenlik otomasyonu boru hatlarında Python tabanlı denetim ajanları ile JSON şemaları üzerinden sürekli doğrulanmalı ve standart dışı (örneğin açık metin Telnet, internete doğrudan açık RDP, kök kullanıcı izinli SSH) yapılandırmalar otomatik tespit edilip reddedilmelidir.

---

### Soru ve Didaktik Çözüm
**Soru:**  
Bir kurumun yerel ağında uzaktan yönetim servislerinin güvenliğini denetleyecek bir otomasyon aracı geliştiriyorsunuz. Bu araç girdi olarak sunulan matris verisini nasıl doğrulamalı, hangi olumlu ve olumsuz test senaryolarından geçmeli ve etik/operasyonel sınırları ne olmalıdır?

**Didaktik Çözüm:**  
- **Kontrollü Girdi ve Şema Doğrulaması:**
  Geliştirilen denetim motoru (`secure_remote_management_auditor.py`), JSON formatındaki servis girdilerini doğrular. Her servis için:
  - Servis adı boş bırakılamaz.
  - Port numarası 1 ile 65535 arasında geçerli bir tam sayı olmak zorundadır (negatif sayılar veya stringler `ValueError` ile yakalanmalıdır).
  - İzin verilen kaynak ağ (CIDR) tanımlı olmalıdır; `0.0.0.0/0` (tüm internet) görüldüğü an yüksek riskli ihlal alarmı üretilmelidir.
  - Açık metin aktarım yapan güvensiz protokoller (Telnet TCP 23, FTP TCP 21, HTTP TCP 80 yönetim arayüzleri) derhal kural dışı kabul edilip kritik zaafiyet olarak etiketlenmelidir.
- **Olumlu ve Olumsuz Doğrulama:**
  - *Olumlu Test:* Standart Bastion IP'sinden gelen, Ed25519 anahtarı ve MFA zorunlu tutulmuş, merkezi syslog'a bağlı SSH servisi 100/100 tam uyumluluk puanı alır.
  - *Olumsuz Test (Negatif Kontrol):* Bozunmuş JSON dosyaları, geçersiz portlar (örneğin port 999999 veya port -1), eksik parametreler ve string içeren port alanları test suite tarafından yakalanarak sistemin çökmesi (crash) engellenir ve zararsız hata mesajı üretilir.
- **Etik ve Operasyonel Sınır:**
  Denetim aracı yerel yapılandırma dosyalarını ve matris politikalarını pasif olarak okur ve simüle eder; asla hedef sistemlere yetkisiz paket göndermez, aktif port taraması (SYN scan) veya kaba kuvvet denemesi yapmaz. Bu sayede üretim bandındaki sistemlerin kararlılığı bozulmaz ve KVKK/etik kurallar ihlal edilmez.

---

### Savunma ve Tespit Kılavuzu
- **Yetkilendirme Matrisi Uygulama Adımları:**
  1. **Envanter Çıkarma:** Ağdaki tüm dinleyen yönetim servislerini listeleyin (`nmap -sS -p 22,3389,5985,5986 --open 10.0.0.0/16`).
  2. **Matris Eşleme:** Tespit edilen her açık portu iş ihtiyacı ve onaylı sistem yöneticisi listesiyle eşleştirin.
  3. **Güvenlik Duvarı Kuralı Üretimi:** Matristeki CIDR ve port kuralını doğrudan güvenlik duvarı nesnesine dönüştürün. Örnek `iptables` kuralı:
     ```bash
     iptables -A INPUT -p tcp -s 10.50.0.10 --dport 22 -j ACCEPT
     iptables -A INPUT -p tcp --dport 22 -j DROP
     ```
  4. **Kural İhlali Alarmı:** Denetim ajanının JSON matrisini periyodik olarak okuyup, yetkisiz IP/protokol tespit ettiğinde anında Slack/Teams veya SIEM webhook'una ihlal bildirimi göndermesini sağlayın.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, kod yazarken 'Kullanıcı bana her zaman doğru veri verir' dersen, ilk hacker'ın ilk hatalı paketinde yazılımın çöker. Bizim bugün geliştirdiğimiz `secure_remote_management_auditor.py` modülündeki `validate_remote_access_entry()` fonksiyonuna iyi bak. Port string mi gelmiş? Negatif mi gelmiş? Zorunlu alanlar var mı? Hepsini tek tek sınıyoruz. Siber güvenlikte savunma kodu, saldırı kodundan daha dayanıklı olmak zorundadır. İşte bu yüzden negatif testlerimiz (14/14 PASS) bize gerçek mühendislik güvencesi verir."*

---

## [G040-SC3] Uzaktan Erişimde Risk Analizi: Gereksiz İzinler, Yanlış Servisler ve Geri Alınabilir Yapılandırma

### Temel Kavram ve Güvenlik Mekanizması
Uzaktan yönetim altyapılarında meydana gelen veri sızıntılarının büyük çoğunluğu, karmaşık sıfır-gün açıklarından ziyade **"Yanlış Yapılandırma" (Misconfiguration)** ve **"Aşırı Tanımlanmış Yetkiler" (Over-Privileged Access)** nedeniyle gerçekleşir.

Bu kapsamdaki başlıca risk desenleri şunlardır:
1. **Gereksiz İzinler:** Bir sistem yöneticisinin rutin görevleri için kök kullanıcı (`root` veya `Domain Admin`) hesabı üzerinden oturum açması; `sudo` yetkilerinin parola sormadan tüm komutlara (`ALL=(ALL) NOPASSWD: ALL`) verilmesi.
2. **Yanlış Servisler:** Hızlı sorun çözmek veya geçici test amacıyla kurulan ancak unutulan VNC, TeamViewer, AnyDesk, Telnet veya şifresiz HTTP yönetim panellerinin aktif bırakılması.
3. **Geri Alınamaz Değişiklikler:** Canlı sistemlerde yapılan yapılandırma değişikliklerinin (örneğin `/etc/ssh/sshd_config` düzenlemesi) yedek alınmadan ve otomatik geri alma (rollback) mekanizması kurulmadan uygulanması; bir hata anında tüm yöneticilerin sunucunun dışında kalarak (lockout) hizmet kesintisine yol açması.

---

### Soru ve Didaktik Çözüm
**Soru:**  
Bir kurumda uzaktan yönetim altyapısında "Gereksiz izin, yanlış servis ve hatalı yapılandırma" risklerini tespit etmek ve önlemek için nasıl bir kullanıcı/izin/servis envanteri ve fark analizi raporu kurulmalıdır? En az ayrıcalık ve geri alınabilir yapılandırma ilkeleri pratikte nasıl işletilir?

**Didaktik Çözüm:**  
- **Kullanıcı, İzin ve Servis Envanteri Çıkarma:**
  - *Servis Envanteri:* `systemctl list-unit-files --state=enabled` ve `ss -tulpn` komutlarıyla aktif ve başlangıçta çalışan servisler listelenir. Telnet (`telnetd`), rsh, rlogin, vsftpd gibi güvensiz miras servisler tespit edilir edilmez kaldırılır (`apt purge / yum remove`).
  - *Kullanıcı ve İzin Envanteri:* `/etc/passwd` dosyasında geçerli bir kabuğa (`/bin/bash`) sahip kullanıcılar ve `/etc/sudoers` ile `/etc/sudoers.d/*` dosyalarındaki yöneticilik yetkileri taranır. SSH anahtar dosyaları (`~/.ssh/authorized_keys`) denetlenerek kimliği belirsiz veya süresi dolmuş anahtarlar ayıklanır.
- **Fark Raporu (Drift Analysis):**
  - Güvenli onaylı ana hat (Golden Baseline) yapılandırma dosyası ile canlı sistemdeki mevcut yapılandırma düzenli olarak karşılaştırılır (`diff -u`).
  - Onaylanmamış bir port açıldığında, yeni bir kullanıcı `sudo` grubuna eklendiğinde veya `sshd_config` içinde `PermitRootLogin yes` yapıldığında fark analizi derhal kırmızı bayrak (Red Flag) üretir.
- **En Az Ayrıcalık (Least Privilege) ve Geri Alınabilir Yapılandırma (Rollback):**
  - *En Az Ayrıcalık:* Sistem yöneticilerine doğrudan `root` hesabı verilmez. Görev odaklı `sudo` kuralları yazılır (örneğin yalnızca Nginx yeniden başlatma: `%webadmin ALL=(ALL) /bin/systemctl restart nginx`).
  - *Geri Alınabilirlik:* SSH yapılandırması değiştirildiğinde servis yeniden başlatılmadan önce `sshd -t` komutu ile sentaks testi yapılır. Ayrıca `ansible` veya `bash` otomasyonlarında geçici bir zamanlayıcı (`sleep 300 && cp /backup/sshd_config /etc/ssh/sshd_config && systemctl reload ssh`) kullanılarak olası bir kilitlenme durumunda sistemin kendini otomatik olarak eski güvenli yapılandırmaya döndürmesi sağlanır.

---

### Savunma ve Tespit Kılavuzu
- **Tespit ve Denetim Komutları:**
  - SSH anahtarlarının yetki seviyelerini doğrulayın: `chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys`. Yanlış izinler OpenSSH tarafından doğrudan reddedilir (`StrictModes yes`).
  - `sudo` ihlallerini ve şüpheli komutları takip edin:
    ```bash
    grep 'COMMAND=' /var/log/auth.log | tail -n 20
    ```
  - Windows Sistemlerinde açık RDP oturumlarını denetleyin: `query user` ve `qwinsta`.
- **Savunma Mimarisi:**
  - SSH üzerinde "Jump Host" kurgularken `ProxyJump` ve `ProxyCommand` yönergelerini kullanarak hedef sunucuların asla internet yönlendirmesine sahip olmamasını sağlayın (`ssh -J bastion_user@bastion.sirket.com:22 target_user@10.0.1.25`).
  - PAM (Pluggable Authentication Modules) entegrasyonu ile Google Authenticator veya Duo Security üzerinden 2FA doğrulamasını SSH oturumlarına ekleyin (`/etc/pam.d/sshd` -> `auth required pam_google_authenticator.so`).

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, bir sunucunun `sshd_config` dosyasını düzenlerken sakın mevcut SSH oturumunu kapatma! Değişikliği yaptın, servisi yeniden başlattın; HEMEN ikinci bir terminal penceresi açıp yeni bir oturum başlatmayı dene. Eğer bir hata yaptıysan ilk oturumun hâlâ açık kalır ve kendini sistemden dışarı kilitlemeden hatayı düzeltebilirsin. Canlı sistemlerde kahramanlık yapılmaz; yedek alınır, test edilir, onaylanır ve ancak ondan sonra yürürlüğe konur."*
