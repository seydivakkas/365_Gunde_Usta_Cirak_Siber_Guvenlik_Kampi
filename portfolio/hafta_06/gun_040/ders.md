<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 040 — Güvenli Uzaktan Yönetim Başlangıcı Mimarisi

**Usta-Çırak / Hoca Dersi**  
*Aşama 02: Sistem ve Ağ Temelleri — Hafta 06: İşletim Sistemi Güvenliği ve Temel Ağ Mimarisi*

---

## 1. Usta Girişi: Kalenin Kapısı ve Uzaktan Yönetim Gerçeği
Evlat, bir işletim sistemini fiziksel olarak ne kadar sertleştirirsen sertleştir; diski şifrele, saatini eşitle, en son yamaları geç... Eğer o sistemin uzaktan yönetim kapısını (SSH, RDP, WinRM) yanlış yapılandırmışsan veya internete doğrudan açmışsan, kalenin tüm anahtarlarını sokaktaki kalabalığa dağıtmışsın demektir.

Siber saldırı istatistikleri (Verizon DBIR, Mandiant M-Trends vb.) bize çok net bir gerçeği haykırır: **Dünya genelindeki fidye yazılımı ve veri sızıntısı vakalarının %60'ından fazlası, doğrudan internete açık bırakılmış güvensiz RDP veya zayıf parolalı SSH portları üzerinden başlar.**

Saldırganlar Shodan, Censys veya otomatik botnet tarayıcılarıyla internetteki tüm IPv4 uzayını (`0.0.0.0/0`) 15 dakika içinde tarar. Açık bir 3389 (RDP) veya 22 (SSH) portu buldukları anda saniyede binlerce parola deneyen kaba kuvvet (brute-force) veya kimlik bilgisi doldurma (credential stuffing) motorlarını devreye sokarlar.

Bugün seninle uzaktan yönetimin temellerini; **Ağ Sınırını**, **Bastion (Sıçrama) Mimarisini**, **Kimlik Doğrulama Sertleştirmesini** ve **Adli Oturum Günlüklemesini** inşa edeceğiz.

---

## 2. İlk Kural: Açık Metin (Plaintext) Protokollerin Yasaklanması
Bilişim tarihinin ilk uzaktan yönetim araçları olan **Telnet (Port 23)** ve **rlogin/rsh (Port 513/514)**, 1980'lerin "herkesin birbirine güvendiği" ARPANET döneminde geliştirilmiştir.
- Bu protokollerde **hiçbir kriptografik şifreleme yoktur**.
- Kullanıcı adı, şifre ve ekranda yazılan her bir komut (örneğin `passwd` veya `sudo su -`), yerel ağdan geçen Ethernet çerçeveleri içinde kabak gibi açık metin (cleartext) olarak akar.
- Aynı ağdaki bir saldırgan `tcpdump` veya `wireshark` çalıştırarak, hatta ARP zehirlemesi (ARP Poisoning) yaparak saniyeler içinde tüm kimlik bilgilerini toplar.

**Usta Kuralı:** Şirket ağında Telnet, rlogin veya şifresiz VNC (5900) gördüğün an o servisi derhal kapatacaksın. Yerine Linux/Unix için **SSHv2 (Secure Shell)**, Windows için **WinRM over HTTPS (Port 5986)** veya sertifikalı **RDP over TLS** kuracaksın.

---

## 3. Ağ Sınırı ve Bastion (Jump Host) Mimarisi
Bir sunucuya uzaktan bağlanmak ile o sunucunun yönetim portunu tüm dünyaya açmak aynı şey değildir!

```text
[ Genel İnternet: 0.0.0.0/0 ]
              │
              ▼ (IPsec / WireGuard VPN Tüneli + MFA Zorunluluğu)
[ Çevre Güvenlik Duvarı (Perimeter Firewall) ]
              │
              ▼ (Yalnızca VPN İstemcileri Erişebilir)
[ BASTION / JUMP HOST (Sıçrama Sunucusu) ]
  - Yalnızca Ed25519 SSH Anahtarı + FIDO2 Donanım Anahtarı
  - Doğrudan Root Girişi Yasak (PermitRootLogin no)
  - Fail2ban ile Kaba Kuvvet Koruması
  - Oturumun Baştan Sona Kaydı (Session Recording)
              │
              ▼ (Dahili İzole Yönetim VLAN'ı: 10.10.100.0/24)
┌─────────────┴─────────────┐
▼                           ▼
[ Kritik Veritabanı ]       [ Domain Controller ]
(Dış dünyadan görünmez)     (Yalnızca Bastion IP'sinden RDP/SSH kabul eder)
```

### Bastion Host (Sıçrama Sunucusu) İlkeleri:
1. **Tek Giriş Kapısı (Single Ingress Point):** Kurumdaki 500 farklı sunucunun 500'ünün de yönetim portunu güvenlik duvarından açamazsın. Yalnızca 1 adet son derece sertleştirilmiş "Bastion Host" açılır. Yöneticiler önce buraya bağlanır, buradan iç sunuculara sıçrar (jump eder).
2. **Saldırı Yüzeyinin Daraltılması:** Bastion host üzerinde web sunucusu, veritabanı, derleyici veya gereksiz hiçbir paket barındırılmaz; yalnızca SSH veya PAM (Privileged Access Management) servisi çalışır.
3. **Ağ İzolasyonu:** Kritik üretim sunucuları güvenlik duvarı seviyesinde yalnızca Bastion Host'un IP adresinden (`10.10.100.5`) gelen 22/3389 bağlantılarına izin verecek şekilde filtrelenir.

---

## 4. SSH Sertleştirmesi (Deep Dive: /etc/ssh/sshd_config)

Linux sunucularda varsayılan OpenSSH yapılandırması genellikle uyumluluk adına esnek bırakılır. Güvenlik uzmanı bu dosyayı şu katı kurallarla sertleştirmelidir:

```ini
# 1. Doğrudan Root Girişini Kapat (Hesap Verebilirlik ve Kaba Kuvvet Engeli):
PermitRootLogin no

# 2. Parola ile Oturum Açmayı Tamamen Yasakla:
PasswordAuthentication no

# 3. Kriptografik Açık Anahtarlı Kimlik Doğrulamayı Zorunlu Kıl:
PubkeyAuthentication yes

# 4. Yalnızca Güçlü Kriptografik Algoritmalara İzin Ver (RSA 1024 ve SHA-1 yasak):
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com

# 5. Deneme Sayısını ve Zaman Aşımını Sınırla:
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2

# 6. Boş Parolaları Yasakla:
PermitEmptyPasswords no

# 7. X11 ve Ajan Yönlendirmesini Güvenlik Gereği Kısıtla:
X11Forwarding no
AllowAgentForwarding no
```

### Neden `PermitRootLogin no`?
Saldırganlar bir Linux sisteminde "root" adında bir süper kullanıcının kesinlikle var olduğunu bilirler. Eğer root girişi açıksa, kullanıcı adını bulma zahmetine girmeden doğrudan root parolasına yüklenirler. Ayrıca root ile doğrudan girildiğinde "Ahmet mi girdi, Mehmet mi girdi, kim `rm -rf` çekti?" sorusunun cevabı loglarda bulunamaz. Kişisel kullanıcı adıyla girilip `sudo` ile yetki yükseltildiğinde her komut denetim izine (audit trail) yazılır.

---

## 5. RDP Sertleştirmesi: Ağ Düzeyinde Kimlik Doğrulama (NLA) ve BlueKeep

Windows dünyasında Uzak Masaüstü (Remote Desktop Protocol - RDP - Port 3389), sistem yöneticilerinin vazgeçilmezidir. Ancak en tehlikeli saldırı vektörlerinden biridir.

### Ağ Düzeyinde Kimlik Doğrulama (NLA - Network Level Authentication) Nedir?
- **NLA Kapalıyken (Eski / Tehlikeli Durum):** İstemci RDP portuna bağlandığı anda, Windows sunucu henüz kullanıcı adı ve şifre sormadan önce istemci için tam bir Windows Grafik Oturumu (Logon GUI), bellek alanları ve RDP kanalları tahsis eder.
  *Tehlike:* Bu ön-oturum (pre-authentication) aşamasında RDP sürücüsünde (`termdd.sys`) bulunan bir bellek taşması zafiyeti (**BlueKeep - CVE-2019-0708**), saldırganın hiçbir şifre bilmeden uzaktan SYSTEM yetkisiyle kod çalıştırmasına (Wormable RCE) imkan tanır.
- **NLA Açıkken (Modern / Güvenli Durum):** İstemci CredSSP (Credential Security Support Provider) protokolü üzerinden kimliğini doğrulamadan sunucu hiçbir RDP grafik ekranı veya oturum belleği açmaz. Kimliksiz gelen paketler anında kapıda düşürülür. BlueKeep gibi zafiyetler NLA arkasında tamamen etkisiz hale gelir.

---

## 6. Kaba Kuvvet (Brute-Force) Savunması ve Oturum Günlükleme
1. **Otomatik Engelleme (Fail2ban & pam_faillock):**
   Bir IP adresinden arka arkaya 3 kez başarısız oturum denemesi geldiğinde, güvenlik duvarı (iptables/nftables) seviyesinde o IP adresi 24 saat boyunca tamamen engellenmelidir. Windows tarafında ise "Account lockout threshold" 5 deneme olarak yapılandırılmalıdır.
2. **Merkezi SIEM Oturum Günlüklemesi:**
   - Linux: `/var/log/auth.log` veya `/var/log/secure` içindeki başarılı (Accepted publickey) ve başarısız (Failed password) denemeler `rsyslog` ile anında SOC SIEM platformuna akmalıdır.
   - Windows: Security Olay Günlüğündeki **Event ID 4624 (Başarılı Oturum Açma - Logon Type 10 / RemoteInteractive)** ve **Event ID 4625 (Başarısız Oturum Açma)** olayları gerçek zamanlı korelasyona tabi tutulmalıdır. Gece saat 03:00'te gelen 50 başarısız oturum denemesi anında alarm üretmelidir.

---

## 7. Usta-Çırak Özeti
Çırak! Bir sunucuyu teslim aldığında uzaktan yönetim denetim listesi şu 4 adımdan ibarettir:
1. "Telnet var mı?" -> Varsa yok et, yerine SSH koy.
2. "İnternete (0.0.0.0/0) açık mı?" -> Açıksa hemen kapat; erişimi VPN veya Bastion arkasına çek.
3. "Root ile doğrudan giriliyor mu, NLA açık mı?" -> Root girişini kapat, RDP'de NLA'yı zorunlu kıl.
4. "Fail2ban ve SIEM logları devrede mi?" -> Devrede değilse sistemi kör bırakmışsın demektir!

Geliştirdiğimiz denetçi (`secure_remote_management_auditor.py`) bu kuralların tamamını otomatik denetleyen bir kalkan görevi görür!
