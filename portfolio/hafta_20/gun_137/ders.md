# Gün 137: Linux SSH Anahtar Güvenliği ve Sunucu Sertleştirmesi (Hoca Dersi / Usta-Çırak Rehberi)

**Eğitmen / Usta:** Seydi Eryılmaz (@seydivakkas)  
**Kapsam:** Güvenli Kabuk (SSH) Protokolü, Asimetrik Kriptografi, Ed25519 vs RSA/DSA Algoritmaları, Anahtar Dosya/Dizin İzinleri, authorized_keys Kısıtlamaları ve CIS Benchmark Section 5.2 OpenSSH Sunucu Sertleştirmesi  
**Seviye:** İleri Düzey Güvenlik Mühendisliği / Sistem Savunması  

---

## 1. Giriş: Kurumsal Kalenin Ön Kapısı — SSH

Evlat, bir Linux sunucusunun dış dünyaya veya iç yönetim ağına bakan en kritik kapısı **SSH (Secure Shell - TCP Port 22)** servisidir. 

Sistem yöneticileri, geliştiriciler, veri mühendisleri ve otomasyon betikleri (Ansible, Terraform, CI/CD) sunucuya erişmek için SSH kullanır. Eğer bu kapı parola tabanlı kimlik doğrulamaya açık bırakılmışsa, doğrudan `root` girişine izin veriyorsa veya sunucudaki SSH anahtarlarının dosya izinleri gevşek tutulmuşsa; kapıda çelik kilit olduğunu sanırsın ama arka duvarda kocaman bir delik vardır.

Bugün seninle:
1. SSH anahtarlarının matematiksel ve kriptografik altyapısını,
2. Neden eski DSA ve kısa RSA anahtarlarını derhal çöpe atmamız gerektiğini,
3. Dosya izinlerinin (`0600`, `0700`) neden yaşamsal olduğunu,
4. `/etc/ssh/sshd_config` sunucusunu CIS Benchmark standartlarında nasıl kurşungeçirmez hale getireceğimizi satır satır inceleyeceğiz.

---

## 2. Kriptografik Anahtar Türleri ve Algoritma Evrimi

SSH, kimlik doğrulamada asimetrik (açık anahtar / gizli anahtar) kriptografiyi kullanır. İstemcide özel anahtar (`private key`), sunucudaki `~/.ssh/authorized_keys` dosyasında ise açık anahtar (`public key`) tutulur.

Peki hangi algoritma ne kadar güvenlidir?

```text
+-------------------------------------------------------------------------------+
|                       SSH ANAHTAR ALGORİTMALARI KIYASI                        |
+-------------------------------------------------------------------------------+
| 1. Ed25519 (Curve25519 - Edwards-curve Digital Signature Algorithm) [ÖNERİLEN] |
|    • 256-bit anahtar uzunluğu (RSA 3072-bit seviyesinde güvenlik).            |
|    • Yan kanal (side-channel) ve önbellek zamanlama saldırılarına bağışık.    |
|    • Çok hızlı imzalama ve doğrulama performansı.                             |
|    • Komut: ssh-keygen -t ed25519 -a 100                                      |
+-------------------------------------------------------------------------------+
| 2. RSA (Rivest–Shamir–Adleman) [ŞARTLI KABUL: >= 3072 bit]                    |
|    • 2048 bit: Asgari sınır (emekliye ayrılmak üzere).                        |
|    • 3072 / 4096 bit: Kurumsal standartlarda kabul edilebilir.                |
|    • < 2048 bit: Kesinlikle YASAK (Faktoring saldırılarına açık).             |
|    • Komut: ssh-keygen -t rsa -b 4096                                         |
+-------------------------------------------------------------------------------+
| 3. ECDSA (Elliptic Curve Digital Signature Algorithm - NIST Eğrileri)         |
|    • nistp256, nistp384, nistp521 eğrileri kullanılır.                        |
|    • Rastgele sayı üretecinde (RNG) oluşabilecek en ufak bir zayıflık veya    |
|      bias, özel anahtarın saniyeler içinde ifşa olmasına yol açar.            |
+-------------------------------------------------------------------------------+
| 4. DSA (Digital Signature Algorithm - 1024 bit) [KESİNLİKLE YASAK / BROKEN]   |
|    • 1024-bit sınırı kriptografik olarak kırılmıştır.                         |
|    • OpenSSH 7.0+ sürümlerinde varsayılan olarak devre dışı bırakılmıştır.    |
+-------------------------------------------------------------------------------+
```

---

## 3. SSH Dosya ve Dizin İzinleri Matrisi (CWE-732 / T1552.004)

OpenSSH istemcisi ve sunucusu dosya izinleri konusunda son derece titizdir; ancak yöneticiler bazen `chmod 777` veya `666` yaparak ölümcül hatalara imza atarlar.

```text
+----------------------------+------------+---------------+--------------------------------------+
| Dosya / Dizin Yolu         | İzin Modu  | Sahiplik      | Güvenlik Riski / Açıklama            |
+----------------------------+------------+---------------+--------------------------------------+
| ~/.ssh/                    | 0700       | user:user     | Dizin listelenemez ve yazılamaz.     |
| ~/.ssh/id_ed25519 (Private)| 0600       | user:user     | Başkası okursa özel anahtar çalınır! |
| ~/.ssh/id_ed25519.pub      | 0644       | user:user     | Açık anahtar dünyaca okunabilir.     |
| ~/.ssh/authorized_keys     | 0600       | user:user     | Başkası yazarsa arka kapı ekler!     |
| /etc/ssh/sshd_config       | 0600       | root:root     | Sunucu yapılandırması koruması.      |
| /etc/ssh/ssh_host_*_key    | 0600       | root:root     | Sunucu kimlik host anahtarları.      |
+----------------------------+------------+---------------+--------------------------------------+
```

### Kritik Risk: Unprotected Private Key
Eğer bir özel anahtarın (`id_rsa`, `id_ed25519`) izinleri `0644` veya `0666` yapılırsa:
1. Sunucu üzerinde düşük yetkili bir kullanıcı veya web uygulaması kabuğu (`www-data`) bu dosyayı doğrudan okuyabilir (`cat /home/deploy/.ssh/id_rsa`).
2. Saldırgan anahtarı kendi makinesine indirir ve hedef sunuculara veya AWS/GitHub altyapısına doğrudan `deploy` kimliğiyle giriş yapar (Lateral Movement / T1552.004).
3. OpenSSH istemcisi bu hatayı tespit ettiğinde bağlantıyı şu uyarıyla derhal reddeder:
   `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@`  
   `@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @`  
   `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@`

---

## 4. `sshd_config` CIS Benchmark Sertleştirme Kuralları

Kurumsal bir üretim sunucusunda `/etc/ssh/sshd_config` dosyasında şu parametrelerin bulunması zorunludur:

### 1. `PermitRootLogin no` (CIS 5.2.5 / CWE-250)
- Doğrudan `root` kullanıcısı ile SSH oturumu açılmasını engeller.
- Yöneticiler önce kendi adlarına tanımlı yetkisiz hesapla (örneğin `seydivakkas`) giriş yapmalı, ardından `sudo` ile denetimli yetki yükseltmelidir. Bu sayede her komut kimin tarafından çalıştırıldığı bilinecek şekilde loglanır.

### 2. `PasswordAuthentication no` (CIS 5.2.9 / CWE-307)
- Parola ile oturum açmayı tamamen yasaklar. Yalnızca kriptografik SSH anahtarı olanlar girebilir.
- Bu tek satırlık ayar, internetten sunucuya yöneltilen yüz binlerce kaba kuvvet (brute-force) ve parola deneme saldırısını anında anlamsız hale getirir.

### 3. `PermitEmptyPasswords no` (CIS 5.2.11 / CWE-258)
- Sistemde şifresi olmayan (veya `passwd -d` yapılmış) hesapların şifresiz oturum açmasını engeller.

### 4. `MaxAuthTries 3` (CIS 5.2.7)
- Bir oturumda yapılabilecek başarısız kimlik doğrulama denemesini 3 ile sınırlar; aşıldığında bağlantı anında koparılır.

### 5. `ClientAliveInterval 300` & `ClientAliveCountMax 2` (CIS 5.2.16 / CWE-613)
- 300 saniye (5 dakika) boyunca hiçbir aktivite göstermeyen istemcilere kontrol paketi gönderir; 2 kez yanıt alınamazsa oturum düşürülür. Açık bırakılan terminallerin istismarını önler.

### 6. `X11Forwarding no` (CIS 5.2.6)
- Sunucu üzerinde GUI uygulamalarının grafik pencerelerini istemciye aktaran X11 tünellemesini kapatır. X11 protokolünün doğasında bulunan tuş vuruşu izleme (keystroke sniffing) riskini bertaraf eder.

---

## 5. `authorized_keys` İçinde İleri Düzey Yetki Kısıtlamaları

Evlat, açık anahtarı `authorized_keys` içine öylece yapıştırıp geçmek acemiliktir. Usta bir mühendis, anahtarın yetkilerini satır başında kısıtlar:

```text
from="10.0.10.0/24",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,command="/usr/local/bin/backup.sh" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... backup@backup-srv
```
Bu satır ne yapar?
1. `from="10.0.10.0/24"`: Bu anahtar yalnızca şirket içi yönetim IP bloğundan geliyorsa kabul edilir. İnternetten veya başka bir IP'den gelirse reddedilir!
2. `no-port-forwarding`: Saldırganın sunucu üzerinden tünel açmasını (tunneling / proxying) engeller.
3. `no-pty`: İnteraktif terminal (kabuk) tahsis edilmesini engeller.
4. `command="/usr/local/bin/backup.sh"`: İstemci ne isterse istesin, bu anahtarla bağlandığında YALNIZCA belirtilen yedekleme betiği çalışır; başka hiçbir komut yürütülemez!

---

## 6. Ustanın Çırağa Öğüdü

Evlat! Bir sunucuda parola kimlik doğrulaması açık bırakılmışsa, o sunucu internette açık hedef tahtasıdır.
- Her zaman `ssh-keygen -t ed25519 -a 100` ile Ed25519 anahtarı üret.
- Anahtarına mutlaka güçlü bir parola (passphrase) koy; parolasız anahtar yerde unutulmuş ev anahtarı gibidir.
- Sunucuda `PasswordAuthentication no` ve `PermitRootLogin no` yapmayı asla unutma.
- Dosya izinlerini (`0600` ve `0700`) sistemin omurgası bil.

Bugün inşa ettiğimiz denetim motoru ve CLI aracı, kurumsal altyapılardaki tüm SSH anahtarlarını ve sunucularını denetleyip sana raporlayacak güçtedir.
