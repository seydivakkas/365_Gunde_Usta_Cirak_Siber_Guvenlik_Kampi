# Gün 136: Linux Servisleri ve Systemd Güvenliği (Hoca Dersi / Usta-Çırak Rehberi)

**Eğitmen / Usta:** Seydi Eryılmaz (@seydivakkas)  
**Kapsam:** Linux PID 1 (systemd) Mimarisi, Unit Dosyaları, Sandboxing Direktifleri, Linux Namespaces, Linux Capabilities Kısıtlamaları ve CIS Benchmark Servis Sertleştirme Standartları  
**Seviye:** İleri Düzey Güvenlik Mühendisliği / Sistem Savunması  

---

## 1. Giriş: Çekirdek ile Süreç Arasındaki Gardiyan — Systemd

Evlat, modern kurumsal Linux sistemlerinde (RHEL, Ubuntu, Debian, SUSE, Arch) çekirdek (Linux Kernel) yüklendikten ve donanım hazırlandıktan sonra başlatılan ilk kullanıcı alanı süreci **PID 1**, yani `systemd` daemon'ıdır. 

Geleneksel Unix SysVinit mimarisinde servisler yalnızca kabuk betikleri (`/etc/init.d/`) üzerinden ve çoğunlukla denetimsiz, kısıtlamasız `root` haklarıyla başlatılırdı. Bir servis ele geçirildiğinde, saldırgan doğrudan sistemin mutlak hakimi olurdu.

Systemd ise yalnızca bir init sistemi değildir; Linux çekirdeğinin sunduğu **Namespaces (İsim Alanları)**, **Control Groups (cgroups)**, **Seccomp (Güvenli Hesaplama Filtreleri)** ve **Capabilities (Çekirdek Yetenekleri)** mekanizmalarını tek bir birim dosyasında (`.service`) deklaratif olarak yapılandıran devasa bir **işlem kum havuzu (process sandbox) orkestratörüdür**.

Eğer bir güvenlik mühendisi veya sistem yöneticisi systemd'nin sunduğu sandboxing direktiflerini bilmez ve servisleri varsayılan haliyle çalıştırırsa, en ufak bir RCE (Remote Code Execution) zafiyeti tüm sunucunun `root` seviyesinde düşmesine sebep olur.

Bugün seninle systemd servis birimlerinin anatomisini, saldırganların servisler üzerinden nasıl yetki yükselttiğini ve bir servisin çekirdek seviyesinde nasıl kilit altına alınacağını satır satır inceleyeceğiz.

---

## 2. Systemd Birim (Unit) Dosya Mimarisi ve Hiyerarşisi

Systemd, servisleri yapılandırırken belirli bir arama ve öncelik sırasını takip eder:

```text
+-------------------------------------------------------------------------------+
|                       SYSTEMD UNIT DOSYA ÖNCELİK SIRASI                       |
+-------------------------------------------------------------------------------+
| 1. /etc/systemd/system/        [EN YÜKSEK ÖNCELİK - Sistem Yöneticisi / Yerel]|
|    • Özel oluşturulan servisler ve yönetici ezmeleri (override) burada yaşar. |
+-------------------------------------------------------------------------------+
| 2. /run/systemd/system/        [ORTA ÖNCELİK - Çalışma Zamanı / Geçici]       |
|    • Geçici olarak bellek tabanlı üretilen unit dosyaları.                     |
+-------------------------------------------------------------------------------+
| 3. /lib/systemd/system/        [DÜŞÜK ÖNCELİK - Dağıtım Paket Yöneticisi]     |
|    (/usr/lib/systemd/system/)                                                 |
|    • APT/RPM paketleri tarafından kurulan orijinal şablon servisler.          |
+-------------------------------------------------------------------------------+
```

### Kritik Dosya İzinleri Kuralı (CWE-732 / MITRE ATT&CK T1543.002)
Bir saldırganın yerel bir kabuk (low-privilege shell) elde ettiğinde ilk kontrol ettiği dizinlerden biri `/etc/systemd/system/` dizinidir.
- Eğer bir `.service` dosyası dünyaca yazılabilir (world-writable, `0666` veya `0777`) veya yetkisiz bir kullanıcıya/gruba ait bırakılmışsa, saldırgan dosya içerisindeki `ExecStart=` satırını bir reverse shell komutuyla (`/bin/bash -i >& /dev/tcp/...`) değiştirir.
- Ardından servis yeniden başladığında veya sistem reboot edildiğinde komut **PID 1 (root)** yetkileriyle çalıştırılır!
- **Kural:** Tüm unit dosyaları istisnasız `root:root` sahipliğinde ve en fazla `0644` (veya `0640`) izin modunda olmalıdır.

---

## 3. Sandboxing Direktifleri ile Servis İzolasyonu

Usta bir güvenlik mimarı, geliştirdiği ya da yönettiği her bir servis biriminin `[Service]` bloğuna aşağıdaki CIS ve NIST SP 800-123 uyumlu direktifleri yerleştirmelidir:

### 1. `User=` ve `Group=` (Ayrılmış Yetkisiz Kimlik)
- Systemd varsayılan olarak `User=` tanımlanmadığında servisi **root** olarak çalıştırır.
- Bir web servisi, API veya veritabanı kesinlikle root ile koşmamalıdır.
- Her servisin kendi izole kullanıcısı olmalıdır: `User=nginx`, `User=appuser`.

### 2. `NoNewPrivileges=yes` (Yetki Artışına Karşı Kalkan)
- Çekirdek seviyesinde `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` sistem çağrısını tetikler.
- Anlamı şudur: Bu servis süreci ve onun çatallayacağı (fork) hiçbir alt süreç, SUID (`chmod u+s`) veya SGID biti olan dosyaları çalıştırarak daha yüksek bir UID/GID kazanamaz. Servis içerisinden `/bin/su` veya `/usr/bin/sudo` çalıştırılsa bile yetki yükseltme çekirdek tarafından reddedilir.

### 3. `ProtectSystem=strict` (Salt-Okunur Kök Dosya Sistemi)
- Servis için özel bir mount namespace oluşturur.
- `/usr`, `/boot`, `/etc` ve `/bin` dizinlerini servisin gözünde tamamen **Salt-Okunur (Read-Only)** olarak bağlar.
- Saldırgan servisi exploit etse bile sistem dosyalarını, kütüphaneleri veya konfigürasyonları değiştiremez.
- Servisin yazması gereken belirli dizinler varsa `ReadWritePaths=/var/log/myapp /var/lib/myapp` şeklinde beyaz listeye alınır.

### 4. `ProtectHome=yes` (Kullanıcı Verilerini Gizleme)
- `/home`, `/root` ve `/run/user` dizinlerini servis için tamamen erişilemez (`/dev/null` veya boş dizin) hale getirir.
- Saldırgan servisi kullanarak kullanıcıların SSH anahtarlarını (`~/.ssh/id_rsa`), bash geçmişlerini (`.bash_history`) veya kişisel verilerini çalamaz.

### 5. `PrivateTmp=yes` (İzole Geçici Dizinler)
- Servise özel, yalıtılmış bir `/tmp` ve `/var/tmp` dosya sistemi (mount namespace) tahsis eder.
- Servis dışındaki kullanıcılar veya diğer servisler bu geçici dosyaları göremez.
- Paylaşımlı `/tmp` üzerindeki sembolik bağ (symlink) tuzakları ve yarış koşulları (race condition / CWE-377) tamamen ortadan kalkar.

### 6. `PrivateDevices=yes` (Ham Donanım Blokajı)
- Servisin `/dev` dizini altındaki fiziksel donanım aygıtlarına (`/dev/sda`, `/dev/mem`, `/dev/kmem`, `/dev/nvme0n1`) doğrudan erişmesini engeller.
- Servise yalnızca `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom` gibi güvenli sanal aygıtlar gösterilir.

### 7. `ProtectKernelTunables=yes` & `ProtectControlGroups=yes`
- `/proc/sys`, `/sys` ve `/sys/fs/cgroup` dosya sistemlerini salt-okunur bağlar. Servisin çekirdek parametrelerini değiştirmesi engellenir.

---

## 4. Linux Capabilities Sınırlandırması (`CapabilityBoundingSet=`)

Geleneksel Unix mantığında süreç ya tam yetkili `root` (UID 0) ya da sıradan kullanıcıdır. Linux çekirdeği ise root yetkilerini **Capabilities (Yetenekler)** adı verilen bağımsız parçalara bölmüştür.

Bir web sunucusunun 80 veya 443 gibi ayrıcalıklı portları dinleyebilmesi için tam `root` olmasına gerek yoktur; yalnızca `CAP_NET_BIND_SERVICE` yeteneğine ihtiyacı vardır.

Systemd içinde:
```ini
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```
yazıldığında, servis çalışırken bu listede olmayan tüm çekirdek yetenekleri (özellikle son derece tehlikeli olan `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_SYS_RAWIO`) geri dönülemez biçimde düşürülür (drop edilir).

---

## 5. `systemd-analyze security` Mekanizması

Systemd, servislerin güvenlik derecesini ölçmek için yerleşik bir maruziyet analiz aracı barındırır:
```bash
systemd-analyze security nginx.service
```
Bu araç, her servisin güvenlik parametrelerini tartarak **0.0 (Tamamen Güvenli / İdeal Sandboxed)** ile **10.0 (Aşırı Tehlikeli / Unsafe)** arasında bir risk maruziyet puanı (exposure level) üretir.

Geliştirdiğimiz denetim motoru (`LinuxSystemdSecurityEngine`), kurumsal sistemlerdeki servisleri bu standartlara göre tarar, risk puanı hesaplar ve zafiyetli servisler için sistem yöneticilerine drop-in override (`override.conf`) sıkılaştırma dosyaları üretir.

---

## 6. CIS Linux Benchmark: Gereksiz ve Güvensiz Servislerin Kapatılması

CIS Linux Benchmark Section 2.1 ve 2.2 kuralları gereğince kurumsal sunucularda şu eski ve şifrelenmemiş servisler derhal kapatılmalı ve kilitlenmelidir:
1. `telnet.socket` / `telnet.service` (Metin tabanlı şifresiz iletişim)
2. `rsh.service` / `rlogin.service` / `rexec.service` (Güvensiz uzaktan çalıştırma)
3. `tftp.service` / `tftp.socket` (Parolasız dosya transferi)
4. `xinetd.service` (Eski süper sunucu)
5. `avahi-daemon.service` (mDNS ağ yayını)
6. `cups.service` (Sunucuda yazdırma gereksizdir)

Bu servisleri yalnızca `systemctl stop` ve `disable` yapmak yetersiz kalabilir; başka bir paket bağımlılık olarak onları tetikleyebilir. Bu yüzden kesin çözüm `systemctl mask <servis>` uygulamaktır.

---

## 7. Ustanın Çırağa Öğüdü

Evlat! Bir sunucuya girdiğinde "Ben bu servisi root harici çalıştırdım, işim bitti" deme. 
- Servisin unit dosyası kime ait?
- Binary dosyasında SUID biti unutulmuş mu?
- `/tmp` alanı izole mi?
- Dosya sistemi salt-okunur korumada mı?

Bu soruların her birine "Evet, kilitledim" diyemiyorsan o sunucu savunmasızdır. Bugün geliştirdiğimiz motor ve araçlar, yarın kurumsal ortamda sunucularını denetlerken senin en sadık kalkanın olacak.
