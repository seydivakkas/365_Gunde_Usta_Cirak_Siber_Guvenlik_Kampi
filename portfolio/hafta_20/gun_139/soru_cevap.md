<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 139: Linux Audit ve Journal Güvenliği — Usta-Çırak Soru & Cevap

Bu belgede, Linux çekirdeğinin Denetim Alt Sistemi (`auditd`) ve systemd'nin yapılandırılmış günlükleme servisi (`journald`) ile kurumsal düzeyde kurcalamaya karşı korumalı (tamper-evident) log mimarilerinin inşasında karşılaşılan kritik güvenlik meseleleri derinlemesine ele alınmıştır.

---

## Soru 1: Çekirdek Düzeyinde Audit Koruması ve Kurcalanamazlık (-e 2 Bayrağı)

### 1. Soru Başlığı ve Tanımı
Linux çekirdeğinin `audit` mekanizmasında `-e 2` (immutable/değiştirilemez) bayrağı nedir, audit loglarının saldırgan tarafından kapatılmasını veya kurcalanmasını nasıl engeller ve bu bayrak aktifken kurallar nasıl güncellenir?

### 2. Derinlemesine Teknik Analiz
Linux denetim alt sistemi çekirdek (kernel space) düzeyinde çalışır. Çekirdek, `audit_status` yapısı ve Netlink soketleri aracılığıyla kullanıcı alanındaki `auditctl` ve `auditd` ile haberleşir. Denetim alt sisteminin çalışma durumunu belirleyen `audit_enabled` bayrağı 3 farklı değere sahip olabilir:
1. `0`: Audit alt sistemi tamamen kapalıdır (disable).
2. `1`: Audit alt sistemi etkindir, kurallar yüklenebilir, silinebilir veya dinamik olarak değiştirilebilir.
3. `2`: Audit alt sistemi kilitlenmiştir (immutable/frozen).

Saldırgan bir Linux sunucuya yetkisiz root (UID 0) veya `CAP_AUDIT_CONTROL` capability'si ile sızdığında, geride bıraktığı adli bilişim (forensics) izlerini silmek için ilk yapacağı işlem `auditctl -D` komutuyla tüm kuralları silmek veya `auditctl -e 0` ile denetimi durdurmaktır.

Eğer `/etc/audit/rules.d/audit.rules` dosyasının en son satırına `-e 2` kuralı konulmuşsa, çekirdek `audit_enabled` değerini `2` olarak sabitler. Bu bayrak bir kez set edildikten sonra çekirdek seviyesinde kilitleme devreye girer. Root kullanıcısı dahil hiç kimse çalışan çekirdekte kuralları değiştiremez, silemez (`auditctl -D` çağrısı `EPERM - Operation not permitted` döner) veya servisi sonlandıramaz. Kural güncellemesi yapabilmenin **tek yolu**, kural dosyalarını disk üzerinde güncelledikten sonra sistemi yeniden başlatmaktır (reboot).

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Kritik bir ödeme geçidi (FinTech) Linux sunucusuna `CVE-2024-6387` (regreSSHion) benzeri bir güvenlik zafiyeti üzerinden `root` yetkisi elde eden tehdit aktörü girmiştir. Saldırgan adli iz bırakmamak için hemen şu komutları koşturur:
```bash
auditctl -D
systemctl stop auditd
```
Ancak sistem yöneticisi CIS Benchmark 4.1.18 standardına uygun olarak `/etc/audit/rules.d/audit.rules` dosyasına `-e 2` direktifini eklemiştir.

**Sonuç ve Çözüm:**
Saldırganın `auditctl -D` komutu işletim sistemi çekirdeği tarafından reddedilir:
```
Error sending status request (Operation not permitted)
Kernel is locked, audit rules cannot be changed until reboot.
```
Saldırganın disk üzerindeki dosyalara dokunması, kullanıcı hesaplarını değiştirmesi veya yetki yükseltme araçlarını çalıştırması saniye saniye `audit.log` içine kaydedilir ve eşzamanlı olarak uzaktaki SIEM/Wazuh sunucusuna `audisp-syslog` eklentisiyle sevk edilir. Tehdit aktörü izlerini silemeden SOC ekibi tarafından izole edilir.

### 4. Ustanın Çırağa Tavsiyesi
> "Evlat, unutma: Eğer bir root kullanıcısı sistemdeki güvenlik loglarını silebiliyorsa, o loglama sistemi değil yalnızca bir 'dilek kutusu'dur! Üretim ortamlarında audit kurallarını daima `-e 2` ile mühürle. Ancak uyarayım: Test ortamında kural geliştirirken `-e 2` koyarsan her kural değişikliğinde makineye reboot atmak zorunda kalırsın. Bu yüzden staging'de test et, production'da mühürle."

---

## Soru 2: systemd-journald İleri Yönde Güvenli Mühürleme (Forward Secure Sealing - FSS)

### 1. Soru Başlığı ve Tanımı
`systemd-journald` bileşenindeki Forward Secure Sealing (FSS) teknolojisi nedir, geçmiş günlüklerin kurcalanmasını matematiksel olarak nasıl engeller ve doğrulama anahtarı mimarisi nasıl kurgulanmalıdır?

### 2. Derinlemesine Teknik Analiz
Geleneksel metin tabanlı log dosyaları (örneğin `/var/log/messages`) bir tehdit aktörü tarafından metin editörüyle açılıp belirli satırları silinerek veya değiştirilerek manipüle edilebilir. `systemd-journald`, logları ikili (binary) formatta tutmanın ötesinde, kriptografik olarak kurcalanmaya karşı dayanıklı hale getirmek için **Forward Secure Sealing (FSS)** mekanizmasını (RFC 4398 / Bellare & Miner forward-secure signature standardı) sunar.

FSS mimarisi şöyle işler:
1. `journalctl --setup-keys` komutu çalıştırıldığında bir çift kriptografik anahtar üretilir:
   - **Mühürleme Anahtarı (Sealing Key):** Sunucu üzerinde RAM'de saklanır. Belirli bir zaman aralığında (varsayılan 15 dakika) tek yönlü bir fonksiyonla (cryptographic hash ratchet) güncellenir ve eski anahtar bellekten kalıcı olarak silinir.
   - **Doğrulama Anahtarı (Verification Key):** Sistemin dışında, güvenli bir kasada veya harici adli bilişim sunucusunda saklanır.
2. Log kayıtları bloklar halinde mühürlenir. Her mühürleme işleminde dönemin mühürleme anahtarı kullanılır.
3. Bir saldırgan sistemi ele geçirip mevcut mühürleme anahtarını ele geçirse bile, tek yönlü fonksiyonun matematiksel özelliği gereği **geçmiş dönemlerin anahtarlarını türetemez**. Dolayısıyla, saldırıdan önce kaydedilmiş hiçbir günlüğü değiştiremez veya sahte mühür basamaz.
4. Adli tıp ekibi `journalctl --verify` komutunu harici doğrulama anahtarıyla çalıştırarak logların bütünlüğünü ve ilk tahrifatın yapıldığı anı kesin olarak tespit eder.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir Linux veritabanı sunucusuna yetkisiz erişim sağlayan kötü niyetli bir kurum içi çalışan (insider threat), saat 14:00'te hassas müşteri tablolarını kopyalamış, ardından 14:30'da `root` ayrıcalığı elde ederek `/var/log/journal/` altındaki binary journal loglarını bir hex editörle açıp 14:00'e ait olayları sıfırlamaya (zero-out) çalışmıştır.

**Uygulama ve Çözüm:**
Sunucuda `journald.conf` dosyasında `Seal=yes` aktif edilmiş ve anahtarlar kurulmuştur:
```ini
[Journal]
Storage=persistent
Compress=yes
Seal=yes
ForwardToSyslog=yes
```
Adli inceleme uzmanı olay yerine intikal ettiğinde elindeki güvenli doğrulama anahtarıyla sistemi inceler:
```bash
journalctl --verify --verify-key="a1b2-c3d4-e5f6..."
```
Çıktıda şu hata açıkça görülür:
```
14:00:15 UTC: File corruption detected! Seal verification failed at entry 14820!
Inconsistency detected in epoch 98. Previous epochs [0-97] intact and cryptographically verified.
```
Saldırgan geçmişi manipüle edememiş, mühür bozulduğu anda tahrifatın kesinleştiği adli bir kanıt ortaya çıkmıştır.

### 4. Ustanın Çırağa Tavsiyesi
> "Çırak, FSS kurarken yapılan en ölümcül hata nedir bilir misin? Doğrulama anahtarını (verification key) sunucunun üzerinde `/root/verification_key.txt` diye bırakmaktır! Doğrulama anahtarını derhal o makineden çıkaracaksın; ya fiziksel bir kasadaki şifreli diske ya da merkezi güvenlik ekibinin kasasına (Vault) koyacaksın. Anahtarı hırsızla aynı odada bırakırsan kilidin ne anlamı kalır?"

---

## Soru 3: Kritik Sistem Çağrısı (Syscall) Denetimi ve Performans Dengelemesi

### 1. Soru Başlığı ve Tanımı
Linux audit kurallarında `init_module`, `delete_module`, `settimeofday` ve dosya izin değişiklikleri (`chmod`, `chown`) gibi sistem çağrılarının denetlenmesi neden zorunludur ve çekirdek performans darboğazı yaşamamak için kural yazarken nelere dikkat edilmelidir?

### 2. Derinlemesine Teknik Analiz
Linux çekirdeğinde rootkit'ler, kalıcılık (persistence) sağlamak ve adli sistemleri körleştirmek için dinamik çekirdek modülleri (LKM - Loadable Kernel Modules) yüklerler. Bu işlem kullanıcı alanından `init_module` veya `finit_module` sistem çağrılarıyla tetiklenir. Çekirdek modülünün kaldırılması ise `delete_module` ile yapılır.

Aynı şekilde, zaman damgalarının manipüle edilmesi (timestomping), logların sırasını bozarak korelasyon algoritmalarını ve SIEM kurallarını aldatmayı hedefler. Bu da `adjtimex`, `settimeofday` ve `clock_settime` sistem çağrılarıyla gerçekleştirilir.

Bu sebeple CIS Benchmark standardı şu sistem çağrısı filtrelerini şart koşar:
```bash
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_modules
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
```

**Performans Dengelemesi:**
Her sistem çağrısında audit filtresinin tetiklenmesi CPU context switch maliyetini artırır. Çok yoğun I/O yapan bir sunucuda (örneğin PostgreSQL veya Nginx) `open` veya `read` sistem çağrılarını filtresiz denetlemek sunucuyu çökertebilir.
Performansı korumak için 3 altın kural uygulanır:
1. **Mimari Filtresi (`-F arch=b64`):** Yalnızca hedeflenen sistem mimarisine ait sistem çağrıları dinlenir.
2. **Kullanıcı Filtresi (`-F auid>=1000 -F auid!=unset`):** Daemon ve sistem servislerinin rutin çağrıları elenir, yalnızca gerçek oturum açmış kullanıcıların (AUID) çağrıları yakalanır.
3. **Başarı/Hata Durumu (`-F exit=-EACCES -F exit=-EPERM`):** Yetki aşımı denemelerinde yalnızca reddedilen (EPERM/EACCES) çağrılar filtrelenerek log hacmi %90 oranında düşürülür.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir Linux sunucusuna gizlice bir Rootkit (örneğin Diamorphine LKM) yüklemeye çalışan saldırgan, `insmod diamorphine.ko` komutunu çalıştırır. Ardından logları şaşırtmak için sistem saatini 3 yıl geriye alır: `date -s "2023-01-01"`.

**Tespit Mekanizması:**
Audit motorumuzdaki CIS kuralları devreye girer:
1. `init_module` çağrısı anında yakalanır ve `/var/log/audit/audit.log` dosyasına şu kayıt düşer:
   `type=SYSCALL msg=audit(1762084800.123:450): arch=c000003e syscall=175 success=yes exit=0 a0=55f8... auid=1001 uid=0 gid=0 exe="/usr/bin/kmod" key="kernel_modules"`
2. `clock_settime` çağrısı anında yakalanır:
   `type=SYSCALL msg=audit(1762084800.890:451): arch=c000003e syscall=227 success=yes exit=0 auid=1001 uid=0 exe="/usr/bin/date" key="time_change"`
3. `ausearch -k kernel_modules` veya `aureport -m` komutuyla olay saniyeler içinde raporlanır ve saldırganın hangi oturum ID'si (ses=) ve gerçek kullanıcı kimliği (auid=1001) ile işlemi yaptığı kanıtlanır.

### 4. Ustanın Çırağa Tavsiyesi
> "Gözünü dört aç evlat! Bir sistemde root olan saldırgan kimliğini gizlemek için `sudo su -` yapar ve UID'si `0` olur. Ama çekirdek asla unutmaz; kullanıcının ilk giriş yaptığı andaki `auid` (Audit User ID) değerini mezara kadar taşır. Bir adli incelemede `uid=0` yazmasına aldanma, daima `auid` değerine bak; suçlunun gerçek parmak izi ordadır!"
