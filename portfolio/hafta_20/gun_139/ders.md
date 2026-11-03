# Gün 139: Linux Audit ve Journal Güvenliği (Hoca Dersi / Usta-Çırak Rehberi)

**Eğitmen / Usta:** Seydi Eryılmaz (@seydivakkas)  
**Kapsam:** Linux Çekirdeği Denetim Çatısı (kauditd & auditd), Sistem Çağrısı (Syscall) Filtreleri, Dosya İzleme (Watch Rules), Kuralların Değiştirilemezlik Kilidi (-e 2), systemd-journald Kalıcı Günlükleme ve Kriptografik Mühürleme (Forward Secure Sealing - FSS)  
**Seviye:** İleri Düzey Güvenlik Mühendisliği / Sistem Savunması  

---

## 1. Giriş: Görünmez Göz — Linux Denetim ve Günlükleme

Evlat, bir siber saldırgan sunucuna sızdığında ilk yapacağı şey nedir bilir misin?  
İzlerini silmek! `/var/log/messages`, `/var/log/auth.log` veya bash geçmişini (`.bash_history`) temizleyerek sanki hiç orada olmamış gibi davranmaya çalışır.

Eğer sisteminde yalnızca sıradan kullanıcı alanı loglaması varsa, `root` yetkisini alan bir saldırgan tek bir `rm -rf /var/log/*` komutuyla seni kör eder.

İşte bu yüzden kurumsal güvenlik mimarisinde sıradan günlükleme yetmez; doğrudan **Linux Çekirdeğinin (Kernel) kalbine entegre çalışan bir denetim motoru (Linux Audit Framework - auditd)** ve kriptografik olarak mühürlenen bir sistem günlüğü (**systemd-journald FSS**) gerekir.

Bugün seninle:
1. Çekirdek düzeyinde her sistem çağrısının (syscall) ve dosya erişiminin nasıl izlendiğini,
2. Bir saldırgan `root` olsa bile audit kurallarını silmesini engelleyen `-e 2` (Immutable) kilidini,
3. Journald Forward Secure Sealing (FSS) ile logların kriptografik olarak nasıl mühürlendiğini satır satır öğreneceğiz.

---

## 2. Linux Audit Framework Mimarisi: Çekirdek ile Disk Arasındaki Köprü

Linux Audit sistemi üç ana katmandan oluşur:

```text
+-------------------------------------------------------------------------------+
|                      1. KERNEL ALANI: KAUDITD SUBSYSTEM                       |
|   • Sistem çağrılarını (open, chmod, execve, init_module) anında yakalar.     |
|   • Dosya izleme kancalarını (file watches) kontrol eder.                     |
|   • Netlink soketi üzerinden olayları tampon belleğe (backlog) yazar.         |
|     (audit_backlog_limit = 8192)                                              |
+-------------------------------------------------------------------------------+
                                       |
                                       v (Netlink Socket)
+-------------------------------------------------------------------------------+
|                      2. KULLANICI ALANI: AUDITD DAEMON                        |
|   • Çekirdekten gelen olay akışını okur.                                      |
|   • /etc/audit/auditd.conf politikalarına göre diske güvenle yazar.           |
|   • Disk dolduğunda önceden tanımlı güvenli aksiyonu alır (halt / single).    |
+-------------------------------------------------------------------------------+
                                       |
                                       v
+-------------------------------------------------------------------------------+
|                      3. ADLİ BİLİŞİM VE RAPORLAMA ARAÇLARI                    |
|   • ausearch: Belirli bir kullanıcıyı, komutu veya anahtarı arar (-k identity)|
|   • aureport: Sistem olaylarının özet istatistiklerini üretir.                |
|   • auditctl: Çalışma zamanında kuralları yönetir ve kilitler.                |
+-------------------------------------------------------------------------------+
```

---

## 3. CIS Benchmark Uyumlu İki Temel Kural Türü

Audit kuralları `/etc/audit/rules.d/audit.rules` dosyasında tanımlanır ve iki ana gruba ayrılır:

### A. Dosya ve Dizin İzleme Kuralları (File Watches: `-w`)
Sistemdeki kritik yapılandırma ve kimlik dosyalarına bir okuma, yazma veya izin değiştirme işlemi yapıldığında tetiklenir:
- **Sözdizimi:** `-w <dosya_yolu> -p <izinler> -k <anahtar>`
  - `-p wa`: Yazma (`w`) ve öznitelik/izin değişikliğini (`a`) izle.
- **Kritik Kurallar:**
  ```ini
  # Kimlik ve parola dosyalarını izle (CIS 4.1.4)
  -w /etc/shadow -p wa -k identity
  -w /etc/passwd -p wa -k identity
  -w /etc/group -p wa -k identity

  # Sudo yetki devrini izle (CIS 4.1.14)
  -w /etc/sudoers -p wa -k actions
  -w /etc/sudoers.d/ -p wa -k actions

  # PAM kimlik doğrulama modüllerini izle (CIS 4.1.13)
  -w /etc/pam.d/ -p wa -k pam
  ```

### B. Sistem Çağrısı Kuralları (Syscall Rules: `-a`)
Kullanıcıların veya arka plan süreçlerinin doğrudan Linux çekirdeğinden talep ettiği kritik eylemleri izler:
- **Çekirdek Modülü Yükleme/Çıkarma (Rootkit Tespiti - CIS 4.1.16):**
  ```ini
  -a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
  ```
  Bir saldırgan sisteme bir kernel rootkit (LKM) enjekte etmeye çalıştığında `init_module` syscall'ı tetiklenir ve saldırganın UID'si, PID'si ve çalıştırdığı ikili dosya anında audit loguna kazınır!
- **Yetkisiz Dosya Erişim Denemeleri (Yetki Aşımı Tespiti - CIS 4.1.10):**
  ```ini
  -a always,exit -F arch=b64 -S open,openat,creat -F exit=-EACCES -F auid>=1000 -k access
  -a always,exit -F arch=b64 -S open,openat,creat -F exit=-EPERM -F auid>=1000 -k access
  ```
  Sıradan bir kullanıcının yetkisi olmayan bir dosyayı okumaya veya değiştirmeye çalışması (EACCES veya EPERM hata kodları) anında alarm üretir.

---

## 4. Değiştirilemezlik Kilidi: `-e 2` (Anti-Tampering)

Evlat, en kritik satır burasıdır!  
Bir saldırgan sunucuda `root` yetkisi elde ettiğinde ilk yapacağı şey `auditctl -D` komutuyla tüm denetim kurallarını silmektir.

Eğer `/etc/audit/rules.d/audit.rules` dosyasının en son satırına:
```ini
-e 2
```
eklersen, çekirdek denetim altyapısını **Değiştirilemez (Immutable)** moduna sokar.
- Anlamı şudur: Artık `root` kullanıcısı dahi kuralları silemez, değiştiremez veya durduramaz!
- Kuralların değiştirilebilmesi için sunucunun fiziksel olarak yeniden başlatılması (reboot) şarttır.
- Bu bayrak, saldırganın izlerini silmesini çekirdek düzeyinde engelleyen en güçlü zırhtır.

---

## 5. Systemd Journald ve Kriptografik Mühürleme (Forward Secure Sealing - FSS)

Modern Linux dağıtımlarında `systemd-journald` servisi tüm süreç loglarını ikili (binary) formatta toplar. Ancak varsayılan olarak iki büyük risk barındırır:
1. `Storage=volatile` ise loglar RAM'de tutulur; sunucu kapandığında tüm adli deliller yok olur!
2. Loglar tahrif edilebilir.

### Çözüm: Kalıcı Depolama ve FSS (Forward Secure Sealing)
`/etc/systemd/journald.conf` içinde:
```ini
[Journal]
Storage=persistent
Compress=yes
Seal=yes
ForwardToSyslog=yes
```
- **Forward Secure Sealing (FSS):** Journald, bir anahtar çifti oluşturur. Belirli zaman aralıklarında (örneğin her 15 dakikada bir) log kayıtlarını kriptografik olarak mühürler ve eski imzalama anahtarını bellekten siler.
- Saldırgan sunucuda root olup log dosyasını ele geçirse bile, geçmişe dönük logları değiştiremez; çünkü eski anahtar artık bellekte yoktur!
- `journalctl --verify` komutu çalıştırıldığında, tahrif edilmiş veya aradan silinmiş tek bir log satırı bile anında kırmızı alarm verir.

---

## 6. Ustanın Çırağa Öğüdü

Evlat! Bir sistemde log yoksa güvenlik de yoktur, adalet de yoktur.
- `auditd` servisini sunucunun kara kutusu bileceksin.
- `/etc/shadow` ve `/etc/sudoers` dosyalarının üzerine gözünü dikeceksin.
- Kurallarının sonuna `-e 2` kilidini asmadan o sunucuyu canlıya almayacaksın.
- Ve Journald'yi mutlaka `persistent` ve `seal=yes` yapacaksın ki yarın bir olay olduğunda geriye dönüp baktığında kimin ne yaptığını bir dedektif gibi kanıtlayabilesin.

Bugün geliştirdiğimiz motor ve araçlar, hem auditd hem de journald altyapısını CIS standartlarında denetleyip sana teslim edecek güçtedir.
