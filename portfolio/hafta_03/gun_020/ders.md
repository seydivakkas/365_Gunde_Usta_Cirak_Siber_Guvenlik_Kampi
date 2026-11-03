# GÜN 020: Linux Dosya Ağacı ve Dosya Sistemi Hiyerarşisi Standardı (FHS)

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu eğitim materyali Siber Güvenlik 365 Gün Müfredatı kapsamında hazırlanmıştır. İzinsiz kopyalanamaz, çoğaltılamaz ve ticari amaçla kullanılamaz.*

---

## 1. Derse Giriş ve Kavramsal Çerçeve: Linux Tek Kök (`/`) ve FHS Mimarisi

Sevgili öğrencim, dünkü dersimizde Windows'un sürücü harflerine (`C:`, `D:`) dayalı ve NTFS dosya sisteminin sağladığı ACL, MFT ve ADS mimarilerini incelemiştik. Bugün ise kurumsal sunucu altyapılarının, bulut konteynerlerinin ve siber güvenlik savunma araçlarının omurgasını oluşturan **Linux Dosya Sistemi Mimarisi** ve **Filesystem Hierarchy Standard (FHS 3.0)** derinliklerine iniyoruz.

Linux ve Unix türevi sistemlerde "Her şey bir dosyadır" (*Everything is a file*) felsefesi hakimdir. Donanım aygıtları (`/dev/sda`), çalışan süreçlerin bellekleri (`/proc/1234/mem`), çekirdek ayarları (`/sys/kernel/`), ağ soketleri ve borular (pipes) tek bir hiyerarşik ağaç altında temsil edilir. Windows'taki gibi bağımsız sürücü harfleri yoktur; tüm depolama birimleri, ağ paylaşımları ve sanal sözde dosya sistemleri tek bir kök dizine (`/`) bağlanır (*mount edilir*).

FHS standardı (güncel sürüm FHS 3.0), bu hiyerarşi içerisindeki dizinlerin amaçlarını, hangi tür verilerin nerede saklanması gerektiğini ve paylaşılan/paylaşılamayan, statik/değişken veri ayrımını standardize eder. Siber güvenlik mühendisi için FHS, bir sistemin güvenlik sınırlarını, saldırganların yetki yükseltme (privilege escalation) için hedef alacağı alanları ve savunucunun dosya bütünlüğü izleme (FIM) kurallarını belirlediği haritadır.

```
                            / (Tek Kök Dizin)
                                   |
    +--------------+---------------+---------------+---------------+
    |              |               |               |               |
  /bin, /sbin    /etc            /var            /tmp            /home
 (Statik İkili) (Yapılandırma) (Değişken Veri) (Geçici Alan)   (Kullanıcılar)
```

---

## 2. FHS 3.0 Çekirdek Dizinleri ve Siber Güvenlik Rolleri

FHS standardı, sistem dosyalarını iki eksende sınıflandırır:
1. **Paylaşılabilir (Shareable) vs Paylaşılamaz (Unshareable):** Ağ üzerinden diğer sistemlerle paylaşılabilenler (`/usr`, `/opt`) ve yerel makineye özgü olanlar (`/etc`, `/boot`).
2. **Statik (Static) vs Değişken (Variable):** Sistem yöneticisi müdahale etmedikçe değişmeyenler (`/bin`, `/sbin`, `/usr/bin`) ve çalışma zamanında sürekli dinamik olarak değişenler (`/var/log`, `/var/run`, `/tmp`).

### A. `/etc` (Sistem Genelindeki Statik Yapılandırma Dosyaları)
- **Amaç:** İşletim sisteminin ve yüklü servislerin (SSH, Nginx, veritabanı, PAM) yapılandırma dosyalarını barındırır.
- **Güvenlik Önemi:** Yalnızca `root` kullanıcısı tarafından yazılabilir olmalıdır (`0755` dizin izni, kritik dosyalar `0644` veya `0640`). Bu dizindeki bir dosyanın (örneğin `/etc/passwd` veya `/etc/sudoers`) izinsiz değiştirilmesi tam sistem ele geçirmesiyle sonuçlanır.
- **Kritik Dosyalar:**
  - `/etc/passwd`: Kullanıcı kimlikleri, UID, varsayılan kabuk (Tüm kullanıcılar okuyabilir: `0644`).
  - `/etc/shadow`: Parola hash'leri ve yaşlandırma parametreleri (Yalnızca root ve shadow grubu: `0640` / `0600`).
  - `/etc/sudoers`: Yetkili komut çalıştırma kuralları (Yalnızca root: `0440`).

### B. `/var` (Değişken Çalışma Verileri ve Kayıtlar)
- **Amaç:** Loglar (`/var/log`), posta kuyrukları (`/var/spool`), veritabanı dosyaları (`/var/lib`) ve geçici servis verilerini tutar.
- **Güvenlik Önemi:** Log Taşkını (Log Injection) ve Disk Tüketimi (Disk Exhaustion DoS) saldırılarına karşı kök dizinden (`/`) ayrı bir disk bölümü (partition) olarak yapılandırılmalıdır. Aksi halde `/var/log` dolduğunda sistem kilitlenebilir.

### C. `/home` (Kullanıcı Kişisel Ev Dizinleri)
- **Amaç:** Normal sistem kullanıcılarının kişisel dosyaları, belgeleri ve kullanıcı kabuk yapılandırmaları (`~/.bashrc`, `~/.ssh/authorized_keys`).
- **Güvenlik Önemi:** Kullanıcıların ev dizinleri arasında yetkisiz gezinme engellenmeli (`0750` veya `0700` izinleri). Ayrıca, kullanıcıların kendi ev dizinlerine SUID bitli zararlı ikili yükleyip yetki yükseltmelerini engellemek için `/home` dizini `nosuid` ve `nodev` seçenekleriyle bağlanmalıdır.

### D. `/tmp` (Ortak Geçici Dosya Alanı)
- **Amaç:** Sistemdeki tüm süreçlerin ve kullanıcıların geçici tampon dosyalarını yazabileceği dünya çapında yazılabilir (*world-writable*) ortak dizin (`1777` veya `rwxrwxrwt`).
- **Güvenlik Önemi:** Burası saldırganların zararlı yük (payload) indirdiği ve çalıştırdığı bir numaralı yerdir. Mutlaka **Sticky Bit** (`+t`) aktif olmalıdır (böylece Ali, Veli'nin dosyasını silemez/değiştiremez) ve `/tmp` bağımsız bir partition üzerinde `noexec,nosuid,nodev` parametreleriyle mount edilmelidir.

### E. `/dev` (Donanım ve Sanal Aygıt Dosyaları - devtmpfs)
- **Amaç:** Çekirdeğin donanım ve sanal aygıtları bir dosya arabirimiyle kullanıcı alanına sunduğu dizindir (`/dev/sda` blok disk aygıtı, `/dev/urandom` kriptografik rastgele sayı üreticisi, `/dev/null` veri yutucu).
- **Güvenlik Önemi:** Ham disk bloklarına (`/dev/sda`) doğrudan okuma/yazma erişimi olan bir saldırgan dosya izinlerini baypas ederek tüm veriyi çekebilir. Bu nedenle standart kullanıcılara kısıtlıdır.

### F. `/proc` ve `/sys` (Sanal Sözde Dosya Sistemleri - procfs ve sysfs)
- **Amaç:** Sabit diskte yer kaplamayan, doğrudan çekirdek (kernel) bellek durumunu ve süreç tablolarını dosya hiyerarşisi biçiminde sunan sanal dosya sistemleridir.
- **Güvenlik Önemi:** `/proc` altında her çalışan süreç kendi PID numarasıyla bir dizine sahiptir (`/proc/$$/status`, `/proc/$$/cmdline`). Standart yapılandırmada bir kullanıcı diğer tüm kullanıcıların süreçlerini ve parametrelerini görebilir. Bu durum `hidepid=2` mount seçeneğiyle sertleştirilmelidir.

---

## 3. Güvenlik Mekanizmaları: Sticky Bit ve Mount İzolasyonları

Linux'ta dosya sistemi güvenliğinin en kritik iki kalkanı vardır:

### A. Sticky Bit (+t / Oktal 1000)
Normal bir dizinde yazma (`w`) iznine sahip olan herhangi bir kullanıcı, dosyanın sahibi kim olursa olsun o dizindeki dosyaları silebilir veya yeniden adlandırabilir (çünkü dosya silmek dizinin içeriğini değiştirmektir).
`/tmp` ve `/var/tmp` gibi herkesin yazabildiği (`0777`) alanlarda bu bir felakettir; saldırgan diğer kullanıcıların geçici kilit dosyalarını silebilir veya değiştirebilir.
**Sticky Bit Çözümü:** İzin `1777` yapıldığında, dosyayı yalnızca dosyanın sahibi, dizinin sahibi veya `root` silebilir.

### B. Mount Sertleştirme Bayrakları (`/etc/fstab`)
CIS Benchmark ve NIST SP 800-53 kılavuzları gereğince kritik bölümler aşağıdaki bayraklarla sınırlandırılmalıdır:
- `nodev`: Bu dosya sistemi üzerinde karakter veya blok aygıt özel dosyası (`mknod`) oluşturulmasını ve çalıştırılmasını yasaklar.
- `nosuid`: Bu dosya sistemi üzerindeki ikililerde bulunan SUID ve SGID bitlerinin göz ardı edilmesini sağlar; yetki yükseltmeyi doğrudan engeller.
- `noexec`: Bu dosya sistemi üzerinde hiçbir ikilinin (ELF) veya betiğin doğrudan çalıştırılmasına izin vermez. Saldırgan `/tmp` içine zararlı yük indirse dahi çalıştıramaz.

---

## 4. Kritik Sistem Dosyaları ve CWE Zafiyet Analizi

Linux sistem denetiminde ilk incelenen dosya izin matrisi:

| Dosya Yolu | İdeal İzin | İdeal Sahip | Tehdit & CWE Eşleşmesi |
|---|---|---|---|
| `/etc/shadow` | `0640` / `0600` | `root:shadow` veya `root:root` | **CWE-732:** Yanlış İzin Yönetimi. Herkes okuyabilirse parola hash'leri sızar ve çevrimdışı (offline) kırılır. |
| `/etc/passwd` | `0644` | `root:root` | Standart kullanıcılar yazabilirse (`0666`), root yetkisinde yeni kullanıcı eklenebilir. |
| `/etc/sudoers` | `0440` | `root:root` | Dosya üzerinde yazma izni olması durumunda yetkisiz `NOPASSWD: ALL` tanımı yapılabilir. |
| `/tmp` | `1777` | `root:root` | **CWE-377:** Güvensiz Geçici Dosya Oluşturma. Sticky bit eksikse race condition ve dosya gaspı gerçekleşir. |

---

## 5. Saldırı Vektörleri ve Kötüye Kullanım Senaryoları

Bir sızma testinde veya saldırıda FHS zafiyetleri nasıl kullanılır?
1. **World-Writable Dizin Avı:** Saldırgan `find / -type d -perm -0002` komutuyla sticky bit içermeyen herkesin yazabildiği dizinleri arar. Bulduğunda buraya paylaşımlı kütüphane (`.so`) veya zararlı betik bırakır.
2. **SUID Backdoor Barındırma:** Saldırgan `/home` veya `/tmp` üzerinde `chmod +s /tmp/rootbash` oluşturur. Eğer ilgili dizin `nosuid` ile mount edilmemişse, normal kullanıcı bu kabuğu çalıştırarak `root` olur.
3. **Log Injection:** Kötü niyetli girdi göndererek `/var/log/syslog` veya `/var/log/nginx/` dosyalarını aşırı büyüterek kök dizini tüketmek (eğer `/var` ayrı partition değilse servisler çöker).

---

## 6. Savunma, Denetim ve İzleme Stratejileri

Kurumsal savunmada uygulanacak adımlar:
1. **FHS Partition Ayrımı:** Kök (`/`), `/home`, `/var`, `/var/log`, `/var/audit`, `/tmp` mutlaka bağımsız mantıksal birimlere (LVM) ayrılmalıdır.
2. **CIS Benchmark Uyumu:** `/etc/fstab` içinde `/tmp` ve `/home` dizinlerine `nodev,nosuid,noexec` eklenmeli.
3. **Auditd Kuralları:** Kritik FHS alanlarındaki değişiklikler çekirdek düzeyinde denetlenmelidir:
   `-w /etc/shadow -p wa -k identity_modification`
   `-w /etc/sudoers -p wa -k privilege_escalation`
4. **Dosya Bütünlüğü İzleme (FIM):** AIDE veya Tripwire ile `/etc`, `/bin`, `/sbin` hash veritabanı oluşturulup periyodik doğrulanmalıdır.

---

## 7. Usta Notu, Özet ve Çıkarımlar

> **Usta Diyor ki:**  
> "Çırak, Linux'ta kök dizin (`/`) bir ormandır; ancak her ağacın yeri bellidir. Bir saldırgan sistemde ilk ayak izini bıraktığında `/tmp` veya `/dev/shm` dizinine bakar; çünkü oraya yazabileceğini bilir. İyi bir sistem yöneticisi ve güvenlikçi, saldırganın adım atacağı bu alanları `noexec,nosuid,nodev` ile mayınlar ve Sticky Bit ile kilitler. FHS'yi ezberlemek değil, her bir dizinin güvenlik izolasyon mantığını kavramak seni sıradan bir operatörden savunma mimarına dönüştürür."

Yarın **Gün 021** dersimizde, bu dosya ağacı üzerinde çalışan **Linux İzin Yapısı, Erişim Denetimi, Umask ve Özel İzinler (SUID/SGID/Sticky)** konularını kod ve laboratuvar düzeyinde inceleyeceğiz.
