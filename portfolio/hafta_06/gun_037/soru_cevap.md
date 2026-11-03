<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 037 — Soru & Cevap ve Didaktik İnceleme

## G037-SC1: Disk Bölümleri, Birimler ve Dosya Sistemleri Katman Ayrımı ve Güvenlik Önemi

### Temel Kavram ve Güvenlik Mekanizması
Depolama mimarisinde fiziksel aygıt, bölüm (partition), birim (volume) ve dosya sistemi (filesystem) birbirine bağımlı ancak işletim sistemi soyutlamasında tamamen farklı katmanları temsil eder:
1. **Fiziksel / Mantıksal Disk (Block Device):** Donanım düzeyindeki ham depolama alanıdır (örn. `/dev/nvme0n1`, `\\.\PhysicalDrive0`). Doğrudan bloklar (LBA - Logical Block Addressing) halinde veri okuma ve yazma arayüzü sunar.
2. **Bölüm (Partition):** Diskin bölüm tablosu (MBR veya GPT) tarafından belirlenen kesintisiz LBA sektör aralıklarıdır (örn. `/dev/nvme0n1p1`). Fiziksel diskin sınırlarını çizer.
3. **Birim (Volume):** Bir veya birden fazla bölümün üzerine inşa edilen, bazen yazılımsal RAID, LVM (Logical Volume Manager) veya şifreleme katmanı (LUKS `dm-crypt`, Windows BitLocker) ile sarmalanan mantıksal depolama alanıdır (örn. `/dev/mapper/cryptroot`, `C:\`).
4. **Dosya Sistemi (Filesystem):** Bu birim üzerine biçimlendirilen ve veriyi insan tarafından anlaşılabilir dizin ağaçları, dosyalar, meta veriler (inodeler, MFT) ve erişim kontrol listeleri (POSIX DAC, NTFS ACL) halinde organize eden mantıksal yapıdır (örn. ext4, NTFS, XFS).

Güvenlik ve Veri Bütünlüğü Riski: Bu katmanların sınırları karıştırıldığında, örneğin bir dosya sistemi denetimi (`fsck`) yerine ham disk bölümüne doğrudan biçimlendirme komutu verildiğinde (`mkfs.ext4 /dev/nvme0n1` yerine yanlışlıkla tüm diski ezen ham aygıta müdahale), veya LUKS şifreli birimin altındaki ham bölüme (`/dev/nvme0n1p2`) dosya sistemi yazıldığında, tüm kriptografik üstbilgiler (LUKS header) kalıcı olarak yok olur ve kurtarılamaz veri kaybı yaşanır.

### Soru ve Didaktik Çözüm
**Soru:** Disk bölümleri, birimler ve dosya sistemleri arasındaki mimari ve kavramsal farklar nelerdir? Bu katmanların işletim sisteminde yanlış tanımlanması veya yanlış birime müdahale edilmesi ne tür güvenlik açıklarına ve operasyonel felaketlere yol açar?

**Didaktik Çözüm:**
- **Kavramsal Ayrım:**
  - Bir bölüm fiziksel bir sınır çizgisidir (haritada bir arsanın sınırları gibidir).
  - Birim, bu sınırların üzerine çekilen mantıksal temeldir (arsaya dökülen beton zemin).
  - Dosya sistemi ise o beton zeminin üzerine inşa edilen odalar, kapılar ve kilitlerdir (yapısal düzenleme ve erişim yetkileri).
- **Yanlış Müdahale Senaryoları:**
  1. **Kriptografik Başlık İmhası:** LUKS2 veya BitLocker ile şifrelenmiş bir disk bölümünde, şifrelenmiş kapsayıcı açılmadan (unlocked edilmeden) doğrudan ham bölüme yazma yapılırsa, anahtar yuvaları (keyslots) ezilir. İçerideki petabaytlarca veri matematiksel olarak sonsuza kadar kilitlenir.
  2. **Bağlama Noktası ve Yetki Çakışması:** `/tmp` için ayrılan bölüm yerine yanlışlıkla `/var` bölümü `noexec` bayrağıyla bağlanırsa, `/var/lib` altındaki paket yöneticileri (dpkg/apt) ve dinamik kütüphaneler çalıştırılamaz hale gelir ve sistem anında felç olur.
  3. **Adli Bilişim Delil Bozulması:** Adli kopya (forensic image) alınırken `/dev/sda1` (tek bir bölüm) yerine `/dev/sda` (tüm disk) alınmazsa, MBR/GPT tablosu, silinmiş bölümler arasındaki ayrılmamış alanlar (unallocated space) ve Slack Space alanlarındaki gizli saldırgan izleri delil zincirinden düşer.

### Savunma ve Tespit Kılavuzu
- **Tespit ve Doğrulama:**
  - Linux'ta katmanları hiyerarşik olarak haritalamak:
    ```bash
    lsblk -f
    # Çıktıda NAME, FSTYPE, FSVER, LABEL, UUID, FSAVAIL, FSUSE%, MOUNTPOINTS hiyerarşisi görülür.
    ```
  - Windows'ta PowerShell ile disk, bölüm ve birim ilişkisini listelemek:
    ```powershell
    Get-Disk | Get-Partition | Get-Volume
    ```
- **Savunma Stratejisi:**
  - Kritik disk işlemlerinden (`fdisk`, `parted`, `mkfs`, `cryptsetup`) önce mutlaka aygıt UUID'leri kontrol edilmelidir (`blkid`). Sabit `/dev/sdX` isimlendirmeleri sistem yeniden başlatıldığında değişebileceğinden, `/etc/fstab` dosyalarında her zaman `UUID=xxxx` kullanılmalıdır.
  - Salt-okunur doğrulama yapılmadan hiçbir biçimlendirme veya yeniden boyutlandırma komutu çalıştırılmamalıdır.

### Usta-Çırak İpuçları ve Laboratuvar Notu
- *Usta Notu:* "Evlat, komut satırında elin `mkfs` veya `dd` komutuna gidiyorsa iki kez değil, on kez durup düşüneceksin. `/dev/sdb` ile `/dev/sdb1` arasındaki tek bir rakam farkı, bir şirketin 10 yıllık müşteri veritabanının yok olmasıyla sonuçlanabilir. Siber güvenlikte acele eden değil, doğrulamayı ilke edinen hayatta kalır."
- *Laboratuvar İpucu:* Geliştirdiğimiz denetçi (`disk_partition_fs_auditor.py`), diskleri ve bölümleri hiyerarşik olarak ayrı nesneler halinde modeller ve kullanılan alanın toplam alanı aşması gibi tutarsızlıkları peşinen reddeder.

---

## G037-SC2: Bağımsız Salt-Okunur Disk Denetimi, Kontrollü Girdi ve Negatif Test Metodolojisi

### Temel Kavram ve Güvenlik Mekanizması
Üretim ortamlarında ve olay müdahale (incident response) süreçlerinde disk ve dosya sistemleri denetlenirken sistemin canlı durumuna zarar vermemek esastır. Bu ilkeye **Salt-Okunur İnceleme Prensibi (Read-Only Inspection Principle)** denir.

Güvenilir bir disk güvenlik denetçisinin mimari bileşenleri:
1. **Kontrollü Girdi (Controlled Input):** Sistem telemetrisi doğrulanmış, yapılandırılmış bir JSON şeması ile alınır. Girdi şeması; disk boyutları, bölüm tabloları, dosya sistemleri ve bağlama seçeneklerini eksiksiz içermelidir.
2. **Gözlenebilir Çıktı (Observable Output):** Üretilen rapor; insan tarafından okunabilir Markdown ve konsol metin formatlarında, her bir bulgunun ciddiyet derecesini (`CRITICAL`, `HIGH`, `MEDIUM`, `WARNING`), etkilenen hedefi ve somut iyileştirme adımlarını (remediation) açıkça ortaya koymalıdır.
3. **Olumlu ve Olumsuz Doğrulama:**
   - *Olumlu Test (Positive Control):* Standart, geçerli telemetri verisi hatasız ayrıştırılmalı, bilinen güvenlik zaafları (MBR kullanımı, FAT32 veri diski, /tmp üzerinde missing `noexec`, şifresiz birimler) doğru kategorize edilmelidir.
   - *Olumsuz Test (Negative Control):* Mantıksal ve şematik olarak bozulmuş veriler (negatif disk boyutu, `used_gb > total_gb`, sayısal olmayan kapasite, string olmayan dosya sistemi türü) denetçi tarafından anında tespit edilmeli ve temiz bir `DiskTelemetryValidationError` fırlatılmalıdır.
4. **Etik ve Operasyonel Sınırlar:** Canlı disk üzerinde zararlı kod enjeksiyonu veya agresif formatlama yapılmaz; yalnızca işletim sisteminin sunduğu `lsblk`, `df`, `findmnt` veya Windows WMI/CIM salt-okunur arayüzleri kullanılır.

### Soru ve Didaktik Çözüm
**Soru:** Disk bölümleri ve dosya sistemlerini denetleyen bağımsız bir güvenlik laboratuvarının kontrollü girdisi, işlem basamakları, beklenen çıktıları ve negatif kontrol senaryoları neler olmalıdır?

**Didaktik Çözüm:**
1. **Girdi:** `sample_disk_telemetry.json` dosyası. Bu dosya `/dev/nvme0n1` (GPT, LUKS şifreli root, unhardened `/tmp`) ve `/dev/sdb` (MBR, unencrypted FAT32 storage, %93 doluluk) bileşenlerini içerir.
2. **İşlem:**
   - Şema doğrulama (`validate_telemetry_schema`)
   - Bölüm tablosu denetimi (`audit_partition_tables`) -> MBR tespiti
   - Dosya sistemi ve şifreleme analizi (`audit_filesystem_and_encryption`) -> FAT32 ve şifresiz birim tespiti
   - Bağlama seçenekleri sertleştirme kontrolü (`audit_mount_options_hardening`) -> `/tmp` üzerinde `noexec/nosuid/nodev` kontrolü
   - Kapasite tükenme analizi (`audit_capacity_and_exhaustion`) -> %85 ve %95 eşik kontrolleri
3. **Beklenen Çıktı:** 100 üzerinden hesaplanan güvenlik puanı, metrik tablosu ve her bir bulgu için düzeltme reçetesi içeren Markdown raporu.
4. **Negatif Kontroller:** `corrupted_disk_telemetry_test_cases.json` dosyasında tanımlanan:
   - Negatif boyut: `-500 GB` -> Doğrulama hatası yakalanır.
   - Kapasite taşması: `100 GB` toplam alanda `150 GB` kullanım -> Doğrulama hatası yakalanır.
   - Eksik disks anahtarı -> Doğrulama hatası yakalanır.
   - Hatalı tip: Dosya sistemi alanı tamsayı (`12345`) -> Doğrulama hatası yakalanır.

### Savunma ve Tespit Kılavuzu
- **Canlı Sistemde Salt-Okunur Komut Seti:**
  ```bash
  # Linux: Blok aygıtları ve bağlama bayraklarını salt-okunur dökme:
  lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,RO,RM
  findmnt -l -o TARGET,SOURCE,FSTYPE,OPTIONS
  
  # Windows: Disk ve birim durumunu salt-okunur dökme:
  Get-BitLockerVolume
  Get-Volume | Select-Object DriveLetter, FileSystemType, SizeRemaining, Size
  ```
- **Otomasyon ve Sürekli İzleme:** Denetim aracı CI/CD veya merkezi yapılandırma denetim sistemlerine (Ansible/OpenSCAP) entegre edilerek sunucu dağıtımlarında fstab sertleştirmesi otomatik denetlenmelidir.

### Usta-Çırak İpuçları ve Laboratuvar Notu
- *Usta Notu:* "Bir denetim yazılımının gücü sadece doğruyu bulmasıyla değil, yanlış veya bozuk veriyi gördüğünde paniklemeden, sessizce çökmeden, zarifçe hatayı yakalayıp operatöre bildirmesiyle ölçülür. Negatif kontroller mühendisin sigortasıdır."
- *Laboratuvar İpucu:* 14 birim testimiz (`test_disk_partition_fs_auditor.py`), bu kontrol matrisini 0.003 saniyede %100 kapsama ile doğrulamaktadır.

---

## G037-SC3: Disk ve Dosya Sistemi Yapılandırma Riskleri, Ayrıcalık Kötüye Kullanımı ve En Az Ayrıcalık Kuralı

### Temel Kavram ve Güvenlik Mekanizması
Disk bölümleri ve dosya sistemleri seviyesindeki zafiyetler sistemin en derin güvenlik katmanlarını tehdit eder:
1. **Dünya Tarafından Yazılabilir Geçici Dizinlerde Kod Yürütme (World-Writable Execution):** `/tmp` ve `/var/tmp` gibi dizinler tasarım gereği tüm kullanıcılar ve servisler tarafından yazılabilmelidir (`chmod 1777`). Ancak bu dizinler `noexec` bayrağı olmadan bağlanırsa, sisteme sızan bir saldırgan (örneğin Apache veya Nginx yetkisiyle çalışan bir web kabuğu) `/tmp/evil.elf` dosyasını diske yazar ve doğrudan çalıştırarak komut satırına erişir.
2. **SUID İle Yerel Yetki Yükseltme (SUID Abuse on Non-Root Mounts):** Harici bir USB bellek veya paylaşımlı depolama alanı `nosuid` bayrağı olmadan bağlanırsa; saldırgan kendi yetkisindeki bir makinede kök yetkisi verilmiş bir kabuk (`chmod 4755 /bin/bash`) oluşturup USB'ye kopyalar. Hedef sunucuya bu USB'yi taktığında, hedefte root yetkisi elde eder.
3. **Korumasız Dosya Sistemleri (FAT32/exFAT):** Dahili sunucu disklerinde FAT32 kullanılması, işletim sisteminin tüm kimlik denetimini (authentication) ve yetkilendirme (authorization) mimarisini etkisiz hale getirir. Dosyaların sahibi ve erişim izinleri olmadığı için herkes her şeye tam yetkilidir.
4. **Hizmet Reddi (Disk Exhaustion DoS):** Disk kotaları ve log döndürme (logrotate) yapılandırılmadığında, `/var/log` bölümü dolar. Disk dolduğunda `sshd`, `sudo`, `systemd-journald` gibi kritik servisler yeni oturum açamaz ve denetim kayıtları yazılamayarak adli görünürlük kaybolur.

### Soru ve Didaktik Çözüm
**Soru:** Disk bölümleri ve dosya sistemleri bağlamında; gereksiz izinler, yanlış servisler ve hatalı bağlama yapılandırmaları ne tür riskler doğurur? Bu riskler kullanıcı, izin ve servis envanteriyle nasıl tespit edilir ve "En Az Ayrıcalık" ile "Geri Alınabilir Yapılandırma" ilkeleriyle nasıl engellenir?

**Didaktik Çözüm:**
1. **Risk Tespiti ve Envanter:**
   - **Bağlama Bayrakları Envanteri:** `/etc/fstab` ve canlı bağlama tablosu (`/proc/mounts`) incelenerek `/tmp`, `/var/tmp`, `/dev/shm` dizinlerinde `noexec,nosuid,nodev` bayraklarının varlığı taranır.
   - **Dosya Sistemi Envanteri:** `blkid` ve `lsblk` ile FAT32, exFAT gibi izinsiz dosya sistemlerinin sunucu disklerinde bulunup bulunmadığı listelenir.
   - **Şifreleme Envanteri:** `cryptsetup status` ve Windows `Get-BitLockerVolume` ile şifresiz veri birimleri tespit edilir.
   - **Disk Doluluk Envanteri:** `df -h` ve `df -i` (inode doluluğu) ile %85 üzeri birimler belirlenir.
2. **Savunma Stratejisi (En Az Ayrıcalık):**
   - **fstab Sertleştirmesi:**
     ```text
     # /tmp dizini için en az ayrıcalık:
     tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=2G 0 0
     ```
   - **Anında ve Geri Alınabilir Uygulama:**
     Sistemi yeniden başlatmadan bayrakları güncellemek:
     ```bash
     mount -o remount,noexec,nosuid,nodev /tmp
     ```
   - **Rollback Güvencesi:** `/etc/fstab` değiştirilmeden önce zaman damgalı yedek alınmalıdır (`cp -p /etc/fstab /etc/fstab.bak.$(date +%F)`). Hatalı bir fstab sistemin kurtarma moduna (emergency mode) düşmesine yol açabilir.
   - **Disk Kotaları ve Bölüm Ayrımı:** Kök (`/`), günlükler (`/var/log`), geçici dosyalar (`/tmp`) ve kullanıcı ev dizinleri (`/home`) bağımsız disk bölümlerine ayrılmalıdır. Böylece `/tmp` veya `/var/log` dolsa dahi sistemin kök dosya sistemi kilitlenmez.

### Savunma ve Tespit Kılavuzu
- **Sertleştirme Doğrulama Tablosu:**
  | Bölüm | Zorunlu Bayraklar | Risk Açıklaması |
  | :--- | :--- | :--- |
  | `/tmp` | `noexec, nosuid, nodev` | Zararlı ikili çalıştırmayı ve SUID yetki yükseltmeyi önler. |
  | `/var/tmp` | `noexec, nosuid, nodev` | Uzun ömürlü geçici dosya alanı üzerinden istismarı engeller. |
  | `/dev/shm` | `noexec, nosuid, nodev` | Paylaşılan bellek tabanlı kabuk çalıştırmalarını durdurur. |
  | `/home` | `nosuid, nodev` | Kullanıcıların kendi dizinlerinde sahte aygıt veya SUID oluşturmasını engeller. |
- **Windows Karşılığı:** Windows'ta NTFS sürücülerinde "AppLocker" veya "Software Restriction Policies" ile `C:\Windows\Temp` ve `AppData` dizinlerinden `.exe` ve `.dll` çalıştırılması engellenir.

### Usta-Çırak İpuçları ve Laboratuvar Notu
- *Usta Notu:* "Çırak, bir Linux sunucuyu sertleştirmeye gittiğinde fstab'a bakıp `/tmp` satırında `noexec` görmüyorsan, o kapıyı kilitleyip anahtarı üzerinde bırakmışsın demektir. Web uygulamasındaki küçücük bir dosya yükleme açığı, `/tmp` üzerinde `noexec` varsa basit bir metin dosyası olarak kalır; `noexec` yoksa bir kök kabuğuna (root shell) dönüşür."
- *Laboratuvar İpucu:* Geliştirdiğimiz denetim yazılımı, `/tmp` üzerinde `noexec` eksikliğini doğrudan **HIGH** önem seviyesinde raporlayarak savunma uzmanına hazır fstab yönergesi sunmaktadır.
