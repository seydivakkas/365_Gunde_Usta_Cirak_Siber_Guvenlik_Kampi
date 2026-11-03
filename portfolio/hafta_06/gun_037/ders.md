<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 037 — Disk Bölümleri ve Dosya Sistemleri Mimarisi

**Usta-Çırak / Hoca Dersi**  
*Aşama 02: Sistem ve Ağ Temelleri — Hafta 06: İşletim Sistemi Güvenliği ve Temel Ağ Mimarisi*

---

## 1. Usta Girişi: Diskin Anatomisi ve Katmanlar Ayrımı
Evlat, dün seninle işletim sisteminin beyni olan belleği, sanal adreslemeyi ve takas alanını inceledik. Bugün ise işletim sisteminin kalıcı hafızasına, yani **Disk Bölümleri (Partitions)** ve **Dosya Sistemleri (Filesystems)** dünyasına iniyoruz.

Bir siber güvenlik uzmanının veya sistem mimarının asla düşmemesi gereken en büyük kavram karmaşası şudur: **Fiziksel Disk**, **Bölüm (Partition)**, **Birim (Volume)** ve **Dosya Sistemi (Filesystem)** aynı şey değildir! Bu dört katmanı birbirine karıştıran bir uzman; adli bilişim incelemesinde delili bozar, sistem sertleştirmede (hardening) kritik bir güvenlik bayrağını atlar ve veri kurtarma operasyonunda tüm diski sıfırlar.

Katman hiyerarşisi şöyledir:
```text
[ Fiziksel / Mantıksal Donanım ] : /dev/nvme0n1 veya PhysicalDrive0
              │
              ▼ (Bölümleme Tablosu: MBR veya GPT)
[ Bölümler (Partitions) ]         : /dev/nvme0n1p1, /dev/nvme0n1p2 (LBA sektör aralıkları)
              │
              ▼ (Kriptografik Katman / Mantıksal Birim: LUKS, BitLocker, LVM)
[ Birimler (Volumes) ]            : /dev/mapper/cryptroot, C:\, D:\
              │
              ▼ (Dosya Sistemi Formatı: ext4, NTFS, XFS, Btrfs, FAT32)
[ Dosya Sistemi (Filesystem) ]    : Dizin ağacı, Inode/MFT tabloları, erişim izinleri (ACL/DAC)
              │
              ▼ (İşletim Sistemi Çekirdeği VFS Bağlantısı: Mount)
[ Bağlama Noktası (Mount Point)]  : /, /tmp, /var, /boot/efi
```

Şimdi bu katmanları mimari, adli bilişim ve saldırı-savunma ekseninde adım adım parçalayalım.

---

## 2. Bölüm Tabloları Mimarisi: Eski MBR vs Modern GPT

### 2.1. Eski MBR (Master Boot Record) Mimarisi ve Güvenlik Zaafı
MBR, 1983 yılında IBM PC DOS 2.0 ile hayatımıza giren ve sektör 0'a (LBA 0 - ilk 512 bayt) sığdırılmış ilkel bir yapıdır:
- **0 - 445 Bayt:** Birincil Önyükleme Kodu (Bootstrap Code). BIOS bu 446 baytı RAM'in `0x7C00` adresine kopyalar ve CPU kontrolünü buraya bırakır.
- **446 - 509 Bayt:** Bölüm Tablosu (Partition Table). Her biri 16 bayt olan yalnızca **4 adet** birincil bölüm kaydı barındırır ($16 \times 4 = 64$ bayt).
- **510 - 511 Bayt:** Önyükleme İmzası (Magic Boot Signature: `0x55 0xAA`).

**MBR'ın Siber Güvenlik Riskleri:**
1. **Bootkit ve Sektör 0 Manipülasyonu:** MBR'ın ilk 446 baytına yazma hakkı elde eden bir zararlı yazılım (MBR Rootkit / Bootkit, örn. Stone, Petya, Stoned), işletim sistemi çekirdeği yüklenmeden önce CPU'yu ele geçirir. Antivirüs veya EDR daha belleğe yüklenmediği için tespit edilemez.
2. **Yedek Tablo Eksikliği:** MBR diskin yalnızca başında bulunur. Sektör 0 bozulduğunda veya üzerine tek bir bayt rastgele yazıldığında tüm disk geometrisi ve bölüm haritası anında yok olur.
3. **Bütünlük Doğrulaması Yoktur:** Bölüm tablosu verilerini doğrulayan hiçbir sağlama toplamı (CRC/Checksum) veya dijital imza bulunmaz.
4. **2.2 TB Adresleme Sınırı:** 32-bit LBA adresleme sebebiyle $2^{32} \times 512 = 2.19\text{ TB}$ üzerindeki disk alanlarını adresleyemez.

### 2.2. Modern GPT (GUID Partition Table) ve UEFI Güvenliği
GPT, modern UEFI standardının bir parçası olarak tasarlanmıştır ve MBR'ın tüm yapısal zaaflarını çözer:
1. **Protective MBR (Koruyucu MBR - LBA 0):** GPT diskin ilk sektörüne (LBA 0) sahte bir MBR kaydı yerleştirilir. Eski MBR tabanlı disk araçları bu diski gördüğünde "tüm diski kaplayan tek bir bilinmeyen bölüm" zanneder ve diski silmeye çalışmaz.
2. **Birincil GPT Başlığı (Primary GPT Header - LBA 1):** Diskin benzersiz GUID kimliğini, disk boyutunu, bölüm tablosunun konumunu ve en önemlisi **GPT başlığının CRC32 sağlama toplamını** içerir.
3. **128 Bölüm Girdisi (LBA 2 - 33):** Her biri 128 bayt olan en az 128 adet bağımsız bölüm tanımlanabilir. Her bölümün kendine ait bir Bölüm Türü GUID'i (Partition Type GUID) ve Benzersiz Bölüm GUID'i vardır.
4. **Yedek / İkincil GPT (Secondary GPT - Diskin En Sonu):** GPT başlığı ve 128 bölüm kaydı, diskin en son sektörlerinde (LBA -34 ile LBA -1) birebir kopyalanır. Birincil başlık bozulsa veya zararlı bir müdahale olsa dahi UEFI yazılımı ve çekirdek, yedek başlıktaki CRC32 doğrulamasıyla bölüm haritasını anında onarır.
5. **Secure Boot Entegrasyonu:** UEFI Secure Boot ile birlikte GPT disklerdeki önyükleme bölümleri (`/boot/efi`) yalnızca Microsoft veya kurum sertifikasıyla imzalanmış bootloader'ların (shim, grub2, Windows Boot Manager) çalışmasına izin verir.

---

## 3. Dosya Sistemleri ve Yetki Modelleri (DAC vs İzin Yoksunluğu)

### 3.1. ext4 (Linux Fourth Extended Filesystem)
Linux dünyasının en olgun günlüklemeli (journaling) dosya sistemidir:
- **Superblock:** Dosya sisteminin toplam blok sayısı, boş bloklar, boş inode sayısı, blok boyutu (genelde 4096 bayt) ve dosya sistemi durum bayraklarını tutar.
- **Inode (Index Node):** Dosyanın adı hariç tüm meta verilerini depolar: Dosya boyutu, sahip kullanıcı kimliği (UID), grup kimliği (GID), erişim modları (POSIX rwxrwxrwx, SUID, SGID, Sticky bit), zaman damgaları (atime, mtime, ctime) ve veri bloklarının fiziksel adreslerini gösteren Extent ağacı.
- **Journaling (JBD2):** Elektrik kesintisi veya ani çökme anında dosya sistemi bütünlüğünün bozulmasını önlemek için disk işlemlerini önce günlüğe (journal) yazar, ardından ana bloklara işler.

### 3.2. NTFS (New Technology File System)
Windows NT tabanlı modern sistemlerin standart dosya sistemidir:
- **Master File Table ($MFT):** Diskteki her dosya ve dizin için en az bir 1024 baytlık kayıt tutan devasa bir veritabanıdır. Dosya boyutu küçükse ($< 700$ bayt) verinin kendisi doğrudan MFT kaydı içine yazılır ("resident file").
- **Gelişmiş Güvenlik Tanımlayıcıları ($Secure & ACLs):** Her dosya bir Güvenlik Tanımlayıcısına (Security Descriptor - SD) sahiptir. İçinde Sahip SID, DACL (Discretionary Access Control List) ve SACL (System Access Control List - Denetim/Olay Günlüğü) bulunur.
- **Alternatif Veri Akışları (Alternate Data Streams - ADS):** Bir dosya altında birden fazla veri akışı saklanabilir (`dosya.txt:gizli.exe`). Saldırganlar ve EDR sistemleri tarafından zararlı payload gizleme veya webden indirilen dosyalara "Zone.Identifier:Identifier=3" (Mark-of-the-Web - MOTW) basma amacıyla kullanılır.

### 3.3. Güvensiz Dosya Sistemleri: FAT32 ve exFAT Tuzağı
FAT (File Allocation Table) mimarisi 1970'lerin sonlarında disketler için tasarlanmıştır:
- **POSIX İzni veya Windows ACL Desteği KESİNLİKLE YOKTUR.**
- Dosya bazında Okuma/Yazma/Çalıştırma izinleri tanımlanamaz. Bir Linux sunucuda `/dev/sdb1` FAT32 ile bağlanırsa, tüm dosyalar varsayılan bağlama izinleriyle (`fmask=0000`, `dmask=0000` -> `0777`) görünür.
- Sistemdeki en yetkisiz servis veya web kullanıcısı (`nobody`, `www-data`), o dosya sistemindeki her veriyi okuyabilir, silebilir ve çalıştırabilir.
- Sabit sunucu disklerinde veya veri depolarında FAT32 kullanmak ölümcül bir güvenlik ve denetim zaafıdır.

---

## 4. Bağlama Bayrakları ve Sertleştirme (Mount Options Hardening)
Linux'ta `/etc/fstab` dosyası sistemin hangi disk bölümlerini hangi dizinlere, hangi güvenlik kısıtlamalarıyla bağlayacağını belirler.

Bir saldırganın sisteme sızdığında ilk aradığı şey **"Dünya tarafından yazılabilir ama üzerinde ikili dosya çalıştırılabilir"** (World-Writable & Executable) dizinlerdir. Bunların başında `/tmp`, `/var/tmp` ve `/dev/shm` gelir.

| Bağlama Seçeneği | Güvenlik Mekanizması ve Saldırı Engelleme |
| :--- | :--- |
| `noexec` | İlgili dosya sistemi üzerinde hiçbir ikili dosyanın (ELF executable) doğrudan `execve()` sistem çağrısıyla çalıştırılmasına izin vermez. Saldırgan web kabuğu (webshell) ile `/tmp` dizinine zararlı derleyip çalıştıramaz. |
| `nosuid` | Dosya sistemi üzerindeki SUID (Set User ID) ve SGID bitlerini hükümsüz kılar. Saldırgan bir kök kabuğu (suid bash) kopyalasa dahi dosya normal kullanıcı yetkisiyle icra edilir; yetki yükseltme (LPE) engellenir. |
| `nodev` | Dosya sistemi üzerinde karakter veya blok aygıt dosyalarının (`mknod` ile `/dev/sda` benzeri düğümlerin) oluşturulmasını ve okunmasını engeller. |
| `ro` | Dosya sistemini salt-okunur (read-only) yapar. Değiştirilemez olması gereken ikili kütüphaneler (`/usr` veya yedek bölümleri) için uygulanır. |

**Örnek Sertleştirilmiş `/etc/fstab` Girişi:**
```text
# <file system>                             <mount point>   <type>  <options>                       <dump>  <pass>
/dev/mapper/nvme0n1p2_crypt                 /               ext4    errors=remount-ro               0       1
/dev/mapper/nvme0n1p3_crypt                 /var            ext4    defaults,nodev,nosuid           0       2
tmpfs                                       /tmp            tmpfs   defaults,noexec,nosuid,nodev    0       0
tmpfs                                       /dev/shm        tmpfs   defaults,noexec,nosuid,nodev    0       0
```

---

## 5. Tam Disk Şifreleme (FDE - Full Disk Encryption) ve Uyuyan Tehdit
Veri hareketsizken (Data-at-Rest) korunmuyorsa, sunucunun kapısındaki fiziksel kilit veya işletim sisteminin oturum açma şifresi sahte bir güvenlik hissiyatından ibarettir.

Eğer sunucunun sabit diski şifrelenmemişse:
1. Saldırgan makineyi yeniden başlatıp bir Ubuntu Live USB takar.
2. BIOS/UEFI önyükleme sırasını USB'ye verir.
3. Kök dosya sistemini bağlar:
   ```bash
   mount /dev/nvme0n1p2 /mnt
   cat /mnt/etc/shadow
   chroot /mnt passwd root
   ```
4. Parolayı saniyeler içinde değiştirir veya tüm veritabanı dosyalarını harici diske çeker.

**Savunma Reçetesi:**
- **Linux:** LUKS2 (Linux Unified Key Setup) ile `dm-crypt` çekirdek modülü üzerinden `aes-xts-plain64` şifrelemesi.
- **Windows:** TPM 2.0 (Trusted Platform Module) çipiyle donanım düzeyinde kilitlenmiş BitLocker (XTS-AES 256).
- **Önyükleme Doğrulaması:** TPM PCR (Platform Configuration Register) yazmaçları ile önyükleme yazılımının (shim, grub, kernel) bütünlüğü ölçülür; kod değiştirilmişse şifre çözme anahtarı asla TPM'den dışarı verilmez.

---

## 6. Usta-Çırak Özeti ve Laboratuvar Görevi
Çırak! Bugün yazdığımız denetçi (`disk_partition_fs_auditor.py`) sana bir sistemin disk altyapısını salt-okunur telemetri üzerinden nasıl röntgenleyeceğini gösterdi. 
- MBR gördüğünde: "Eski mimari, bootkit riski, modern GPT'ye geç!" diyeceksin.
- FAT32'yi veri diskinde gördüğünde: "Burada dosya izinleri yok, güvenlik delik deşik!" diyeceksin.
- `/tmp` üzerinde `noexec` olmadığını gördüğünde: "Saldırgan buraya zararlı indirip çalıştırabilir, hemen fstab'ı sertleştir!" diyeceksin.
- Şifresiz disk gördüğünde: "Fiziksel temas anında tüm sırlar ifşa olur, LUKS/BitLocker şart!" diyeceksin.

Şimdi bu mimariyi soru-cevap ve raporlama adımlarıyla taçlandıralım!
