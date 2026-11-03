<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 036 — Soru & Cevap ve Didaktik İnceleme

## G036-SC1: Sanal Bellek Mimarisi, Sayfalama (Paging) ve Swap Bellekteki Hassas Veri Kalıntıları

### Temel Kavram ve Güvenlik Mekanizması
Modern işletim sistemlerinde sanal bellek (virtual memory), işlemci (CPU) bünyesindeki Bellek Yönetim Birimi (MMU - Memory Management Unit) ile çekirdek (kernel) sayfa tablosu (page table) mekanizmasının ortaklaşa yürüttüğü donanım destekli bir soyutlamadır. Her kullanıcı alanı (user-space) süreci, 0x0000000000000000 ile mimarinin sınırına kadar uzanan kesintisiz, izole bir sanal adres uzayına (Virtual Address Space - VAS) sahip olduğunu "zanneder". 

Bu sanal adres uzayı tipik olarak 4 KB'lık (veya HugePages ile 2 MB / 1 GB'lık) mantıksal bloklara, yani "sayfalara" (pages) bölünür. Fiziksel RAM ise aynı boyuttaki "sayfa çerçevelerine" (page frames) ayrılmıştır. Süreç bir bellek adresine erişmek istediğinde MMU, çekirdeğin kontrolündeki sayfa tablosunu sorgular; adres geçerli ve RAM'deyse işlem mikro-saniye mertebesinde gerçekleşir. Sayfa henüz RAM'e yüklenmemişse veya diskteki swap alanına takas edilmişse (paged out), MMU bir donanım kesmesi olan **Sayfa Hatası (Page Fault)** tetikler. Çekirdek kesmeyi yakalar, ilgili sayfayı diskten fiziksel RAM'e okur (page-in) ve sürecin çalışmasına kaldığı yerden devam etmesini sağlar.

Sanal belleğin temel güvenlik mekanizmaları:
1. **Süreç İzolasyonu (Process Isolation):** Hiçbir süreç, komşu bir sürecin sanal adres uzayına çekirdek köprüsü (örneğin `ptrace` veya `process_vm_readv`) ve özel ayrıcalıklar olmaksızın doğrudan erişemez.
2. **Erişim İzinleri ve W^X İlkesi:** Sayfa tablosu girişlerinde Okuma (R), Yazma (W) ve Çalıştırma (X) bitleri yer alır. DEP/NX (Data Execution Prevention / No-Execute) mekanizmasıyla bellek sayfaları ya yazılabilir ya çalıştırılabilir yapılır; her ikisi aynı anda verilmez (`W ^ X`). Bu sayede yığıt (stack) ve öbek (heap) üzerindeki kabuk kodların (shellcode) icrası engellenir.
3. **Swap / Paging Risk Alanı:** Fiziksel RAM yetersizleştiğinde işletim sistemi LRU (Least Recently Used) algoritmasıyla aktif olmayan bellek sayfalarını diske (swap partition veya swapfile) yazar. Bu takas işlemi sırasında şifresiz RAM sayfaları doğrudan kalıcı manyetik/NVMe depolama sektörlerine yazılır. Sistem kapatılsa dahi diskten silinmeyen bu veriler; şifrelenmemiş oturum anahtarları, parola karmaları, JWT token'ları ve özel kriptografik anahtarlar (RSA private keys) içerebilir. Soğuk önyükleme (cold boot) ve disk adli bilişim (forensic analysis) saldırılarına açık kapı bırakır.

### Soru ve Didaktik Çözüm
**Soru:** Sanal bellek adresleme mimarisi işletim sisteminde bellek izolasyonunu ve sayfalama mekanizmasını nasıl sağlar? RAM yetersiz kaldığında devreye giren swap (takas) alanının adli bilişim ve veri sızıntısı açısından oluşturduğu somut güvenlik riskleri nelerdir?

**Didaktik Çözüm:**
Sanal bellek mimarisinde adres çözümleme MMU ve Sayfa Tabloları (CR3 yazmacı / sayfa dizini) üzerinden hiyerarşik (PGD -> P4D -> PUD -> PMD -> PTE) olarak yönetilir. Her sürecin sayfa tablosu birbirinden yalıtılmıştır. Süreç A, kendi sanal `0x00400000` adresine veri yazdığında bu fiziksel RAM'de `Frame 1024`'e yazılırken; Süreç B kendi sanal `0x00400000` adresine yazdığında fiziksel RAM'de tamamen farklı bir adres olan `Frame 8490`'a yazılır. Bu sayede bir sürecin diğerinin belleğini kazara veya kasıtlı olarak çiğnemesi donanımsal düzeyde engellenir.

Swap alanının oluşturduğu somut güvenlik riskleri ise şunlardır:
1. **Kalıcı Depolama Sızıntısı (Persistent Plaintext Exposure):** Normal şartlarda RAM uçucu (volatile) bir bellektir; elektrik kesildiğinde içerisindeki kapasitör yükleri birkaç saniye içinde boşalır. Ancak swap alanı disktir (non-volatile). Diske yazılan sayfa, sistem kapatılsa dahi aylar boyunca sektörlerde silinmeden kalır.
2. **Adli Bilişim ve Ham Veri Kurtarma:** Saldırgan veya yetkisiz adli incelemeci, canlı sistemde doğrudan swap aygıtından (`/dev/dm-X` veya `/swapfile`) veya disk imajından ham veri okuyabilir:
   ```bash
   strings /swapfile | grep -iE 'bearer|password|authorization|private.key'
   ```
   Bu komutla swap alanı taranarak veritabanı bağlantı şifreleri, API gizli anahtarları ve kullanıcı parolaları açık metin (cleartext) olarak çekilebilir.
3. **Korumasız Swap Alanı (Unencrypted Swap):** LUKS veya dm-crypt ile tam disk şifrelemesi (FDE) uygulanmamış sistemlerde swap alanı en zayıf halkadır.

### Savunma ve Tespit Kılavuzu
- **Tespit Mekanizmaları:**
  - Canlı sistemde swap yapılandırmasını ve şifreleme durumunu denetleme:
    ```bash
    swapon --show
    lsblk -f
    cryptsetup status cryptswap1
    ```
  - Hassas süreçlerin sanal bellek haritasını (VMA) ve swap kullanımını izleme:
    ```bash
    cat /proc/<PID>/smaps | grep -i swap
    ```
- **Savunma Stratejileri:**
  1. **Şifreli Swap (Encrypted Swap):** Swap alanı Linux'ta `cryptsetup` ile rastgele anahtarla (`/dev/urandom`) her açılışta yeniden şifrelenmeli veya LUKS altında tutulmalıdır.
  2. **`mlock()` ve `mlockall()` Kullanımı:** Hassas kriptografik anahtarlar ve parola verileri barındıran uygulamalar (örneğin OpenSSL, HashiCorp Vault, GnuPG), ilgili bellek sayfalarını `mlock()` sistem çağrısıyla kilitlemeli ve çekirdeğin bu sayfaları diske takas etmesini kesinlikle engellemelidir.
  3. **Swappiness Optimizasyonu:** Sunucularda gereksiz agresif swap kullanımını engellemek için `vm.swappiness` değeri (varsayılan 60) güvenli ve düşük bir değere (örneğin 10 veya 1) çekilmelidir:
     ```bash
     sysctl -w vm.swappiness=10
     ```
  4. **Güvenli Temizleme (Secure Erase on Shutdown):** Takas alanının sistem kapatılırken rastgele baytlarla ezilmesi (`swapoff -a && shred /swapfile && mkswap /swapfile`).

### Usta-Çırak İpuçları ve Laboratuvar Notu
- *Usta Notu:* "Evlat, geliştiricilerin en büyük yanılgısı 'Ben hassas veriyi RAM'de tuttum, diske hiç yazmadım, o halde güvendeyim' sanmalarıdır. İşletim sistemi RAM baskısı hissettiği anda senin o 'güvenli' sandığın belleğini alıp diskin derinliklerine açık metin olarak çakar. Kripto yazarken `mlock()` çağırmayan geliştirici, anahtarı sokak kapısının paspasının altına bırakmış demektir."
- *Laboratuvar İpucu:* Geliştirdiğimiz denetçi (`memory_virtual_swap_auditor.py`), telemetri verisinde swap alanının şifresiz olduğunu tespit ettiğinde bunu doğrudan **CRITICAL** bulgu olarak raporlamakta ve şifreleme reçetesini sunmaktadır.

---

## G036-SC2: RAM ve Swap Telemetri Analizi, Kontrollü Girdi ve Adli Bellek Denetimi

### Temel Kavram ve Güvenlik Mekanizması
İşletim sistemi telemetri analizinde bellek metrikleri üç ana kategoride incelenir:
1. **Genel Bellek Sağlığı (Host Memory Health):** Toplam RAM, Kullanılan RAM, Boş RAM, Ön Belleğe Alınan (Cached/Buffers) RAM ve Swap doluluk oranı.
2. **Süreç Bazlı Ayak İzi (Process Memory Footprint):**
   - **VSS / VSIZE (Virtual Set Size):** Sürecin talep ettiği ve rezerve ettiği tüm sanal adres uzayı boyutu (yüklenen dinamik kütüphaneler dahil).
   - **RSS (Resident Set Size):** Sürecin o anda fiziksel RAM'de tutulan fiili sayfa çerçevelerinin toplam boyutu.
   - **USS (Unique Set Size):** Yalnızca o sürece özel tahsis edilmiş, başka hiçbir süreçle paylaşılmayan bellek boyutu.
   - **Swap Kullanımı (Swap Paged Out):** Sürecin diske takas edilmiş bellek miktarı.
3. **Kalıntı ve Tehdit Belirteçleri (Artifact Indicators):** Swap alanı veya işlemci bellek dökümü incelendiğinde ortaya çıkan; bellek sızıntısı (memory leak), şişen süreçler (bloated processes), bellek enjeksiyonu şüphesi (yüksek sanal bellek, anomalik RSS) ve şifrelenmemiş swap üzerinde bulunan açık metin sırlar (plaintext credentials).

### Soru ve Didaktik Çözüm
**Soru:** RAM ve swap telemetrisini denetleyen bir araç geliştirirken kontrollü girdi, gözlenebilir çıktı, olumlu/olumsuz testler ve etik sınırlar nasıl modellenmelidir? Bellek metrikleri üzerinden sistem sağlığı ve güvenlik anomalileri nasıl tespit edilir?

**Didaktik Çözüm:**
Güvenilir ve adli geçerliliği olan bir bellek analiz aracı şu mühendislik prensipleriyle inşa edilir:
1. **Kontrollü Girdi (Controlled Input):** Sistem telemetrisi doğrulanmış, yapılandırılmış bir şema ile alınmalıdır (JSON telemetri standardı). Girdide negatif bellek değerleri, eksik zorunlu alanlar veya `used_mb > total_mb` gibi mantıksal tutarsızlıklar peşinen doğrulanmalı (`TelemetryValidationError`), kirli verinin analiz motoruna girmesi engellenmelidir.
2. **Gözlenebilir Çıktı (Observable Output):** Analiz sonuçları hem insan okuyucu için açık metin formatında (Özet, Detay Tablosu, Kritik Bulgular, İyileştirme Önerileri) hem de SIEM/SOAR sistemleri için yapılandırılmış JSON formatında üretilmelidir.
3. **Olumlu ve Olumsuz Doğrulama:**
   - *Olumlu Test:* Standart ve normal sınır lardaki telemetri doğru ayrıştırılmalı, eşik aşımları ve şifresiz swap varlığı hatasız listelenmelidir.
   - *Olumsuz Test:* Negatif RAM değeri (`-16384`), harf içeren metrikler (`"sekiz_bin"`), eksik `host_memory` bloğu ve boş/geçersiz girdi anında yakalanıp temiz hata mesajı üretmelidir.
4. **Etik ve Operasyonel Sınır:** Bellek analizi canlı sistemde yürütülürken çekirdek bellek sayfalarına kontrolsüz yazma yapılmamalı, yalnızca telemetri ve adli kopyalar üzerinden salt-okunur (read-only) analiz gerçekleştirilmelidir. Üretim sistemlerinde `swapoff` komutu aniden çalıştırılarak sistem OOM (Out-of-Memory) paniğine sokulmamalıdır.

### Savunma ve Tespit Kılavuzu
- **Eşik Değer Yönetimi:**
  - RAM Kullanım Oranı: `%80` üzeri UYARI (WARNING), `%90` üzeri KRİTİK (CRITICAL).
  - Swap Kullanım Oranı: `%50` üzeri UYARI, `%75` üzeri KRİTİK.
  - Swap Şifreleme: `is_encrypted: false` ise doğrudan **CRITICAL**.
  - Bireysel Süreç RSS: Tek bir sürecin toplam RAM'in `%25`'inden fazlasını tüketmesi potansiyel DoS veya bellek sızıntısı uyarısıdır.
- **Müdahale Protokolü:**
  - Yüksek RAM tüketen süreçlerin `pmap -x <PID>` veya Windows `vmmap` ile incelenmesi.
  - Bellek sızıntısı olan süreçlerin güvenli yeniden başlatılması veya kaynak limitlerinin (systemd `MemoryMax` veya cgroups) belirlenmesi.

### Usta-Çırak İpuçları ve Laboratuvar Notu
- *Usta Notu:* "Bir sistemde Swap doluluk oranı yükselmeye başlamışsa makine can çekişiyor demektir; disk I/O tavan yapar, sistem 'thrashing' denilen bellek takas girdabına girer ve komutlara dahi yanıt veremez hale gelir. Güvenlik uzmanı sadece saldırıyı değil, sistemin kaynak tükenmesi sonucu servisin çökmesini (Denial of Service) de vaktinde görmelidir."
- *Laboratuvar İpucu:* `tests/test_memory_virtual_swap_auditor.py` modülümüzde 14 bağımsız birim test ile hem matematiksel oran hesaplamaları hem de sınır durumlar (boundary conditions) test edilmiştir.

---

## G036-SC3: Bellek ve Swap Yapılandırma Riskleri, Ayrıcalık Kötüye Kullanımı ve En Az Ayrıcalık İlkesi

### Temel Kavram ve Güvenlik Mekanizması
Bellek ve swap yönetimi, işletim sisteminin en kritik ayrıcalık alanlarından biridir. Linux'ta swap alanını açmak (`swapon`), kapatmak (`swapoff`) veya bellek sayfalarını kilitlemek (`mlock`) doğrudan `CAP_SYS_ADMIN` ve `CAP_IPC_LOCK` çekirdek yetkilerine dayanır. Windows tarafında ise `SeLockMemoryPrivilege` ve `SeIncreaseWorkingSetPrivilege` hakları yönetici hesaplarına tahsis edilir.

Yapılandırma hataları ve zafiyet senaryoları:
1. **Dünya Tarafından Okunabilir Swap Dosyası (World-Readable Swapfile):** Yöneticinin `/swapfile` oluştururken izinleri `0600` yerine varsayılan `0644` bırakması, sistemdeki en düşük yetkili yerel kullanıcının dahi çekirdek ve süreç bellek sayfalarını doğrudan okuyabilmesine yol açar (Yerel Yetki Yükseltme - LPE ve Bilgi İfşası).
2. **Gereksiz Servisler ve Şişen Bellek:** Sunucuda gereksiz çalışan arka plan servisleri (legacy daemons) hem saldırı yüzeyini genişletir hem de fiziksel RAM'i tüketerek kritik süreçlerin swap alanına itilmesine neden olur.
3. **Bellek Aşımı ve Güvensiz OOM-Killer Davranışı:** Sistem belleği tükendiğinde çekirdeğin OOM-Killer (Out of Memory Killer) mekanizması devreye girer. Yanlış `oom_score_adj` yapılandırması sebebiyle çekirdek, saldırganın şişirdiği zararlı süreç yerine kritik güvenlik izleme ajanını (örneğin EDR veya SIEM ileticisini) öldürebilir.

### Soru ve Didaktik Çözüm
**Soru:** Bellek, sanal bellek ve swap yönetimi bağlamında; gereksiz izinler, yanlış yapılandırılmış servisler ve hatalı yetkiler ne tür güvenlik riskleri doğurur? Bu riskler kullanıcı/izin/servis envanteri ile nasıl tespit edilir ve "En Az Ayrıcalık" ilkesiyle nasıl kalıcı biçimde savunulur?

**Didaktik Çözüm:**
1. **Risk Analizi:**
   - Bir swap dosyası veya bölümü yetkisiz okuma izinlerine sahipse, `/dev/kmem` veya `/proc/kcore` gibi çekirdek bellek arayüzlerinin açık bırakılmasıyla eşdeğer bir felaket yaşanır. Saldırgan `grep` veya basit bir Python betiğiyle root süreçlerinin şifrelerini cımbızlar.
   - Bellek kısıtlaması (Memory Limits / Quotas) konulmamış konteyner veya servisler, kontrolsüz bellek ayırma çağrılarıyla (`malloc` bombardımanı) ana makinenin tüm RAM'ini ve swap'ını tüketerek komşu servisleri çökertir (Noisy Neighbor / DoS).
2. **Tespit ve Envanter Yöntemi:**
   - Swap dosyası dosya sistemi izinlerinin denetlenmesi:
     ```bash
     ls -la /swapfile
     # Beklenen izin kesinlikle: -rw------- 1 root root (0600)
     ```
   - Yetkili süreçlerin bellek izinlerinin ve yetkilerinin taranması:
     ```bash
     getpcaps <PID>
     # Yalnızca ihtiyaç duyan servislerde CAP_IPC_LOCK olmalıdır.
     ```
   - Servis bellek kotalarının dökümü:
     ```bash
     systemctl show <servis_adi> -p MemoryCurrent -p MemoryMax
     ```
3. **Savunma Stratejisi (En Az Ayrıcalık & Geri Alınabilir Yapılandırma):**
   - **Swap İzinlerinin Sıkılaştırılması:**
     ```bash
     chmod 0600 /swapfile && chown root:root /swapfile
     ```
   - **Systemd ile Servis İzolasyonu:** Arka plan servislerine bellek üst sınırı konulmalı ve bellek sayfalarını manipüle etme hakları kısıtlanmalıdır:
     ```ini
     [Service]
     MemoryMax=512M
     MemoryHigh=400M
     ProtectKernelTunables=yes
     ProtectControlGroups=yes
     CapabilityBoundingSet=~CAP_SYS_ADMIN ~CAP_IPC_LOCK
     ```
   - **Kriptografik Swap Anahtarlama:** `/etc/crypttab` üzerinden her açılışta `/dev/urandom` ile rastgele anahtar üreten tek kullanımlık şifreli swap yapılandırılması. Sistem kapatıldığında anahtar bellekten silindiği için diskteki swap kalıntısı matematiksel olarak çözülemez hale gelir.

### Savunma ve Tespit Kılavuzu
- **Denetim Listesi (Audit Checklist):**
  1. `/etc/fstab` içinde tanımlı swap alanlarının dosya/bölüm izinleri kontrol edildi mi? (Yalnızca root okuyabilir/yazabilir).
  2. Swap şifrelenmiş mi? (`cryptsetup` veya `dm-crypt`).
  3. Hassas süreçlerde `mlock` kullanılıyor mu ve çekirdeğin bellek sınırları (`ulimit -l`) güvenli aralıkta mı?
  4. Kritik güvenlik servislerinin `oom_score_adj` değeri negatif yapılarak OOM-Killer tarafından sonlandırılması engellendi mi? (`echo -1000 > /proc/<PID>/oom_score_adj`).
- **Geri Alınabilirlik:** Yapılan sysctl (`/etc/sysctl.d/99-security-memory.conf`) ve crypttab değişiklikleri konfigürasyon yönetim araçlarıyla (Ansible/Puppet) versiyonlanmalı, bir sorun anında eski yapılandırmaya dönebilmek için yedekleme yapılmalıdır.

### Usta-Çırak İpuçları ve Laboratuvar Notu
- *Usta Notu:* "Çırak! Bir sunucuya root yetkisiyle girdiğinde ilk yapacağın işlerden biri `ls -l /swapfile` çekmektir. Eğer orada `rw-r--r--` görüyorsan, o sistemin anahtarı yerdeki çamurun içine düşmüş demektir. Sistem yöneticisinin ihmalini saldırgan affetmez."
- *Laboratuvar İpucu:* Geliştirdiğimiz denetim aracı, `corrupted_memory_telemetry_test_cases.json` dosyasında modellediğimiz mantıksal bozulmaları ve yetkisiz bellek tüketimlerini tespit ederek güvenlik uzmanına anında aksiyon planı çıkarmaktadır.
