# GÜN 012: Soru-Cevap Odası (Derinlemesine Teknik Analiz)
**Konu:** Anlık Görüntü (Snapshot), Yedekleme ve Geri Dönüş Mekanizmaları  
**Tarih:** 2026-10-27  

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

### Soru 1 (G012-SC1): Anlık görüntü, yedek ve geri dönüş: Temel mekanizmayı ve güvenlik önemini açıkla.

#### 1. Net ve Doğrudan Yanıt
Snapshot (anlık görüntü), sanal makinenin mevcut durumunu dondurup değişiklikleri bir delta (fark) diskine yazarak saniyeler içinde test öncesine dönmeyi sağlayan geçici bir referans noktasıdır; asla bağımsız bir yedek değildir. Yedek (backup) ise verinin ana depolama havuzundan tamamen bağımsız, farklı bir ortama kopyalanarak olağanüstü durum ve felaket senaryolarında kurtarılmasını sağlayan kalıcı kopyadır.

#### 2. Derin Teknik Gerekçe ve Mantık
Snapshot alındığında hypervisor ana sanal diski (VHDX/VMDK) salt-okunur (read-only) olarak kilitler ve tüm yeni I/O yazma işlemlerini yeni açılan bir delta/differencing diskine yönlendirir (Copy-on-Write / Redirect-on-Write). Geri dönüş (rollback) işlemi yalnızca bu delta dosyasının atılması veya sıfırlanmasıyla gerçekleştiğinden saniyeler sürer; bu durum laboratuvarda zararlı yazılım analizi ve sızma testi deneyleri için muazzam bir hız sağlar. Ancak delta diski ana diske göbekten bağlıdır; ana diskin bulunduğu fiziksel depolama ünitesi (LUN/RAID) çökerse veya fidye yazılımı ana diski bozarsa tüm snapshot zinciri yok olur. Gerçek bir yedekleme ise ana diskten bağımsızdır, 3-2-1-1-0 kuralı gereğince ağdan izole veya değişmez (WORM) depolarda tutulur ve ana makine tamamen yansa bile veriyi ayağa kaldırabilir.

#### 3. Yaygın Hata ve Sektör Yanılgısı
En ölümcül hata, snapshot'ı kalıcı bir yedekleme stratejisi sanmaktır. Bir diğer yaygın operasyonel hata, snapshot'ları haftalarca açık bırakmaktır. Açık unutulan snapshot'lar kontrolsüzce büyüyerek (snapshot sprawl/bloat) hypervisor'ın tüm veri deposunu doldurur ve o depoyu paylaşan düzinelerce sanal sunucunun aynı anda kilitlenip çökmesine yol açar.

#### 4. Resmî Standart ve Kaynak
- **NIST SP 800-209:** *Security Guideline for Storage Infrastructure* (Bölüm 5.3: Virtual Storage and Snapshot Isolation).
- **ISO/IEC 27001:2022 Control 8.13:** *Information Backup* (Yedeklerin ana sistemden bağımsız, test edilmiş ve fiziksel/mantıksal olarak izole tutulması gerekliliği).

---

### Soru 2 (G012-SC2): Anlık görüntü, yedek ve geri dönüş: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

#### 1. Net ve Doğrudan Yanıt
Laboratuvarın girdisi; sanal makine disk ve snapshot konfigürasyonunu içeren envanter verisi (`vm_lab_envanteri.json`) ve geri dönüş politikasıdır (`restore_drill_policy.json`). İşlemi; snapshot oluşturma, rollback icrası, değişmez (immutable) tam yedek üretimi ve 6 kritik kritere göre risk denetimidir. Beklenen sonucu; temiz duruma saniyeler içinde dönülmesi ve doğrulanmış SHA-256 özetli bağımsız yedek alınmasıdır. Negatif kontrolü ise; snapshot'ı yedek sanma hatasının, 72 saatlik yaş aşımının ve hash uyuşmazlığında geri yüklemenin reddedilmesinin (`BackupIntegrityError`) doğrulanmasıdır.

#### 2. Derin Teknik Gerekçe ve Mantık
Laboratuvar motoru (`vm_snapshot_backup_manager.py`), işletim sisteminden bağımsız olarak sanallaştırma disk katmanını ve yedekleme politikalarını denetler. Pozitif akışta, 3-2-1 kuralına uygun ve değişmez (WORM) yedekli Linux sunucusu 100/100 tam puan alır. Negatif kontrollerde ise:
1. Yedeği olmayan fakat snapshot'ı olan makinede `RISK-01-SNAP-AS-BACKUP` uyarısı verilir.
2. 72 saati aşan snapshot tespit edildiğinde `RISK-02-SNAPSHOT-AGE-EXCEEDED` cezası uygulanır.
3. 3'ten fazla iç içe geçmiş snapshot varsa I/O gecikme riski (`RISK-03-DEEP-SNAPSHOT-CHAIN`) raporlanır.
4. Geri yükleme tatbikatında dosyanın SHA-256 özeti eşleşmediğinde (örneğin fidye yazılımı dosyayı tahrif etmişse), motor işlemi durdurarak veri tabanının zehirlenmesini engeller.

#### 3. Yaygın Hata ve Sektör Yanılgısı
Laboratuvarda negatif kontrolü test etmeden yalnızca "snapshot aldım ve çalıştı" demek, savunmanın doğrulanmadığı anlamına gelir. Gerçek dünyada bir yedekleme sürecinin en kritik adımı, yedek dosyasının tahrif edildiği (bit-rot veya kötü niyetli enjeksiyon) senaryoda sistemin bu durumu yakalayıp geri yüklemeyi reddetme refleksini test etmektir.

#### 4. Resmî Standart ve Kaynak
- **NIST NICE Framework:** *Work Role: Systems Security Integration (OM-NET-001) & Incident Response (PR-IR-001)*.
- **CIS Critical Security Controls v8:** *Control 11: Data Recovery* (11.1: Automated Backups, 11.2: Perform Complete System Restores, 11.4: Protect Backups with Immutability).

---

### Soru 3 (G012-SC3): 'Anlık görüntü, yedek ve geri dönüş' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Net ve Doğrudan Yanıt
Risk; kurumun tek bir savunma mekanizmasını (yalnızca yerel snapshot veya yerel VSS gölge kopyalarını) eksiksiz bir felaket kurtarma kalkanı sanmasıyla oluşur. Tespit; depolama analizlerinde 72 saati aşmış devasa delta disklerinin bulunması, bağımsız yedek eksikliği ve saldırganın `vssadmin delete shadows` komutunu çalıştırmasıyla oluşan olay günlükleriyle (Event ID 4688) yapılır. Önleme ise; 3-2-1-1-0 yedekleme mimarisi, WORM değişmezlik kilidi ve ağdan izole hava boşluğu (air-gap) kontrolleriyle sağlanır.

#### 2. Derin Teknik Gerekçe ve Mantık
Bir saldırgan kurumsal ağa sızıp yetki yükselttiğinde (Domain Admin veya Local System), şifreleme öncesi işletim sisteminin yerel gölge kopyalarını (`vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`) siler ve hypervisor snapshot'larını imha eder. Eğer savunmacı yalnızca bu yerel mekanizmalara güvenmişse, veri kaybı %100'e ulaşır.
- **Tespit Mekanizmaları:**
  - *Windows Güvenlik Günlükleri (Event ID 4688 - Process Creation):* `vssadmin.exe` veya `wmic.exe` araçlarının şüpheli parametrelerle (`delete shadows`, `shadowcopy delete`) çalıştırılması anında SIEM alarmı üretmelidir.
  - *Hypervisor Depolama Alarmları:* LUN/Datastore doluluk oranı %80'i aştığında veya delta diski boyutu ana diskin %50'sine ulaştığında uyarı tetiklenmelidir.
- **Savunma Kontrolleri:**
  - *Değişmezlik (Immutability / WORM):* S3 Object Lock veya Linux Hardened Repository üzerinde yedekler belirli süre silinemez kılınır. Saldırgan root yetkisiyle dahi silme komutu gönderse depolama denetleyicisi komutu reddeder.
  - *Air-Gap (Hava Boşluğu):* Yedek sunucusu kurumsal Active Directory'den tamamen ayrı, bağımsız kimlik denetimiyle ve yalnızca yedekleme penceresinde açılan izole kanallarla korunur.

#### 3. Yaygın Hata ve Sektör Yanılgısı
En ölümcül sektör yanılgısı; "Bir güvenlik önlemini tek başına eksiksiz savunma sanmaktır." VSS veya Snapshot bir konfor aracıdır; siber saldırı veya donanım arızası karşısında tek başlarına birer hiçtirler. Savunma ancak derinlemesine savunma (Defense-in-Depth) ve çok katmanlı bağımsız kopyalarla ayakta kalır.

#### 4. Resmî Standart ve Kaynak
- **MITRE ATT&CK Framework:** *Technique T1490: Inhibit System Recovery* (Saldırganların VSS, snapshot ve yedek kataloglarını silme teknikleri).
- **CISA Alert (AA23-061A):** *#StopRansomware Guide* (Yedeklerin çevrimdışı tutulması, değişmezlik kilitleri ve düzenli geri yükleme tatbikatları tavsiyeleri).
