# GÜN 012: Sanal Makine Anlık Görüntü (Snapshot), Yedekleme ve Geri Dönüş Mimarisi
**Aşama 01: Temel Güvenlik ve Altyapı | Hafta 02: Sanallaştırma ve Laboratuvar Temelleri**

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 🧭 1. Hocanın Giriş Sohbeti & Zihinsel Model

Evlat, bugün masamızda bir siber güvenlik uzmanının hayatını hem kurtarabilen hem de yanlış anlaşıldığında bir şirketin tüm veri varlığını bir gecede haritadan silebilen en kritik konulardan biri var: **Anlık Görüntü (Snapshot), Yedekleme (Backup) ve Geri Dönüş (Rollback / Restore)**.

Şimdi gözlerini kapat ve şu analojiyi kafanda canlandır:
Bir bilim insanısın ve ölümcül, son derece bulaşıcı bir virüs üzerinde deney yapıyorsun. Laboratuvar masasında virüs tüpünü açmadan önce bir fotoğraf çekiyorsun ve masadaki her şeyin yerini donduruyorsun. Deney sırasında bir kaza oluyor, virüs masaya saçılıyor. Bir düğmeye basıyorsun ve zaman geriye sarıyor; oda anında virüsün hiç açılmadığı o temiz fotoğraf anına dönüyor! İşte bu mucizevi mekanizmanın adı **Snapshot (Anlık Görüntü)**'tür. 

Peki ya laboratuvarın bulunduğu bina aniden çökerse ya da yangın çıkarsa? O fotoğraf da laboratuvarla birlikte kül olur gider! Çünkü fotoğraf, masanın kendisi değildir; masaya bağımlı geçici bir referanstır. Masadaki tüm eşyaların birebir kopyasını alıp şehrin öbür ucundaki nükleer sığınaktaki yangına dayanıklı çelik bir kasaya kilitlediysen, işte onun adı **Yedek (Backup)**'tır!

Sektöre yeni adım atan gençlerin ve hatta ne yazık ki bazı sistem yöneticilerinin düştüğü en ölümcül yanılgı şudur:  
*"Biz her gece sanal makinelerin snapshot'ını alıyoruz, yedeğimiz tam!"*  
Bu cümle, bilişim dünyasında duyabileceğin en tehlikeli cehalettir. 

Bir SOC analisti, zararlı yazılım araştırmacısı veya sızma testçisi olarak laboratuvarında fidye yazılımlarını (ransomware), truva atlarını patlatacaksın. Sistemi enfekte edip davranışını inceleyecek, ardından saniyeler içinde **Altın Durum'a (Golden State)** geri döneceksin. Bunu snapshot ile yapacaksın. Ancak o laboratuvarın ya da kurumunun verilerini korurken, fidye yazılımlarının bile silemeyeceği **Değişmez (Immutable / WORM)** yedek mimarilerini inşa edeceksin. Bugün bu iki kavramın farkını, hypervisor çekirdeğindeki disk blokları seviyesinde iliklerine kadar öğreneceksin.

---

## 🔬 2. Sıfırdan Kristal Netliğinde Teori (Under the Hood)

Sanal makinelerde disk ve bellek yönetiminin arka planına inelim. Bir sanal disk dosyası (VHDX, VMDK, QCOW2), hypervisor için fiziksel depolama üzerinde duran devasa bir ikili (binary) dosyadan ibarettir.

```
+-------------------------------------------------------------------------------+
|                    ANLIK GÖRÜNTÜ (SNAPSHOT) DİSK MEKANİZMASI                  |
+-------------------------------------------------------------------------------+

  [1. Normal Durum]
  VM Yazma/Okuma ──► [ Ana Disk (base.vhdx) ] (Okuma / Yazma)

  [2. Snapshot Alındığı An]
  Hypervisor:
    a) base.vhdx dosyasını derhal SALT-OKUNUR (Read-Only) olarak kilitler.
    b) Yeni bir Delta / Fark Diski oluşturur (base_diff.avhdx).
    c) (İsteğe bağlı) Bellek (RAM) durumunu diske yazar (.vsv / .vmem).

  [3. Snapshot Sonrası Çalışma]
  VM Okuma İsteği ──► Önce Delta Diske bakar. Blok ordaysa oradan okur;
                      yoksa Ana Diskten okur.
  VM Yazma İsteği ──► YALNIZCA Delta Diske yazar! (Ana diske asla dokunulmaz!)

  [4. Rollback (Geri Dönüş)]
  Hypervisor: Delta diski (base_diff.avhdx) çöpe atar / sıfırlar!
  VM, Ana Diskin dondurulduğu andan tertemiz başlar. Süre: 2-3 saniye!
```

### A. Snapshot Bir Yedek Değildir: Neden?
1. **Ana Diske Mutlak Bağımlılık:** Delta diski tek başına anlamsız bir fark yığınıdır. Ana disk bozulursa, silinirse veya depolama havuzunda (SAN/LUN) donanımsal sektör hatası oluşursa, elindeki tüm snapshot zinciri tamamen ÇÖP olur.
2. **Snapshot Yaşı ve Disk Şişmesi (Snapshot Bloat):** Bir sanal makinede işletim sistemi çalıştıkça loglar yazar, güncellemeler yapar, dosyalar siler. Snapshot açıkken her değişiklik delta diskine yazılır. Zamanla delta diski ana diskten bile daha büyük hale gelebilir! 72 saatten uzun açık kalan snapshot'lar hypervisor'ın tüm veri deposunu (datastore) doldurur. Depolama alanı %100 dolduğunda hypervisor üzerindeki TÜM sanal makineler I/O kilitlenmesine (freeze/crash) girer!
3. **Okuma Gecikmesi (I/O Latency) ve Zincir Derinliği (Sprawl):** Üst üste 4-5 snapshot aldığında (Snapshot 1 -> Snapshot 2 -> Snapshot 3), işletim sistemi bir veri bloğu okumak istediğinde hypervisor zincir boyunca geriye doğru her katmanı taramak zorunda kalır. Disk okuma gecikmesi 5 ms'den 200 ms'ye fırlar; sistem felç olur.
4. **Doğru Kullanım: Geçici Kontrol Noktası:** Snapshot'ın endüstri standardı ömrü maksimum **24 - 72 saattir**. Yama yükleyeceksen veya zararlı analiz edeceksen alırsın; işin bitince ya **Rollback** ile silersin ya da **Merge / Commit** ile delta'yı ana diske birleştirirsin.

### B. Bağımsız Yedekleme ve Kurumsal 3-2-1-1-0 Standardı
Gerçek bir yedekleme, verinin ana depolama mimarisinden tamamen bağımsız bir yere, doğrulanabilir bir bütünlükle kopyalanmasıdır. Modern siber güvenlik dünyasında kabul gören kural **3-2-1-1-0 Kuralı**dır:

| Kural Kodu | Prensip Adı | Teknik Açıklama ve Güvenlik Amacı |
| :---: | :--- | :--- |
| **3** | **En Az 3 Kopya** | 1 Üretim verisi + 2 bağımsız yedek kopyası. |
| **2** | **2 Farklı Medya** | Verileri tek bir teknolojiye emanet etme (Örn: Yerel NVMe SSD + LTO Teyp Kartuşu veya Bulut Nesne Depolama). |
| **1** | **1 Harici (Off-Site) Kopya** | Veri merkezinde yangın, sel veya deprem olursa kopyalardan biri başka bir coğrafi bölgede olmalıdır. |
| **1** | **1 Değişmez (Immutable / WORM) veya Air-Gapped Kopya** | Write Once, Read Many. Hiçbir yetki (Domain Admin veya Root dahil) bu veriyi belirlenen saklama süresi (retention) boyunca silemez ve değiştiremez! |
| **0** | **0 Hata ile Doğrulama (Zero Errors)** | Periyodik geri yükleme tatbikatı yapılmamış ve SHA-256 bütünlüğü doğrulanmamış yedek, yedek değildir! |

### C. RPO ve RTO: Güvenlik Mimarisinin İki Metriği
- **RPO (Recovery Point Objective - Kurtarma Noktası Hedefi):** Bir felaket anında ne kadarlık veri kaybını göze alabilirsin? (Örn: Günde 1 kez gece yedek alıyorsan RPO = 24 saattir; gün içindeki tüm veriler uçar. Saatlik snapshot/log yedeklemesiyle RPO = 1 saate düşürülür).
- **RTO (Recovery Time Objective - Kurtarma Süresi Hedefi):** Sistem çöktükten sonra operasyonu yeniden çalışır hale getirmek için izin verilen maksimum süre nedir? (Örn: RTO = 30 dakika).

---

## ⚔️ 3. İki Yönlü Bakış: Saldırganın Gözü vs Savunmacının Kalkanı

### 🔴 Saldırganın Gözü (Offensive Perspective)
Bir kuruma sızan modern bir fidye yazılımı (LockBit, BlackCat/ALPHV, Conti) veya APT grubu, sistem dosyalarını şifrelemeye başlamadan önce savunmacının geri dönebileceği tüm köprüleri havaya uçurur:
1. **Windows Gölge Kopyalarının (VSS) İmhası:**
   Saldırgan yetki yükselttiği anda şu komutları otomatik çalıştırır:
   ```cmd
   vssadmin delete shadows /all /quiet
   wmic shadowcopy delete
   wbadmin delete catalog -quiet
   bcdedit /set {default} bootstatuspolicy ignoreallfailures
   bcdedit /set {default} recoveryenabled no
   ```
   Bu komutlar işletim sisteminin yerel geri yükleme noktalarını siler ve Windows'un başlangıç onarım mekanizmasını felç eder.
2. **Hypervisor ve Snapshot İmhası:**
   Saldırgan ESXi veya Hyper-V yönetim paneline sızarsa, tüm VM snapshot'larını `vim-cmd vmsvc/snapshot.removeall` veya `Remove-VMSnapshot` ile siler.
3. **Açık Ağ Yedeklerinin Şifrelenmesi:**
   Eğer yedek depolama alanı aynı yerel ağda (flat network) bir SMB paylaşımı olarak duruyorsa ve Domain Admin kimliğiyle erişilebiliyorsa, saldırgan yedek dosyalarını (.vbk, .tib, .vhdx) ya siler ya da doğrudan şifreler.
4. **Zaman Bombası (Sleeper Payload):**
   Saldırgan sisteme girdikten sonra hemen şifreleme yapmaz. 90 gün boyunca sessizce bekler. Kurum 30 günlük yedek tutuyorsa, 30 günün sonunda tüm yedek depoları farkında olmadan saldırganın arka kapısını (backdoor) yedeklemiş olur!

### 🔵 Savunmacının Kalkanı (Defensive Perspective)
1. **WORM ve Değişmezlik (Object Lock / Linux Hardened Repository):**
   Yedek sunucusu Linux üzerinde `chattr +i` veya AWS S3 / MinIO üzerinde `Object Lock (Compliance Mode)` ile yapılandırılır. Domain Admin veya yedek yöneticisi bile olsa, API veya konsoldan silme isteği gönderildiğinde donanım seviyesinde `Access Denied` yanıtı döner.
2. **Hava Boşluğu (Air-Gapping) ve Ağ İzolasyonu:**
   Yedek sunucusu üretim Active Directory etki alanına (domain) ASLA üye yapılmaz. Tamamen ayrı bir yönetim VLAN'ında, izole kimlik doğrulama ile tutulur.
3. **Kriptografik Bütünlük (SHA-256 Manifest):**
   Her alınan tam yedek dosyasının anında SHA-256 özeti çıkarılır ve kriptografik bir manifestoya yazılır. Geri dönüş yapılmadan önce dosyanın özeti tekrar hesaplanır. Tek bir bit dahi uyuşmazsa geri yükleme durdurulur.
4. **Periyodik Geri Dönüş Tatbikatları (Restore Drills):**
   Yedeğin çalıştığını kanıtlamanın tek yolu, onu izole bir sanal ağda ayağa kaldırmaktır.

---

## 🛠️ 4. Hocayla Birlikte Canlı Laboratuvar

Şimdi kendi terminalimizde çalıştıracağımız gerçek komutlarla ve geliştirdiğimiz otomasyon aracıyla snapshot ve yedek yönetimini icra edeceğiz.

### Adım 1: Hyper-V / PowerShell Üzerinde Gerçek Snapshot Komutları
Eğer Windows üzerinde Hyper-V kullanıyorsan, yönetici PowerShell penceresinde şu komutları kullanırsın:

```powershell
# 1. Sanal makinenin durumunu ve mevcut disklerini listele
Get-VM -Name "Windows-11-Analiz-Hostu"

# 2. Zararlı yazılım testi öncesi anlık görüntü (Checkpoint/Snapshot) oluştur
Checkpoint-VM -Name "Windows-11-Analiz-Hostu" -SnapshotName "Temiz_Altin_Durum_Pre_Infection"

# 3. Alınan snapshot'ı doğrula
Get-VMSnapshot -VMName "Windows-11-Analiz-Hostu"

# 4. Test bitti, zararlı bulaştı; anında temiz duruma geri dön (Rollback)
Restore-VMSnapshot -VMName "Windows-11-Analiz-Hostu" -Name "Temiz_Altin_Durum_Pre_Infection" -Confirm:$false

# 5. İnceleme bittiğinde snapshot'ı silerek delta diskini ana diske birleştir (Merge)
Remove-VMSnapshot -VMName "Windows-11-Analiz-Hostu" -Name "Temiz_Altin_Durum_Pre_Infection"
```

### Adım 2: Linux KVM / QEMU Üzerinde Gerçek Snapshot Komutları
Eğer Linux terminalindeysen:

```bash
# 1. Ana diskten salt-okunur türetilmiş bir delta diski oluştur (QCOW2)
qemu-img create -f qcow2 -b ubuntu_base.qcow2 -F qcow2 ubuntu_diff.qcow2

# 2. Virsh ile canlı sanal makine anlık görüntüsü al
virsh snapshot-create-as --domain Ubuntu-SIEM --name "Guncelleme_Oncesi_Snap" --description "Cekirdek oncesi kontrol noktasi"

# 3. Snapshot listesini ve hiyerarşisini gör
virsh snapshot-list --domain Ubuntu-SIEM --tree

# 4. Temiz duruma geri dön
virsh snapshot-revert --domain Ubuntu-SIEM --snapshotname "Guncelleme_Oncesi_Snap"
```

### Adım 3: Geliştirdiğimiz Python Aracı ile Denetim ve Güvenlik Analizi
Laboratuvarımızdaki sanal makinelerin snapshot sağlığını ve fidye yazılımı açıklarını denetleyelim:

```bash
# Tüm laboratuvar sanal makinelerini denetle
python portfolio/hafta_02/gun_012/uygulama/vm_snapshot_backup_manager.py --envanter portfolio/hafta_02/gun_012/ornek_veri/vm_lab_envanteri.json

# VM-SEC-WIN-01 için derinlemesine risk analizi yap
python portfolio/hafta_02/gun_012/uygulama/vm_snapshot_backup_manager.py --envanter portfolio/hafta_02/gun_012/ornek_veri/vm_lab_envanteri.json --vm-id VM-SEC-WIN-01 --denetle

# Yeni bir güvenlik snapshot'ı oluştur
python portfolio/hafta_02/gun_012/uygulama/vm_snapshot_backup_manager.py --envanter portfolio/hafta_02/gun_012/ornek_veri/vm_lab_envanteri.json --vm-id VM-SEC-WIN-01 --snapshot-al "Pre_Exploit_Rollback_Point"

# Rollback icra ederek sistemi temiz duruma getir
python portfolio/hafta_02/gun_012/uygulama/vm_snapshot_backup_manager.py --envanter portfolio/hafta_02/gun_012/ornek_veri/vm_lab_envanteri.json --vm-id VM-SEC-WIN-01 --rollback SNAP-WIN-01
```

---

## ⚠️ 5. Hocanın "Ölümcül Hatalar" Notu

1. **"Snapshot Aldık, Güvendeyiz" Yanılgısı:**  
   Bir snapshot, ana disk dosyasından bağımsız değildir. Hypervisor depolama alanı bozulursa hem ana disk hem de snapshot zinciri aynı anda buharlaşır. Snapshot bir yedek değil, geçici bir geri alma noktasıdır.
2. **Snapshot'ı Unutmak (Snapshot Bloat / Datastore Exhaustion):**  
   Yama yaparken veya test amacıyla alınan bir snapshot 1 ay unutulursa, delta diski yüzlerce gigabayt büyür. Sonunda hypervisor diskinde 1 bayt bile boş yer kalmaz; aynı depolama havuzunu paylaşan tüm kritik üretim sunucuları aniden kilitlenir ve çöker.
3. **Schrödinger'in Yedeği:**  
   Geri yükleme tatbikatı (restore drill) yapılmamış bir yedeğin sağlam olup olmadığını bilemezsin. Yedekleme yazılımı ekranda yeşil yandı diye yedeği çalışıyor sanmak intihardır. Veri tabanları kilitli dosyalar yüzünden bozuk yedeklenmiş olabilir.
4. **Yedek Sunucusunu Active Directory Domain'ine Katmak:**  
   Yedek sunucunuz kurumsal domain'e üyeyse, domain admin parolasını ele geçiren bir saldırgan doğrudan yedek sunucusuna da girer ve tüm yedekleri siler. Yedekleme altyapısı daima izole ve harici kimlik doğrulamalı olmalıdır.
5. **Geri Dönüş Öncesi Bütünlük (Hash) Kontrolü Yapmamak:**  
   Bozulmuş veya kötü niyetli kişilerce manipüle edilmiş bir yedek imajını doğrudan canlı ortama yüklemek, sistemin açılmamasına veya sistem içine yerleştirilmiş bir arka kapının bizzat yönetici eliyle canlıya alınmasına yol açar.

---

## 🎯 6. Günün Pratik Görevi + Çözüm Yürüyüşü

### Pratik Görev Tanımı:
Aşama 01 Hafta 02 kapsamındaki sentetik laboratuvar ortamında yer alan `VM-SEC-WIN-01` (Windows Analiz Hostu) ve `VM-VULN-SRV-99` makinelerinin denetlenmesi; tespit edilen "Snapshot-as-Backup" yanılgısının, 72 saat aşımının ve WORM kilidi eksikliğinin raporlanması; ardından `VM-SEC-WIN-01` üzerinde yeni bir temiz analiz snapshot'ı alınarak güvenli rollback ve kriptografik hash doğrulamalı tam bağımsız yedekleme akışının icra edilmesi.

### Adım Adım Çözüm Yürüyüşü:
1. **Envanter ve Politika Yüklemesi:** `ornek_veri/vm_lab_envanteri.json` ve `restore_drill_policy.json` dosyaları yüklendi.
2. **Risk Denetiminin Çalıştırılması:**  
   `VM-SEC-WIN-01` makinesinde:
   - `RISK-01-SNAP-AS-BACKUP`: Snapshot var fakat hiçbir bağımsız yedek yok (-30 puan).
   - `RISK-02-SNAPSHOT-AGE-EXCEEDED`: Snapshot yaşı 73.5 saat (> 72 saat sınırı aşıldı, -20 puan).
   - `RISK-04-IMMUTABILITY-MISSING`: Değişmezlik kilidi kapalı (-20 puan).
   Toplam denetim skoru 30/100 (TEHLİKELİ) olarak saptandı.
3. **Temiz Snapshot Alınması:**  
   `snapshot_olustur("VM-SEC-WIN-01", "Pre_Exploit_Rollback_Point", ...)` çağrısıyla ana disk salt-okunur kilitlendi, yeni delta diski açıldı.
4. **Rollback Doğrulaması:**  
   Zararlı bulaşması simülasyonu sonrası `snapshot_geri_don` metoduyla delta diski sıfırlandı ve sistem saniyeler içinde altın duruma döndürüldü.
5. **Değişmez Bağımsız Tam Yedek Üretimi:**  
   `tam_yedek_olustur` metoduyla bağımsız bir depolama hedefine (`s3://immutable-lab-backups/...`) SHA-256 özetli ve WORM kilitli tam yedek çıkarıldı.
6. **Birim Test Kapsamı:** Yazılan 14 test ile pozitif altın akış, negatif güvenlik sınırları ve hash manipülasyonu durumunda `BackupIntegrityError` fırlatılması %100 doğrulandı.

---

## ❓ 7. Hocanın Soru Odası

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
