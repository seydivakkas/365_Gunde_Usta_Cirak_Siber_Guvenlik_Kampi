# Gün 151: Yedek Doğrulama ve Kurtarma Noktası — Soru & Cevap

---

## 1. Soru: Değiştirilemez Depolama (WORM / Object Lock) ve Compliance vs Governance Modu

### Soru
3-2-1-1-0 yedekleme kuralında yer alan Değiştirilemezlik (Immutability / WORM) kavramı ile bulut nesne depolamadaki (AWS S3 Object Lock) "Compliance Mode" ve "Governance Mode" arasındaki mimari fark nedir ve bir fidye yazılımı saldırısında neden yalnızca Compliance modu tam garanti sağlar?

### Detaylı ve Kapsamlı Teknik Cevap
WORM (Write Once, Read Many), bir verinin depolama medyasına bir kez yazıldıktan sonra belirlenen saklama süresi (retention period) boyunca hiçbir kullanıcı, süreç veya sistem yöneticisi tarafından silinmesini veya değiştirilmesini engelleyen donanımsal ve mantıksal bir kilit mekanizmasıdır. Modern bulut ve nesne depolama sistemlerinde (AWS S3, Azure Blob Immutable, Google Cloud Storage Bucket Lock) bu mekanizma **Object Lock** API'si ile yönetilir.

Object Lock iki temel çalışma moduna sahiptir:
1. **Governance Mode (Yönetişim Modu):**
   - Bu modda korunan bir nesneyi standart kullanıcılar veya servis hesapları silemez.
   - Ancak özel bir IAM iznine (`s3:BypassGovernanceRetention`) veya root/admin yetkisine sahip bir kullanıcı, silme korumasını atlayabilir veya saklama süresini kısaltabilir.
   - **Fidye Yazılımı Açığı:** Günümüz fidye yazılımı çeteleri (LockBit, BlackCat) yalnızca yerel sunucuları ele geçirmekle kalmaz; ortamdaki `.aws/credentials`, Azure CLI token'ları veya Terraform kasalarını tarayarak bulut yönetici anahtarlarını çalarlar. Eğer yedekler Governance modundaysa, saldırgan `s3:BypassGovernanceRetention` parametresini kullanarak tüm bulut yedeklerini saniyeler içinde silebilir.
2. **Compliance Mode (Yasal Uyum / Regülasyon Modu):**
   - Bu mod, SEC Rule 17a-4, FINRA ve CFTC gibi en katı finansal regülasyonlara uygun olarak tasarlanmıştır.
   - Bir nesne Compliance modunda mühürlendiğinde; **AWS HESABININ ROOT KULLANICISI DAHİL HİÇBİR IAM ROLÜ, KULLANICI VEYA AWS DESTEK MÜHENDİSİ** o nesneyi saklama süresi dolana kadar silemez, üzerine yazamaz veya retention süresini geriye çekemez.
   - Hatta bu sürede AWS hesabı kapatılmak istense bile, içerisinde kilitli Compliance nesneleri bulunan S3 bucket silinemez.

Bu sebeple fidye yazılımlarına karşı kurumsal dayanıklılık inşa edilirken Governance modu asla nihai savunma hattı olarak kabul edilemez; yasal ve siber garanti yalnızca **Compliance Mode** ile sağlanır.

### Ustanın Çırağa Tavsiyesi / Altın Kural
"Evlat, yedekleme mimarına 'Yedeklerimiz bulutta değiştirilemez mi?' diye sorduğunda sana 'Evet, governance modunda tutuyoruz' derse, ona fidyecilerin ilk önce o governance yetkisini çalacağını hatırlat. Bir yedeğe root kullanıcısı bile dokunabiliyorsa, o yedek fidye yazılımı karşısında sahipsizdir. Kural basittir: Kritik kopyayı **Object Lock COMPLIANCE** modunda mühürleyeceksin; anahtarı da takvime asacaksın, süresi dolmadan kimse o kilidi açamayacak."

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2021 yılında uluslararası bir lojistik şirketi hedefli bir fidye yazılımı saldırısına uğradı. Saldırganlar bir DevOps mühendisinin bilgisayarına sızarak AWS Admin yetkilerine sahip API anahtarlarını ele geçirdiler. Şirketin tüm yerel sunucuları şifrelendikten sonra saldırganlar buluttaki S3 yedekleme bucket'ına yöneldiler. Şirket S3 üzerinde Object Lock kullanıyordu ancak ayar **Governance Mode** olarak bırakılmıştı. Saldırganlar ele geçirdikleri admin yetkisiyle `aws s3api delete-object --bypass-governance-retention` komutunu çalıştırarak 45 TB'lık tüm kurumsal yedek arşivini tamamen sildiler. Şirket hiçbir yedekten geri dönemedi ve operasyonlarını 3 hafta boyunca kağıt-kalemle yürütmek zorunda kaldı.

---

## 2. Soru: RPO ve RTO Hesaplama Tuzakları ve Sessiz Veri Bozulması (Bit Rot)

### Soru
RPO (Recovery Point Objective) ve RTO (Recovery Time Objective) metrikleri belirlenirken yapılan en kritik mimari hesaplama hataları nelerdir ve bant genişliği darboğazları, veri tekilleştirme (deduplication) yeniden oluşturma (rehydration) süreleri ile sessiz veri bozulması (bit rot) RTO'yu nasıl felakete sürükler?

### Detaylı ve Kapsamlı Teknik Cevap
RPO ve RTO genellikle iş birimleri tarafından kağıt üzerinde "RPO: 15 dakika, RTO: 1 saat" şeklinde kolayca talep edilir. Ancak bu hedeflerin teknik altyapı ile doğrulanmaması büyük bir felaket illüzyonuna yol açar.

**1. Veri Tekilleştirme (Deduplication) ve Rehydration Tuzağı:**
Modern yedekleme cihazları (Data Domain, ExaGrid) depolama maliyetini düşürmek için 10:1 veya 20:1 oranında tekilleştirme yapar. Veri yazılırken bloklar parçalanır ve işaretçilerle (pointers) saklanır. Ancak felaket anında terabaytlarca veriyi geri yüklerken cihaz o parçalanmış blokları tekrar birleştirmek (**Rehydration**) zorundadır. Yazarken 1 GB/s ile yazan bir yedekleme ünitesi, tekilleştirilmiş veriyi birleştirip geri yüklerken 80-100 MB/s seviyesine düşebilir. 50 TB'lık bir veritabanının geri yüklenmesi kağıt üzerinde 4 saat hesaplanırken, rehydration darboğazı yüzünden 28 saat sürebilir ve RTO hedefi feci şekilde patlar!

**2. Ağ ve Bant Genişliği Darboğazı:**
Bulutta duran 100 TB'lık bir yedeği yerel veri merkezine çekmek istediğinizde, şirketinizin 1 Gbps internet hattı tam kapasiteyle (gece-gündüz hiç aksamadan) çalışsa bile bu transfer matematiksel olarak yaklaşık **10 gün** sürer! RTO hedefiniz 4 saat ise buluttan ham veri indirme planı baştan çökmüştür. Bu nedenle hızlı RTO için yerel birincil önbellek kopyası (Local Fast Restore Appliance) zorunludur.

**3. Sessiz Veri Bozulması (Bit Rot) ve Kriptografik Sağlama:**
Manyetik disklerde depolanan arşiv dosyalarında bit seviyesinde meydana gelen bozulmalar (Bit rot), dosyanın işletim sistemi tarafından okunabilmesini engellemez; ancak geri yükleme aracının veri bloklarını açarken `CRC/Checksum Error` verip durmasına yol açar. Eğer yedekler periyodik olarak SHA-256 bütünlük taramasından (Scrubbing) geçirilmemişse, yönetici felaket anında 3 saat boyunca geri yükleme yapar ve %99'a geldiğinde arşivin bozuk olduğu ortaya çıkar. Bu durum RTO süresini sıfırlar ve şirketi ikinci bir felakete sürükler.

### Ustanın Çırağa Tavsiyesi / Altın Kural
"Çırak, yöneticiler RTO'yu 1 saat yazdığında onlara Excel tablosunu değil, fizik ve matematik kurallarını göstereceksin. '100 TB veriyi 1 Gbps hattan kaç saatte çekersin?' diye soracaksın. Yedekleme mühendisliği kağıt üzerindeki temennilerle değil; disk I/O hızı, rehydration gecikmesi, ağ bant genişliği ve periyodik geri yükleme test sürelerinin toplamıyla yapılır. Test etmediğin süreyi SLA diye kimseye taahhüt etmeyeceksin."

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2020 yılında büyük bir e-ticaret platformu Black Friday öncesinde veritabanı sunucusunda donanımsal arıza yaşadı. Şirketin taahhüt ettiği RTO 2 saatti ve son tam yedekleri mevcuttu. Ancak yedekleme yazılımı aşırı tekilleştirme (extreme deduplication) kullanıyordu ve veritabanı dosyaları yüz binlerce parçaya bölünmüştü. Geri yükleme başlatıldığında yedekleme ünitesinin CPU'su rehydration işlemi sırasında %100'e kilitlendi ve geri yükleme hızı saniyede 12 MB'a kadar düştü. 2 saatte açılması gereken sistem tam 36 saat boyunca kapalı kaldı. Şirket milyonlarca dolar ciro kaybı yaşadı ve hisse değerleri sert düştü.

---

## 3. Soru: Windows Volume Shadow Copy (VSS) İstismarı ve Çekirdek Seviyesi Savunma

### Soru
Windows ortamlarında çalışan fidye yazılımları (LockBit, Conti, REvil) sistem kurtarmayı engellemek (MITRE ATT&CK T1490) için Volume Shadow Copy (VSS) mekanizmasını nasıl hedef alır ve sistem yöneticileri `vssadmin`, `wmic` ve PowerShell tabanlı gölge kopya silme girişimlerini çekirdek ve ACL seviyesinde nasıl bloke eder?

### Detaylı ve Kapsamlı Teknik Cevap
Windows'un yerel anlık görüntü (snapshot) mekanizması olan **VSS (Volume Shadow Copy Service)**, kullanıcıların yanlışlıkla sildiği veya değiştirdiği dosyaları bir önceki gölge kopyadan dakikalar içinde geri getirmesini sağlayan harika bir kurtarma aracıdır.

Ancak fidye yazılımları bu mekanizmanın sistemin can damarı olduğunu çok iyi bilir. Sisteme sızan bir fidye yazılımı (LockBit, DarkSide, Conti), diski şifrelemeye başlamadan önceki **ilk 3 saniyede** şu komut dizilerini çalıştırır (MITRE ATT&CK T1490 - Inhibit System Recovery):
```cmd
vssadmin.exe delete shadows /all /quiet
wmic.exe shadowcopy delete
wbadmin.exe delete catalog -quiet
bcedit.exe /set {default} bootstatuspolicy ignoreallfailures
bcedit.exe /set {default} recoveryenabled no
powershell.exe -Command "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }"
```
Bu komutlar çalıştığı anda Windows'taki tüm gölge kopyalar ve kurtarma katalogları geri döndürülemez şekilde yok edilir; kullanıcılar "Önceki Sürümler (Previous Versions)" sekmesine tıkladıklarında bomboş bir liste görürler.

**Çekirdek ve ACL Seviyesinde Savunma Stratejileri:**

1. **İkili Dosya İzinlerinin Kısıtlanması (Binary ACL Sıkılaştırma):**
   `vssadmin.exe`, `wbadmin.exe` ve `bcdedit.exe` araçları standart kullanıcılar veya ele geçirilmiş servis hesapları tarafından çalıştırılamamalıdır. `icacls` kullanılarak bu ikili dosyaların çalıştırma izinleri yalnızca `TrustedInstaller` ve yerel `SYSTEM` hesabına bırakılmalı; `Users` ve `Domain Users` gruplarına açıkça `DENY` verilmelidir:
   ```powershell
   icacls C:\Windows\System32\vssadmin.exe /deny "Users:(X)"
   ```
2. **EDR / Davranışsal İhlal Önleme (Tamper Protection & Behavioral Rules):**
   Modern EDR sensörleri (CrowdStrike, Microsoft Defender for Endpoint, SentinelOne), herhangi bir sürecin `vssadmin delete shadows` veya WMI üzerinden shadow delete çağırmasını birincil fidye yazılımı göstergesi kabul eder. EDR kuralları ile bu komut parametreleri görüldüğü anda çağıran süreç çekirdek seviyesinde (`NtTerminateProcess`) öldürülür ve uç nokta anında ağdan izole edilir.
3. **WMI ve PowerShell Komut Satırı Bloklaması:**
   AppLocker veya Windows Defender Application Control (WDAC) politikaları ile `wmic shadowcopy` komutlarının çağrılması engellenmeli; komut satırı denetimi (Event ID 4688 ve PowerShell Script Block Logging Event ID 4104) ile SIEM/SOC merkezine anlık yüksek öncelikli alarm üretilmelidir.

### Ustanın Çırağa Tavsiyesi / Altın Kural
"Çırak, bir Windows sunucusunda `vssadmin.exe` dosyasını varsayılan izinleriyle bırakmak, hırsıza evin anahtarıyla birlikte kasayı açacak levye hediye etmektir. Bir sunucu kurduğun gün `vssadmin` ve `bcdedit` izinlerini kilitleyeceksin; EDR'ında 'shadow copy deletion' kuralını bloklama moduna alacaksın. Saldırgan gölge kopyayı silemediği sürece o sunucunun patronu daima sensin."

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2021 yılında bir belediyenin bilgi işlem ağına sızan Conti fidye yazılımı grubu, gece yarısı Active Directory üzerinden tüm sunuculara yayılmaya başladı. Ancak belediyenin kıdemli sistem mühendisi, birkaç ay önce tüm Windows sunucularda `vssadmin.exe` ve `wmic.exe` izinlerini sıkılaştırmış, standart servis hesaplarının bu araçları çalıştırmasını Grup İlkesi (GPO) ile yasaklamıştı. Fidye yazılımı sunucularda çalıştığında gölge kopyaları silemedi (`Access Denied` hatası aldı) ve EDR bu başarısız denemeyi yakalayarak sunucuları otomatik karantinaya aldı. Belediye, şifrelenen birkaç dosya sunucusunu Windows Gölge Kopyaları sayesinde 25 dakika içinde hiçbir fidye ödemeden %100 kurtarmayı başardı.
