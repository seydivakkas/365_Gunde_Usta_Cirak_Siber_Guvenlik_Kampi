# Gün 151: Yedek Doğrulama, Kurtarma Noktası (RPO/RTO) ve Değiştirilemezlik (WORM) Mimarisi
**Hoca Dersi — Usta-Çırak Derinlemesine Teknik Eğitim Modülü**

---

## 1. Giriş ve Temel Felsefe: "Yedek Almak Bir İbadet Değil, Kurtarabilmek Bir Marifettir"

Evlat, bilişim ve siber güvenlik sektöründe yıllarını geçirmiş kıdemli bir mühendisin kulağına küpe olmuş en büyük kural şudur: **"Alınan bir yedeğin varlığına ancak ve ancak o yedekten canlı bir sistemi ayağa kaldırıp son veriyi doğruladığın gün inanabilirsin. Test edilmemiş her yedek, sadece bir umuttur; siber güvenlikte ise umut bir strateji değildir."**

Geçmişte sistem yöneticileri cuma akşamları bir yedek başlatır, pazartesi sabahı yedekleme yazılımında yeşil bir onay işareti (Status: Completed) görünce derin bir nefes alıp arkalarına yaslanırlardı. Ancak felaket günü geldiğinde; veritabanı bozulduğunda, disk denetleyicisi çöktüğünde ya da şirkete bir fidye yazılımı (ransomware) bulaştığında o yedek dosyası açılmaya çalışılır ve acı gerçekle yüzleşilirdi:
1. Ya yedek dosyası sessizce bozulmuştur (Bit rot / Silent Data Corruption).
2. Ya yedekleme yazılımı veriyi şifreli ve kilitli dosyalar açıkken atlamıştır.
3. Ya da fidye yazılımı ilk iş olarak Active Directory'yi ele geçirip yedek sunucusuna girmiş, tüm yedek arşivlerini ve gölge kopyaları silmiştir!

İşte bu derste; **3-2-1-1-0 yedekleme kuralını**, **RPO (Kurtarma Noktası Hedefi)** ve **RTO (Kurtarma Süresi Hedefi)** mühendisliğini, modern **Değiştirilemez Depolama (WORM / Object Lock)** teknolojisini ve fidye yazılımlarının yedek imha mekanizmalarına karşı nasıl aşılmaz kaleler inşa edileceğini inceleyeceğiz.

---

## 2. 3-2-1 Kuralından Modern 3-2-1-1-0 Mimarisine

Geleneksel 3-2-1 kuralı Peter Krogh tarafından fotoğrafçılar için ortaya atılmış, daha sonra BT dünyasının amentüsü olmuştur. Ancak modern fidye yazılımları ve sofistike APT grupları karşısında bu kural yetersiz kalmış ve **3-2-1-1-0** modeline evrilmiştir:

```
+------------------------------------------------------------------------------------+
|               MODERN SİBER DİRENÇLİ YEDEKLEME KURALI: 3-2-1-1-0                    |
+------------------------------------------------------------------------------------+
| [3] En Az 3 Kopya Veri       : 1 Birincil Üretim Verisi + 2 Bağımsız Yedek Kopyası |
| [2] En Az 2 Farklı Medya     : Disk (NVMe/SAN) + Bulut Nesne Depolama / Teyp       |
| [1] En Az 1 Saha Dışı Kopya  : Coğrafi olarak farklı bir lokasyon veya Bulut Bölgesi|
| [1] En Az 1 Değiştirilemez   : WORM (Write Once Read Many) veya Hava Boşluklu (Air-gap)|
| [0] Sıfır Kurtarma Hatası    : Otomatik sağlama toplamı (SHA-256) ve sandbox testi  |
+------------------------------------------------------------------------------------+
```

### 2.1. Neden Medya Çeşitliliği (2 Farklı Ortam)?
Eğer tüm yedek kopyalarını aynı marka NAS cihazında veya aynı RAID dizisinde tutarsan; o üreticinin firmware'indeki bir bug, bir voltaj dalgalanması veya kontrol kartı arızası bütün kopyaları aynı saniyede imha eder. Bu yüzden en az biri yüksek hızlı blok depolama (SAN/NVMe), diğeri ise farklı bir dosya sistemine sahip bulut nesne depolama (S3) veya manyetik teyp olmalıdır.

### 2.2. Değiştirilemezlik (WORM - Write Once Read Many / Object Lock)
Fidye yazılımları (LockBit, BlackCat/ALPHV, Conti) kurumsal ağa sızdıklarında ilk iş olarak canlı sistemleri değil, **yedekleri hedeflerler**. Çünkü yedekleri silinmemiş bir şirket fidyeyi ödemez!

Saldırgan Domain Admin veya Enterprise Admin yetkisine sahip olsa bile yedekleri silememelidir. İşte bunu sağlayan teknoloji **WORM (Write Once Read Many)** veya bulut sağlayıcılarındaki **Object Lock COMPLIANCE Modu**dur:
- **Governance Modu:** Özel yetkili belirli IAM rollerine sahip kullanıcılar yedeği silebilir (Fidye yazılımı bu rolü çalarsa yedeği siler).
- **Compliance Modu (Yasal Uyum Modu):** **HESAP SAHİBİ (ROOT KULLANICI DAHİL) HİÇ KİMSE**, belirlenen saklama süresi (Retention Period - örneğin 30 gün) dolana kadar o nesneyi silemez, değiştiremez veya üzerine yazamaz! AWS/Azure/GCP destek ekibi dahi API seviyesinde bu kilidi kaldıramaz.

---

## 3. RPO ve RTO Mühendisliği: SLA ve Maliyet Dengesi

İş sürekliliği ve felaket kurtarma (DR - Disaster Recovery) planlamasının iki temel metriği vardır:

```
 Zaman Akışı:
 ====[ Son Başarılı Yedek ]==========[ FELAKET ANI ]==================[ SİSTEM AYAĞA KALKTI ]====>
             <----------------------------->   <---------------------------------->
               KAYBEDİLEN VERİ (RPO)               SİSTEM KESİNTİ SÜRESİ (RTO)
```

1. **RPO (Recovery Point Objective - Kurtarma Noktası Hedefi):**
   - Felaket anında geriye dönük olarak kurumun katlanabileceği **maksimum veri kaybı süresidir**.
   - Örneğin bir bankanın RPO'su 5 dakikadır. Eğer son yedek 2 saat önce alınmışsa ve sistem çökerse, aradaki 1 saat 55 dakikalık finansal işlem verisi yok olur. Bu kurum için kabul edilemez bir SLA ihlalidir.
   - Düşük RPO (sıfıra yakın veri kaybı) sağlamak için **Sürekli Veri Koruma (CDP - Continuous Data Protection)** veya veritabanı işlem günlüğü (Transaction Log Shipping / WAL Replication) gerekir.

2. **RTO (Recovery Time Objective - Kurtarma Süresi Hedefi):**
   - Felaket anından itibaren sistemin işler hale getirilip kullanıcılara açılmasına kadar geçen **maksimum kesinti süresidir**.
   - Örneğin RTO = 2 saat ise; donanımın temini, yedeğin diskten/buluttan okunup transfer edilmesi, veritabanının bütünlük kontrolü ve servislerin ayağa kalkması 2 saati aşamaz.
   - Buluttan veya teypten terabaytlarca veri indirmek saatler alabilir. Bu yüzden hızlı RTO için yerel birincil önbellek kopyası (Local Fast Cache) şarttır.

---

## 4. Sessiz Veri Bozulması (Bit Rot) ve Kriptografik Doğrulama

Manyetik ve optik disklerde, hatta kurumsal SSD'lerde zamanla kozmik radyasyon, zayıflayan manyetik yükler veya firmware hataları nedeniyle sektörlerdeki bitler ters dönebilir ($0 \rightarrow 1$ veya $1 \rightarrow 0$). Buna **Sessiz Veri Bozulması (Bit Rot / Silent Data Corruption)** denir.

İşletim sistemi bu hatayı okuma anında fark etmez; dosya görünürde oradadır ama açıldığında veritabanı çöker (Corrupted Database).

**Savunma Mekanizması:**
- Her yedek dosyası oluşturulduğu anda SHA-256 sağlama toplamı (Checksum) hesaplanmalı ve bağımsız bir metadata veritabanında saklanmalıdır.
- Periyodik bütünlük taramaları (Data Scrubbing) ile diskteki yedeğin hash'i tekrar hesaplanmalı ve ilk hash ile karşılaştırılmalıdır. Tek bir bit dahi değişmişse yedekleme sistemi derhal alarm vermeli ve hasarlı blokları sağlıklı ikincil kopyadan (Self-Healing) onarmalıdır.

---

## 5. Fidye Yazılımlarının Yedek İmha Taktikleri ve Savunma Matrisi

| Saldırı Vektörü | MITRE Tekniği | Saldırı Yöntemi | Savunma ve Sertleştirme Çözümü |
|---|---|---|---|
| **VSS Gölge Kopya İmhası** | T1490 | `vssadmin delete shadows /all /quiet` veya `wmic shadowcopy delete` çalıştırılarak anlık görüntülerin yok edilmesi. | VssAdmin çalıştırılabilir dosyasına kullanıcı ve servis hesabı çalıştırma engeli (Deny ACL) koyulmalı, EDR tamper koruması açılmalıdır. |
| **Yedek Paylaşımını Şifreleme** | T1486 | Ağdaki SMB/NFS yedek paylaşımına Domain Admin yetkisiyle bağlanıp `.bak` ve `.tib` dosyalarının şifrelenmesi. | Yedekleme sunucusu ve depolama alanı Active Directory etki alanından tamamen izole edilmeli (Out-of-band IAM); Linux Hardened Repository kullanılmalıdır. |
| **Yedek Konsolunu Silme** | T1485 | Veeam, Commvault veya Acronis konsoluna sızarak tüm yedekleme işlerinin ve kayıtlı depoların silinmesi. | Yedekleme konsolunda Çok Faktörlü Kimlik Doğrulama (MFA) ve Dört Göz Kuralı (Four-Eyes Principle / Çoklu onay) zorunlu tutulmalıdır. |
| **Bulut Kopyasını Silme** | T1565 | Çalınan AWS root/admin API anahtarlarıyla S3 bucket'larının silinmesi. | S3 Object Lock **COMPLIANCE** modu aktif edilmeli; saklama süresi dolmadan root dahil kimsenin silemeyeceği garanti altına alınmalıdır. |

---

## 6. Usta-Çırak Uygulama Notları ve Özet

Evlat, bugün geliştirdiğimiz `backup_recovery_engine.py` motoru; bir kurumun yedekleme mimarisinin sadece "yedek alıp almadığını" değil, bir fidye yazılımı dalgası geçtiğinde o kurumun hayatta kalıp kalamayacağını (Survivability) matematiksel ve kriptografik olarak kanıtlar.

Unutma: **En iyi siber güvenlik uzmanı; sistemleri hiç çökmeyen değil, çöktüğü anda elindeki değiştirilemez kanıtla sistemi ayağa kaldıran uzmandır.**
