<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 039 — Yedekleme Stratejisi ve 3-2-1 Kuralı Mimarisi

**Usta-Çırak / Hoca Dersi**  
*Aşama 02: Sistem ve Ağ Temelleri — Hafta 06: İşletim Sistemi Güvenliği ve Temel Ağ Mimarisi*

---

## 1. Usta Girişi: Siber Güvenliğin Son Savunma Hattı
Evlat, siber güvenlikte "Mükemmel savunma yoktur; her kale eninde sonunda düşebilir" ilkesi geçerlidir. Güvenlik duvarların aşılabilir, sıfır-gün (zero-day) açığıyla sunucun ele geçirilebilir veya bir çalışan oltalama (phishing) e-postasına tıklayarak tüm etki alanını fidye yazılımı (ransomware) çetesine teslim edebilir.

İşte o en karanlık günde, şirketin iflas bayrağını mı çekeceğini yoksa birkaç saat içinde küllerinden yeniden mi doğacağını belirleyen tek bir şey vardır: **Yedekleme Stratejin ve Geri Yükleme Kabiliyetin.**

Ancak bilişim dünyasının en büyük ve en acı tecrübeleri, yedekleme konusunda yaşanan cehaletten doğar. Şirket yöneticisi "Bizim her gece yeşil yanan yedekleme yazılımımız var" diyerek rahat uyur; fidye yazılımı vurduğunda ise:
1. Yedeğin aslında canlı veriyle aynı SAN havuzundaki bir anlık görüntüden (snapshot) ibaret olduğu ve saldırganın onu tek tıkla sildiği,
2. Yedeğin şifrelenmemiş bir SMB paylaşımında durduğu ve canlı verilerle birlikte fidye yazılımı tarafından şifrelendiği,
3. Yedek arşivinin bozuk olduğu ve 3 yıldır hiç geri yükleme testi yapılmadığı ortaya çıkar.

Bugün seninle siber güvenliğin altın standardı olan **3-2-1 Kuralını**, fidye yazılımlarına karşı **Değiştirilemezliği (Immutability)** ve **Schrödinger'in Yedeği Paradoksunu** inceleyeceğiz.

---

## 2. Altın Standart: 3-2-1 Yedekleme Mimarisi
Modern felaket kurtarma ve iş sürekliliği mimarisinin temeli olan 3-2-1 kuralı, matematiksel ve istatistiksel bir risk dağıtım modelidir:

```text
               [ 3 KOPYA ]               En az 3 adet veri kopyası:
                                         - 1 adet Canlı Üretim Kopyası (Primary Production)
                                         - 2 adet Bağımsız Yedek Kopyası
                   │
                   ▼
            [ 2 FARKLI MEDYA ]           Kopyalar en az 2 farklı teknoloji/ortamda saklanmalı:
                                         - Medya A: Yerel Hızlı Disk / SAN / NAS
                                         - Medya B: Manyetik Teyp (LTO) veya Bulut Nesne Deposu (S3)
                   │
                   ▼
         [ 1 TESİS DIŞI (Offsite) ]      En az 1 kopya ana veri merkezinin coğrafi olarak dışında olmalı:
                                         - İkincil Felaket Kurtarma Merkezi (DR Site) veya Genel Bulut
                   │
                   ▼
   [ +1 DEĞİŞTİRİLEMEZ (Immutable) ]     Modern Siber Güvenlik Eki:
                                         - WORM (Write Once Read Many), S3 Object Lock veya Çevrimdışı Hava Boşluğu (Air-Gap)
```

### Neden 3 Kopya?
İki kopyanın (1 üretim + 1 yedek) aynı anda bozulma olasılığı, tek kopyaya göre düşüktür ancak felaket anında birincil veri çöktüğünde yedeği geri yüklerken yedek diski de yoğun I/O baskısı altında arızalanabilir (çift disk arızası). 3 kopya, geri yükleme esnasında yaşanabilecek ikincil felaketlere karşı matematiksel güvenlik marjı sağlar.

### Neden 2 Farklı Medya Türü?
Aynı üreticinin, aynı seri numaralı mekanik disklerinden oluşan iki ayrı depolama ünitesi alırsan; aynı bellenim (firmware) hatası veya aynı elektrik dalgalanması her iki üniteyi de aynı anda yakabilir (Ortak Arıza Alanı - Common Failure Domain). Bir kopyayı diskte, diğerini manyetik teypte (LTO) veya bulut nesne mimarisinde tutmak bu korelasyonu kırar.

### Neden 1 Tesis Dışı (Offsite)?
Yangın, su baskını, bina çökmesi veya fiziksel hırsızlık durumunda aynı sunucu odasındaki tüm yedekler aynı anda kül olur. Tesis dışı kopya fiziksel felaketlere karşı yegane kalkandır.

---

## 3. Ölümcül Kavram Yanılgıları: Yedek vs Snapshot vs RAID

| Mekanizma | Amacı ve Kapsamı | Ne Zaman İşe Yarar? | Neden Yedek Değildir? |
| :--- | :--- | :--- | :--- |
| **RAID** (RAID-1/5/6) | Donanımsal disk arızasında sistemin durmasını önlemek (Yüksek Erişilebilirlik). | Bir veya iki fiziksel disk bozulduğunda pariteyle sistemi ayakta tutar. | **Asla yedek değildir!** Dosyayı silersen veya fidye yazılımı şifrelerse, bu işlem milisaniyede tüm disklere yazılır. Geçmişe dönemez. |
| **Snapshot** (Anlık Görüntü) | Dosya sistemi veya sanal makine durumunun anlık dondurulması (Copy-on-Write). | Güncelleme öncesi hızlı geri dönüş (rollback) sağlar. | **Aynı depolama havuzundaysa yedek değildir!** Birincil SAN ünitesi çökerse snapshot da gider. Fidye yazılımı hypervisor'a girip tek komutla tüm snapshot'ları siler (`vssadmin delete shadows` / `esxcli vm`). |
| **Gerçek Yedek (3-2-1)** | Verinin bağımsız, yalıtılmış ve taşınabilir bir arşiv kopyasının oluşturulması. | Tüm felaket senaryolarında (fidye yazılımı, yangın, insan hatası, donanım kaybı) veriyi kurtarır. | Sistemden izoledir, kimlik doğrulama yetkisi farklıdır, geçmişe dönük versiyonlama sunar. |

---

## 4. "Schrödinger'in Yedeği" Paradoksu ve Geri Yükleme Testleri
Usta der ki: **"Geri yükleme testi başarıyla icra edilmemiş bir yedeğin durumu, Schrödinger'in kutusundaki kedi gibidir: Kutu açılana kadar o yedek hem vardır hem de yoktur!"**

Şirketler yıllarca "Başarılı" uyarısı veren yedekleme raporlarına aldanırlar. Ancak gerçek bir felaket anında yedeği geri yüklemeye kalktıklarında:
- Yedek arşivinin disk bloklarının bozulduğu (Bit rot / Silent Corruption),
- Veritabanı transaction loglarının eksik alındığı ve veritabanının tutarsız durumda açılamadığı,
- Yedeği şifreleyen özel anahtarın (encryption key) sadece o çöken sunucuda saklandığı ve anahtar olmadan yedeğin çözülemediği ortaya çıkar.

**Kural:** En az 90 günde bir (çeyreklik olarak) izole bir test ortamına tam geri yükleme tatbikatı (Full Restore Drill) yapılmalı; işletim sistemi, veritabanı ve kritik servislerin çalıştığı gözlemlenmelidir.

---

## 5. Fidye Yazılımları (Ransomware) Çağında Değiştirilemezlik (Immutability / WORM)
Modern fidye yazılımı çeteleri (LockBit, Black Basta, Akira vb.) eski usul "girdiği anda şifrele" mantığıyla çalışmaz. 
1. Ağda ortalama 15-30 gün sessizce gezinirler (Dwell time).
2. İlk hedefleri Active Directory Domain Controller ve **Yedekleme Sunucusudur (Veeam, Commvault, Backup Exec)**.
3. Domain Admin yetkisiyle yedekleme yönetim konsoluna girer, tüm yedekleme depolarını biçimlendirir veya silerler.
4. Ardından canlı sistemleri şifrelerler. Kurban arkasını döndüğünde yedeklerinin de yok edildiğini görür ve fidyeyi ödemeye mecbur kalır.

### Savunma: Değiştirilemez Yedekleme (Immutable Backups / WORM)
- **WORM (Write Once, Read Many):** Veri diske bir kez yazılır, belirlenen saklama süresi (örneğin 30 gün) boyunca **kök kullanıcı (root) veya etki alanı yöneticisi (Domain Admin) dahil hiç kimse tarafından silinemez veya değiştirilemez**.
- **AWS S3 Object Lock (Compliance Mode):** AWS hesap sahibi veya root anahtarı dahi dosyayı silemez; AWS'nin donanım politikası bunu engeller.
- **Hava Boşluğu (Air-Gap):** Kopyanın ağdan fiziksel olarak ayrılmasıdır. Manyetik teybin (LTO) sürücüden çıkarılıp bir yangın kasasına kilitlenmesi veya fiziksel bir robotik kütüphanede çevrimdışı tutulmasıdır. Saldırgan ağ üzerinden kablosu takılı olmayan bir teybe hiçbir siber komutla ulaşamaz.

---

## 6. RPO ve RTO: İş Etki Analizinin Temel Taşı
- **RPO (Recovery Point Objective - Kurtarma Noktası Hedefi):** Bir felaket anında göze alınabilecek azami veri kaybı süresidir.
  *Örnek:* RPO = 1 saat ise, sistem her saat başı yedek almalıdır. Sistem çöktüğünde en fazla 59 dakikalık veri kaybedilir.
- **RTO (Recovery Time Objective - Kurtarma Zamanı Hedefi):** Felaket anından sistemin yeniden ayağa kaldırılıp çalışır hale gelmesine kadar geçen azami tolere edilebilir kesinti süresidir.
  *Örnek:* RTO = 2 saat ise, yedek arşivinden veriyi okuyup sunucuyu ayağa kaldırmak 2 saati geçmemelidir.

---

## 7. Usta-Çırak Özeti
Çırak! Bir kurumun yedekleme politikasını incelerken şu 4 soruyu soracaksın:
1. "Kaç kopya var ve kaçı tesis dışında?" (Cevap: En az 3 kopya, en az 1 tesis dışı).
2. "Bu yedekler değiştirilemez mi (immutable/WORM) yoksa Domain Admin hesabını alan saldırgan bunları silebilir mi?"
3. "En son ne zaman geri yükleme testi yaptınız?" (90 günden eskiyse veya hiç yapılmadıysa o yedek sahtedir).
4. "RAID'e veya aynı depolama ünitesindeki snapshot'a mı güveniyorsunuz?" (Güveniyorlarsa o şirkette felaket kapıdadır).

Geliştirdiğimiz denetçi (`backup_strategy_321_auditor.py`) bu ölümcül zafiyetleri gözünün yaşına bakmadan yakalamakta ve raporlamaktadır!
