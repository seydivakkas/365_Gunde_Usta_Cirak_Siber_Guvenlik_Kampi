# Gün 150: Disk Şifreleme ve TPM 2.0 Güvenlik Mimarisi
**Hoca Dersi — Usta-Çırak Derinlemesine Teknik Eğitim Modülü**

---

## 1. Giriş ve Temel Felsefe: Hareketsiz Verinin (Data at Rest) Kalesi

Evlat, bir siber güvenlik uzmanının asla unutmaması gereken bir hakikat vardır: **"Fiziksel erişim sağlanan bir cihaz, eğer üzerinde güçlü bir disk şifreleme ve donanım doğrulaması yoksa, artık senin cihazın değildir."**

Bir şirketin üst düzey yöneticisinin, bir güvenlik analistinin veya bir yazılımcının dizüstü bilgisayarı bir havaalanında unutulduğunda, takside bırakıldığında ya da çalındığında; saldırgan diski söküp harici bir USB kutusuna taktığında veya bir Linux Live USB ile açtığında ne olur? Eğer disk şifrelenmemişse, işletim sisteminin giriş parolası (Windows SAM veya Linux `/etc/shadow`), dosya izinleri ve NTFS/EXT4 ACL kuralları bir anda çöp haline gelir. Saldırgan bütün veritabanlarına, SSH anahtarlarına, kaynak kodlarına ve çerezlere saniyeler içinde erişir.

İşte **Tam Disk Şifreleme (Full Disk Encryption - FDE)** ve **Güvenilir Platform Modülü (TPM 2.0)**, cihaz fiziksel olarak çalındığında dahi verilerin birer anlamsız rastgele bayt yığını (ciphertext) olarak kalmasını sağlayan son savunma hattıdır.

---

## 2. Kriptografik Disk Şifreleme Mimarisi ve Blok Modları

Veri saklama birimlerinde (HDD, NVMe SSD) veriler sektörler (genellikle 512 bayt veya 4096 bayt) halinde saklanır. Bu durum disk şifrelemeyi ağ trafiği şifrelemesinden (TLS/HTTPS) tamamen ayırır. Ağda veri bir akıştır (stream); diskte ise rastgele sektörlere doğrudan okuma/yazma (random access) yapılır.

```
+------------------------------------------------------------------------------------+
|               DİSK ŞİFRELEME BLOK MODLARININ TARİHSEL GELİŞİMİ                     |
+------------------------------------------------------------------------------------+
| 1. ECB Modu : [KRİTİK HATA] Aynı bloklar aynı şifreyi üretir (Penguin Zaafı)        |
| 2. CBC Modu : Bit çevirme ve su damgası (watermarking) saldırılarına açıktır       |
| 3. XTS-AES  : [ENDÜSTRİ STANDARDI] Tweakable Block Cipher (IEEE 1619 Standardı)    |
+------------------------------------------------------------------------------------+
```

### 2.1. Neden XTS-AES (IEEE 1619 Standardı)?
- **ECB (Electronic Codebook) Felaketi:** Aynı düz metin blokları daima aynı şifreli metin bloklarını üretir. Verideki desenler (pattern) şifrelense dahi görünür kalır.
- **CBC (Cipher Block Chaining) Zaafı:** Her blok bir önceki şifreli blokla XOR'lanır. Ancak disk sektörlerinde bir baytı değiştirmek bir sonraki blokta tahmin edilebilir bit çevirme (bit-flipping) manipülasyonlarına yol açar.
- **XTS-AES (XEX-based Tweaked-codebook with ciphertext Stealing):** Modern disk şifrelemenin altın standardıdır. Her sektör için sektör numarasına dayalı benzersiz bir "Tweak Anahtarı" üretilir. Böylece aynı içeriğe sahip iki sektör (örneğin sıfırlarla dolu iki veri bloğu) diskin farklı sektörlerinde bambaşka şifreli çıktılar üretir. BitLocker ve LUKS2 varsayılan olarak **XTS-AES-256** kullanır.

---

## 3. TPM 2.0 (Trusted Platform Module) ve Platform Bütünlüğü

TPM, anakarta doğrudan lehimlenmiş (discrete TPM - dTPM) veya CPU içine gömülmüş (firmware TPM - fTPM), kendi mikrodenetleyicisi, kriptografik motoru ve korumalı belleği olan bağımsız bir donanım güvenlik yongasıdır.

### 3.1. TPM Temel Anahtar Hiyerarşisi
1. **Endorsement Key (EK):** Üretici fabrikada çipe kazınan (burned-in), asla dışarı sızdırılamayan ve üretici CA sertifikasıyla doğrulanan benzersiz çip kimlik anahtarıdır.
2. **Storage Root Key (SRK):** Sistem sahibi (Owner) çipi devraldığında üretilen ve TPM içindeki diğer anahtarları hiyerarşik olarak koruyan kök anahtardır.
3. **Platform Configuration Registers (PCR - Platform Yapılandırma Kaydedicileri):** TPM 2.0'da en az 24 adet (0-23) kaydedici bulunur. Bu kaydediciler doğrudan yazılamaz! Yalnızca kriptografik "Genişletme (Extend)" işlemi yapılabilir.

### 3.2. PCR Genişletme (Extend) Zinciri
Önyükleme sırasında her donanım ve bellenim bileşeni çalıştırılmadan önce kendisinden bir sonraki bileşenin hash'ini alır ve TPM PCR'ına şu matematiksel formülle ekler:

$$\text{PCR}_{\text{yeni}} = \text{SHA256}(\text{PCR}_{\text{eski}} \parallel \text{SHA256}(\text{Bileşen}))$$

Bu tek yönlü zincirleme sayesinde, önyükleme sırasında 1 baytlık bir kod dahi değişse (örneğin zararlı bir önyükleyici yüklense), zincirin sonundaki PCR değeri tamamen değişir ve eski haline asla döndürülemez!

| PCR No | Ölçülen Bileşen (TCG Standardı) | Siber Güvenlikteki Önemi |
|---|---|---|
| **PCR 0** | Core Root of Trust for Measurement (CRTM), UEFI BIOS Bellenim Kodu | Anakart bellenimine bulaşan UEFI Bootkit/Rootkit tespiti. |
| **PCR 2** | Genişleme Kartları (PCIe, GPU) Option ROM Bellenimleri | Sahte donanım kartı veya kötü niyetli PCIe bellenimi tespiti. |
| **PCR 4** | Windows Boot Manager / Linux GRUB Önyükleyici Kodu | Evil Maid saldırısıyla önyükleyicinin değiştirilmesini önler. |
| **PCR 7** | UEFI Güvenli Önyükleme (Secure Boot) Durumu ve Sertifikaları | Secure Boot kapatıldığında veya sahte PK/db sertifikası yüklendiğinde alarm verir. |
| **PCR 11** | BitLocker Erişim Kontrol Politikası | BitLocker kural setinin bütünlüğünü korur. |

---

## 4. Anahtar Mühürleme (Sealing) ve Mühür Çözme (Unsealing)

TPM'in en büyüleyici güvenlik mekanizması **Sealing (Mühürleme)** işlemidir:

1. **Mühürleme (Sealing):** Disk şifreleme anahtarı (BitLocker VMK veya LUKS anahtarı), TPM'e verilir ve bir mühürleme politikası tanımlanır (örneğin: *"Bu anahtarı PCR 0, 2, 4 ve 7 değerleri şu hash'e eşit olduğunda ve kullanıcı şu PIN'i girdiğinde çöz"*). TPM bu anahtarı SRK ve PCR özetleriyle şifreleyerek diske "Mühürlü Blok (Sealed Blob)" olarak kaydeder.
2. **Mühür Çözme (Unsealing):** Bilgisayar her açıldığında donanım bileşenleri PCR'ları extend eder. Açılışta TPM'den anahtarı çözmesi istenir. TPM o anki PCR bankasını kontrol eder:
   - Eğer BIOS, Secure Boot, Ekran Kartı ve Bootloader orijinal ve temizse -> **TPM anahtarı çözer, disk açılır.**
   - Eğer saldırgan bir USB takmış, GRUB/Bootmgr dosyasını kurcalamış (Evil Maid) veya Secure Boot'u kapatmışsa -> **PCR 4 veya 7 uyuşmaz, TPM anahtarı çözmeyi KESİNLİKLE REDDEDER!**
   - Sistem kilitlenir ve 48 haneli sayısal **BitLocker Kurtarma Parolası (Recovery Key)** sorar.

---

## 5. Donanım Seviyesi Saldırı Vektörleri ve Savunma Yöntemleri

```
[ SALDIRI VE SAVUNMA MATRİSİ ]
+----------------------------+------------------------------------+------------------------------------------+
| Saldırı Türü               | Saldırı Yöntemi                    | Savunma ve Sertleştirme Çözümü           |
+----------------------------+------------------------------------+------------------------------------------+
| 1. Evil Maid (Bootkit)     | Önyükleyiciye sahte kod yazma      | PCR 4 + PCR 7 Mühürleme + Secure Boot    |
| 2. SPI/LPC Bus Sniffing    | TPM ile CPU arasındaki yolu dinleme| TPM + PIN Koruması (Parameter Encryption)|
| 3. DMA Thunderbolt Saldırısı| Harici porttan doğrudan RAM okuma  | Intel VT-d / AMD-Vi Kernel DMA Protection|
| 4. Cold Boot Saldırısı     | RAM'i dondurup anahtarı okuma      | Bellek Sıfırlama (MOR bit) + XTS-AES     |
+----------------------------+------------------------------------+------------------------------------------+
```

### 5.1. SPI / LPC Bus Sniffing ve Neden "Yalnızca TPM" Yetersizdir?
Evlat, pek çok kurum BitLocker'ı "Yalnızca TPM" (kullanıcı parola/PIN girmeden bilgisayarın doğrudan açılması) modunda kurar. Kullanıcı konforu için harika görünür ama güvenlik açısından ölümcül bir gediktir!

Ayrı bir çip olan discrete TPM (dTPM), çözdüğü anahtarı CPU'ya anakart üzerindeki SPI veya LPC veri yolları üzerinden gönderir. Bir saldırgan 10 dolarlık bir mantık analizörü (logic analyzer) veya Raspberry Pi Pico ile anakart üzerindeki TPM çipinin bacaklarına (CLK, MOSI, MISO) fiziksel problar tutturarak, bilgisayar açıldığı anda veri yolundan geçen şifre çözme anahtarını (VMK) düz metin olarak yakalayabilir!

**Çözüm:** **TPM + PIN (Başlangıç PIN Kodu)** zorunlu kılınmalıdır. Kullanıcı doğru PIN'i girmeden önce TPM veri yoluna tek bir bayt anahtar bile göndermez.

### 5.2. Doğrudan Bellek Erişimi (DMA) ve IOMMU Savunması
Thunderbolt ve USB4 portları, yüksek hız için PCIe veri yoluna doğrudan bağlıdır. Saldırgan PCilée veya Thunderbolt portuna özel bir DMA donanımı takarak işletim sistemi çekirdeğini atlatıp doğrudan RAM'i okuyabilir.

**Çözüm:** BIOS'ta **IOMMU (Intel VT-d / AMD-Vi)** ve Windows'ta **Kernel DMA Protection** etkinleştirilmelidir. IOMMU, harici cihazların belleğin yalnızca kendilerine tahsis edilen izole alanlarına erişmesine izin verir; işletim sistemi ve disk şifreleme anahtarlarının bulunduğu RAM bölgelerini donanımsal olarak kilitler.
