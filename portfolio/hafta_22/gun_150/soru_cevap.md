# Gün 150: Disk Şifreleme ve TPM 2.0 — Soru & Cevap

---

## 1. Soru: TPM 2.0 PCR Mekanizması, Extend Zinciri ve Mühürleme (Sealing) Politikası

### Soru
TPM 2.0 yongasında Platform Configuration Registers (PCR) mekanizması nasıl çalışır, PCR Extend işlemi neden geri döndürülemez bir tek yönlü matematiksel zincirdir ve BitLocker / LUKS mühürleme (sealing) politikalarında neden özellikle PCR 7 (Secure Boot) ve PCR 4 (Bootloader) bir arada kilitlenmelidir?

### Detaylı ve Kapsamlı Teknik Cevap
TPM 2.0 spesifikasyonunda PCR (Platform Configuration Register) kaydedicileri, sistemin önyükleme sırasındaki donanım, bellenim ve yazılım durumunu kriptografik olarak kaydeden özel dahili bellek alanlarıdır. Bir PCR kaydedicisine işletim sistemi veya bellenim doğrudan bir değer yazamaz (`write` işlemi engellenmiştir). Bunun yerine yalnızca **Extend (Genişletme)** adı verilen tek yönlü bir işlem uygulanabilir:

$$\text{PCR}_{\text{yeni}} = \text{SHA256}(\text{PCR}_{\text{mevcut}} \parallel \text{SHA256}(\text{Ölçüm Verisi}))$$

Bu matematiksel modelin sağladığı en büyük güvenlik garantisi **sıra bağımlılığı ve tek yönlülüktür (non-reversibility)**. Örneğin sistem önce BIOS'u (A), ardından önyükleyiciyi (B) ölçerse çıkan nihai hash değeri, önce B'yi sonra A'yı ölçmekten tamamen farklıdır. Saldırgan sistem başladıktan sonra sahte ölçümler göndererek PCR'ı geçmişteki meşru bir duruma asla geri getiremez (çünkü SHA-256'nın tersi alınamaz).

BitLocker ve LUKS'ta **Mühürleme (Sealing)** yapıldığında, disk şifreleme anahtarı (BitLocker VMK veya LUKS Master Key) belirli PCR indekslerinin belirli hash değerlerine kilitlenir. Mühür çözme (Unseal) sırasında TPM, o anki donanım durumunu mühürlemedeki beklenen durumla karşılaştırır:
- **PCR 4 (Önyükleyici):** Windows Boot Manager (`bootmgr`), Linux GRUB veya kernel görüntüsünü ölçer. Eğer saldırgan diske fiziksel erişim sağlayıp sahte bir önyükleyici enjekte ederse (Evil Maid atağı), PCR 4 değişir.
- **PCR 7 (Secure Boot):** UEFI Güvenli Önyükleme'nin açık olup olmadığını, anahtar sertifikalarını (Platform Key - PK, Key Exchange Key - KEK, Yetkili İmzalar Veritabanı - db ve Yasaklı İmzalar Veritabanı - dbx) ölçer.

Eğer mühürleme politikasında yalnızca PCR 0 ve 4 kilitlenip PCR 7 ihmal edilirse, saldırgan BIOS'a girip Secure Boot'u devre dışı bırakabilir veya kendi sahte sertifikasını `db` veritabanına ekleyebilir. PCR 7 kilitli olmadığından TPM bu değişikliği algılamaz ve şifre çözme anahtarını teslim eder. Bu sebeple kurumsal güvenlik standartları (NIST SP 800-155 ve Microsoft BitLocker Best Practices) PCR 0, 2, 4 ve 7'nin ayrılmaz bir bütün olarak kilitlenmesini şart koşar.

### Ustanın Çırağa Tavsiyesi / Altın Kural
"Evlat, TPM'e bir anahtar emanet ediyorsan, ona sadece 'Ahmet'in bilgisayarı' demeyeceksin. 'Bu anakartın BIOS'u orijinalken (PCR 0), ekran kartı bellenimi ellenmemişken (PCR 2), Windows önyükleyicisi temizken (PCR 4) ve Secure Boot kapısı kilitliyken (PCR 7) bu anahtarı ver' diyeceksin. Bu zincirden tek bir halkayı (özellikle PCR 7'yi) çıkarırsan, saldırgan BIOS'a tek bir tuşla girip bütün güvenlik kaleni yıkar."

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2021 yılında bir siber güvenlik konferansında araştırmacılar, yalnızca PCR 0, 2, 4 kaydedicilerini kullanan bir kurumsal dizüstü bilgisayarda BitLocker korumasını baypas ettiler. Araştırmacılar, BIOS pilini sökerek UEFI ayarlarını fabrika ayarlarına sıfırladılar ve Secure Boot'u devre dışı bıraktılar. PCR 7 mühürleme profiline dahil edilmediği için, saldırganlar imzasız özel bir Linux çekirdeği yükleyerek cihazı açtılar ve TPM'in PCR 0, 2 ve 4 doğrulamasını geçip BitLocker anahtarını RAM'e yüklemesini sağladılar. Sonuç olarak kurumsal diskin tamamı çözüldü. Bu vaka sonrasında Microsoft, Windows 11 ve modern Intune politikalarında PCR 7'yi varsayılan zorunlu profil haline getirdi.

---

## 2. Soru: BitLocker "TPM-Only" Tuzağı ve SPI/LPC Bus Sniffing Donanım Saldırısı

### Soru
Kurumsal ortamlarda yaygın olarak kullanılan "TPM-Only" (Kullanıcı müdahalesiz otomatik açılış) BitLocker yapılandırmasının donanımsal zafiyeti (SPI/LPC Bus Sniffing) nedir, saldırgan anakarta fiziksel temasla VMK anahtarını nasıl çalar ve TPM+PIN bu zafiyeti kriptografik olarak nasıl engeller?

### Detaylı ve Kapsamlı Teknik Cevap
Pek çok kurum, çalışanların konforunu düşünerek BitLocker'ı "Yalnızca TPM (TPM-Only)" modunda dağıtır. Bu senaryoda kullanıcı bilgisayarın güç düğmesine basar, hiçbir parola veya PIN girmeden Windows giriş ekranına kadar gelir. 

Ancak bu konforun arkasında ölümcül bir donanımsal kör nokta yatar: **Ayrık TPM (Discrete TPM - dTPM) ve Anakart Veri Yolu (SPI / LPC Bus).**
1. Birçok kurumsal dizüstü ve masaüstü bilgisayarda TPM, CPU'nun içinde değil, anakart üzerinde ayrı bir entegre devre (örneğin Infineon SLB 9665) olarak bulunur.
2. TPM, CPU ve anakart yonga seti (PCH) ile **SPI (Serial Peripheral Interface)** veya **LPC (Low Pin Count)** veri yolu üzerinden haberleşir. Bu veri yolları genellikle 24-33 MHz hızında çalışan, fiziksel olarak anakart üzerindeki lehim bacakları veya test noktaları (test points) ile dışarıdan erişilebilen yollardır.
3. "TPM-Only" modunda, bilgisayar açıldığı anda UEFI bellenimi PCR ölçümlerini tamamlar ve TPM'den Volume Master Key (VMK) anahtarını talep eder (`TPM2_Unseal`).
4. Eğer TPM parametre şifrelemesi (Parameter Encryption) kullanılmıyorsa veya zayıfsa, TPM çözdüğü 256-bit VMK anahtarını SPI veri yolunun `MISO` (Master In, Slave Out) hattı üzerinden **düz metin (plaintext)** olarak CPU'ya gönderir!
5. Saldırgan cihazın alt kapağını açıp 5 dolarlık bir Raspberry Pi Pico veya mantık analizörünü (logic analyzer) SPI yongasının CLK, CS ve MISO bacaklarına bağlar. Bilgisayarı açtığı anda veri yolundan akan paketleri yakalar ve BitLocker VMK anahtarını ekranda düz metin olarak görür.
6. Elde edilen VMK anahtarı `dislocker` (Linux) veya `libbde` araçlarına verilerek şifreli disk saniyeler içinde çözülür.

**TPM + PIN Koruması Bu Saldırıyı Nasıl Durdurur?**
BitLocker **TPM + PIN** ile yapılandırıldığında, anahtarın çözülmesi için sadece donanım bütünlüğü yetmez; TPM içerisindeki yetkilendirme oturumu (Auth Session) kullanıcının girdiği PIN kodunun hash'ini talep eder. Saldırgan cihazı açtığında TPM açılış aşamasında bekler (`TPM_RC_AUTH_FAIL`); veri yoluna tek bir bayt bile anahtar iletmez. Doğru PIN girilmediği sürece veri yolunda yakalanabilecek hiçbir kriptografik sır akmaz.

### Ustanın Çırağa Tavsiyesi / Altın Kural
"Çırak, 'Bizim bilgisayarlarda BitLocker var, çalınsa da bir şey olmaz' diyen yöneticiye acıyarak bakacaksın. Eğer açılışta PIN sormuyorsa, o disk sadece sokaktaki kapkaççıya karşı şifrelidir; elinde bir tornavidası ve 5 dolarlık bir mikrodenetleyicisi olan herhangi bir stajyer o diski 10 dakikada açar. Kurumsal uç noktalarda TPM+PIN bir lüks değil, donanım düzeyinde zorunluluktur."

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2023 yılında bir güvenlik araştırmacısı, popüler bir oyun konsolu ve kurumsal dizüstü bilgisayar serisi üzerinde yalnızca 10 dolarlık bir Raspberry Pi Pico kullanarak BitLocker anahtarını 43 saniyede ele geçirdiği videoyu yayınladı. Anakart üzerindeki SPI veri yoluna yaylı iğneler (pogo pins) ile temas eden cihaz, TPM'in bilgisayar açılırken CPU'ya yolladığı `TPM2_CC_Unseal` cevabını yakalayarak FVEK anahtarını logladı ve diski tamamen açtı. Olay dünya çapında yankı uyandırdı ve kurumsal SOC/CISO ekipleri Grup İlkeleri üzerinden derhal TPM+PIN zorunluluğunu devreye almak zorunda kaldı.

---

## 3. Soru: Linux LUKS2'de KDF Güvenliği ve `systemd-cryptenroll` TPM2 Entegrasyonu

### Soru
Linux LUKS2 mimarisinde anahtar türetme fonksiyonu (KDF) olarak PBKDF2 yerine Argon2id kullanılmasının önemi nedir ve `systemd-cryptenroll` aracı ile TPM2 yongasına PCR bağlamalı otomatik şifre çözme yapılandırılırken karşılaşılan tuzaklar nelerdir?

### Detaylı ve Kapsamlı Teknik Cevap
Linux Unified Key Setup (LUKS), Linux çekirdeğinin `dm-crypt` altyapısı üzerinde çalışan endüstri standardı disk şifreleme formatıdır. LUKS mimarisinde diski şifreleyen gerçek bir "Master Key" bulunur. Bu master key, disk başlığındaki (header) **Keyslots (Anahtar Yuvaları)** içerisinde kullanıcının parolası veya TPM sırrı ile şifrelenmiş olarak saklanır.

**1. KDF Evrimi: Neden PBKDF2 İflas Etti ve Argon2id Şarttır?**
- **PBKDF2 (Password-Based Key Derivation Function 2):** LUKS1 standardında kullanılan PBKDF2, yalnızca CPU işlem döngüsü (iteration count) ile zorluk yaratır. Ancak bellek gereksinimi (memory footprint) son derece düşüktür (birkaç kilobayt). Bu durum, modern saldırganların paralel işlem yeteneğine sahip GPU kümeleri (Nvidia RTX 4090 serisi) veya özel ASIC çipler kullanarak saniyede milyarlarca parola denemesi yapabilmesine (kaba kuvvet atağı) olanak tanır.
- **Argon2id (Password Hashing Competition Kazananı):** LUKS2 varsayılanı olan Argon2id, hem zaman zorluğu (time cost) hem de yüksek bellek zorluğu (memory cost - varsayılan olarak 1 GB RAM tahsisi) gerektirir. GPU'ların yüksek paralellikte çalışabilmesi için çekirdek başına çok küçük bellek gerekir. Bir parola denemesi için 1 GB bellek gerektiğinde, GPU'nun belleği anında tükenir ve paralel kırma saldırıları imkansız hale gelir. Ayrıca Argon2id, yan kanal (side-channel) saldırılarına ve GPU takaslarına karşı hibrit koruma sunar.

**2. `systemd-cryptenroll` ve TPM2 Entegrasyonu:**
Modern Linux dağıtımlarında (Fedora, RHEL, Ubuntu 23+) LUKS2 birimlerini TPM 2.0 yongasına mühürlemek için `systemd-cryptenroll` kullanılır:
```bash
systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+2+4+7 --tpm2-with-pin=yes /dev/nvme0n1p3
```
Bu komut, LUKS başlığına yeni bir keyslot ekler ve anahtarı TPM'e mühürler.

**Karşılaşılan Kritik Tuzaklar:**
1. **Çekirdek Güncellemesi Tuzağı (PCR 8/9):** Eğer mühürleme politikasına PCR 8 veya 9 (Linux çekirdek ve initramfs ölçümleri) eklenirse; sistem her `apt upgrade` veya `dnf update` alıp yeni bir kernel derlendiğinde PCR 8/9 değişecek ve sistem açılışta TPM kilidini açamayarak acil durum kurtarma moduna düşecektir! Bu sebeple Linux'ta sistem güncellemelerinden etkilenmemek ama donanım manipülasyonunu engellemek için PCR 0, 2 ve 7'ye mühürleme tercih edilir.
2. **Korumasız Initramfs ve UKI (Unified Kernel Image):** Linux açılışında `/boot` dizini genellikle şifresizdir. Saldırgan `/boot/initramfs.img` dosyasını manipüle edip içine ters kabuk atan bir betik koyarsa (Evil Maid), disk şifresi çözüldüğü anda ana makineye sızabilir. Bu tuzağı aşmak için çekirdek, initramfs ve komut satırı tek bir EFI ikilisinde birleştirilip imzalanmalı (**Unified Kernel Image - UKI**) ve PCR 11/12 ile korunmalıdır.

### Ustanın Çırağa Tavsiyesi / Altın Kural
"Çırak, Linux sunucu veya dizüstü kurarken `cryptsetup luksFormat` komutunu ezbere çalıştırma. Başlığı kontrol et: Eğer KDF satırında `pbkdf2` görüyorsan, o diski hemen `cryptsetup luksConvertKey --pbkdf argon2id` ile modernize edeceksin. TPM bağlarken de PCR listesini rastgele doldurmayacaksın; ilk çekirdek güncellemesinde sunucunun başında ağlamak istemiyorsan ölçüm politikasını iyi hesaplayacaksın."

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2022 yılında bir savunma sanayii firmasının Ar-Ge mühendisinin dizüstü bilgisayarı otel odasından çalındı. Cihazda LUKS1 ile şifrelenmiş Ubuntu yüklüydü ve 10 karakterli alfanumerik bir parola kullanılıyordu. Saldırganlar disk başlığını bir kopyalayıcı ile alıp 8 adet Nvidia A100 GPU'dan oluşan bir kırma kümesine yüklediler. PBKDF2 kullanıldığı için GPU kümesi saniyede 12 milyar parola deneyerek mühendisin parolasını 48 saatte kırdı ve diski tamamen açtı. Yapılan adli analizde, aynı parola Argon2id (1 GB RAM maliyeti) ile korunmuş olsaydı aynı GPU kümesinin parolanın kırılması için 340 yıl çalışması gerekeceği raporlandı.
