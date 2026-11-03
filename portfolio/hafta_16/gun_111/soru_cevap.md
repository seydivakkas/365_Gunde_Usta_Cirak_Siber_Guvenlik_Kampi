# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 111: Anahtar Yönetimi ve Rotasyon — Soru ve Cevaplar

---

## Soru 1: Zarf Şifreleme (Envelope Encryption) ve Re-wrapping Mimarisi

### 1. Soru Başlığı ve Tanımı
Zarf Şifreleme (Envelope Encryption) nedir ve KEK (Key Encryption Key) ile DEK (Data Encryption Key) hiyerarşik ayrımı neden zorunludur? Büyük ölçekli kurumsal veritabanlarında petabaytlarca veriyi doğrudan tek bir anahtarla şifrelemenin operasyonel ve kriptografik riskleri nelerdir? "Re-wrapping" işlemi $O(1)$ karmaşıklığında sıfır kesintili anahtar rotasyonunu nasıl mümkün kılar?

### 2. Derinlemesine Teknik Analiz
Büyük ölçekli sistemlerde (AWS S3, Google Cloud Storage, kurumsal SQL/NoSQL veritabanları) veriyi tek bir statik simetrik anahtarla doğrudan şifrelemek iki büyük felakete yol açar:
1. **Kriptografik Aşınma (Cryptographic Wear-out):** AES-GCM gibi modern AEAD algoritmalarında aynı anahtarla çok fazla veri şifrelendiğinde ($2^{32}$'den fazla paket), 96-bitlik rastgele Nonce değerlerinin çarpışma ihtimali (Birthday Paradox) kritik seviyeye ulaşır. Tek bir Nonce iki farklı pakette tekrarlanırsa, saldırgan GCM kimlik doğrulama anahtarını ($H$) hesaplayabilir ve tüm veritabanı bütünlüğünü bozar (CWE-329).
2. **Rotasyon Çıkmazı:** Yıllık anahtar rotasyonu gerektiğinde, 500 Terabaytlık veriyi baştan sona deşifre edip yeni anahtarla yeniden şifrelemek günler sürer, devasa disk I/O ve CPU tüketir ve sistemin durmasına (downtime) sebep olur.

**Zarf Şifreleme (Envelope Encryption) Çözümü:**
- **KEK (Key Encryption Key):** Donanımsal Güvenlik Modülü (HSM) veya bulut KMS içerisinde yaşayan, hiçbir zaman o güvenli donanımdan dışarı çıkmayan 256-bitlik anahtardır.
- **DEK (Data Encryption Key):** Uygulama katmanında her veri kaydı veya dosya için CSPRNG ile üretilen tek kullanımlık 256-bitlik geçici simetrik anahtardır.
- **Şifreleme Akışı:**
  $$\text{DataCiphertext} = \text{AES-GCM-Encrypt}(\text{DEK}, \text{Plaintext})$$
  $$\text{WrappedDEK} = \text{AES-GCM-Encrypt}(\text{KEK}, \text{DEK})$$
  $$\text{Zarf Paketi} = [\text{WrappedDEK} \parallel \text{DataCiphertext}]$$

**Re-wrapping Prensibi ($O(1)$ Hızında Rotasyon):**
KEK rotasyonu yapıldığında (KEK-1 emekliye ayrılıp KEK-2 aktif edildiğinde), devasa `DataCiphertext` bloğuna **kesinlikle dokunulmaz**!
- Yalnızca zarfın başlığındaki 32 baytlık `WrappedDEK` eski KEK-1 ile çözülür, anında yeni KEK-2 ile şifrelenir ve başlığa geri yazılır:
  $$\text{DEK} = \text{Decrypt}(\text{KEK}_1, \text{WrappedDEK}_1)$$
  $$\text{WrappedDEK}_2 = \text{Encrypt}(\text{KEK}_2, \text{DEK})$$
- 500 Terabaytlık veritabanının anahtar rotasyonu saniyeler içerisinde, veriler yerinden kımıldatılmadan, sıfır kesintiyle tamamlanır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir sağlık teknolojisi şirketi, 20 milyon hastanın tıbbi görüntüleme dosyalarını (PACS/DICOM) tek bir AES anahtarıyla şifrelemiştir. Denetim kurulu yıllık anahtar rotasyonu talep ettiğinde, sistem mühendisleri 800 TB veriyi yeniden şifrelemeye çalışmış, sunucular aşırı I/O yükünden kilitlenmiş ve acil servis görüntüleme sistemi 18 saat boyunca hizmet verememiştir.

**Pratik Çözüm:**
Zarf şifreleme ve Re-wrapping motoru devreye alınmalıdır:
```python
def rotate_and_rewrap_database_records(records, kms_service, envelope_engine):
    # 1. KEK rotasyonu: KEK-1 -> KEK-2
    new_kek = kms_service.rotate_kek("kek_v2", bit_length=256)
    # 2. Her kayıt için O(1) Re-wrapping yürüt
    for record in records:
        # Büyük veri şifreli metnine dokunmadan sadece DEK'i yeni KEK ile sar
        record.envelope = envelope_engine.re_wrap_envelope(record.envelope)
        record.save()
```

### 4. Ustanın Çırağa Tavsiyesi
Çırak! Dağı yerinden oynatmak akıl işi değildir; dağın anahtarını değiştirmek akıl işidir. 500 Terabaytlık veriyi her yıl baştan şifrelemeye kalkan mühendis hamallık yapar. Zarf şifreleme kullanacaksın; veriyi küçük bir DEK ile kilitleyecek, o küçük anahtarı da KEK ile saracaksın. Rotasyon vakti geldiğinde sadece minik zarfı değiştireceksin; devasa ambarın kapısı bile gıcırdamayacak!

---

## Soru 2: NIST SP 800-57 Yaşam Döngüsü ve "DEPRECATED" Durumunun Hassasiyeti

### 1. Soru Başlığı ve Tanımı
NIST SP 800-57 standardında bir kriptografik anahtarın yaşam döngüsü evreleri (Active, Deprecated, Compromised, Destroyed) nelerdir? Bir anahtarın kriptoperiyodu dolduğunda doğrudan silinmek yerine neden **"DEPRECATED"** durumuna geçirilmesi gerekir? Bu durumdaki bir anahtarla yeni veri şifrelenmesi (CWE-320) neden engellenmelidir?

### 2. Derinlemesine Teknik Analiz
Kriptografik anahtarlar ikili (var/yok) mantığıyla yönetilemez. NIST SP 800-57, anahtar durumlarını ve yetkilerini kesin çizgilerle ayırır:
1. **ACTIVE (Aktif):** Anahtar meşrudur. Hem yeni verileri şifreleme (Encrypt/Sign) hem de var olan verileri çözme (Decrypt/Verify) yetkisine sahiptir.
2. **DEPRECATED (Emekli / Kullanımdan Kaldırılmış):** Anahtarın kriptoperiyodu dolmuştur veya yeni bir anahtara geçilmiştir.
   - **Kritik Kural:** DEPRECATED anahtar **YALNIZCA VE YALNIZCA DEŞİFRE (DECRYPT) İÇİN KULLANILABİLİR!**
   - Bu anahtarla kesinlikle yeni bir veri şifrelenemez (`ENCRYPT IS FORBIDDEN` / CWE-320).
   - **Neden Doğrudan Silinmez?** Çünkü geçmişte bu anahtarla şifrelenmiş arşiv verileri, yedekler ve eski loglar mevcuttur. Eğer anahtar süre biter bitmez silinirse, geçmiş 5 yılın tüm verisi bir daha açılamaz hale gelir (Ransomware etkisi)!
3. **COMPROMISED (İhlal Edilmiş / Sızmış):** Anahtarın sızdığı veya yetkisiz erişime uğradığı teyit edilmiştir.
   - **Kritik Kural:** Hem şifreleme hem de deşifre anında durdurulur! Bu anahtarla gelen hiçbir talep kabul edilmez.
4. **DESTROYED (Kriptografik Olarak İmha Edilmiş):** Anahtara bağlı tüm veriler yeni anahtarlara re-wrap edilmiş veya güvenle silinmiştir. Anahtar bellekte ve diskte üzerine yazma (Zeroization) ile tamamen yok edilmiştir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir e-fatura yazılımında eski KEK anahtarının süresi dolduğunda sistem yöneticisi anahtar durumunu güncellememiş, yazılım yeni kesilen faturaları 5 yıl önce süresi dolmuş KEK ile şifrelemeye devam etmiştir. Maliye denetiminde eski anahtarın kripto-analitik olarak zayıfladığı tespit edilmiş ve kurum ağır regülasyon cezasına çarptırılmıştır.

**Pratik Çözüm:**
KMS motorunda katı durum denetimi uygulanmalıdır:
```python
def validate_key_for_operation(key: KeyMetadata, operation: str) -> None:
    if key.state == KeyState.COMPROMISED:
        raise KeyCompromisedError("CWE-320: İhlal edilmiş anahtarla hiçbir işlem yapılamaz!")
    if key.state == KeyState.DESTROYED:
        raise KeyAlreadyDestroyedError("CWE-226: İmha edilmiş anahtar kullanılamaz!")
    if operation == "ENCRYPT":
        if key.state == KeyState.DEPRECATED:
            raise KeyDeprecatedError("CWE-320: DEPRECATED durumdaki anahtarla YENİ ŞİFRELEME YASAKTIR!")
        if key.state != KeyState.ACTIVE:
            raise KeyManagementError("Yalnızca ACTIVE anahtarlarla yeni şifreleme yapılabilir.")
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat! Emekli bir askere yeni savaşa gitmesi için kılıç verilmez ama geçmiş zaferlerin madalyasını okuması için kütüphaneye girmesine izin verilir. DEPRECATED anahtar işte böyledir; geçmişi okuyabilir ama geleceği yazamaz! Bir anahtarın durumunu takip etmeyen mühendis, emekli generali cepheye süren acemi komutan gibi ordusunu felakete sürükler.

---

## Soru 3: Çift Kontrol (Dual Control) ve Kriptografik Sıfırlama (Zeroization)

### 1. Soru Başlığı ve Tanımı
Kritik anahtar yönetim sistemlerinde **Çift Kontrol (Dual Control / Split Knowledge)** prensibi nedir ve tekil yönetici riskini nasıl ortadan kaldırır? Emekliye ayrılan bir anahtarın diskten ve bellekten silinmesinde standart işletim sistemi silme komutları neden yetersizdir? **Kriptografik Sıfırlama (Zeroization / CWE-226)** nasıl icra edilmelidir?

### 2. Derinlemesine Teknik Analiz
**1. Dual Control ve Split Knowledge (CWE-320 Önlemi):**
Bir kurumda Master KEK veya Kök CA özel anahtarına tek bir kişinin tam erişiminin olması devasa bir tekil arıza noktası (Single Point of Failure) ve iç tehdit (Insider Threat) kaynağıdır.
- **İki Kişi Kuralı (Dual Control):** Anahtarın üretilmesi, etkinleştirilmesi veya yedekten yüklenmesi için en az iki bağımsız yetkilinin (örn. Güvenlik Yöneticisi ve Sistem Yöneticisi) birlikte oturum açması zorunludur.
- **Split Knowledge (2-of-2 XOR Prensibi):**
  Anahtar iki parçaya ayrılır:
  $$\text{MasterKey} = \text{Share}_A \oplus \text{Share}_B$$
  $$\text{Share}_A \leftarrow \text{CSPRNG}(256\text{ bit}), \quad \text{Share}_B = \text{MasterKey} \oplus \text{Share}_A$$
  Ne Yönetici A ne de Yönetici B tek başına anahtarı bilemez. İkisi de parçalarını aynı anda HSM/KMS arayüzüne girmedikçe anahtar oluşturulamaz.

**2. Artık Veri (Remanence / CWE-226) ve Zeroization Zorunluluğu:**
Geleneksel programlamada bir anahtar silinirken `del key` veya `free(key)` denir. Bu işlem yalnızca bellek işaretçisini siler; anahtarın ham baytları RAM'de kalmaya devam eder!
- İşletim sistemi RAM içeriğini diske takas (swap/pagefile) ettiğinde, anahtar açık metin olarak sabit diske yazılır.
- Sunucu çöktüğünde üretilen bellek dökümleri (`crash dump / core dump`), saldırganlar tarafından incelenerek eski anahtarlar kolayca çalınabilir (Heartbleed ve Mimikatz mantığı).
- **Zeroization (Kriptografik Sıfırlama / FIPS 140-3):**
  Bellekteki ve diskteki anahtarın üzerine doğrudan şu üç geçişli silme protokolü uygulanmalıdır:
  1. `0x00` (Tüm bitler sıfırlanır).
  2. `0xFF` (Tüm bitler bire çekilir).
  3. Kriptografik rastgele baytlar (`secrets.token_bytes`) yazılır.
  4. Ardından bellek serbest bırakılır. Bu sayede RAM kalıntısı veya soğuk önyükleme (Cold Boot Attack) saldırıları tamamen etkisiz hale gelir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir kripto para borsasında altyapı mühendisi, soğuk cüzdan master anahtarını Python ortamında belleğe yüklemiş ve işlem bitince `del master_key` demiştir. Birkaç hafta sonra sunucuda oluşan bir arıza nedeniyle alınan memory crash dump dosyası harici bir teknik servise gönderilmiş ve servis mühendisleri bellek dökümü içerisinden borsanın master anahtarını ayıklayarak cüzdandaki varlıkları transfer etmiştir.

**Pratik Çözüm:**
Anahtar nesnesine güvenli zeroization fonksiyonu entegre edilmelidir:
```python
def secure_zeroize_bytearray(key_buffer: bytearray) -> None:
    """RAM'deki anahtar materyalini üzerine 3 geçişle yazarak sıfırlar."""
    length = len(key_buffer)
    # 1. Geçiş: Sıfırlar
    for i in range(length):
        key_buffer[i] = 0x00
    # 2. Geçiş: Birler
    for i in range(length):
        key_buffer[i] = 0xFF
    # 3. Geçiş: Kriptografik Rastgele Baytlar
    random_bytes = secrets.token_bytes(length)
    for i in range(length):
        key_buffer[i] = random_bytes[i]
```

### 4. Ustanın Çırağa Tavsiyesi
Çırak! Yazdığın kodun bellekte bıraktığı ayak izi, karda yürüyen hırsızın ayak izi gibidir; üzerini süpürmezsen arkandan gelen herkes izin sahibini bulur. Bir anahtarla işin bittiğinde onu arkanda çöp gibi bırakma; önce sıfırlarla, sonra birlerle, en son rastgele fırtınayla ez ki, o bellek hücresi bir zamanlar bir sır taşıdığını kendisi bile hatırlamasın!
