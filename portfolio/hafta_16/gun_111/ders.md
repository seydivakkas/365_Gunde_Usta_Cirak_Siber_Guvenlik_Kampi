# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 111: Anahtar Yönetimi ve Rotasyon (Key Management and Rotation)

## Usta-Çırak Başlangıç Hasbihali
**Usta:** Evlat, bugüne kadar simetrik şifrelemeyi (AES), asimetrik kriptografiyi (RSA/ECC), dijital imzaları, X.509 zincirlerini ve TLS protokol sınırlarını öğrendin. Ancak kriptografide Auguste Kerckhoffs'un 1883'te koyduğu altın kuralı asla unutmayacaksın: *"Bir kripto sisteminin güvenliği, algoritmanın gizliliğine değil; yalnızca ve yalnızca anahtarın gizliliğine ve yönetimine dayanmalıdır!"* Dünyanın en kırılmaz algoritmasını yazsan bile, anahtarını yanlış yönetirsen, rotasyon yapmazsan veya emekli anahtarı bellekte unutursan tüm sarayın anahtarını hırsıza kendi elinle teslim etmiş olursun!

**Çırak:** Hocam, bir anahtar üretip veriyi şifreledikten sonra o anahtarı güvenli bir sunucuda tutmak yetmez mi? Neden anahtarları sürekli değiştirmek (rotasyon) ve karmaşık durum makineleri (NIST SP 800-57) kurmak zorundayız?

**Usta:** Bir anahtar tek bir kilit için sonsuza kadar kullanılamaz evlat. Zaman geçtikçe şifrelenen veri miktarı artar; şifrelenen veri arttıkça saldırgana kripto-analitik malzeme (aynı anahtarla üretilmiş şifreli metin havuzu) vermiş olursun. Üstelik bir gün o anahtar sızarsa, tüm geçmiş ve gelecek verin buharlaşır. İşte bu yüzden **NIST SP 800-57** standardı, anahtarlar için doğumdan ölüme kadar katı kurallar koyar. Bugün seninle Zarf Şifreleme (Envelope Encryption), Re-wrapping ve Kriptografik Sıfırlama (Zeroization) mekanizmalarını inşa edeceğiz.

---

## 1. NIST SP 800-57 Kriptografik Anahtar Yaşam Döngüsü

NIST SP 800-57 (Recommendation for Key Management), bir anahtarın geçirdiği 6 temel durumu tanımlar:

```
+-----------------------------------------------------------------------------------+
| 1. PRE-ACTIVATION: Anahtar CSPRNG ile üretildi, metaverisi yazıldı, henüz pasif.   |
|         |                                                                         |
|         v                                                                         |
| 2. ACTIVE: Anahtar geçerli; hem yeni veri şifreler hem de eski veriyi çözer.      |
|         |                                            |                            |
|         | (Kriptoperiyot veya Hacim Sınırı Doldu)    | (Güvenlik İhlali / Sızıntı)|
|         v                                            v                            |
| 3. DEPRECATED:                                  5. COMPROMISED:                   |
|    Yeni veri şifreleyemez (CWE-320);               Anahtar sızdı; tüm işlemler     |
|    yalnızca eski veriyi çözebilir.                 derhal kilitlenir!             |
|         |                                            |                            |
|         v                                            v                            |
| 4. DESTROYED (ZEROIZED): Anahtar materyali bellekte ve diskte ezilerek yok edildi.|
+-----------------------------------------------------------------------------------+
```

### 1.1 Kriptoperiyot (Cryptoperiod) Mantığı
Kriptoperiyot, bir anahtarın meşru kullanım için yetkilendirildiği zaman aralığıdır. İki kritik sınırla tetiklenir:
1. **Zaman Sınırı:** KEK için genellikle 1 ila 2 yıl; DEK için 90 gün. Süre dolduğunda anahtar `DEPRECATED` durumuna geçirilir.
2. **Hacim Sınırı (Kriptografik Aşınma):** Özellikle AES-GCM gibi AEAD şifreleyicilerde, aynı anahtarla $2^{32}$'den fazla paket şifrelenirse Birthday Paradox gereği 96-bitlik Nonce çarpışması riski belirir. Bu yüzden belirli bir işlem sayısında (örn. 1.000.000 şifreleme) anahtar zorunlu olarak rotasyona sokulmalıdır (CWE-329 Savunması).

---

## 2. Zarf Şifreleme Mimarisi (Envelope Encryption: KEK vs DEK)

Devasa veritabanlarını veya petabaytlarca bulut verisini tek bir Master anahtarla doğrudan şifrelemek operasyonel bir intihardır:
- Master anahtar değiştirilmek istendiğinde 500 Terabaytlık veritabanını baştan sona deşifre edip yeni anahtarla yeniden şifrelemek günler sürer, veritabanını kilitler ve muazzam I/O maliyeti üretir.

İşte bu sorunu **Zarf Şifreleme (Envelope Encryption)** çözer:

```
                       [ KMS / HSM Donanım Sınırı ]
                                    |
                    +---------------+---------------+
                    | KEK (Key Encryption Key)      |
                    | (Master Anahtar - Asla Çıkmaz)|
                    +---------------+---------------+
                                    |
                           (Key Wrapping / AEAD)
                                    v
                         [ Şifreli DEK + Tag ]
                                    |
                                    v
+-----------------------------------------------------------------------+
| UYGULAMA KATMANI:                                                     |
| 1. Her şifreleme isteğinde anlık tek kullanımlık DEK üretilir.        |
| 2. Veri doğrudan DEK ile şifrelenir: Ciphertext = Encrypt(DEK, Data)  |
| 3. DEK ise KEK ile şifrelenir: WrappedDEK = Encrypt(KEK, DEK)         |
| 4. Zarf Paketi: [ WrappedDEK (32B) ] + [ Ciphertext (500 TB) ]        |
+-----------------------------------------------------------------------+
```

### 2.1 Re-wrapping: $O(1)$ Sürede Anında Anahtar Rotasyonu
Zarf şifrelemenin en büyük mucizesi **Re-wrapping** işlemidir:
- KEK rotasyonu geldiğinde (KEK-1 -> KEK-2), 500 TB'lık `Ciphertext`'e **kesinlikle dokunulmaz**!
- Yalnızca zarfın başındaki 32 baytlık `WrappedDEK` eski KEK-1 ile çözülür, anında yeni KEK-2 ile şifrelenir ve yerine yazılır!
- Petabaytlarca verinin rotasyonu saniyeler içinde, sıfır kesintiyle ($O(1)$ zaman karmaşıklığında) tamamlanır!

---

## 3. Çift Kontrol ve Bilgi Ayrımı (Dual Control & Split Knowledge)

Büyük kurumlarda veya nükleer/askeri sistemlerde hiçbir tek yönetici bir KEK master anahtarına tek başına erişememelidir. Aksi takdirde kötü niyetli bir yönetici veya kaçırılan bir hesap tüm sistemi ele geçirebilir.

- **Dual Control (İki Kişi Kuralı):** Bir kriptografik anahtarın üretilmesi, etkinleştirilmesi veya kurtarılması için en az iki yetkili uzmanın bağımsız olarak sistemde kimlik doğrulaması yapmasıdır.
- **Split Knowledge (Shamir / XOR Prensibi):** Anahtar parçalara bölünür:
  $$\text{MasterKey} = \text{Share}_1 \oplus \text{Share}_2$$
  Tek bir parçaya sahip olan kişi matematiksel olarak sıfır bilgiye (Zero Information) sahiptir; anahtarı yeniden inşa etmek için iki parçanın da bir araya gelmesi zorunludur (CWE-320 Savunması).

---

## 4. Kriptografik Sıfırlama (Zeroization / Crypto-Shredding)

Bir anahtar emekliye ayrıldığında veya silindiğinde işletim sisteminin `free()` çağrısı ya da diskten dosya silme (`rm / unlink`) işlemi yetersizdir. Çünkü modern işletim sistemleri ve SSD denetleyicileri veriyi hemen silmez; bellek bloklarında ve wear-leveling sektörlerinde artık veriler (Remanence / CWE-226) aylarca yaşayabilir.

- **FIPS 140-2 / 140-3 Zeroization Standardı:**
  1. **Geçiş 1:** Anahtarın bulunduğu bayt dizisinin üzerine `0x00` (sıfırlar) yazılır.
  2. **Geçiş 2:** Üzerine `0xFF` (birler) yazılır.
  3. **Geçiş 3:** İşletim sisteminin CSPRNG motorundan alınan kriptografik rastgele baytlar yazılır.
  4. İşaretçi `None` yapılarak çöp toplayıcıya devredilir.
  Bu sayede fiziksel bellek dökümü (RAM dump) veya adli bilişim analizi yapılsa bile eski anahtar kurtarılamaz!

---

## Ustanın Çırağa Öğüdü
Evlat! Anahtar yönetimi yazılımcının vicdanıdır. Kodu ekrana basabilirsin, performansı övebilirsin ama anahtarı hardcoded (`CWE-321`) bırakan, süresi dolmuş anahtarla işlem yapan (`CWE-320`) veya eski anahtarı çöpe atmayan mühendis sadece işini savsaklamış olmaz, tüm organizasyonu uçurumun kenarına sürükler. 
1. Anahtarı asla kodun içine gömme; KMS/HSM arkasına sakla.
2. Zarf şifreleme ve Re-wrapping kullan; veriyi değil, zarfı döndür.
3. Vadesi dolanı tereddütsüz sıfırla (zeroize) ve her kritik anahtara çift kilit vur (Dual Control)!
