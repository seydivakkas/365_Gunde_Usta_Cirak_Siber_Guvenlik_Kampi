# GÜN 103: SORU & CEVAP VE TEKNİK MÜLAKAT DOSYASI
**Aşama 05 — Kriptografi Temelleri ve Uygulamaları**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) — Tüm Hakları Saklıdır.*

---

### SORU 1: AES Blok Şifresinin İç Yapısında SubBytes ve MixColumns Adımları Hangi Kriptografik İlkeleri (Shannon Prensipleri) Gerçekleştirir ve Neden Son Turda MixColumns Uygulanmaz?

#### 1. Soru Başlığı ve Tanımı
FIPS 197 standardı AES algoritmasının iç tur dönüşümlerinde yer alan `SubBytes`, `ShiftRows`, `MixColumns` ve `AddRoundKey` adımlarının matematiksel işlevleri; Claude Shannon'ın Karışıklık (Confusion) ve Yayılma (Diffusion) kuramlarıyla ilişkisi ve algoritmanın son turunda MixColumns adımının atlanmasının mimari nedeni.

#### 2. Derinlemesine Teknik Analiz
Claude Shannon, 1949 yılında yayımladığı *"Communication Theory of Secrecy Systems"* makalesinde güvenli bir şifreleme algoritmasının iki temel niteliğe sahip olması gerektiğini ortaya koymuştur:
1. **Karışıklık (Confusion):** Şifreli metin ile gizli anahtar arasındaki ilişkinin mümkün olduğunca karmaşık, doğrusal olmayan ve tahmin edilemez olmasıdır.
2. **Yayılma (Diffusion):** Düz metindeki tek bir bitin veya anahtardaki tek bir bitin değişmesi durumunda, şifreli metindeki bitlerin yaklaşık yarısının rastgele değişmesidir (Çığ Etkisi - Avalanche Effect).

AES algoritması bu ilkeleri şu dönüşümlerle sağlar:
- **SubBytes (Confusion):** Durum matrisindeki her bayt, Galois Alanı $GF(2^8)$ üzerinde tersi alınıp afin dönüşümünden geçirilerek oluşturulmuş S-Box tablosu ile değiştirilir. Matematiksel olarak $S(x) = M \cdot x^{-1} + b$ fonksiyonudur. Bu işlem tamamen doğrusal değildir (non-linear) ve diferansiyel/doğrusal kriptoanaliz saldırılarına karşı en kritik savunma hattıdır.
- **ShiftRows ve MixColumns (Diffusion):** ShiftRows adımı durum matrisinin satırlarını dairesel olarak sola kaydırarak baytları sütunlar arasına dağıtır. Hemen ardından gelen MixColumns adımı, her bir sütunu $GF(2^8)$ üzerinde sabit bir matrisle çarpar:
  $$\begin{bmatrix} s'_{0,c} \\ s'_{1,c} \\ s'_{2,c} \\ s'_{3,c} \end{bmatrix} = \begin{bmatrix} 02 & 03 & 01 & 01 \\ 01 & 02 & 03 & 01 \\ 01 & 01 & 02 & 03 \\ 03 & 01 & 01 & 02 \end{bmatrix} \begin{bmatrix} s_{0,c} \\ s_{1,c} \\ s_{2,c} \\ s_{3,c} \end{bmatrix}$$
  Bu işlem sayesinde tek bir bayttaki en küçük değişiklik, sadece iki tur içinde tüm durum matrisine (128 bit) yayılır.

**Son Turda Neden MixColumns Atlanır?**
AES şifre çözme (deşifre) işlemi şifrelemenin tersine adımlardan oluşur. Eğer son turda MixColumns uygulansaydı, şifre çözme işleminin başlangıcında `AddRoundKey` yapıldıktan hemen sonra `InvMixColumns` uygulamak gerekirdi. Son turun MixColumns adımının çıkarılması, şifreleme ve şifre çözme mimarisinin simetrik bir yapıda kalmasını sağlar ve donanımsal devre tasarımında (ASIC/FPGA) silikon maliyetini ve gecikmeyi ciddi oranda azaltır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir IoT donanım güvenlik denetiminde, mühendislerin gömülü cihazın işlemci gücünü artırmak amacıyla AES turlarını 10 turdan 4 tura indirdiği ve MixColumns adımını devre dışı bıraktığı tespit edilir.

**Pratik Çözüm:**
Tur sayısını veya MixColumns/SubBytes adımlarını azaltmak difüzyon ve konfüzyon bariyerlerini yıkar; Diferansiyel Kriptoanaliz (Differential Cryptanalysis) ile anahtarın birkaç saat içinde çıkartılmasına yol açar. Gömülü sistemlerde daima FIPS 197 tam standart tur sayıları (AES-128 için 10, AES-256 için 14 tur) ve donanım kripto motorları (ARM Crypto Extensions / AES-NI) kullanılmalıdır:
```python
# FIPS 197 Standart Tam Tur Uygulaması
from uygulama.aes_cipher_engine import encrypt_block, key_expansion

# AES-128: 10 tur eksiksiz çalıştırılır
w, nr = key_expansion(aes_128_key)  # nr = 10
ciphertext_block = encrypt_block(plaintext_block, w, nr)
```

#### 4. Ustanın Çırağa Tavsiyesi
"Evladım, 'biraz daha hızlı çalışsın' diye kriptografik algoritmanın içindeki matematiksel çarklarla oynayan bir yazılımcı, kapının kilidindeki dişleri törpüleyen bir çilingire benzer. SubBytes ve MixColumns öyle bir matematiksel dengedir ki, tek bir turu eksiltsen tüm kale çöker. Standartlara dokunma, optimizasyonu algoritmayı bozarak değil, donanım komut setlerini (AES-NI) kullanarak yap!"

---

### SORU 2: ECB (Electronic Codebook) Modu Neden Güvensizdir (CWE-327) ve CBC/CTR Modları Rastgele Başlangıç Vektörü (IV) ile Bu Açığı Nasıl Kapatır?

#### 1. Soru Başlığı ve Tanımı
Blok şifre işletim modları arasında ECB modunun doğurduğu desen sızıntısı (Pattern Leakage / ECB Penguin) zaafı; CBC ve CTR modlarının çalışma mantığı ve rastgele Başlangıç Vektörünün (IV / Initialization Vector) matematiksel zorunluluğu (CWE-329).

#### 2. Derinlemesine Teknik Analiz
ECB modunda her 16 baytlık düz metin bloğu $P_i$, diğer bloklardan tamamen bağımsız olarak aynı gizli anahtarla şifrelenir:
$$C_i = E_K(P_i)$$
Bu formülün kaçınılmaz sonucu şudur: **Eğer $P_i = P_j$ ise, $C_i = C_j$ olmak zorundadır.**

Bir veri dosyasında, veritabanı yedeğinde veya bitmap görselde tekrarlayan kalıplar (boşluklar, sıfır dizileri, tekrarlayan veri alanları) yer alır. ECB ile şifrelendiğinde bu desenler şifreli metne birebir yansır. Ünlü **"ECB Penguin"** deneyi bu durumu görselleştirir: Linux Tux pengueni resmi ECB ile şifrelendiğinde pikseller değişse de aynı renkteki bloklar aynı şifreli deseni oluşturduğu için penguenin ana hatları şifreli resimde görünmeye devam eder.

**CBC ve CTR Modlarının Savunması:**
- **CBC (Cipher Block Chaining):**
  $$C_0 = E_K(P_0 \oplus IV), \quad C_i = E_K(P_i \oplus C_{i-1})$$
  Her blok kendinden önceki şifreli blokla XOR'lanır. İlk blok ise rastgele bir IV ile XOR'lanır. Böylece iki özdeş düz metin bloğu ($P_1 = P_2$) şifrelense dahi, girdileri farklı ($P_1 \oplus C_0 \neq P_2 \oplus C_1$) olacağı için şifreli çıktılar tamamen farklı ve rastgeledir.
- **CTR (Counter Mode):**
  $$C_i = P_i \oplus E_K(\text{Nonce} \parallel \text{Counter}_i)$$
  Blok şifre akış şifresine dönüştürülür. Şifrelenen şey sayaç değeridir. Her blokta sayaç arttığı için anahtar akışı (keystream) benzersizdir ve desen sızıntısı imkansızdır.

**IV'nin Güvenlik Eşiği (CWE-329):**
CBC ve CTR modlarında IV gizli olmak zorunda değildir, ancak **kesinlikle tahmin edilemez ve her oturumda benzersiz (`secrets.token_bytes(16)`)** olmalıdır. Statik, ardışık veya sıfırlardan oluşan bir IV kullanmak, saldırganın ilk blok üzerinde seçilmiş düz metin saldırısı (Chosen-Plaintext Attack - CPA) yapmasına imkan tanır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir sağlık teknolojisi şirketi, hasta tıbbi tahlil sonuçlarını veritabanında `AES/ECB/PKCS5Padding` ile şifrelemektedir. Saldırgan veritabanına sızdığında şifreyi çözemese bile, "NEGATİF" ve "POZİTİF" sonuçlarının şifreli karşılıklarının her zaman aynı 16 baytlık blok olduğunu fark eder. Hangi hastaların HIV veya kanser pozitif olduğunu hiç anahtar bilmeden sadece şifreli blokları sayarak teşhis eder!

**Pratik Çözüm:**
Sistem derhal AES-CBC veya AES-CTR moduna geçirilmeli, her kayıt için kriptografik rastgele IV üretilmelidir:
```python
import secrets
from uygulama.aes_cipher_engine import AESCipherEngine

# Kriptografik rastgele IV ile CBC şifreleme
rastgele_iv = secrets.token_bytes(16)
sonuc = AESCipherEngine.encrypt_cbc(
    plaintext="Tahlil Sonucu: NEGATİF",
    key=kurumsal_anahtar,
    iv=rastgele_iv
)
# Veritabanında iv_hex ve ciphertext_hex birlikte saklanır
```

#### 4. Ustanın Çırağa Tavsiyesi
"Çırağım, kodunda `ECB` harflerini gördüğün an arkana bakmadan kaç! ECB şifreleme değil, verinin üzerini tülle örtmektir; şekli yine belli olur. CBC veya CTR kullanırken de 'her seferinde rastgele IV üretmekle uğraşmayayım, sabit bir IV belirleyeyim' tembelliğine kapılma (`CWE-329`). Kriptografide tembellik, felakete davetiyedir!"

---

### SORU 3: Simetrik Şifreleme Neden Tek Başına Veri Bütünlüğünü Koruyamaz (Bit-Flipping Saldırısı) ve AEAD (Authenticated Encryption) Neden Zorunludur?

#### 1. Soru Başlığı ve Tanımı
Şifrelemenin yalnızca gizlilik (Confidentiality) sağladığı, veri bütünlüğünü (Integrity) ve orijinalliğini (Authenticity) garanti etmediği gerçeğinin analizi; CBC/CTR modlarında Bit-Flipping saldırısı mekanizması ve AEAD (Encrypt-then-MAC / GCM) çözümünün incelenmesi (CWE-353).

#### 2. Derinlemesine Teknik Analiz
Bir simetrik şifreleme algoritması (örneğin AES-CTR veya AES-CBC), veriyi yabancı gözlerden gizler. Ancak şifreli metin ağ üzerinden taşınırken veya diskte saklanırken yetkisiz bir aktör tarafından manipüle edilebilir.

**CTR Modunda Bit-Flipping Saldırısı:**
CTR modunda şifreleme formülü $C_i = P_i \oplus K_i$'dir. Burada $K_i$ şifreli sayaç çıktısıdır (keystream).
Bir saldırgan $P_i$'nin içeriğini tahmin edebiliyorsa (örneğin protokol başlığında bir para miktarı veya kullanıcı yetkisi olduğunu biliyorsa):
- Saldırgan şifreli metindeki ilgili baytı $C_i' = C_i \oplus \Delta$ şeklinde değiştirir.
- Alıcı şifreyi çözdüğünde:
  $$P_i' = C_i' \oplus K_i = (C_i \oplus \Delta) \oplus K_i = (P_i \oplus K_i \oplus \Delta) \oplus K_i = P_i \oplus \Delta$$
- Sonuç: Alıcı, hiçbir hata mesajı almadan saldırganın istediği yeni veriyi ($P_i \oplus \Delta$) deşifre eder! Örneğin "USER" yetkisi bit çevirme ile "ROOT" yetkisine dönüştürülebilir.

**AEAD (Authenticated Encryption with Associated Data) Çözümü:**
AEAD mimarisi, gizlilik ve bütünlüğü tek bir kriptografik yapıda birleştirir. **Encrypt-then-MAC (EtM)** standardında:
1. Veri önce şifrelenir ($C = E_{K_1}(P)$).
2. Şifreli metin, IV ve ilişkili açık metaveri (AAD) üzerinden kriptografik bir kimlik doğrulama etiketi (Authentication Tag) hesaplanır:
   $$T = \text{HMAC}_{K_2}(IV \parallel C \parallel AAD)$$
3. Şifre çözme aşamasında, alıcı önce etiketi **sabit zamanlı (`hmac.compare_digest`)** doğrular.
4. Eğer saldırgan şifreli metinde veya IV'de tek bir biti bile değiştirmişse, etiket tutmaz ve sistem `AuthenticationTagMismatchError` (`CWE-353`) fırlatarak şifre çözme işlemini başlatmadan reddeder!

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir telekomünikasyon şirketi, yönlendiriciler arasındaki yönlendirme tablolarını ve yapılandırma komutlarını sadece AES-CTR ile şifreleyerek aktarmaktadır. Araya giren (MitM) bir saldırgan, IP paketindeki hedef port baytına denk gelen şifreli biti çevirerek ağ trafiğini kendi sahte sunucusuna yönlendirir. Şifreleme aktif olduğu halde veri manipüle edilmiştir.

**Pratik Çözüm:**
Şirket haberleşme protokolünü AEAD Encrypt-then-MAC mimarisine geçirmelidir:
```python
from uygulama.aes_cipher_engine import AESCipherEngine

# AEAD Şifreleme (Şifreli metin + HMAC etiketi üretir)
res = AESCipherEngine.encrypt_aead_etm(
    plaintext="TRANSFER_AMOUNT=000100_TL",
    encryption_key=aes_key,
    mac_key=hmac_key
)

# Alıcı tarafında kurcalanma kontrolü ve güvenli deşifre
dec_res = AESCipherEngine.decrypt_aead_etm(
    ciphertext_hex=res.ciphertext_hex,
    encryption_key=aes_key,
    mac_key=hmac_key,
    iv_hex=res.iv_hex,
    tag_hex=res.tag_hex
)
# Tek bir bit kurcalanırsa AuthenticationTagMismatchError fırlatılır
```

#### 4. Ustanın Çırağa Tavsiyesi
"Çırağım, 'şifreledim, o halde güvenlidir' demek, evin kapısını kilitleyip anahtar deliğine dinamit yerleştirmeye izin vermeye benzer! Hırsız kapıyı açamaz ama kilidi patlatıp içeri girer. Bütünlük doğrulaması (AEAD) olmayan bir şifreleme sistemi yarı çıplaktır. Kurumsal projelerinde çıplak CBC veya CTR kullanma; daima ya AES-GCM ya da Encrypt-then-MAC (EtM) standardını zorunlu kıl!"
