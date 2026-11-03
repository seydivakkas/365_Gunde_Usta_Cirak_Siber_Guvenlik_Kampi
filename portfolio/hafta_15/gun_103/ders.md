# GÜN 103: SİMETRİK ŞİFRELEME VE AES (ADVANCED ENCRYPTION STANDARD)
**Aşama 05 — Kriptografi Temelleri ve Uygulamaları (Hafta 15 / Gün 103)**  
*Eğitmen / Usta: Seydi Eryılmaz (@seydivakkas)*

---

## 1. USTANIN DERS GİRİŞİ: "MODERN DÜNYANIN ÇELİK KASASI: AES"

Evladım, dijital çağda banka hesaplarımızdan askeri telsiz iletişimine, internet trafiğimizden (HTTPS/TLS) telefonumuzdaki kilitli dosyalara kadar her şey tek bir matematiksel kalenin arkasında korunur: **AES (Advanced Encryption Standard)**.

1970'lerde dünya, IBM tarafından tasarlanan DES (Data Encryption Standard) algoritmasını kullanıyordu. Ancak DES'in 56-bitlik anahtar boyutu, 1990'ların sonuna gelindiğinde kaba kuvvet (brute-force) saldırıları karşısında yetersiz kaldı; özel donanımlarla birkaç saat içinde kırılabilir hale geldi.

Bunun üzerine Amerikan Ulusal Standartlar ve Teknoloji Enstitüsü (NIST), 1997 yılında dünya çapında açık bir yarışma başlattı. Dünyanın en parlak kriptologları algoritmalarını yarıştırdı. Sonunda iki Belçikalı kriptografın — **Vincent Rijmen ve Joan Daemen** — tasarladığı **Rijndael** algoritması, sunduğu üstün güvenlik, yüksek matematiksel zarafet ve hem donanımda hem yazılımda sergilediği hız performansı sayesinde birinci seçildi ve 2001 yılında **FIPS 197** standardı olarak kabul edildi.

Bugünkü dersimizde; AES'in içindeki çarkların nasıl döndüğünü, Galois Alanı $GF(2^8)$ matematiğini, işletim modlarını (ECB, CBC, CTR) ve kurumsal sistemlerde neden AEAD (Kimlik Doğrulamalı Şifreleme) kullanmak zorunda olduğumuzu en ince ayrıntısına kadar öğreneceksin.

---

## 2. AES BLOK ŞİFRE MİMARİSİ VE MATEMATİKSEL İÇ YAPISI

AES, bir **Yer Değiştirme-Permütasyon Ağıdır (Substitution-Permutation Network - SPN)**. Veriyi 128-bitlik (16 baytlık) bloklar halinde işler. Bloklar 4x4 boyutunda iki boyutlu bir bayt matrisi (State Matrix) olarak ele alınır:

$$\begin{bmatrix} s_{0,0} & s_{0,1} & s_{0,2} & s_{0,3} \\ s_{1,0} & s_{1,1} & s_{1,2} & s_{1,3} \\ s_{2,0} & s_{2,1} & s_{2,2} & s_{2,3} \\ s_{3,0} & s_{3,1} & s_{3,2} & s_{3,3} \end{bmatrix}$$

### 2.1. Anahtar Boyutu ve Tur Sayısı
AES algoritması anahtar uzunluğuna göre farklı sayıda ardışık turdan (rounds) oluşur:
- **AES-128:** 16 bayt anahtar, 10 tur ($N_r = 10$).
- **AES-192:** 24 bayt anahtar, 12 tur ($N_r = 12$).
- **AES-256:** 32 bayt anahtar, 14 tur ($N_r = 14$).

### 2.2. Bir Turun Dört Temel Adımı
Her bir tur, Claude Shannon'ın ortaya koyduğu iki büyük güvenlik ilkesini — **Karışıklık (Confusion)** ve **Yayılma (Diffusion)** — sağlamak için şu 4 matematiksel dönüşümü sırayla uygular:

1. **SubBytes (Doğrusal Olmayan Yer Değiştirme):**
   - Her bayt, Galois Alanı $GF(2^8)$ üzerinde tersi alınıp afin dönüşümünden geçirilerek oluşturulmuş 256 baytlık sabit bir tablo (S-Box) ile değiştirilir.
   - Doğrusal kriptoanaliz ve diferansiyel ataklara karşı maksimum direnç sağlar (Karışıklık / Confusion).

2. **ShiftRows (Satır Kaydırma):**
   - 0. satır sabit kalır.
   - 1. satır 1 bayt sola kaydırılır.
   - 2. satır 2 bayt sola kaydırılır.
   - 3. satır 3 bayt sola kaydırılır.
   - Sütunlar arasındaki bayt ilişkilerini harmanlar (Yayılma / Diffusion).

3. **MixColumns (Sütun Karışımı):**
   - Her sütun, $GF(2^8)$ alanında $c(x) = 03x^3 + 01x^2 + 01x + 02$ polinomu ile matris çarpımına tabi tutulur.
   - İndirgenemez polinom: $m(x) = x^8 + x^4 + x^3 + x + 1$ (Hex: `0x11B`).
   - Tek bir bayttaki değişiklik, sonraki turda tüm 16 bayta yayılır (Çığ Etkisi - Avalanche Effect).
   - *Not:* Son turda (Round $N_r$) MixColumns adımı uygulanmaz; böylece şifre çözme algoritması şifreleme ile simetrik bir yapı kazanır.

4. **AddRoundKey (Tur Anahtarı Ekleme):**
   - Durum matrisinin her bir sütunu, anahtar genişletme algoritmasından (Key Schedule) gelen ilgili tur anahtarı ile bit düzeyinde XOR (`^`) işlemine sokulur.

---

## 3. İŞLETİM MODLARI (MODES OF OPERATION): DOĞRU MODU SEÇMEK

Blok şifreler doğası gereği yalnızca 16 baytlık tek bir bloğu şifreler. 16 bayttan uzun verileri (dosyalar, ağ paketleri) şifrelemek için **İşletim Modları** kullanılır.

### 3.1. ECB (Electronic Codebook): Kurumsal Felaket (CWE-327)
ECB modunda verinin her 16 baytlık bloğu diğerlerinden tamamen bağımsız olarak aynı anahtarla şifrelenir.
- **Büyük Tehlike (Desen Sızıntısı):** Eğer veride iki özdeş 16 baytlık blok varsa (örneğin kurumsal veritabanındaki boşluklar veya bir bitmap resmin pikselleri), şifreli metindeki bloklar da birbirinin tıpatıp aynısı olur.
- Kriptografi dünyasında meşhur olan **"ECB Penguin"** deneyi bunu açıkça gösterir: Linux pengueni resmi ECB ile şifrelendiğinde tüm renkler kaybolur ancak penguenin silüeti ve hatları şifreli resmin içinde apaçık görünmeye devam eder!
- **Hüküm:** ECB modu üretim sistemlerinde **KESİNLİKLE YASAKTIR**.

### 3.2. CBC (Cipher Block Chaining): Zincirleme ve IV
CBC modunda her düz metin bloğu, şifrelenmeden önce bir önceki şifreli blokla XOR'lanır.
- İlk bloğu XOR'lamak için **Başlangıç Vektörü (IV - Initialization Vector)** kullanılır.
- **IV'nin Altın Kuralı (CWE-329):** IV gizli olmak zorunda değildir, ancak **kesinlikle tahmin edilemez ve her şifrelemede rastgele (`secrets.token_bytes(16)`)** olmalıdır. Statik veya sıfır IV kullanmak CBC'yi çözer!
- **Dolgu Zorunluluğu (PKCS#7):** Veri 16'nın katı olmak zorundadır. Eksik kalan baytlar, eksik bayt sayısı değeriyle doldurulur (Örn: 3 bayt eksikse `\x03\x03\x03`).
- **Tehdit:** CBC modu, hata mesajları dikkatli yönetilmezse Dolgu Oracle (Padding Oracle) saldırılarına maruz kalabilir.

### 3.3. CTR (Counter Mode): Blok Şifreyi Akış Şifresine Çevirmek
CTR modunda şifrelenen şey verinin kendisi değil, sürekli artan bir sayaçtır (`Nonce || Counter`).
- Üretilen şifreli sayaç çıktısı (keystream), düz metinle doğrudan XOR'lanır.
- **Avantajları:** Dolgu (padding) gerektirmez; veri kaç bayt ise şifreli metin de o kadar bayttır. Bloklar birbirini beklemez; paralel çekirdeklerde aynı anda şifrelenebilir.

---

## 4. AEAD (AUTHENTICATED ENCRYPTION): GİZLİLİK VE BÜTÜNLÜĞÜN EVLİLİĞİ

Çırağım, genç mühendislerin yaptığı en yaygın hatalardan biri şudur: *"Metni AES-CBC ile şifreledim, artık kimse okuyamaz ve değiştiremez."*

Yanlış! Klasik şifreleme yalnızca **Gizlilik (Confidentiality)** sağlar; **BÜTÜNLÜK (Integrity)** sağlamaz!
Bir saldırgan şifreli metnin içeriğini okuyamasa bile, araya girerek (Man-in-the-Middle) şifreli metindeki belirli bitleri çevirebilir (Bit-Flipping Attack). Örneğin banka transfer talimatındaki tutar hanesine denk gelen biti çevirdiğinde, alıcı şifreyi çözdüğünde $100 yerine $900 görebilir!

İşte bu yüzden modern siber güvenlikte **AEAD (Authenticated Encryption with Associated Data)** zorunludur:
- **AES-GCM (Galois/Counter Mode)** veya **Encrypt-then-MAC (AES-CTR + HMAC-SHA256)**:
- Veri şifrelenir ve şifreli metnin üzerine kriptografik bir imza (Authentication Tag) eklenir.
- Şifre çözülmeden önce etiket sabit zamanlı (`hmac.compare_digest`) kontrol edilir. Şifreli metindeki tek bir bit bile değişmişse işlem derhal iptal edilir (`AuthenticationTagMismatchError - CWE-353`).

---

## 5. USTADAN ÇIRAĞA TAVSİYELER

1. **ECB Modunu Derhal Terk Et:** Kodlarında `MODE_ECB` gördüğün anda kırmızı alarm ver.
2. **IV'yi Asla Tekrar Etme:** CBC ve CTR modlarında aynı anahtar ile aynı IV/Nonce'u iki kez kullanmak felakettir.
3. **AES-128 mi AES-256 mı?** Standart kurumsal veriler için AES-128 fazlasıyla güvenli ve çok hızlıdır. Ancak devlet sırları ve kuantum sonrası tehdit öngörüleri için AES-256 tercih et.
4. **Daima AEAD Kullan:** Üretim mimarilerinde çıplak CBC yerine daima AES-GCM veya Encrypt-then-MAC mimarisini standart haline getir.
