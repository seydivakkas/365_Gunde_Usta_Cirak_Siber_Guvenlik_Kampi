# Gün 106: Asimetrik Kriptografi Temelleri ve RSA Mimarisi
## Usta-Çırak / Hoca Dersi: Matematiksel Temeller, Güvenli Dolgulama (OAEP) ve "Textbook RSA" Zafiyetleri

---

### 1. Ustanın Giriş Dersi: "Gizli Anahtar Paylaşmadan Güvenli İletişim Nasıl Mümkündür?"

Evlat, geçen hafta simetrik kriptografiyi (AES) ve mesaj kimlik doğrulamayı (HMAC) derinlemesine inceledik. Orada aşamadığımız devasa bir mimari sorun vardı:
> *"Alice ile Bob birbirleriyle hiç karşılaşmamışken ve aralarındaki tüm hatlar düşman tarafından dinleniyorken, ortak bir gizli simetrik anahtarı birbirlerine nasıl güvenle iletebilirler?"*

Eğer simetrik anahtarı hat üzerinden düz metin gönderirsen saldırgan kapar. Şifreleyip göndereceksen, onu ne ile şifreleyeceksin? Bu bir tavuk-yumurta kısırdöngüsüdür.

1976'da Whitfield Diffie ve Martin Hellman, 1977'de ise Ron Rivest, Adi Shamir ve Leonard Adleman (RSA) bu problemi kökünden çözdü. Çözüm: **Tek yönlü tuzak kapılı fonksiyonlar (Trapdoor One-Way Functions)** ve **Asimetrik (Genel/Özel) Anahtar Çifti** kavramıdır.

```
       [ Genel Anahtar (Public Key: e, n) ] ──► Herkese Açık (Posta Kutusu Yuvası)
                         │
                         ▼
             [ Mesaj Şifreleme: c = m^e mod n ]
                         │
                         ▼
        [ Şifreli Metin (Ciphertext: c) ] ──► Güvensiz İnternet Hattı
                         │
                         ▼
       [ Özel Anahtar (Private Key: d, n) ] ──► Yalnızca Alıcıda (Kasa Anahtarı)
                         │
                         ▼
            [ Mesaj Çözme: m = c^d mod n ]
```

Birisi sana mesaj göndereceği zaman senin **Genel Anahtarını** alır, mektubu kilitler ve posta kutuna atar. Mektup kilitlendikten sonra onu kilitleyen kişi dahi geri açamaz! Kilidi açabilecek tek varlık, gizli **Özel Anahtarı** elinde tutan alıcıdır.

---

### 2. RSA Algoritmasının Matematiksel Temelleri

RSA'nın güvenliği, çok büyük iki asal sayının çarpımını ($n = p \cdot q$) hesaplamanın çok kolay ($O(N^2)$), ancak bu çarpımı ($n$) tekrar çarpanlarına ($p$ ve $q$) ayırmanın (Tamsayı Çarpanlara Ayırma Problemi - Integer Factorization) klasik bilgisayarlar için imkansıza yakın derecede zor olmasına dayanır.

#### Adım 1: Büyük Asal Sayıların Üretimi ve Miller-Rabin Testi
RSA için önce iki büyük, bağımsız asal sayı ($p$ ve $q$) üretilir. Bir sayının asal olup olmadığını anlamak için basit bölme yapmak imkansızdır. Bu nedenle **Miller-Rabin Olasılıksal Asallık Testi** kullanılır.
$n-1 = 2^s \cdot d$ şeklinde ayrıştırılır ve rastgele $a$ tabanları için Fermat'nın Küçük Teoremi test edilir. $k=40$ tur testten geçen bir sayının bileşik olma olasılığı $4^{-40} \approx 10^{-24}$ mertebesindedir; bu oran pratikte kesin asallık anlamına gelir.

```python
# Kriptografik rastgele aday üretimi
candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
# Miller-Rabin testi ile asallık garantilenir
if is_probable_prime(candidate, k=40):
    return candidate
```

#### Adım 2: Modül ve Euler Totient Hesabı
- Modül: $n = p \cdot q$ (Örneğin 2048 bit).
- Euler Totient: $\phi(n) = (p - 1)(q - 1)$. $\phi(n)$, $n$'den küçük ve $n$ ile aralarında asal olan pozitif tam sayıların adedidir.

#### Adım 3: Genel Üs (Public Exponent) Seçimi
Genel üs $e$, $\phi(n)$ ile aralarında asal olmalıdır: $\gcd(e, \phi(n)) = 1$.
Endüstri standardı (FIPS 186-4) olarak her zaman **Fermat Asalı $F_4$ ($e = 65537 = 2^{16} + 1$)** seçilir. İkili gösteriminde yalnızca iki adet '1' biti (`0b10000000000000001`) bulunduğu için modüler üs alma işlemi (Square-and-Multiply) son derece hızlı gerçekleşir.

#### Adım 4: Özel Üs (Private Exponent) Hesabı
Özel üs $d$, $e$'nin $\phi(n)$ modülündeki çarpmaya göre tersidir:
$$e \cdot d \equiv 1 \pmod{\phi(n)}$$
Bu denklem **Genişletilmiş Öklid Algoritması (Extended Euclidean Algorithm)** kullanılarak çözülür.

---

### 3. Ölümcül Hata: Düz (Textbook) RSA Neden Asla Kullanılamaz? (CWE-327)

Akademik kitaplarda RSA anlatılırken formül şöyle verilir:
- Şifreleme: $c = m^e \pmod n$
- Şifre Çözme: $m = c^d \pmod n$

Buna **Düz (Textbook) RSA** denir. Üretim sistemlerinde düz RSA kullanmak **Kritik Kriptografik Zafiyettir (CWE-327)**! Sebepleri şunlardır:

#### A. Determinizm Zafiyeti
Düz RSA deterministiktir. Aynı $m$ mesajı aynı genel anahtarla şifrelendiğinde daima aynı $c$ şifreli metnini üretir. Saldırgan sözlükteki tüm kelimeleri veya "EVET"/"HAYIR" gibi olası yanıtları genel anahtarla şifreleyip eşleştirerek mesajın içeriğini anında anlar.

#### B. Çarpımsal Homomorfizm ve Şekillendirilebilirlik (Malleability)
RSA'nın modüler üs alma mantığı matematikte çarpımsaldır:
$$(m_1)^e \cdot (m_2)^e \equiv (m_1 \cdot m_2)^e \pmod n$$
Eğer saldırgan hat üzerinden geçen $c_1$ ($m_1$'in şifrelisi) ve $c_2$ ($m_2$'in şifrelisi) paketlerini yakalarsa; bunları çarparak $c_{\text{yeni}} = c_1 \cdot c_2 \pmod n$ oluşturur. Alıcı bu paketi açtığında meşru bir şekilde $m_1 \cdot m_2$ sonucunu elde eder! Saldırgan banka havalesindeki miktarı veya oy sayısını özel anahtara sahip olmadan manipüle etmiş olur.

#### C. Küçük Üs ($e=3$) ve Küp Kök Açığı
Eğer $e=3$ seçilmişse ve şifrelenen mesaj küçükse (örneğin $m < \sqrt[3]{n}$), $m^3 < n$ olacağından modüler indirgeme ($\pmod n$) hiç devreye girmez!
$$c = m^3$$
Saldırgan lise matematiğiyle tam sayı küp kökü alarak ($\sqrt[3]{c}$) özel anahtara hiç ihtiyaç duymadan mesajı anında çözer!

---

### 4. Güvenli Çözüm: RSA-OAEP (Optimal Asymmetric Encryption Padding)

Düz RSA'nın tüm zafiyetlerini ortadan kaldıran standart **RSA-OAEP (PKCS#1 v2.2 / RFC 8017)** şemasıdır.
OAEP iki aşamalı bir Feistel benzeri maskeleme ağıdır:

```
    [ Mesaj: M ] ──► DB = lHash || 0x00...00 || 0x01 || M
                           │                  ▲
                           │                  │ dbMask = MGF1(Seed)
                           ▼                  │
                        [ XOR ] ◄─────────────┘
                           │
                           ▼
                       maskedDB ──────────────► MGF1 ──► seedMask
                           │                               │
                           │                               ▼
                           │                  Seed ◄──── [ XOR ]
                           │                   │
                           ▼                   ▼
    EM = 0x00 || maskedSeed || maskedDB
```

1. **Rastgelelik (Semantik Güvenlik - IND-CCA2):** Her şifrelemede 32 baytlık kriptografik rastgele bir tohum (`seed`) üretilir. Aynı mesaj arka arkaya bin defa şifrelense dahi her seferinde tamamen farklı bir şifreli metin üretilir.
2. **Homomorfizmi Yok Eder:** Mesaj rastgele maskelerle karıştırıldığı için şifreli metinlerin çarpımı anlamsız gürültüye dönüşür ve dolgu çözme aşamasında reddedilir.
3. **Zamanlama Koruması (CWE-208):** Dolgu çözülürken sabit zamanlı (`hmac.compare_digest`) karşılaştırmalar yapılır; böylece Bleichenbacher dolgu kahini (padding oracle) saldırıları engellenir.

---

### 5. Ustanın Altın Kuralları

1. **Asla Düz RSA Kullanma:** RSA'yı her zaman OAEP dolgusu ile birlikte çalıştır.
2. **Anahtar Boyutundan Taviz Verme (CWE-326):** 1024 bit RSA günümüzde kırılma sınırındadır. Üretimde asgari **2048 bit**, yüksek güvenlikli sistemlerde **3072 veya 4096 bit** kullan.
3. **Genel Üssü Değiştirme:** Fantezi arayıp $e=3$ veya çift sayılar seçme; daima FIPS onaylı $e = 65537$ kullan.
4. **Büyük Verileri RSA ile Şifreleme (Hibrit Şifreleme Kuralı):** RSA matematiksel olarak çok yavaştır ve blok boyutu anahtar boyutuyla sınırlıdır. Gerçek dünyada büyük veriler AES-GCM ile şifrelenir; AES anahtarı ise RSA-OAEP ile alıcıya iletilir (Hibrit Kriptografi).
