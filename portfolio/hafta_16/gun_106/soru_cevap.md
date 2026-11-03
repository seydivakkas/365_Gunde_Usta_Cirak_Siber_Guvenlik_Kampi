# Gün 106: Asimetrik Kriptografi ve RSA — Soru ve Cevaplar
## Usta-Çırak Derin Teknik Mülakat ve Güvenlik Analizi

---

### Soru 1: Düz (Textbook) RSA'daki "Çarpımsal Homomorfizm" (Malleability) Zafiyeti Nedir ve RSA-OAEP Bu Tehdidi Nasıl Bertaraf Eder?

#### 1. Soru Başlığı ve Tanımı
Düz (dolgu uygulanmamış / textbook) RSA şifrelemesi neden modern kriptografide güvensiz ve şekillendirilebilir (malleable - CWE-327) kabul edilir? Saldırganlar özel anahtara sahip olmadan şifreli metinleri nasıl manipüle edebilir ve RSA-OAEP bu saldırıyı nasıl önler?

#### 2. Derinlemesine Teknik Analiz
Düz RSA'da bir mesajın ($m$) şifrelenmesi doğrudan modüler üs alma formülüyle tanımlanır:
$$c \equiv m^e \pmod n$$
Bu matematiksel yapı doğal bir **çarpımsal homomorfizme** sahiptir. İki farklı $m_1$ ve $m_2$ mesajının şifreli halleri $c_1$ ve $c_2$ olsun:
$$c_1 \equiv m_1^e \pmod n \quad \text{ve} \quad c_2 \equiv m_2^e \pmod n$$
Bir saldırgan hat üzerinden geçen $c_1$ ve $c_2$ paketlerini yakaladığında, bunları modül $n$ altında birbiriyle çarparak yeni bir şifreli metin ($c'$) oluşturabilir:
$$c' = (c_1 \cdot c_2) \pmod n \equiv (m_1^e \cdot m_2^e) \pmod n \equiv (m_1 \cdot m_2)^e \pmod n$$
Alıcı özel anahtarı ($d$) kullanarak bu manipüle edilmiş $c'$ paketini çözdüğünde:
$$m' \equiv (c')^d \pmod n \equiv ((m_1 \cdot m_2)^e)^d \pmod n \equiv (m_1 \cdot m_2) \pmod n$$
Sonuç olarak alıcı, iki orijinal mesajın çarpımını elde eder! Saldırgan özel anahtarın tek bir bitini dahi bilmeden, alıcının sisteminde mantıksal bir veri tahrifatı (tampering) gerçekleştirmiştir.

**RSA-OAEP (Optimal Asymmetric Encryption Padding - RFC 8017) Savunması:**
OAEP şeması, mesajı modüler üsse sokmadan önce iki turlu Feistel benzeri bir maskeleme ağından geçirir.
1. Her şifrelemede kriptografik olarak rastgele 32 baytlık bir tohum (`seed = secrets.token_bytes(32)`) üretilir.
2. Mesaj, MGF1 (SHA-256 tabanlı maske üretim fonksiyonu) ile üretilen maskelerle XOR'lanır.
3. Bu sayede $m$ mesajı matematiksel cebirsel yapısını tamamen kaybeder ve rastgele bir bayt öbeğine (`EM`) dönüşür.
4. İki OAEP şifreli metnini çarpmak, modüler üs alma sonrası anlamsız gürültü üretir. Alıcı bu bloğu çözmeye çalıştığında `first_byte == 0x00`, `lHash` ve `0x01` ayraç bayt kontrolleri başarısız olur ve sistem anında `OAEPPaddingError (CWE-780)` fırlatarak manipülasyonu engeller.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir açık artırma veya elektronik oylama sisteminde teklifler düz RSA ile şifrelenmektedir. Saldırgan, rakip bir firmanın 10.000 TL'lik teklif paketini ($c_1$) dinler. Ardından 2 sayısının şifreli hali olan $c_2 = 2^e \pmod n$ değerini kendisi hesaplar (çünkü genel anahtar $e, n$ herkese açıktır!). Saldırgan ağdaki $c_1$ paketini $c_1 \cdot c_2 \pmod n$ ile değiştirir. Sunucu paketi açtığında teklif 20.000 TL olarak çözülür ve ihale bozulur.

**Pratik Çözüm:**
Tüm asimetrik şifreleme rutinlerinde düz RSA kesinlikle yasaklanmalı ve PKCS#1 v2.2 uyumlu RSA-OAEP standardı zorunlu kılınmalıdır:
```python
# Güvenli: Her şifreleme rastgele tohum içerir ve manipülasyonu engeller
ciphertext = pub_key.encrypt_oaep(message_bytes, label=b"teklif_protokolu_v1")
```

#### 4. Ustanın Çırağa Tavsiyesi
"Çırak, düz RSA yalnızca üniversite amfilerinde tahtaya tebeşirle yazılan soyut bir teoridir. Gerçek dünyada dolgusuz (padding'siz) RSA çalıştırmak, arabanı fren balatası olmadan otobanda son sürat sürmeye benzer. Karşına çıkan her asimetrik kütüphanede ilk işin OAEP dolgusunun açık olup olmadığını denetlemektir!"

---

### Soru 2: Küçük Genel Üs ($e=3$) Neden Büyük Bir Güvenlik Felaketidir ve Neden $e=65537$ Standarttır?

#### 1. Soru Başlığı ve Tanımı
RSA anahtar çifti oluşturulurken şifreleme hızını artırmak amacıyla genel üs olarak $e=3$ seçmek neden ölümcül bir güvenlik zafiyetidir (CWE-327)? Håstad Yayın Saldırısı (Broadcast Attack) ve Doğrudan Küp Kök Açığı nasıl çalışır?

#### 2. Derinlemesine Teknik Analiz
Genel üs $e$, şifreleme işlemindeki üs alma hızını belirler. $e=3$ seçilirse şifreleme için yalnızca 1 çarpma ve 1 kare alma yeterlidir; bu da işlemciye neredeyse sıfır yük bindirir. Ancak bu seçim iki büyük felakete yol açar:

**A. Doğrudan Küp Kök Açığı (Small Message Attack):**
Eğer mesaj $m$ küçükse ve $m^3 < n$ şartı sağlanıyorsa, şifreleme denkleminde modüler indirgeme ($\pmod n$) hiçbir zaman devreye girmez:
$$c = m^3 \pmod n \implies c = m^3$$
Modül $n$ etkisiz kaldığı için tuzak kapı (trapdoor) ortadan kalkar! Saldırgan şifreli metin $c$'nin doğrudan reel küp kökünü hesaplar:
$$m = \lfloor \sqrt[3]{c} \rfloor$$
Özel anahtara hiçbir ihtiyaç kalmadan mesaj saliseler içinde düz metne dönüşür!

**B. Håstad Yayın Saldırısı (Håstad's Broadcast Attack):**
Aynı $m$ mesajı, $e=3$ kullanan 3 farklı alıcıya ($n_1, n_2, n_3$ modülleriyle) gönderilirse:
$$c_1 \equiv m^3 \pmod{n_1}, \quad c_2 \equiv m^3 \pmod{n_2}, \quad c_3 \equiv m^3 \pmod{n_3}$$
Çin Kalan Teoremi (Chinese Remainder Theorem - CRT) kullanılarak bu 3 denklem birleştirilir ve modül $N = n_1 \cdot n_2 \cdot n_3$ altında tek bir $C$ değeri bulunur:
$$C \equiv m^3 \pmod{n_1 n_2 n_3}$$
Her alıcı için $m < n_i$ olduğundan, $m^3 < n_1 n_2 n_3$ kesinlikle doğrudur. Saldırgan $C$'nin doğrudan tam sayı küp kökünü alarak $\sqrt[3]{C} = m$ mesajını ele geçirir!

**Neden $e = 65537$ ($F_4$) Seçilir?**
$65537 = 2^{16} + 1$, dördüncü Fermat asalıdır.
1. İkili (binary) gösterimi `10000000000000001` şeklindedir (yalnızca iki adet '1' biti vardır).
2. Square-and-multiply algoritmasında sadece 16 kare alma ve 1 çarpma gerektirir; bu sayede performansı $e=3$ kadar yüksektir.
3. Ancak $e=65537$ o kadar büyüktür ki $m^{65537} < n$ olması fiziksel olarak imkansızdır; bu da küp kök ve Håstad ataklarını tamamen imkansız kılar.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Eski bir IoT cihazı üreticisi, düşük güçlü mikrodenetleyicilerde pil tüketimini azaltmak için TLS sertifikalarını $e=3$ parametresiyle üretmiştir. Şebekedeki sayaç verileri merkezi sunucuya gönderilirken pasif bir ağ dinleyicisi şifreli sayaç okumalarının küp kökünü alarak tüm tüketim verilerini ve müşteri bilgilerini deşifre eder.

**Pratik Çözüm:**
Sistem anahtar üretim motorunda $e=3$ kesinlikle yasaklanmalı ve FIPS 186-4 gereğince $e=65537$ zorunlu kılınmalıdır:
```python
DEFAULT_PUBLIC_EXPONENT = 65537  # Asla e=3 veya çift sayı kabul edilmez
```

#### 4. Ustanın Çırağa Tavsiyesi
"Evlat, kriptografide 'küçük bir hız kazanımı için parametreleri budamak' şeytanla pazarlık yapmaktır. $e=3$ sana birkaç mikro saniye kazandırabilir ama sisteminin tüm gizlilik kalesini yerle bir eder. 65537 sayısı kriptografinin altın oranıdır; ona sadık kal!"

---

### Soru 3: RSA Anahtar Boyutlarının Evrimi (CWE-326) ve Kuantum Tehdidine (Shor Algoritması) Karşı Durum Nedir?

#### 1. Soru Başlığı ve Tanımı
Neden 512-bit ve 1024-bit RSA anahtarları günümüzde tamamen güvensiz kabul edilmektedir (CWE-326)? Genel Sayı Alanı Eleği (GNFS) ve gelecekteki Kuantum Bilgisayarlar (Shor Algoritması) karşısında güncel anahtar boyutu standartları nelerdir?

#### 2. Derinlemesine Teknik Analiz
RSA'nın güvenliği, $n = p \cdot q$ modülünün çarpanlarına ayrılmasının zorluğuna bağlıdır. Klasik bilgisayarlarda en hızlı tamsayı çarpanlara ayırma algoritması **Genel Sayı Alanı Eleği (General Number Field Sieve - GNFS)** yöntemidir.
GNFS algoritmasının asimptotik karmaşıklığı alt-üsteldir (sub-exponential):
$$\mathcal{O}\left(\exp\left(\left(\sqrt[3]{\frac{64}{9}} + o(1)\right) (\ln n)^{1/3} (\ln \ln n)^{2/3}\right)\right)$$

Bu karmaşıklık ışığında tarihsel kırılmalar:
- **512-bit RSA:** 1999 yılında (RSA-155) akademik ağlar tarafından kırıldı. Günümüzde bir akıllı telefon veya birkaç saatlik bulut sunucusu kümesi ile dakikalar içinde çarpanlarına ayrılabilir.
- **768-bit RSA:** 2009 yılında yüzlerce bilgisayardan oluşan bir küme ile birkaç ayda kırıldı.
- **1024-bit RSA:** Günümüzde ulusal istihbarat örgütleri (NSA, GCHQ) ve devasa süper bilgisayar kümeleri için kırılabilir eşiktedir. NIST, BSI ve ANSSI standartlarına göre 1024-bit anahtarlar kullanımdan kaldırılmıştır (Deprecated - CWE-326).
- **2048-bit RSA:** Günümüzde klasik bilgisayarlara karşı asgari güvenli kabul edilen taban sınırdır (~112 bit simetrik güvenlik eşdeğeri).
- **3072-bit RSA:** NIST SP 800-57'ye göre 2030 ve sonrasında 128-bit simetrik güvenlik seviyesine eşdeğer olarak tavsiye edilen standart boyuttur.

**Kuantum Bilgisayarlar ve Shor Algoritması:**
Gelecekte yeterli sayıda mantıksal kübite sahip bir kuantum bilgisayar inşa edildiğinde, Peter Shor tarafından 1994'te geliştirilen **Shor Algoritması**, tamsayı çarpanlara ayırma problemini polinom zamanda ($\mathcal{O}((\log n)^3)$) çözecektir.
Bu durum, anahtar boyutu 4096 bit dahi olsa RSA'nın kuantum bilgisayarlar karşısında tamamen çökeceği anlamına gelir. Bu nedenle dünya, NIST öncülüğünde **Post-Kuantum Kriptografi (PQC)** standartlarına (ML-KEM / Kyber, ML-DSA / Dilithium) geçiş yapmaktadır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Eski bir kamu kurumunun VPN altyapısında 2012 yılından kalma 1024-bit RSA kök sertifikaları kullanılmaktadır. Güvenlik denetiminde (audit) bu durum tespit edilir. Siber saldırganlar kaydedilmiş ağ trafiğini (harvest now, decrypt later) arşivlemekte ve süper bilgisayar gücüyle bu anahtarları çözerek geriye dönük devlet sırlarını ifşa etme riski taşımaktadır.

**Pratik Çözüm:**
1. Kod tabanında ve sertifika üretim araçlarında 2048 bitin altındaki tüm anahtarlar bloke edilir:
   ```python
   if bits < 2048:
       raise WeakKeySizeError("CWE-326: Üretim ortamında 2048 bitin altında RSA anahtarı kullanılamaz!")
   ```
2. Yeni mimarilerde uzun vadeli gizlilik gerektiren veriler için hibrit PQC (Post-Quantum) algoritmalarına geçiş planlanır.

#### 4. Ustanın Çırağa Tavsiyesi
"Çırak, kriptografide zaman durmaz; dün kırılmaz denen kale bugün kumdan şatoya döner. 1024 bitlik bir anahtar gördüğünde ona tarihi bir müze eseri muamelesi yap ve hemen 2048 veya 3072 bit ile değiştir. Ve asla unutma: Kuantum çağı kapıda; asimetrik kriptografinin matematiğini bugün kavramazsan, yarın kuantum sonrası şifrelemeyi asla yönetemezsin!"
