# Gün 107: Dijital İmza ve Doğrulama — Soru ve Cevaplar
## Usta-Çırak Derin Teknik Mülakat ve Güvenlik Analizi

---

### Soru 1: Dijital İmza ile Simetrik MAC (HMAC) Arasındaki Mimari Fark Nedir ve "İnkar Edilemezlik" (Non-Repudiation) Hukuki/Teknik Olarak Nasıl Sağlanır?

#### 1. Soru Başlığı ve Tanımı
Birçok mühendis hem HMAC'in hem de Dijital İmzanın "mesaj bütünlüğü ve kimlik doğrulama" sağladığını söyleyerek bu iki kavramı birbiri yerine kullanabileceğini düşünür. Bu yaklaşım neden hatalıdır? Simetrik anahtarlı sistemlerde "İnkar Edilemezlik" neden teknik olarak imkansızdır ve Dijital İmza bunu asimetrik anahtar çiftiyle nasıl başarır?

#### 2. Derinlemesine Teknik Analiz
HMAC (Hash-based Message Authentication Code), simetrik bir $K$ anahtarını iki tarafın (örneğin Alice ve Bob) eşit olarak paylaştığı bir düzendir:
$$\text{MAC} = \text{HMAC}_K(M)$$
Bu kurguda $K$ anahtarına hem Alice hem de Bob tam yetkiyle sahiptir.
- Bob bir mesaj aldığında, mesajı gerçekten $K$'ya sahip birinin (yani Alice'in) ürettiğini bilir.
- **Kritik Zafiyet:** Ancak Bob, üçüncü bir tarafa (örneğin bir hakem, mahkeme veya bağımsız denetim sunucusuna) bu mesajı Alice'in ürettiğini **kanıtlayamaz**. Çünkü Bob da $K$ anahtarına sahiptir; dolayısıyla Bob dilerse sahte bir $M_{\text{sahte}}$ mesajı uydurup ona geçerli bir HMAC üretebilir ve suçu Alice'e atabilir. Alice ise *"Bu mesajı ben üretmedim, anahtara sahip olan Bob kendisi üretti"* diyerek inkar edebilir.

**Dijital İmzada İnkar Edilemezlik (Non-Repudiation):**
Dijital imzada asimetrik anahtar çifti kullanılır:
- **Özel Anahtar ($d$):** Sadece ve sadece Alice'e aittir. Kriptografik donanım modülünde (HSM / Secure Enclave) saklanır ve asla dışarı çıkarılamaz.
- **Genel Anahtar ($e, n$):** Tüm dünyaya ilan edilmiştir.

Alice bir belgeyi imzaladığında:
$$s = (H(M))^d \pmod n$$
Bob dahil dünyadaki herhangi biri $s^e \pmod n == H(M)$ denetimi yaparak imzanın geçerliliğini teyit edebilir. Ancak hiç kimse (Bob dahil) $d$ özel anahtarına sahip olmadığı için Alice adına geçerli yeni bir imza üretemez. Alice, belgenin kendi özel anahtarıyla imzalandığını inkar edemez; bu durum hem teknik hem de hukuki kesinlik (5070 Sayılı Elektronik İmza Kanunu, eIDAS) sağlar.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir B2B bankacılık platformunda API üzerinden 10 milyon TL'lik kredi kullanım talimatı iletilmektedir. Sistem tasarımcısı performans gerekçesiyle karşılıklı paylaşılan bir API Secret ile HMAC doğrulaması kurmuştur. Bir gün müşteri şirketin finans müdürü 10 milyon TL'lik transfer talimatı verir, para transfer edilir ve şirket batar. Şirket sahipleri bankayı dava ederek *"Biz böyle bir talimat vermedik, bankanızın sistem yöneticileri bizim API Secret'ımızı biliyordu, talimatı banka personeli uydurdu"* der. Banka mahkemede transferin müşteri tarafından yapıldığını teknik olarak ispatlayamaz ve parayı tazmin etmek zorunda kalır.

**Pratik Çözüm:**
Finansal transferler, hisse senedi alım-satım emirleri ve sözleşmeler gibi hukuki sorumluluk doğuran tüm sistemlerde simetrik HMAC terk edilmeli, mTLS ve RSASSA-PSS / ECDSA dijital imza zorunlu kılınmalıdır:
```python
# Her transfer talimatı istemcinin HSM'deki özel anahtarıyla imzalanır
signature = DigitalSignatureEngine.sign_pss(client_priv_key, transfer_payload_bytes)
```

#### 4. Ustanın Çırağa Tavsiyesi
"Çırak, HMAC iki arkadaşın arasındaki fısıldaşmadır; dijital imza ise noter huzurunda atılan ıslak imzalı mühürdür. Tarafların yarın bir gün mahkemede birbirine düşme ihtimali olan hiçbir iş akışında HMAC kullanma. İnkar edilemezlik istiyorsan, asimetrik imza tek çarendir!"

---

### Soru 2: RSASSA-PSS Neden RSASSA-PKCS1-v1_5'e Göre Üstündür ve Bleichenbacher e=3 İmza Sahteciliği (CVE-2006-4339) Nasıl Çalışır?

#### 1. Soru Başlığı ve Tanımı
Yıllarca kullanılan klasik PKCS#1 v1.5 imza şeması neden modern kriptografi standartlarında (RFC 8017) yerini RSASSA-PSS'e bırakmıştır? Daniel Bleichenbacher tarafından 2006'da keşfedilen $e=3$ imza sahteciliği saldırısı gevşek ayrıştırıcılarda nasıl başarılı olur?

#### 2. Derinlemesine Teknik Analiz
PKCS#1 v1.5 deterministik bir dolgu şemasıdır:
$$\text{EM} = 0x00 \,\|\, 0x01 \,\|\, 0xFF \dots 0xFF \,\|\, 0x00 \,\|\, T$$
Burada $T$, ASN.1 DigestInfo öneki ile hash'in birleşimidir. İmzalanan değer $s = \text{EM}^d \pmod n$ şeklindedir.

**Bleichenbacher Saldırısı (CVE-2006-4339):**
Eğer genel üs $e=3$ ise ve doğrulayıcı kütüphane imzayı çözdüğünde (`s^3 mod n`):
1. `0x00 0x01` ile başladığını teyit ediyorsa,
2. Ardından `0xFF` baytlarını geçip `0x00` ayracını arıyorsa,
3. Ayracın ardındaki ASN.1 özetini ($T$) okuyup eşleştiriyorsa,
4. **Fakat bloğun sonundaki baytları denetlemiyorsa (trailing garbage kontrolü yoksa);**

Saldırgan özel anahtarı hiç bilmeden sahte bir imza üretebilir!
Saldırgan şu yapıyı inşa eder:
$$\text{Sahte EM} = 0x00 \,\|\, 0x01 \,\|\, 0xFF \dots 0xFF \,\|\, 0x00 \,\|\, T \,\|\, \text{Çöp Baytlar}$$
Bu blok $k$ baytlık devasa bir sayıdır ($B$). Saldırgan bu sayının doğrudan tamsayı küp kökünü alır:
$$s_{\text{forged}} = \lceil \sqrt[3]{B} \rceil$$
$e=3$ küçük olduğundan ve küp kök alma işlemindeki hata payı yalnızca alt baytlara (çöp baytların olduğu bölgeye) yansıdığından, $s_{\text{forged}}^3$ hesaplandığında en üst baytlardaki $0x00 0x01 \dots T$ yapısı bozulmaz! Gevşek ayrıştırıcı bu sahte imzayı meşru kabul eder.

**RSASSA-PSS Üstünlüğü:**
1. **Olasılıksal Doğruluk (Probabilistic):** PSS, her imza için rastgele 32 baytlık bir tuz (`salt`) ekler. Mesaj deterministik bir kalıba sokulmaz.
2. **Tam Blok Kapsamı:** MGF1 maskeleme fonksiyonu ve Feistel ağı tüm bloğu birbirine katar. Bloğun sonunda tek bir kontrolsüz çöp bayt dahi kalamaz.
3. **Kanıtlanabilir Güvenlik (Provable Security):** PSS, Rastgele Kahin Modeli'nde doğrudan RSA probleminin zorluğuna indirgenmiştir.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** 2006'da Mozilla Firefox, Thunderbird ve çeşitli TLS implementasyonlarında bu hata tespit edildi. Bir saldırgan, $e=3$ kullanan CA (Sertifika Otoritesi) kök sertifikalarının imzasını taklit ederek `google.com` veya `bank.com` adına sahte SSL sertifikaları imzaladı ve tarayıcılar bu sertifikaları geçerli saydı.

**Pratik Çözüm:**
1. PKCS#1 v1.5 doğrulamasında kesinlikle gevşek ayrıştırma yapılmamalı; beklenen EM bloğu tam olarak yeniden oluşturulup sabit zamanlı (`hmac.compare_digest`) tam eşitlik denetlenmelidir.
2. Yeni projelerde FIPS 186-4 ve RFC 8017 uyarınca doğrudan **RSASSA-PSS** kullanılmalıdır:
   ```python
   # RSASSA-PSS standart kullanımı
   sig = DigitalSignatureEngine.sign_pss(priv_key, payload, salt_len=32)
   ```

#### 4. Ustanın Çırağa Tavsiyesi
"Evlat, veri ayrıştırırken tembellik etmek kriptografinin ölümüdür. 'Başı tuttuysa gerisi mühim değildir' diyen yazılımcı, Bleichenbacher'a kapıyı ardına kadar açmış demektir. Bir kriptografik blok ya baştan sona her baytıyla standartlara uyar, ya da çöptür; ortası yoktur!"

---

### Soru 3: ECDSA Algoritmasında "Nonce Yeniden Kullanımı" (CWE-323) Neden Kök Özel Anahtarın Çalınmasına Yol Açar ve Sony PS3 Nasıl Kırılmıştır?

#### 1. Soru Başlığı ve Tanımı
Eliptik Eğri Dijital İmza Algoritmasında (ECDSA) imza üretilirken kullanılan rastgele $k$ değerinin (nonce) iki farklı mesaj için aynı seçilmesi neden felakettir (CWE-323)? 2010 yılındaki meşhur Sony PlayStation 3 güvenlik kırılması bu açık üzerinden matematiksel olarak nasıl gerçekleşmiştir ve RFC 6979 bunu nasıl çözer?

#### 2. Derinlemesine Teknik Analiz
ECDSA'da bir $m$ mesajı imzalanırken:
1. Mesajın özeti hesaplanır: $z = \text{Hash}(m)$.
2. Kriptografik rastgele bir $k \in [1, q-1]$ nonce değeri seçilir.
3. Eğri üzerindeki nokta hesaplanır: $(x_1, y_1) = k \cdot G$. Buradan $r = x_1 \pmod q$ elde edilir.
4. İmzanın ikinci parçası hesaplanır:
   $$s \equiv k^{-1} \cdot (z + r \cdot d) \pmod q$$
   (Burada $d$ gizli özel anahtar, $q$ eğrinin mertebesidir).

**Aynı $k$'nın İki Kez Kullanılması Felaketi:**
Eğer geliştirici iki farklı mesaj ($z_1$ ve $z_2$) için aynı $k$ değerini kullanırsa:
$r$ değeri yalnızca $k$'ya bağlı olduğundan her iki imzada da $r_1 = r_2 = r$ olur!
İki imza denklemi yazılır:
$$s_1 \equiv k^{-1}(z_1 + r \cdot d) \pmod q$$
$$s_2 \equiv k^{-1}(z_2 + r \cdot d) \pmod q$$

Saldırgan $s_1, s_2, z_1, z_2$ ve $r$ değerlerini ağdan kolayca okur. Bu iki denklemi birbirinden çıkarır:
$$s_1 - s_2 \equiv k^{-1}(z_1 - z_2) \pmod q$$
İki tarafı $k$ ile çarpıp $(s_1 - s_2)$'ye böler:
$$k \equiv (z_1 - z_2) \cdot (s_1 - s_2)^{-1} \pmod q$$
Saldırgan $k$'yı saniyeler içinde buldu!
Şimdi $s_1$ denkleminde $k$'yı yerine koyarak doğrudan **gizli kök özel anahtarı ($d$)** çeker:
$$s_1 \cdot k \equiv z_1 + r \cdot d \pmod q \implies d \equiv (s_1 \cdot k - z_1) \cdot r^{-1} \pmod q$$
Saldırgan artık sistemin sahibidir!

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo (Sony PS3 Olayı - 2010):** Sony, PlayStation 3 konsolunun oyun paketlerini ve çekirdek güncellemelerini doğrulamak için ECDSA kullanıyordu. Ancak imzalama yazılımını yazan mühendisler $k$ üretecine rastgele fonksiyon bağlamak yerine sabit bir sayı atadılar. Fail0verflow grubu iki farklı güncelleme paketinin $r$ değerlerinin birebir aynı olduğunu gördü. Lise düzeyinde modüler aritmetik kullanarak Sony'nin konsolu imzalayan ana özel anahtarını ($d$) tamamen çıkardı. Konsolun donanımsal güvenliği bir gecede sıfırlandı.

**Pratik Çözüm:**
1. $k$ değeri asla sıradan bir rastgele fonksiyonla üretilmemelidir.
2. **RFC 6979 Standardı:** $k$ değeri, gizli anahtar ve mesaj özetinin HMAC'i alınarak **deterministik** olarak türetilmelidir:
   $$k = \text{HMAC}(d, z)$$
   Bu sayede farklı her mesaj için $k$ matematiksel kesinlikle farklı çıkar ve nonce sızıntısı imkansız hale gelir.

#### 4. Ustanın Çırağa Tavsiyesi
"Çırak, asimetrik kriptografi öyle bir sanattır ki, anahtarın 4096 bit de olsa, imzada tek bir rastgele sayıyı ($k$) tekrar kullandığın an tüm krallığının anahtarını düşmana altın tepside sunmuş olursun. Eliptik eğri imzası atacaksan, RFC 6979 deterministik nonce kuralını aklına kazı!"
