# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 099: CIA Triad ve Temel Güvenlik Özellikleri Tekrarı

## Usta-Çırak / Hoca Dersi Girişi

Evlat, Aşama 5'e hoş geldin! Bu aşamada siber güvenliğin en kadim, en temel taşı olan **Kriptografi ve Ağ Güvenliği Temelleri** kapısını aralıyoruz. 

Bugün piyasada "güvenlikçiyim" diye gezen pek çok kişi CIA üçlüsünü (Confidentiality, Integrity, Availability) üç kelimelik bir ezberden ibaret sanır. Onlara "Gizlilik nedir?" diye sorsan "Veriyi şifrelemektir" derler; "Bütünlük nedir?" diye sorsan "Hash almaktır" derler. Fakat bir mimarinin içine girdiklerinde, şifrelenmiş verinin kurcalanabileceğini (malleability), hash fonksiyonunun zamanlama saldırısıyla (timing attack) sızdırılabileceğini ya da hız sınırlaması olmayan bir kriptografik doğrulama servisinin CPU'yu tüketerek sistemi çökertebileceğini (DoS) göremezler!

Bir güvenlik ustası, CIA üçlüsünü ve onun ayrılmaz parçası olan **İnkar Edilemezlik (Non-Repudiation)** ile **Kimlik Doğrulama (Authentication)** niteliklerini matematiksel, algoritmik ve operasyonel düzeyde anlamak zorundadır. Gel şimdi bu sacayağını en ince kılcal damarlarına kadar inceleyelim.

---

## 1. Gizlilik (Confidentiality): Gözlerden Uzak Tutma Sanatı

Gizlilik, bilginin yalnızca yetkilendirilmiş varlıklar (kullanıcılar, süreçler, sistemler) tarafından okunabilmesi ve erişilebilmesidir.

### 1.1 Tehdit Modeli ve Zafiyetler
- **CWE-311 (Missing Encryption of Sensitive Data):** Kredi kartı, parola, TCKN veya sağlık verilerinin veritabanında veya ağ kablosunda açık metin (plaintext) tutulması.
- **CWE-319 (Cleartext Transmission of Sensitive Information):** HTTP, Telnet, FTP gibi açık protokollerle veri taşınması; Man-in-the-Middle (MitM) saldırılarına kapı aralar.
- **CWE-326 (Inadequate Encryption Strength):** 128 bit altındaki kısa anahtarlar (örneğin DES, 512-bit RSA), zayıf PRNG (Pseudo-Random Number Generator) kullanımı.

### 1.2 Matematiksel ve Algoritmik Mekanizma
Kriptografide gizlilik simetrik (AES, ChaCha20) ve asimetrik (RSA, ECC) şifreleme algoritmalarıyla sağlanır. Temel prensip akış veya blok şifrelemedir. Örneğin akış şifrelemede (Stream Cipher) bir sözde-rastgele anahtar akışı (keystream, $K$) üretilir ve açık metin ($P$) ile XOR ($\oplus$) işlemine tabi tutulur:
$$C = P \oplus K$$
Şifreyi çözmek için aynı anahtar akışı tekrar uygulanır:
$$P = C \oplus K = (P \oplus K) \oplus K = P \oplus (K \oplus K) = P \oplus 0 = P$$
Ancak dikkat et: Eğer $K$ yeniden kullanılırsa (Nonce reuse), iki şifreli metin $C_1$ ve $C_2$ XOR'landığında anahtar yok olur ($C_1 \oplus C_2 = P_1 \oplus P_2$), bu da doğrudan açık metnin ifşasına yol açar!

---

## 2. Bütünlük (Integrity): Hakikatin Değişmezliği

Bütünlük, verinin yetkisiz kişilerce veya aktarım sırasında kazara değiştirilmediğinin, silinmediğinin ya da araya sahte veri eklenmediğinin garanti edilmesidir.

### 2.1 Kriptografik Özetler (Hash) vs. Mesaj Doğrulama Kodları (MAC)
Çırakların en büyük yanılgısı salt hash (SHA-256) fonksiyonunun bütünlüğü tam koruduğunu sanmasıdır. Bir saldırgan ağ trafiğindeki paketi değiştirip paketin hash değerini de yeni değere göre güncellerse, alıcı değişikliği anlayamaz!
İşte bu yüzden bütünlük için **HMAC (Hash-based Message Authentication Code)** kullanılır:
$$\text{HMAC}(K, m) = H\Big((K \oplus opad) \parallel H\big((K \oplus ipad) \parallel m\big)\Big)$$
Burada $K$ gizli paylaşımlı anahtar, $m$ mesaj, $opad$ ve $ipad$ ise sabit padding sabitleridir. Saldırgan anahtarı bilmediği için veriyi değiştirse dahi geçerli bir HMAC mührü üretemez.

### 2.2 Zamanlama Saldırıları (Timing Attacks - CWE-208)
Python'da iki dizgiyi `if seal == expected_seal:` şeklinde karşılaştırırsan, standart `==` işleci ilk uyuşmayan karakterde döngüyü sonlandırır. Saldırgan mikrosaniye seviyesindeki yanıt sürelerini ölçerek doğru karakterleri tek tek tahmin edebilir!
**Çözüm:** Her zaman sabit zamanlı karşılaştırma yapan `hmac.compare_digest()` kullanılmalıdır.

---

## 3. Erişilebilirlik (Availability): Kapının Daima Açık Kalması

Erişilebilirlik, yetkili kullanıcıların ihtiyaç duydukları anda verilere ve hizmetlere kesintisiz ulaşabilmesidir.

### 3.1 Tehdit Modeli ve Zafiyetler
- **CWE-400 (Uncontrolled Resource Consumption):** Bellek sızıntıları, sınırsız girdi boyutu kabulü, ReDoS (Regex DoS) ile CPU tüketimi.
- **CWE-770 (Allocation of Resources Without Limits or Throttling):** Hız sınırlaması (rate limit) olmayan API uç noktalarının taşkın isteklerle kilitlenmesi.

### 3.2 Koruma Mekanizmaları
1. **Kayan Pencere / Token Bucket Algoritması:** Her istemci IP veya API anahtarına bir istek kredisi atanır. Belirlenen pencere (örn. 1 saniye) içinde limit aşılırsa `AvailabilityRateLimitExceededError` fırlatılır.
2. **Bellek Tavanı (Payload Capping):** Gelen hiçbir veri yükü doğrulanmadan RAM'e yüklenmez. Katı tavan (örn. 1 MB) konur.

---

## 4. İnkar Edilemezlik (Non-Repudiation): Sözün ve İmzalanan Mührün Arkasında Durma

İnkar edilemezlik, bir eylemi gerçekleştiren aktörün (kullanıcı, servis), o eylemi kendisinin yaptığını sonradan inkar edememesidir.

### 4.1 Kriptografik Denetim Zinciri (Hash-Chained Audit Trail)
Geleneksel metin log dosyaları sistem yöneticisi (root) veya sızan bir saldırgan tarafından silinebilir ya da geriye dönük düzenlenebilir.
Bunun önüne geçmek için **blokzincir mantığıyla kilitlenen denetim zincirleri** kullanılır:
- Her log satırı, bir önceki log satırının HMAC mührünü (`onceki_hash`) referans alır.
- Satır içeriği: $\text{İndeks} \parallel \text{Zaman} \parallel \text{Eylem} \parallel \text{Kullanıcı} \parallel \text{VeriHash} \parallel \text{ÖncekiHash}$.
- Bu içerik anahtarla mühürlenir.
- Eğer saldırgan aradaki tek bir log satırını dahi değiştirirse, zincirdeki tüm sonraki blokların mührü bozulur ve `verify_chain_integrity()` ihlali anında tespit eder.

---

## 5. Ustanın Nasihati

Evlat, güvenlik bir ürün değil, bir dengedir. Gizliliği öyle bir abartırsın ki veriye kimse ulaşamaz, erişilebilirlik çöker. Erişilebilirliği öyle bir açarsın ki gizlilik yerle bir olur. Usta güvenlikçi, bu sacayaklarının hiçbirini diğerine kurban etmeden, hepsini matematiksel bir intizam içinde birleştirebilendir. Bu dersteki `CIASecurityEngine` senin ilk büyük orkestrasyon aracındır. Kodunu iyi tanı, ilkelerini zihnine kazı!
