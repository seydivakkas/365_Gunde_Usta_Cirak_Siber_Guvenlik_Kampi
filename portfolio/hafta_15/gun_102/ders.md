# GÜN 102: SALT, PEPPER VE KDF TABANLI GÜVENLİ PAROLA SAKLAMA
**Aşama 05 — Kriptografi Temelleri ve Uygulamaları (Hafta 15 / Gün 102)**  
*Eğitmen / Usta: Seydi Eryılmaz (@seydivakkas)*

---

## 1. USTANIN DERS GİRİŞİ: "PAROLA SAKLAMAK ŞİFRELEMEK DEĞİLDİR"

Evladım, sektöre yeni adım atan genç yazılımcıların ve tecrübesiz sistem yöneticilerinin düştüğü en büyük ve en tehlikeli yanılgı şudur: *"Kullanıcı parolalarını AES ile şifreledim, veritabanına koydum, anahtar da sunucuda duruyor; artık güvendeyiz."*

Bu düşünce ölümcül bir mimari hatadır! Çünkü simetrik veya asimetrik şifreleme **iki yönlüdür (reversible)**. Şifrelenen bir metin, er ya da geç bir anahtar kullanılarak orijinal haline geri döndürülür. Eğer sunucuna sızılır ve o şifre çözme anahtarı ele geçirilirse, milyonlarca kullanıcının parolası tek bir gecede düz metin (plaintext) olarak açığa çıkar.

Parola saklamanın temel ilkesi şudur: **Sistem yöneticisi, veritabanı yöneticisi veya hatta sistemin kurucusu dahi bir kullanıcının gerçek parolasını ASLA görememeli ve bilememelidir.** Biz parolaları şifrelemeyiz; parolaları **tek yönlü kriptografik anahtar türetme fonksiyonları (KDF)** ile geri döndürülemez matematiksel özetlere (hash) dönüştürürüz.

Bugünkü dersimizde; gökkuşağı tablolarının (Rainbow Tables) nasıl çalıştığını, neden düz SHA-256 kullanmanın ölümcül bir zaaf olduğunu, tuzun (salt) matematiğini, biberin (pepper) mimari gücünü ve kurumsal PBKDF2 standardını en ince detayına kadar inceleyeceğiz.

---

## 2. GÖKKUŞAĞI TABLOLARI (RAINBOW TABLES) VE TUZUN (SALT) ROLÜ

### 2.1. Düz Hashlerin Zaafı ve Önceden Hesaplanmış Sözlükler
Geçmişte yazılımcılar parolaları `md5(parola)` veya `sha1(parola)` şeklinde sakladılar. Bu yöntemde aynı parolaya sahip iki kullanıcının hash değeri tamamen aynıdır. Örneğin "password123" kelimesinin MD5 özeti her zaman `482c811da5d5b4bc6d497ffa98491e38` olacaktır.

Saldırganlar, milyarlarca yaygın parolanın hash özetini önceden hesaplayarak devasa veritabanları oluşturdular. Bir gökkuşağı tablosu; **İndirgeme Fonksiyonları (Reduction Functions)** ve hash zincirleri kullanarak terabaytlarca veriyi kompakt bir şekilde saklar. Bir veritabanı sızdığında, saldırgan tek bir SQL sorgusu veya arama ile saniyede milyonlarca parolanın düz metin karşılığını anında bulur.

### 2.2. Kriptografik Tuz (Salt) Nedir ve Nasıl Çalışır?
Tuz (Salt); her bir kullanıcı için parola hashlenmeden hemen önce üretilen, **kriptografik olarak güçlü rastgele bir bayt dizisidir**.

```
Tuzsuz Hash   : H = Hash(Parola)
Tuzlu Hash    : H = Hash(Tuz || Parola)
```

Tuzun sağladığı 3 büyük kriptografik güvence:
1. **Gökkuşağı Tablolarını Çökertir:** Saldırgan önceden milyarlarca hash hesaplamış olsa bile, sizin kullandığınız rastgele 128-bit tuz o tablodaki hiçbir değerle eşleşmez. Saldırgan her bir kullanıcı için sıfırdan tablo oluşturmak zorunda kalır ki bu matematiksel olarak imkansızdır.
2. **Aynı Parolaların Birbirinden Ayrışması:** İki kullanıcı tesadüfen aynı parolayı ("Ankara2026!") seçse bile, tuzları farklı olduğu için veritabanındaki hash kayıtları tamamen farklı görünür.
3. **Toplu Çözümleme (Batch Cracking) Engeli:** Saldırgan bir hash kırdığında diğer kullanıcıları çözemez; her parola için ayrı emek harcamak zorundadır.

> **Ustanın Altın Kuralı (CWE-760):** Tuz **ASLA** kullanıcı adı, e-posta, statik bir metin veya ardışık sayılar olamaz! Tuz mutlaka işletim sisteminin kriptografik entropi havuzundan (`secrets.token_bytes(16)`) en az 128-bit (16 bayt) uzunluğunda çekilmelidir.

---

## 3. BİBER (PEPPER): MİMARİ İZOLASYON VE DONANIM KORUMASI

### 3.1. Tuz İle Biberin Hayati Farkı
Çıraklar sık sık sorar: *"Ustam, madem tuzumuz var, neden bir de biber (pepper) kullanıyoruz?"*

Tuz veritabanında, kullanıcının hash kaydının hemen yanında açıkça saklanır. Tuz gizli bir sır değildir; amacı benzersizliktir. Eğer bir saldırgan SQL Injection ile veritabanının yedeğini (dump) çalarsa, tuzları da ele geçirmiş olur. Bu noktada saldırgan, elindeki GPU kümeleriyle tuz + hash üzerinde çevrimdışı (offline) sözlük denemelerine başlayabilir.

İşte **Biber (Pepper)** burada devreye girer:
- **Tuz (Salt):** Her kullanıcı için benzersizdir, gizli DEĞİLDİR, veritabanında saklanır.
- **Biber (Pepper):** Tüm sistem veya organizasyon için gizli bir anahtardır, **VERİTABANINDA ASLA SAKLANMAZ**.

### 3.2. Biber Nerede Saklanır?
Biber anahtarı;
- Donanımsal Güvenlik Modülü (HSM - Hardware Security Module),
- Bulut Anahtar Yönetim Servisi (AWS KMS, Azure Key Vault, HashiCorp Vault),
- Veya uygulama sunucusunun izole ortam değişkenlerinde (Environment Variables) tutulur.

### 3.3. Biberin Sızıntı Anındaki Savunması
Veritabanı çalındığında, saldırganın elinde tuzlar ve hashler vardır ancak **biber yoktur**. Biber olmadan bir hash doğrulaması veya tahmini yapmak imkansızdır. Saldırgan elindeki devasa GPU çiftlikleriyle tek bir deneme dahi yapamaz; çünkü hashleme fonksiyonunun bir girdisi (biber) sunucunun donanımında kilitlidir.

---

## 4. KDF (KEY DERIVATION FUNCTION) VE İŞ GÜCÜ MALİYETİ

### 4.1. Neden Düz SHA-256 Parola Saklamak İçin Kullanılamaz? (CWE-916)
SHA-256 çok hızlı bir hash algoritmasıdır. Bir modern grafik kartı (örneğin RTX 4090), saniyede **on milyarlarca** SHA-256 özeti hesaplayabilir. Eğer siz parolanızı `sha256(tuz + parola)` olarak saklarsanız, 8 karakterli karmaşık bir parola bile birkaç saat içinde kırılabilir.

Parola saklamada algoritmanın **hızlı olması bir avantaj değil, ölümcül bir zafiyettir!**

### 4.2. PBKDF2-HMAC-SHA256 ve İterasyon Döngüsü
NIST SP 800-132 ve RFC 8018 standartları, parola saklama için KDF algoritmalarını zorunlu kılar.
PBKDF2 (Password-Based Key Derivation Function 2), parolanın özetini binlerce kez ardışık olarak HMAC işleminden geçirir:

$$DK = \text{PBKDF2}(\text{PRF}, \text{Password}, \text{Salt}, c, dkLen)$$

Buradaki $c$ iterasyon sayısıdır. 
- 2026 yılı kurumsal standardı gereğince **en az 100.000 iterasyon** uygulanmalıdır.
- 100.000 iterasyon, meşru bir kullanıcının giriş yaparken hissetmeyeceği ~50 milisaniyelik bir gecikme yaratır.
- Ancak saniyede milyarlarca deneme yapmak isteyen bir saldırganın kırma hızını saniyede sadece birkaç yüze düşürür. Saldırganın donanım maliyeti ve elektrik faturası astronomik boyutlara ulaşır.

---

## 5. ZAMANLAMA SALDIRILARI (TIMING ATTACKS) VE SABİT ZAMANLI KIYASLAMA

Python'da veya herhangi bir programlama dilinde iki string'i `if hash1 == hash2:` şeklinde kıyasladığınızda, işlemci stringleri baştan sona byte byte kontrol eder. İlk uyuşmayan baytta döngü kırılır ve `False` döner.

Saldırgan, sunucuya milisaniyenin binde biri hassasiyetinde paketler göndererek yanıt sürelerini ölçer. Eğer yanıt süresi 10 nanosaniye daha uzun sürdüyse, ilk baytın doğru tahmin edildiğini anlar. Bu yönteme **Zamanlama Analizi Saldırısı (Timing Attack - CWE-208)** denir.

Bunu engellemek için her zaman `hmac.compare_digest()` kullanılmalıdır. Bu fonksiyon, iki verinin uyuşup uyuşmadığına bakılmaksızın her zaman **sabit sürede (constant-time)** çalışır; CPU zamanlamasından hiçbir bilgi sızdırmaz.

---

## 6. ÖZET VE USTADAN ÇIRAĞA TAVSİYELER

1. **Düz Hash Asla Kullanma:** MD5, SHA-1 ve tek geçişli SHA-256'yı sistemlerinden sök at.
2. **Tuzu Eşsiz ve Kriptografik Üret:** `secrets.token_bytes(16)` kullan. Asla statik tuz kullanma.
3. **Biberi Veritabanından Ayır:** Biberi KMS veya HSM içinde sakla. DB sızsa bile sistemini kurtaran kalkan biberdir.
4. **İterasyondan Tasarruf Etme:** En az 100.000 PBKDF2 iterasyonu uygula.
5. **Kıyaslamayı Sabit Zamanlı Yap:** Parola kontrollerinde `==` değil `hmac.compare_digest` kullan.
