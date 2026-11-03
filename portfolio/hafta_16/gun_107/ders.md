# Gün 107: Dijital İmza ve Doğrulama (Digital Signatures)
## Usta-Çırak / Hoca Dersi: İnkar Edilemezlik, RSASSA-PSS, PKCS#1 v1.5 ve ECDSA Nonce Felaketi

---

### 1. Ustanın Giriş Dersi: "İmza Bir Bütünlük Mührü Değil, Hukuki ve Matematiksel Bir Taahhüttür"

Evlat, dünkü dersimizde asimetrik kriptografi ile gizliliği (şifreleme) nasıl sağladığımızı gördük. Genel anahtarla kilitledik, yalnızca özel anahtarı elinde tutan açabildi.

Bugün madalyonun diğer yüzünü çeviriyoruz: **Dijital İmza (Digital Signature)**.
Burada roller tam tersine döner:
- Kilitleyen (İmzalayan): Yalnızca ve sadece **Özel Anahtarın Sahibi ($d$)**.
- Kilidi Doğrulayan: Dünyadaki **herhangi bir kişi (Genel Anahtar $e, n$)**.

Çırakların en sık düştüğü kafa karışıklığı şudur:
> *"Usta, biz zaten Hafta 15'te HMAC ile mesaj bütünlüğünü ve kimlik doğrulamayı sağlamıştık. Dijital imzaya ne gerek var?"*

Kulaklarını dört aç evlat! Simetrik HMAC'te hem Alice hem Bob aynı $K$ gizli anahtarını paylaşır. Eğer Bob mahkemeye gidip *"Alice bana 1 milyon dolar borçlu olduğunu yazan bir HMAC gönderdi"* derse, Alice ayağa kalkıp *"Hakim bey, bu anahtar Bob'da da var. Bu mesajı ve HMAC'i Bob kendi bilgisayarında kendisi üretti ve bana iftira atıyor"* diyebilir! Ve hakim teknik olarak Alice'i haklı bulur. Çünkü simetrik anahtarda **İNKAR EDİLEMEZLİK (Non-Repudiation)** YOKTUR!

Dijital imzada ise $d$ özel anahtarı SADECE Alice'in elindedir (HSM veya akıllı kartında). Bob bu anahtarı asla bilmez. Dolayısıyla Alice bir belgeyi imzaladığında, *"Ben imzalamadım"* diyemez. Üçüncü şahıslar, noterler ve bağımsız sunucular genel anahtarla imzayı anında doğrulayabilir.

```
┌─────────────────────────┬──────────────────────────┬──────────────────────────┐
│ Kriptografik Özellik    │ Simetrik MAC (HMAC)      │ Asimetrik Dijital İmza   │
├─────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Bütünlük (Integrity)    │ EVET                     │ EVET                     │
│ Kimlik Doğrulama        │ EVET (Taraflar arasında) │ EVET (Herkese açık)      │
│ Doğrulayıcı Kitle       │ Sadece anahtarı bilenler │ Tüm Dünya                │
│ İnkar Edilemezlik       │ HAYIR (İspatlanamaz)     │ EVET (Hukuki Kesinlik)   │
└─────────────────────────┴──────────────────────────┴──────────────────────────┘
```

---

### 2. Neden Ham Veri Değil de Hash Özeti İmzalanır? ($H(M)$ İlkesi)

Hiçbir profesyonel sistem 50 MB'lık bir PDF sözleşmesini veya 2 GB'lık bir işletim sistemi güncellemesini doğrudan RSA formülüne ($M^d \pmod n$) sokmaz.
İki kritik sebepten ötürü daima belgenin **kriptografik özeti ($H(M)$)** imzalanır:

1. **Performans ve Boyut Sınırı:** RSA modüler üs alma işlemi işlemci için çok pahalıdır. Ayrıca RSA bloğu modül boyutuyla (2048 bit = 256 bayt) sınırlıdır. 50 MB'lık bir dosyayı parçalayarak imzalamak sistemi felç eder.
2. **Cebirsel Manipülasyon Engeli:** Ham veri imzalanırsa sayılar üzerinde cebirsel manipülasyonlar yapılabilir. SHA-256 gibi tek yönlü özet fonksiyonları çığ etkisi yaratarak cebirsel yapıyı tamamen yok eder.

---

### 3. Düz (Textbook) RSA İmza Neden Ölümcüldür? (CWE-327)

Düz RSA imza kuralı: $s = m^d \pmod n$. Doğrulama: $s^e \pmod n == m$.
Bu yaklaşım tam bir güvenlik felaketidir:

#### A. Varoluşsal Sahtecilik (Existential Forgery)
Saldırgan özel anahtara ($d$) sahip değildir ama genel anahtarı ($e, n$) bilir.
1. Saldırgan rastgele bir sahte imza sayısı seçer: $s_{\text{forged}} = 424242$.
2. Genel anahtarla mesajı hesaplar: $m_{\text{forged}} = (s_{\text{forged}})^e \pmod n$.
3. Artık saldırganın elinde geçerli bir $(m_{\text{forged}}, s_{\text{forged}})$ çifti vardır! Doğrulayıcı $s^e \equiv m$ eşitliğini görünce imzayı geçerli kabul eder.

#### B. Çarpımsal Homomorfizm
$$s_1 \cdot s_2 \equiv (m_1)^d \cdot (m_2)^d \equiv (m_1 \cdot m_2)^d \pmod n$$
İki geçerli imzayı çarparak, orijinal mesajların çarpımına ait yepyeni bir geçerli imza üretilebilir!

---

### 4. PKCS#1 v1.5 ve Bleichenbacher e=3 İmza Sahteciliği (CVE-2006-4339)

1990'larda geliştirilen RSASSA-PKCS1-v1_5 şeması, hash özetinin önüne sabit ASN.1 DigestInfo ve `0xFF` dolgusu koyar:
$$\text{EM} = 0x00 \,\|\, 0x01 \,\|\, 0xFF \dots 0xFF \,\|\, 0x00 \,\|\, \text{ASN.1} \,\|\, H(M)$$

Ancak 2006 yılında Daniel Bleichenbacher tarihi bir zafiyet keşfetti:
Birçok kütüphane (Firefox, OpenSSL, GnuTLS türevleri), imzayı çözdüğünde (`s^e mod n`):
- `0x00 0x01` ile başlayıp başlamadığına bakıyor,
- Ardından ilk `0x00` ayracını bulup hemen ardındaki ASN.1 özetini okuyordu.
- **Ama bloğun sonundaki baytları denetlemiyordu (Trailing Garbage İhmali)!**

Eğer $e=3$ ise, saldırgan bloğun başına geçerli formatı koyup geri kalanını çöp baytlarla doldurur ve bu sayının doğrudan tamsayı küp kökünü ($\lfloor \sqrt[3]{B} \rfloor$) alarak sahte imza üretir!
Motorumuzda bu zafiyet modellenmiş ve **katı (strict) sabit zamanlı doğrulama** zorunlu kılınmıştır.

---

### 5. Modern Standart: RSASSA-PSS (Probabilistic Signature Scheme)

RFC 8017 (PKCS#1 v2.2) ile getirilen **PSS**, dijital imzaların altın standardıdır:
- **Rastlantısallık (Salt):** Her imza üretiminde 32 baytlık kriptografik rastgele bir tuz (`salt`) eklenir. Aynı belge yüz defa imzalansa dahi yüz tamamen farklı imza üretilir.
- **Kanıtlanabilir Güvenlik (Provable Security):** Rastgele Kahin Modeli'nde (Random Oracle Model) PSS'in kırılmasının doğrudan RSA problemini kırmaya eşdeğer olduğu matematiksel olarak kanıtlanmıştır.
- **Sabit Zamanlı Kontrol (CWE-208):** PSS doğrulaması sabit zamanlı `hmac.compare_digest` ile yürütülerek zamanlama yan kanal saldırıları bertaraf edilir.

```python
# Güvenli RSASSA-PSS İmza Üretimi
signature = DigitalSignatureEngine.sign_pss(priv_key, document_bytes, salt_len=32)
# Sabit zamanlı doğrulama
is_valid = DigitalSignatureEngine.verify_pss(pub_key, document_bytes, signature)
```

---

### 6. ECDSA Nonce Felaketi: Sony PlayStation 3 Nasıl Kırıldı? (CWE-323)

Eliptik Eğri Dijital İmza Algoritmasında (ECDSA):
$$s = k^{-1} \cdot (z + r \cdot d) \pmod q$$
Buradaki $k$ değeri her imza için **tek kullanımlık, kriptografik rastgele bir nonce** olmak zorundadır.

2010 yılında Sony mühendisleri PS3 oyun konsolunun çekirdek imzalama mekanizmasında $k$ değerini sabit (hardcoded) bir sayı olarak bıraktılar!
Eğer iki farklı oyun güncellemesi ($z_1$ ve $z_2$) aynı $k$ ile imzalanırsa:
$$s_1 - s_2 = k^{-1}(z_1 - z_2) \pmod q \implies k = (z_1 - z_2) \cdot (s_1 - s_2)^{-1} \pmod q$$
Saldırgan $k$'yı lise matematiğiyle 1 milisaniyede çözer!
Ve ardından konsolun tüm dünyayı yöneten kök özel anahtarını elde eder:
$$d = (s_1 \cdot k - z_1) \cdot r^{-1} \pmod q$$
Sonuç: Sony'nin milyar dolarlık güvenlik kalesi tek bir gecede çöktü ve konsol tamamen kırıldı (jailbreak).
**Ustanın Kuralı:** ECDSA kullanıyorsan $k$'yı asla rastgele üretecine emanet etme; **RFC 6979 Deterministik Nonce** türetimini zorunlu kıl!

---

### 7. Ustanın Çırağa Altın Öğütleri

1. **İnkar Edilemezlik İhtiyacın Varsa Asla HMAC ile Yetinme:** Hukuki sorumluluk, finansal transfer veya denetim loglarında dijital imza zorunludur.
2. **Düz RSA İmzayı Aklından Bile Geçirme:** Her zaman RSASSA-PSS (tercihen) veya katı doğrulamalı PKCS#1 v1.5 kullan.
3. **Genel Üssü Daima $e=65537$ Yap:** $e=3$ Bleichenbacher kabusuna kapı aralar.
4. **ECDSA'da Nonce Hayattır:** Nonce tekrarı özel anahtarını anında sokağa döker!
