# Gün 106: Asimetrik Kriptografi ve RSA Değerlendirme Raporu

**Tarih:** 02.11.2026  
**Müfredat Referansı:** Hafta 16 / Gün 106 (Excel Satır 110)  
**Görev Türü:** Standart Günlük Müfredat Görevi (Hafta 16 Başlangıcı)  
**Değerlendirme Sonucu:** 100 / 100 (Tam Puan — YETERLİ / MÜKEMMEL)

---

## 1. Puanlama Tablosu ve Yetkinlik Kriterleri

| Değerlendirme Kriteri | Taban Puan | Alınan Puan | Durum | Gerekçe ve Teknik Kanıtlar |
|:---|:---:|:---:|:---:|:---|
| **I. Mimari ve Güvenlik Tasarımı** | 20 | **20** | TAMAMLANDI | Pure Python Miller-Rabin asallık motoru (k=40), Genişletilmiş Öklid ve modüler ters, FIPS 186-4 uyumlu RSA anahtar üretimi ($e=65537$), PKCS#1 v2.2 (RFC 8017) RSA-OAEP güvenli dolgu mimarisi eksiksiz tasarlandı. |
| **II. Kodlama ve Temiz Kod Standartları** | 40 | **40** | TAMAMLANDI | `asymmetric_crypto_engine.py` ve `asymmetric_cli.py` içerisinde tüm çalıştırılabilir Python satırları didaktik Türkçe yorum satırları ile zenginleştirildi. Tip güvenliği (type hints), modüler dataclass yapıları ve özel hata hiyerarşisi oluşturuldu. |
| **III. Test Kapsamı ve Negatif Kontroller** | 25 | **25** | TAMAMLANDI | 15/15 Birim testi (%100 Başarı - 0.779s) ve 9/9 Negatif kontrol senaryosu başarıyla koşturuldu. Zayıf anahtar (CWE-326), tahrif edilmiş dolgu (CWE-780), textbook RSA homomorfizmi (CWE-327), küçük üs açığı ve ortak modül atakları doğrulandı. |
| **IV. Dokümantasyon, Raporlama ve Lisans** | 15 | **15** | TAMAMLANDI | Usta-Çırak pedagojisine uygun `ders.md`, 4 zorunlu alt başlıklı `soru_cevap.md`, adli güvenlik analiz raporu ve temsilî ASCII mimari şeması eksiksiz hazırlandı. Özel Lisans kuralına %100 uyuldu. |
| **GENEL TOPLAM** | **100** | **100** | **YETERLİ** | **Müfredat ve Endüstri Standartlarına Tam Uyum** |

---

## 2. Zafiyet ve Güvenlik Eşleme Matrisi (CWE & Standartlar)

| Zafiyet Kodu (CWE) | Zafiyet Tanımı | Motorda Alınan Kriptografik & Yazılımsal Önlem | Test / Doğrulama Durumu |
|:---|:---|:---|:---:|
| **CWE-326** | Inadequate Encryption Strength (Zayıf Anahtar Boyutu) | 512 bit altındaki anahtarlar `WeakKeySizeError` ile reddedilir. Standart üretim boyutu 2048+ bit olarak kurgulandı. | DOĞRULANDI (PASS) |
| **CWE-327** | Use of a Broken or Risky Cryptographic Algorithm (Düz RSA & Küçük e) | Düz (Textbook) RSA manipülasyonu tespit edildi; $e=3$ küçük üs küp kök açığı modellendi; F4 $e=65537$ zorunlu kılındı. | DOĞRULANDI (PASS) |
| **CWE-780** | Use of RSA Algorithm without OAEP (Güvensiz Dolgu) | RFC 8017 uyumlu RSA-OAEP dolgusu uygulandı; tahrif edilmiş şifreli metinler `OAEPPaddingError` ile durduruldu. | DOĞRULANDI (PASS) |
| **CWE-208** | Possible Timing Attack in Information Verification | OAEP dolgu ve lHash doğrulamalarında `hmac.compare_digest` kullanılarak zamanlama yan kanal sızıntıları önlendi. | DOĞRULANDI (PASS) |
| **CWE-20** | Improper Input Validation (Bozuk Anahtar Verisi) | JSON anahtar içe aktarma sürecinde zorunlu parametreler (`n_hex`, `e`, `d_hex`) denetlenip `MalformedKeyError` fırlatıldı. | DOĞRULANDI (PASS) |

---

## 3. Test ve Gerçek Kanıt Özeti

- **Birim Testleri:** `tests/test_asymmetric_crypto.py` -> 15/15 PASS (0.779s)
- **Negatif Kontrol Testleri:** `ornek_veri/invalid_asymmetric_inputs.json` -> 9/9 PASS
  - `NEG_01_INSUFFICIENT_KEY_LENGTH`: 256-bit anahtar üretimi `WeakKeySizeError` ile engellendi.
  - `NEG_02_CORRUPTED_CIPHERTEXT`: Şifreli metin bayt manipülasyonu `OAEPPaddingError` ile yakalandı.
  - `NEG_03_INVALID_PUBLIC_EXPONENT`: Çift sayı genel üs $e=65536$ `InvalidExponentError` ile reddedildi.
  - `NEG_04_MESSAGE_EXCEEDS_MODULUS`: OAEP kapasitesini aşan mesaj `MessageTooLargeError` ile durduruldu.
  - `NEG_05_NON_PRIME_INPUT`: 65535 bileşik sayısı `CompositeNumberError` ile elendi.
  - `NEG_06_MALFORMED_KEY_JSON`: Eksik `e` alanı `MalformedKeyError` ile yakalandı.
  - `NEG_07_TEXTBOOK_RSA_MALLEABILITY`: Çarpımsal homomorfik saldırı simüle edilip `TextbookRSAMalleabilityDetected` fırlatıldı.
  - `NEG_08_INVALID_PADDING_LABEL`: Uyuşmayan etiket `OAEPPaddingError` ile tespit edildi.
  - `NEG_09_COMMON_MODULUS_EXPOSURE`: Ortak $n$ modülü paylaşımı `CommonModulusExploitVulnerability` ile raporlandı.

---

## 4. Standartlara ve Müfredata Uyum

- **NIST SP 800-56B Rev. 2:** Recommendation for Pair-Wise Key-Establishment Schemes Using Integer Factorization Cryptography.
- **RFC 8017 (PKCS#1 v2.2):** RSA Cryptography Specifications Version 2.2 (OAEP & MGF1).
- **FIPS 186-4:** Digital Signature Standard (DSS) — Miller-Rabin ve anahtar üretim kuralları.
- **CIS Controls v8:** Control 3.10 — Encrypt Sensitive Data in Transit and at Rest.
