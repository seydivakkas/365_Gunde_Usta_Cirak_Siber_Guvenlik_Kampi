# Gün 108: X.509 ve Sertifika Zinciri Değerlendirme Raporu

**Tarih:** 02.11.2026  
**Müfredat Referansı:** Hafta 16 / Gün 108 (Excel Satır 112)  
**Görev Türü:** Standart Günlük Müfredat Görevi  
**Değerlendirme Sonucu:** 100 / 100 (Tam Puan — YETERLİ / MÜKEMMEL)

---

## 1. Puanlama Tablosu ve Yetkinlik Kriterleri

| Değerlendirme Kriteri | Taban Puan | Alınan Puan | Durum | Gerekçe ve Teknik Kanıtlar |
|:---|:---:|:---:|:---:|:---|
| **I. Mimari ve Güvenlik Tasarımı** | 20 | **20** | TAMAMLANDI | Pure Python X.509 v3 veri modeli, 3 kademeli PKI (Root CA -> Intermediate CA -> Leaf), RFC 5280 yol doğrulama, BasicConstraints (`is_ca`, `pathLenConstraint`), KeyUsage, RFC 6125 SAN alan adı denetimi ve CRL/OCSP iptal yapısı eksiksiz modellendi. |
| **II. Kodlama ve Temiz Kod Standartları** | 40 | **40** | TAMAMLANDI | `x509_chain_engine.py` ve `x509_cli.py` içerisinde tüm çalıştırılabilir Python satırları didaktik Türkçe yorum satırları ile zenginleştirildi. Tip güvenliği (type hints), dataclass veri modelleri ve özel hata hiyerarşisi oluşturuldu. |
| **III. Test Kapsamı ve Negatif Kontroller** | 25 | **25** | TAMAMLANDI | 15/15 Birim testi (%100 Başarı - 0.180s) ve 9/9 Negatif kontrol senaryosu başarıyla koşturuldu. Güvensiz kök CA (CWE-295), süresi geçmiş/henüz geçerli olmayan sertifika (CWE-298), alan adı uyuşmazlığı (CWE-297), yetkisiz uç CA davranışı ve tahrif edilmiş imza doğrulandı. |
| **IV. Dokümantasyon, Raporlama ve Lisans** | 15 | **15** | TAMAMLANDI | Usta-Çırak pedagojisine uygun `ders.md`, 4 zorunlu alt başlıklı `soru_cevap.md`, adli güvenlik analiz raporu ve temsilî ASCII mimari şeması eksiksiz hazırlandı. Özel Lisans kuralına %100 uyuldu. |
| **GENEL TOPLAM** | **100** | **100** | **YETERLİ** | **Müfredat ve Endüstri Standartlarına Tam Uyum** |

---

## 2. Zafiyet ve Güvenlik Eşleme Matrisi (CWE & Standartlar)

| Zafiyet Kodu (CWE) | Zafiyet Tanımı | Motorda Alınan Kriptografik & Yazılımsal Önlem | Test / Doğrulama Durumu |
|:---|:---|:---|:---:|
| **CWE-295** | Improper Certificate Validation (Güvensiz Kök & İmza) | Güven deposunda (trust store) bulunmayan kökler `UntrustedRootCAError` ile engellenir; bozuk imzalar `CertificateSignatureInvalidError` üretir. | DOĞRULANDI (PASS) |
| **CWE-295** | Improper Restriction of Operations (Yetkisiz Uç CA) | BasicConstraints `is_ca=False` olan uç sertifikanın alt sertifika imzalaması `NonCACertificateUsedAsCAError` ile engellenir. | DOĞRULANDI (PASS) |
| **CWE-297** | Improper Validation of Certificate with Host Mismatch | RFC 6125 gereğince SAN ve CN alanları talep edilen alan adı ile eşleştirilir; uyuşmazlık durumunda `HostnameMismatchError` fırlatılır. | DOĞRULANDI (PASS) |
| **CWE-298** | Improper Validation of Certificate Expiration | `NotBefore` ve `NotAfter` tarihleri sistem zamanı ile denetlenir; süresi dolmuş veya henüz geçerli olmayan sertifikalar bloke edilir. | DOĞRULANDI (PASS) |
| **CWE-208** | Possible Timing Attack in Information Verification | Sertifika imzalarının ve ASN.1 dolgularının teyidinde `hmac.compare_digest` ile sabit zamanlı doğrulama kullanılır. | DOĞRULANDI (PASS) |
| **CWE-20** | Improper Input Validation (Bozuk Sertifika) | Zorunlu X.509 alanları eksik veya geçersiz olduğunda `MalformedCertificateError` üretilir. | DOĞRULANDI (PASS) |

---

## 3. Test ve Gerçek Kanıt Özeti

- **Birim Testleri:** `tests/test_x509_chain.py` -> 15/15 PASS (0.180s)
- **Negatif Kontrol Testleri:** `ornek_veri/invalid_certificate_inputs.json` -> 9/9 PASS
  - `NEG_01_UNTRUSTED_ROOT_CA`: Güvensiz kök dayanağı `UntrustedRootCAError` ile durduruldu.
  - `NEG_02_EXPIRED_CERTIFICATE`: Tarihi geçmiş sertifika `CertificateExpiredError` ile yakalandı.
  - `NEG_03_NOT_YET_VALID_CERTIFICATE`: Henüz başlamamış geçerlilik `CertificateNotYetValidError` üretti.
  - `NEG_04_HOSTNAME_MISMATCH`: Alan adı uyuşmazlığı `HostnameMismatchError` ile engellendi.
  - `NEG_05_TAMPERED_TBS_SIGNATURE`: Gövdede tahrifat `CertificateSignatureInvalidError` ile yakalandı.
  - `NEG_06_LEAF_ACTING_AS_CA`: Uç sertifikanın yetkisiz CA davranışı `NonCACertificateUsedAsCAError` ile durduruldu.
  - `NEG_07_REVOKED_CERTIFICATE`: İptal edilmiş seri numarası `RevokedCertificateError` üretti.
  - `NEG_08_PATH_LENGTH_EXCEEDED`: Zincir derinliği ihlali `PathLengthExceededError` ile engellendi.
  - `NEG_09_CORRUPTED_CERTIFICATE_FORMAT`: Bozuk sertifika `MalformedCertificateError` ile elendi.

---

## 4. Standartlara ve Müfredata Uyum

- **RFC 5280:** Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile.
- **RFC 6125:** Representation and Verification of Domain-Based Application Service Identity within Internet Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS).
- **CA/Browser Forum Baseline Requirements:** Basic Constraints ve SAN zorunlulukları.
- **CIS Controls v8:** Control 3.10 — Encrypt Sensitive Data in Transit (TLS and Certificate Validation).
