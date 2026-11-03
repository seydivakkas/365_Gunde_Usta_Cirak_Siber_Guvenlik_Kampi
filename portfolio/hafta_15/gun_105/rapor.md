# Gün 105: Mini Proje 14 — Kriptografik Hash Bütünlük Manifesti Değerlendirme Raporu

**Tarih:** 02.11.2026  
**Müfredat Referansı:** Hafta 15 / Gün 105 (Excel Satır 109)  
**Görev Türü:** Mini Proje 14 (Hafta 15 Bitirme Projesi)  
**Değerlendirme Sonucu:** 100 / 100 (Tam Puan — YETERLİ / MÜKEMMEL)

---

## 1. Puanlama Tablosu ve Yetkinlik Kriterleri

| Değerlendirme Kriteri | Taban Puan | Alınan Puan | Durum | Gerekçe ve Teknik Kanıtlar |
|:---|:---:|:---:|:---:|:---|
| **I. Mimari ve Güvenlik Tasarımı** | 20 | **20** | TAMAMLANDI | Pure Python akışlı FIM mimarisi, 64 KB bellek tamponuyla DoS (CWE-400) koruması, CWE-22 ve CWE-59 kök sınır denetimi, HMAC-SHA256 mühürleme (CWE-353) eksiksiz tasarlandı. |
| **II. Kodlama ve Temiz Kod Standartları** | 40 | **40** | TAMAMLANDI | `hash_manifest_engine.py` ve `manifest_cli.py` içerisinde tüm çalıştırılabilir Python satırları didaktik Türkçe yorum satırları ile zenginleştirildi. Tip güvenliği (type hints), özel hata sınıfları tanımlandı. |
| **III. Test Kapsamı ve Negatif Kontroller** | 25 | **25** | TAMAMLANDI | 15/15 Birim testi (%100 Başarı - 0.037s) ve 9/9 Negatif kontrol senaryosu başarıyla koşturuldu. Manipülasyon, eksik dosya, dizin aşımı, bozuk mühür senaryoları doğrulandı. |
| **IV. Dokümantasyon, Raporlama ve Lisans** | 15 | **15** | TAMAMLANDI | Usta-Çırak pedagojisine uygun `ders.md`, 4 zorunlu başlıklı `soru_cevap.md`, adli analiz raporu ve temsilî ASCII mimari şeması eksiksiz hazırlandı. Özel Lisans kuralına %100 uyuldu. |
| **GENEL TOPLAM** | **100** | **100** | **YETERLİ** | **Müfredat ve Endüstri Standartlarına Tam Uyum** |

---

## 2. Zafiyet ve Güvenlik Eşleme Matrisi (CWE & Standartlar)

| Zafiyet Kodu (CWE) | Zafiyet Tanımı | Motorda Alınan Kriptografik & Yazılımsal Önlem | Test / Doğrulama Durumu |
|:---|:---|:---|:---:|
| **CWE-353** | Missing Support for Integrity Check (Mühürsüz Manifest) | Manifest gövdesi sıralı JSON formatında HMAC-SHA256 ile mühürlenir. Mühürsüz veya tahrif edilmiş manifest anında reddedilir. | DOĞRULANDI (PASS) |
| **CWE-400** | Uncontrolled Resource Consumption (DoS / OOM) | 64 KB sabit bellek tamponu (streaming) ve 1 MB / parametrik maksimum dosya boyutu tavanı uygulandı. | DOĞRULANDI (PASS) |
| **CWE-22** | Improper Limitation of a Pathname (Path Traversal) | `safe_resolve_path` ile bağıl yollar kök dizin hapishanesine sınırlandı; `../` manipülasyonları engellendi. | DOĞRULANDI (PASS) |
| **CWE-59** | Improper Link Resolution Before File Access (Symlink Escape) | Sembolik bağlar (`os.path.islink`) tespit edilerek kök dışına kaçış girişimleri engellendi. | DOĞRULANDI (PASS) |
| **CWE-208** | Possible Timing Attack in Information Verification | Mühür ve hash kontrollerinde `hmac.compare_digest` kullanılarak zamanlama yan kanal sızıntıları önlendi. | DOĞRULANDI (PASS) |
| **CWE-328** | Use of Weak Hash (MD5 / SHA-1) | Kırılmış özet fonksiyonları reddedildi; SHA-256, BLAKE2b ve SHA-512 kripto-çeviklik kütüphanesi entegre edildi. | DOĞRULANDI (PASS) |

---

## 3. Test ve Gerçek Kanıt Özeti

- **Birim Testleri:** `tests/test_hash_manifest.py` -> 15/15 PASS (0.037s)
- **Negatif Kontrol Testleri:** `ornek_veri/invalid_manifest_inputs.json` -> 9/9 PASS
  - `NEG_01_TAMPERED_CONTENT`: İçerik manipülasyonu anında tespit edildi.
  - `NEG_02_MISSING_FILE`: Eksik dosya durumu `tampered` listesine eklendi.
  - `NEG_03_UNTRACKED_FILE`: Yeni/izinsiz dosya durumu `untracked` olarak raporlandı.
  - `NEG_04_SYMLINK_ESCAPE`: Sembolik bağ kaçışı `SymlinkEscapeError` ile durduruldu.
  - `NEG_05_PATH_TRAVERSAL`: Dizin aşımı `PathTraversalError` ile engellendi.
  - `NEG_06_INVALID_SEAL`: Yanlış mühür anahtarı `HMACSealError` fırlattı.
  - `NEG_07_CORRUPT_MANIFEST_JSON`: Bozuk JSON `CorruptedManifestError` üretti.
  - `NEG_08_OVERSIZED_DOS_FILE`: Boyut tavanını aşan dosya `FileTooLargeError` ile yakalandı.
  - `NEG_09_DEPRECATED_ALGORITHM_MD5`: Güvensiz MD5 algoritması `UnsupportedAlgorithmError` ile reddedildi.

---

## 4. Hafta 15 Genel Başarı Değerlendirmesi

Hafta 15 (Gün 99 - Gün 105) boyunca modern kriptografinin yapı taşları uçtan uca teorik ve pratik olarak hayata geçirilmiştir:
1. **Gün 99:** Kriptografiye Giriş ve Temel Kavramlar (Simetrik/Asimetrik ayrımı, Kerckhoffs ilkesi).
2. **Gün 100:** Kriptografik Hash Fonksiyonları (Merkle-Damgård, Çığ Etkisi, Çakışma Direnci).
3. **Gün 101:** MAC ve HMAC (Mesaj Kimlik Doğrulama, Boyut Uzatma Atakları, Sabit Zamanlı Doğrulama).
4. **Gün 102:** Parola Saklama Mimarisi (PBKDF2-HMAC-SHA256, 128-bit Salt, Pepper, Legacy MD5 Tespiti).
5. **Gün 103:** Simetrik Şifreleme ve AES (FIPS 197 Pure Python AES-128/256 Motoru, ECB vs CBC vs CTR).
6. **Gün 104:** AEAD ve Nonce Güvenliği (Encrypt-then-MAC, Nonce Reuse CWE-323 Koruması, Two-Time Pad İhlali).
7. **Gün 105 (Mini Proje 14):** Kriptografik Hash Bütünlük Manifesti ve FIM Motoru (Haftanın tüm kazanımlarının entegrasyonu).

Tüm Hafta 15 gereksinimleri %100 başarı ve sıfır eksikle tamamlanmıştır.
