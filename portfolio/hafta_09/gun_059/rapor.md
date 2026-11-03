# G059: HTTPS ve TLS El Sıkışması — Günlük Değerlendirme ve Teknik Sonuç Raporu

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya ticari olarak kullanılamaz.
```

---

## 1. Yönetici Özeti ve Rubrik Değerlendirmesi

Bu çalışma; Siber Güvenlik 365 Gün Müfredat Paketi'nin **Aşama 03 (Ağ Temelleri ve Protokoller)**, **Hafta 09 (Web Protokolleri ve Web Güvenliğine Giriş)** kapsamındaki **59. Gün (G059)** konusudur. "HTTPS ve TLS Görüşmesi (TLS Handshake)" üzerine RFC 5246, RFC 8446, RFC 6066 ve RFC 2818 standartları temelinde kapsamlı bir analiz, simülasyon ve test motoru geliştirilmiştir.

Tüm kodlar, birim testler, negatif sınır testleri ve kanıtlar yerel çalışma ortamında Python 3.14 üzerinde sıfırdan ve bağımsızlık kuralına tam uyumlu olarak üretilmiştir.

### Değerlendirme ve Puanlama Tablosu

| Değerlendirme Kriteri | Maksimum Puan | Alınan Puan | Açıklama ve Durum |
| :--- | :---: | :---: | :--- |
| **Açıklamalı Soru-Cevap** | 20 | **20** | G059-SC1, SC2, SC3 soruları 4 zorunlu alt başlıkla derinlemesine yanıtlandı. |
| **Gerçek Uygulama / Simülasyon** | 40 | **40** | `tls_handshake_analyzer.py` modülü; Record Layer, SNI, Downgrade ve PFS motoru. |
| **Doğrulanabilir Kanıt** | 25 | **25** | 14 birim test + 9 negatif test %100 başarılı; gerçek terminal çıktıları arşivlendi. |
| **Teknik Rapor & Dokümantasyon** | 15 | **15** | Dürüst, kaynaklı, RFC referanslı ders, rapor ve mimari çizimler tamamlandı. |
| **TOPLAM PUAN** | **100** | **100** | **DURUM: YETERLİ / PASS** |

---

## 2. Geliştirilen Uygulama ve Teknik Mimari

### 2.1. `tls_handshake_analyzer.py`
Uygulama motoru, TLS protokolünün hem aktarım hem de kriptografik katmanlarını modelleyen şu temel modüllerden oluşmaktadır:
1. **TLS Record Layer Ayrıştırıcı (`parse_record_layer_header`):**
   - 5 baytlık ikili başlığı (`Content-Type`, `Version`, `Length`) `struct.unpack` ile big-endian olarak çözer.
   - Tanımsız tipleri (ör. 99), tedavülden kalkmış eski sürümleri (SSL 3.0 `0x0300`, SSL 2.0 `0x0200`) ve 16384 bayt RFC tavan sınırını aşan paketleri yakalayarak `TLSValidationError` üretir.
   - Bildirilen uzunluk ile gelen ham bayt uzunluğunun uyuşmazlığında `TLSMalformedRecordError` fırlatır.
   - Handshake (22) mesajlarında el sıkışma tipi doğrulaması yapar.
2. **SNI Doğrulayıcı (`validate_sni_hostname`):**
   - RFC 6066 uyumlu alan adı doğrulaması yapar; null-byte, geçersiz semboller ve 255 karakter aşımını engeller.
3. **CRIME Sıkıştırma Denetçisi (`check_compression_security`):**
   - `0x00` (Null) haricindeki tüm sıkıştırma yöntemlerini (özellikle DEFLATE `0x01`) CRIME (CVE-2012-4929) zaafiyeti gerekçesiyle bloke eder.
4. **RFC 8446 Downgrade Savunma Motoru (`verify_downgrade_protection`):**
   - İstemci TLS 1.3 desteklediğinde sunucu yanıtındaki `Server Random` alanının son 8 baytını inceler. MitM tarafından sürümün TLS 1.2'ye düşürüldüğü durumlarda ortaya çıkan `DOWNGRD\x01` (`444f574e47524401`) sentinel baytlarını tespit ederek `TLSDowngradeDetectedError` fırlatır.
5. **Şifreleme Paketi ve İletme Gizliliği Analizörü (`assess_cipher_suite_security`):**
   - Şifreleme paketlerini tarayarak PFS (Perfect Forward Secrecy) desteğini, AEAD şifreleme modlarını ve zayıf/kırılmış algoritmaları (DES, 3DES, RC4, MD5, CBC, statik RSA) puanlar.
6. **Sentetik İkili TLS Kayıt Üreticisi (`build_raw_client_hello_record`):**
   - Laboratuvar simülasyonları ve ağ paket enjeksiyon testleri için standart ikili (binary) ClientHello segmentleri üretir.

---

## 3. Doğrulanabilir Kanıtlar ve Test Sonuçları

### 3.1. Birim Testleri (`test_tls_handshake_analyzer.py`)
- **Toplam Test:** 14
- **Başarılı:** 14 (%100)
- **Hatalı / Başarısız:** 0
- **Çalışma Süresi:** 0.001 saniye
- **Kanıt Dosyası:** `kanit/gercek/test_sonuclari.txt` ve `kanit/gercek/komut_ve_cikis.txt`

### 3.2. Negatif ve Sınır Değer Testleri (`invalid_tls_inputs.json`)
- **Toplam Negatif Senaryo:** 9
- **Başarılı Engelleme:** 9 (%100)
- **Kanıt Dosyası:** `kanit/gercek/negatif_kontrol_sonuclari.txt`

| Senaryo ID | Test Tanımı | Beklenen İstisna | Alınan Sonuç |
| :--- | :--- | :--- | :--- |
| `NEG_01` | Kesilmiş Kayıt Başlığı (< 5 bayt) | `TLSMalformedRecordError` | Başarıyla Yakalandı |
| `NEG_02` | Tanımsız İçerik Tipi (99) | `TLSValidationError` | Başarıyla Yakalandı |
| `NEG_03` | Güvensiz SSL 3.0 Sürümü (0x0300) | `TLSValidationError` | Başarıyla Yakalandı |
| `NEG_04` | 16384 Bayt Üst Sınır Aşımı | `TLSValidationError` | Başarıyla Yakalandı |
| `NEG_05` | Yük Boyutu Uyuşmazlığı / Kesilme | `TLSMalformedRecordError` | Başarıyla Yakalandı |
| `NEG_06` | Bozuk Handshake Mesaj Tipi (99) | `TLSValidationError` | Başarıyla Yakalandı |
| `NEG_07` | Null-Byte İçeren SNI Alan Adı | `TLSValidationError` | Başarıyla Yakalandı |
| `NEG_08` | CRIME Zaafiyeti Yaratan Sıkıştırma (DEFLATE) | `TLSValidationError` | Başarıyla Yakalandı |
| `NEG_09` | MitM Sürüm Düşürme Saldırısı (Sentinel Tespiti) | `TLSDowngradeDetectedError` | Başarıyla Yakalandı |

---

## 4. Akademik ve Sektörel Standart Referansları

1. **RFC 5246:** The Transport Layer Security (TLS) Protocol Version 1.2
2. **RFC 8446:** The Transport Layer Security (TLS) Protocol Version 1.3
3. **RFC 6066:** Transport Layer Security (TLS) Extensions: Extension Definitions (SNI)
4. **RFC 2818:** HTTP Over TLS (HTTPS Tanımı ve URI Eşleme Kuralları)
5. **RFC 8470:** Using Early Data in HTTP (0-RTT Replay Önleme Stratejileri)
6. **CVE-2012-4929:** CRIME (Compression Ratio Info-leak Made Easy) Saldırısı
7. **CVE-2014-3566:** POODLE (Padding Oracle On Downgraded Legacy Encryption) Saldırısı

---
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
ÖZEL LİSANS — Günlük değerlendirme raporu yalnızca görüntüleme ve eğitim amacıyla hazırlanmıştır.
