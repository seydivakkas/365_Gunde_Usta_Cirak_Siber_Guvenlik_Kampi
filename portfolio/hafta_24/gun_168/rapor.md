# Gün 168: Mini Proje 23 — Güvenli Dosya Servisi Günlük Değerlendirme ve İlerleme Raporu
## Hafta 24: Enjeksiyon ve İstek Güvenliği Sentez Kapanış Raporu

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

## 1. Genel Bilgiler

- **Tarih:** 2026-11-14
- **Eğitim Programı:** 365 Günde Usta-Çırak Siber Güvenlik Kampı
- **Aşama:** Aşama 07: Web Güvenliği
- **Hafta:** Hafta 24: Enjeksiyon ve İstek Güvenliği
- **Konu Başlığı:** Mini proje 23: güvenli dosya servisi (Gün 168 - Excel Satır No: 172)
- **Durum:** Tamamlandı (100/100 PASS)

---

## 2. 100/100 Başarı ve Değerlendirme Puan Kartı

| Kriter Kategorisi | Hedef / Standart | Gerçekleşen | Ağırlık | Alınan Puan | Durum |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Birim Testler (tests/)** | 15/15 Kapsamlı Test, 0 Hata | 15/15 PASS (0.032s) | %20 | 20 | MÜKEMMEL |
| **Uygulama & Mimari (uygulama/)** | Güvenli Dosya Servisi Motoru, CLI, Didaktik Yorumlar | Tam teşekküllü motor & CLI, %100 yorum | %40 | 40 | MÜKEMMEL |
| **Kanıt & Negatif Kontroller (kanit/)** | 9 Negatif Kontrol, Gerçek & Temsili Kanıtlar | 9/9 Savunuldu, Tüm kanıtlar üretildi | %25 | 25 | MÜKEMMEL |
| **Dokümantasyon (ders, soru_cevap)** | Usta-Çırak anlatımı, 3 mülakat sorusu | Eksiksiz ders, soru-cevap ve rapor | %15 | 15 | MÜKEMMEL |
| **GENEL TOPLAM** | **100 Puan Standardı** | **100/100** | **%100** | **100** | **TAM BAŞARI (PASS)** |

---

## 3. Yapılan Çalışmaların Özeti

1. **Uygulama Geliştirme (`uygulama/secure_file_service_engine.py` & `secure_file_service_cli.py`):**
   - Hafta 24 boyunca öğrenilen SQLi, NoSQLi, CSRF, CORS, SSRF ve Path Traversal savunma tekniklerini sentezleyen kurumsal seviyede bir dosya depolama ve indirme ağ geçidi motoru kodlandı.
   - Dosya adı üzerinde Null Byte (`%00`, `\x00`), çok geçişli URL kod çözme (`%252e%252e%252f`), tehlikeli çift uzantı (`.pdf.php`) ve alfanümerik filtreleme uygulayan temizleme fonksiyonu geliştirildi.
   - İstemcinin gönderdiği `Content-Type` başlığına güvenmeyip dosyanın gerçek sihirli baytlarını (`%PDF-`, `\x89PNG`, `\xff\xd8\xff`, `PK\x03\x04`) denetleyen imza doğrulayıcısı yazıldı.
   - Polyglot dosya saldırılarına ve webshell'lere karşı `<?php`, `eval(`, `system(`, `<script` gibi zararlı kalıpları tarayan güvenlik katmanı eklendi.
   - Fiziksel dosya adını gizleyen İndirekt Nesne Referansı (UUIDv4) ve `os.path.realpath` / `os.path.commonpath` kanonik hapishane mimarisi inşa edildi.
   - Çok kiracılı (Multi-Tenant) ortamlarda BOLA / IDOR açıklarını engelleyen kiracı ve kullanıcı sahipliği doğrulama sistemi kuruldu.
   - Dosya indirme sırasında Stored XSS ve MIME koklamasını (Sniffing) sıfırlayan `Content-Disposition: attachment`, `nosniff`, `sandbox CSP` başlıkları üretildi.
   - SSRF riskine karşı döngüsel (Loopback), RFC 1918 ve Bulut Metaveri (`169.254.169.254`) IP'lerini engelleyen güvenli uzak dosya getirme modülü geliştirildi.
   - Her bir çalıştırılabilir kod satırına didaktik Türkçe açıklamalar eklendi.

2. **Birim Test Paketi (`tests/test_secure_file_service.py`):**
   - Geçerli PDF yükleme, geçerli PNG yükleme, dosya adında traversal engeli, URL kodlu traversal engeli, Null byte engeli, çift uzantı engeli, yasaklı uzantı engeli, sihirli bayt uyuşmazlığı engeli, webshell içerik engeli, dosya boyutu kotası, güvenli indirme başlıkları, çapraz kiracı erişim engeli (BOLA), aynı kiracıda yetkisiz kullanıcı engeli, admin rolü indirme testi ve SSRF güvenli getirme senaryolarını kapsayan 15 birim test 0.032 saniyede %100 başarıyla tamamlandı.

3. **Örnek Veri ve Kurumsal Politikalar (`ornek_veri/`):**
   - `enterprise_file_service_policy.json`: Kurumsal dosya saklama, izin verilen uzantılar, MIME eşleştirmeleri, güvenlik başlıkları ve SSRF kurallarını içeren JSON şeması oluşturuldu.
   - `invalid_service_payloads.json`: 9 negatif saldırı kontrol senaryosu oluşturuldu.

4. **Kanıt Üretimi ve Doğrulama (`kanit/`):**
   - `kanit_uretici.py` ile birim test sonuçları, 9/9 negatif kontrol savunma raporu, denetim özeti JSON raporu, arındırılmış işlem kayıtları ve CLI konsol günlükleri üretildi.
   - `kanit/temsili/guvenli_dosya_servisi_mimarisi.txt` dosyası zorunlu `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığıyla ASCII formatında kaydedildi.

---

## 4. Negatif Kontrol Saldırı Senaryoları Tablosu

| Senaryo ID | Saldırı Türü | Girdi / Payload | Tespit Edilen Tehdit | Karar / Kod | Savunma Durumu |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **SCN-SRV-01** | PATH_TRAVERSAL_FILENAME | `../../../../etc/shadow.pdf` | TRAVERSAL_DETECTED | 403 Forbidden | SAVUNULDU |
| **SCN-SRV-02** | DOUBLE_ENCODED_TRAVERSAL | `%252e%252e%252f.../passwd.pdf` | TRAVERSAL_DETECTED | 403 Forbidden | SAVUNULDU |
| **SCN-SRV-03** | NULL_BYTE_INJECTION | `annual_report.pdf%00.exe` | NULL_BYTE_DETECTED | 400 Bad Request | SAVUNULDU |
| **SCN-SRV-04** | DOUBLE_EXTENSION_SHELL | `invoice.pdf.php` | DOUBLE_EXTENSION_DETECTED | 403 Forbidden | SAVUNULDU |
| **SCN-SRV-05** | DISALLOWED_EXTENSION | `ransomware_payload.exe` | EXTENSION_NOT_ALLOWED | 403 Forbidden | SAVUNULDU |
| **SCN-SRV-06** | MAGIC_BYTES_MISMATCH | Fake PNG with text data | MAGIC_BYTES_MISMATCH | 403 Forbidden | SAVUNULDU |
| **SCN-SRV-07** | POLYGLOT_WEBSHELL | `polyglot.pdf` with `<?php system(...)` | MALICIOUS_CONTENT_DETECTED | 403 Forbidden | SAVUNULDU |
| **SCN-SRV-08** | OVERSIZED_PAYLOAD | 6 MB payload (5 MB limit) | FILE_TOO_LARGE | 413 Payload Too Large | SAVUNULDU |
| **SCN-SRV-09** | SSRF_CLOUD_METADATA | `http://169.254.169.254/...` | METADATA_IP_BLOCKED | 403 Forbidden | SAVUNULDU |

---

## 5. Çıkarılan Temel Mühendislik İlkeleri

1. **İstemcinin Hiçbir Beyanına Güvenme:** Ne dosya adı, ne dosya uzantısı, ne de `Content-Type` başlığı güvenilirdir. Dosya içeriğinin ilk baytları (Magic Bytes) mutlaka sunucu tarafında doğrulanmalıdır.
2. **Kullanıcı Girdisini Dosya İsminden Ayır:** Fiziksel dosyalar diskte daima rastgele UUIDv4 ile saklanmalı; orijinal isim sadece bir veritabanı metaverisi olarak tutulmalıdır.
3. **Kanonik Hapishane (Chroot / Jail):** `os.path.realpath` ve `os.path.commonpath` kullanılarak dosya erişimleri her zaman güvenli kök dizinle sınırlanmalıdır.
4. **İndirme Başlıkları Hayat Kurtarır:** `Content-Disposition: attachment` ve `X-Content-Type-Options: nosniff` başlıkları tarayıcının dosyayı doğrudan çalıştırmasını önleyerek Stored XSS saldırılarını sıfırlar.
5. **Kiracı İzolasyonu Mimari Bir Zorunluluktur:** Çok kiracılı SaaS sistemlerinde her indirme isteğinde dosyanın ait olduğu `tenant_id` oturum açan kullanıcının `tenant_id`'si ile karşılaştırılmalıdır.
