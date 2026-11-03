# GÜN 123 DEĞERLENDİRME RAPORU: Güvenli Varsayılanlar ve Fail-Safe Mimarisi

## 1. Genel Bilgiler
- **Tarih:** 2026-11-02
- **Hafta:** 18
- **Gün:** 123
- **Konu Başlığı:** Güvenli varsayılanlar ve fail-safe
- **Genel Durum:** 100/100 TAM BAŞARILI (PASS)

---

## 2. Değerlendirme Kriterleri ve Puan Tablosu

| Kategori | Ağırlık / Azami Puan | Alınan Puan | Açıklama |
|---|---|---|---|
| **Kod Kalitesi ve Mimari** | 20 | 20 | Saf Python standart kütüphanesi, Saltzer-Schroeder Fail-Safe Defaults prensibi, CWE-1188 denetleyicisi, CWE-636 Fail-Closed karar motoru |
| **Birim Test Kapsamı ve Dayanıklılık** | 40 | 40 | 15/15 unit test (%100 PASS, süre: 0.001s), Default-Deny doğrulaması, 4 farklı arıza modu simülasyonu, güvensiz varsayılan taraması |
| **Negatif Kontrol ve Güvenlik Senaryoları** | 25 | 25 | 9/9 negatif kontrol senaryosu (%100 PASS, açık debug, varsayılan şifre, açık CORS, şifresiz iletişim, yetkisiz fail-open ve mükerrer kayıtlar) |
| **Dokümantasyon ve Usta-Çırak Derinliği** | 15 | 15 | ders.md, 3 adet 4 başlıklı soru_cevap.md, rapor.md, README.md, sonuc.json, manifest.json |
| **TOPLAM** | **100** | **100** | **MÜKEMMEL (TAM PUAN)** |

---

## 3. Doğrulama ve Test Sonuçları Özeti

### A. Birim Testler (`tests/test_secure_defaults_failsafe.py`)
- **Toplam Test Sayısı:** 15
- **Başarılı:** 15
- **Başarısız / Hata:** 0
- **Çalışma Süresi:** 0.001 saniye

Test edilen temel fonksiyonlar:
1. `test_01_default_deny_when_no_rules_match`: Saltzer-Schroeder prensibi gereği açık kural yoksa talebin reddedilmesi (Default-Deny).
2. `test_02_explicit_rule_permits_access`: Açıkça tanımlanmış kural eşleştiğinde erişimin onaylanması.
3. `test_03_unknown_resource_default_denied`: Tanımsız kaynağa erişim talebinin güvenli varsayılanla reddedilmesi.
4. `test_04_cwe_1188_debug_mode_detection`: Debug modunun açık bırakılmasının tespiti (`DEBUG_MODE_ENABLED`).
5. `test_05_cwe_1188_default_credentials_active_detection`: Varsayılan parolanın değiştirilmemesinin tespiti (`DEFAULT_CREDENTIALS_ACTIVE`).
6. `test_06_cwe_1188_permissive_cors_detection`: Permissive CORS (*) başlığının tespiti (`PERMISSIVE_CORS`).
7. `test_07_cwe_1188_unencrypted_storage_detection`: Şifresiz durağan depolamanın tespiti (`UNENCRYPTED_STORAGE`).
8. `test_08_cwe_1188_default_permit_access_detection`: Varsayılan erişimi ALLOW yapılmış kaynağın tespiti (`DEFAULT_PERMIT_ACCESS`).
9. `test_09_enforce_secure_defaults_raises_insecure_default_detected`: Güvensiz varsayılan varken `InsecureDefaultDetectedError` fırlatılması.
10. `test_10_fail_secure_on_database_down`: Veritabanı kesintisinde Fail-Secure mekanizmasının erişimi kesmesi (CWE-636).
11. `test_11_fail_secure_on_auth_service_timeout`: Kimlik servisi zaman aşımında Fail-Secure'ın erişimi reddetmesi.
12. `test_12_fail_secure_on_unhandled_exception`: Kod seviyesinde beklenmeyen istisnada Fail-Secure'ın kapıları kapatması.
13. `test_13_cwe_636_unauthorized_fail_open_forbidden`: Yetkisiz Fail-Open girişiminde `InsecureFailOpenForbiddenError` fırlatılması.
14. `test_14_authorized_safety_fail_open_emergency`: Acil durum can güvenliği token'ı varlığında kontrollü açık geçiş izni.
15. `test_15_resilient_secure_defaults_audit_and_report`: Tam uyumlu mimarinin denetimi ve Markdown rapor üretimi.

### B. Negatif Kontroller (`ornek_veri/invalid_failsafe_scenarios.json`)
- **Toplam Senaryo:** 9
- **Başarılı (Beklenen Hata Alındı):** 9 / 9
- Senaryo Tipleri: Debug Modu Açık, Fabrika Çıkışlı Parola Aktif, Açık CORS (*), TLS Şifrelemesi Yok, Şifresiz Depolama, Varsayılan ALLOW Yapılandırması, Yetkisiz Fail-Open İhlali (CWE-636), Boş Kaynak Adı, Mükerrer Kaynak ID.

### C. Kanıt Dosyaları Listesi
1. `kanit/gercek/test_sonuclari.txt` (15/15 PASS detaylı log)
2. `kanit/gercek/negatif_kontrol_sonuclari.txt` (9/9 PASS negatif senaryolar)
3. `kanit/gercek/komut_ve_cikis.txt` (CLI audit ve arıza simülasyonu çıktıları)
4. `kanit/gercek/failsafe_analiz_raporu.txt` (Güvenli varsayılanlar ve politika raporu)
5. `kanit/temsili/failsafe_mimarisi.txt` (ASCII mimari illüstrasyonu)

---

## 4. Standartlar ve CWE Eşleme Tablosu

| Güvenlik Standardı / CWE | Tanım | Motordaki Karşılığı |
|---|---|---|
| **CWE-636** | Not Failing Securely ('Failing Open') | Arıza (Timeout, DB Down, Exception) durumunda sistemin yetkisiz fail-open olmasının engellenmesi ve `FAIL_SECURE` kuralının zorlanması. |
| **CWE-1188** | Insecure Default Initialization of Resource | Debug modu, fabrika çıkışlı parola, açık CORS, şifresiz iletim ve depolama gibi güvensiz varsayılanların otomatik tespiti ve reddi. |
| **Saltzer & Schroeder (1975)** | Principle of Fail-Safe Defaults | Kural eşleşmediğinde açık izin verilmemesi; varsayılan durumun mutlak `DENY` olarak uygulanması. |
| **CISA / NIST** | Secure by Design and Secure by Default | Sistemlerin kutudan çıktığı anda en yüksek güvenlik seviyesinde başlatılmasının zorunlu kılınması. |
| **CWE-276** | Incorrect Default Permissions | Kaynakların varsayılan erişim izninin katı şekilde kısıtlanması. |
