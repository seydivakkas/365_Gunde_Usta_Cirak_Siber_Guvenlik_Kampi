# GÜN 082: PYTEST İLE BİRİM TESTLERİ — DEĞERLENDİRME VE GÜVENLİK RAPORU
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

## 1. YÖNETİCİ ÖZETİ VE GENEL DEĞERLENDİRME

- **Ders Kodu ve Konusu:** G082 — pytest ile Birim Testleri (Unit Testing with pytest in Security Engineering)
- **Aşama:** Aşama 04 — Python ile Güvenlik Otomasyonu ve Savunmacı Kodlama
- **Hafta:** Hafta 12 — Python ile Sistem ve Dosya Güvenliği
- **Değerlendirme Puanı:** **100 / 100 (TAM PUAN — YETERLİ / PASS)**
- **Doğrulama Sonuçları:**
  - Birim Testler (pytest): 14 Test Fonksiyonu, 39 Parametrik Senaryo BAŞARILI (0.07s)
  - Negatif Güvenlik Kontrolleri: 9 / 9 BAŞARILI
  - Satır İçi Didaktik Açıklama Kapsamı: %100 (Tüm çalıştırılabilir kod satırları didaktik Türkçe açıklamalı)
  - Lisans Denetimi: Özel Lisans ("Tüm Hakları Saklıdır") eksiksiz uygulandı.

---

## 2. DÖRT TEMEL KATEGORİ PUAN DAĞILIMI

| Değerlendirme Kategorisi | Maksimum Puan | Alınan Puan | Durum |
| :--- | :---: | :---: | :---: |
| **1. Tasarım ve Mimari (Architecture & Design)** | 20 | **20** | TAM / EKSİKSİZ |
| **2. Uygulama ve Fonksiyonellik (Implementation & Features)** | 40 | **40** | TAM / EKSİKSİZ |
| **3. Test ve Doğrulama (Unit Testing & Verification)** | 25 | **25** | TAM / EKSİKSİZ |
| **4. Güvenlik ve Negatif Kontrol (Security & Negative Controls)** | 15 | **15** | TAM / EKSİKSİZ |
| **TOPLAM PUAN** | **100** | **100** | **YETERLİ / PASS** |

---

## 3. KATEGORİ BAZLI DETAYLI ANALİZ

### Kategori 1: Tasarım ve Mimari (20 / 20)
- **Modern Test Mimarisi ve Fikstürler (Fixtures):** `policy_enforcer` ve `valid_firewall_payload` pytest fikstürleri ile durum sızıntısı (state pollution) engellenmiş, her test bağımsız izole nesnelerle koşturulmuştur.
- **Parametrik Saldırı Matrisleri:** `@pytest.mark.parametrize` kullanılarak parola karmaşıklığı, tehdit puan sınırları, alan adı yol geçişleri ve geçersiz portlar onlarca kombinasyonla test edilmiştir.
- **Özel İşaretleyiciler (Markers):** `conftest.py` üzerinden `@pytest.mark.security` ve `@pytest.mark.negative` işaretleyicileri resmî olarak tanımlanmış, uyarı üretmeyen temiz yapı kurulmuştur.
- **Bağımsız Gün Sınırı:** Hiçbir harici veya önceki gün modülüne bağımlılık bulunmamaktadır; Python 3 ve pytest standartları kullanılmıştır.

### Kategori 2: Uygulama ve Fonksiyonellik (40 / 40)
- **Parola Karmaşıklık Politikası (`validate_password_complexity`):** Asgari 12, azami 64 karakter; büyük/küçük harf, rakam, özel karakter ve sözlük kara listesi (`banned_passwords`) kontrolleri.
- **Sınır Değer Analizi (`classify_security_incident`):** 0-100 aralığında puan denetimi; 0-39 LOW, 40-69 MEDIUM, 70-89 HIGH, 90-100 CRITICAL ve aralık dışı değerler için `ValueError` koruması.
- **Alan Adı Kanonikleştirme ve Sanitizasyon (`sanitize_target_domain`):** Protokol öneki (`http://`, `https://`) temizliği, null-byte ve yol geçişi (`/`, `\`, `..`) reddi, RFC uyumlu FQDN regex denetimi.
- **Güvenlik Duvarı Kural Denetimi (`evaluate_firewall_rule`):** IPv4 adres formatı, 1-65535 port sınırları ve protokol kısıtı (TCP, UDP, ICMP).
- **Hız Sınırı ve Denetim Günlüğü (`SecurityPolicyEnforcer`):** İstemci başına 5 istek eşiği ve tüm işlemlerin `audit_log` içinde adli kayda alınması.

### Kategori 3: Test ve Doğrulama (25 / 25)
- `tests/test_security_policy_enforcer.py` paketi 14 test fonksiyonu altında 39 parametrik senaryo içerir:
  1. `test_01_password_complexity_valid` -> PASSED
  2. `test_02_password_complexity_too_short` (4 parametre) -> 4 PASSED
  3. `test_03_password_complexity_missing_character_classes` (4 parametre) -> 4 PASSED
  4. `test_04_password_complexity_dictionary_blacklist` -> PASSED
  5. `test_05_classify_security_incident_boundaries` (8 sınır değeri) -> 8 PASSED
  6. `test_06_classify_security_incident_out_of_bounds` (4 sınır dışı değer) -> 4 PASSED
  7. `test_07_sanitize_target_domain_valid` (4 geçerli alan adı) -> 4 PASSED
  8. `test_08_sanitize_target_domain_path_traversal_raises` (3 zararlı yol) -> 3 PASSED
  9. `test_09_sanitize_target_domain_null_byte_raises` -> PASSED
  10. `test_10_evaluate_firewall_rule_valid` -> PASSED
  11. `test_11_evaluate_firewall_rule_invalid_port` (5 geçersiz port) -> 5 PASSED
  12. `test_12_evaluate_firewall_rule_invalid_ip` -> PASSED
  13. `test_13_enforcer_rate_limiting_fixture` -> PASSED
  14. `test_14_enforcer_audit_log_recording` -> PASSED
- Testlerin yürütülme süresi: 0.07 saniye.

### Kategori 4: Güvenlik ve Negatif Kontrol (15 / 15)
- `ornek_veri/invalid_pytest_inputs.json` dosyasında tanımlanan 9 gerçekçi saldırı senaryosu tam başarıyla engellenmiştir:
  - `NEG_01_PASSWORD_TOO_SHORT`: 6 karakterlik kısa parola engellendi.
  - `NEG_02_PASSWORD_NO_SPECIAL_CHAR`: Özel karaktersiz parola engellendi.
  - `NEG_03_PASSWORD_COMMON_DICTIONARY`: Bilinen sözlük parolası engellendi.
  - `NEG_04_SEVERITY_SCORE_OUT_OF_BOUNDS_HIGH`: 150 puanlık sınır aşımı engellendi.
  - `NEG_05_SEVERITY_SCORE_OUT_OF_BOUNDS_NEGATIVE`: -25 negatif puan engellendi.
  - `NEG_06_DOMAIN_PATH_TRAVERSAL_INJECTION`: Alan adı içine gizlenen `../../etc/passwd` engellendi.
  - `NEG_07_DOMAIN_NULL_BYTE_POISONING`: Alan adı null-byte zehirlemesi engellendi.
  - `NEG_08_FIREWALL_RULE_INVALID_PORT`: 70000 nolu geçersiz port engellendi.
  - `NEG_09_RATE_LIMIT_BURST_ATTACK`: 6 ardışık istekte hız sınırı kuralı tetiklendi.

---

## 4. KANIT DOSYALARI LİSTESİ

1. `kanit/gercek/test_sonuclari.txt`: 39/39 pytest test başarı raporu (0.07s).
2. `kanit/gercek/komut_ve_cikis.txt`: Terminal yürütme ve stdout/stderr kayıtları.
3. `kanit/gercek/negatif_kontrol_sonuclari.txt`: 9 negatif test senaryosunun doğrulama çıktıları.
4. `kanit/gercek/politika_denetim_raporu.txt`: Motorun ürettiği politika denetim özeti.
5. `kanit/temsili/pytest_ve_guvenlik_mimarisi.txt`: `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığıyla ASCII akış ve test mimarisi.

---

## 5. SONUÇ VE KABUL BEYANI

G082 pytest ile Birim Testleri modülü; pytest fikstürleri, parametrik saldırı matrisleri, sınır değer analizleri, `pytest.raises` ile regex tabanlı hata mesajı denetimi ve hız sınırlama gereksinimlerini eksiksiz karşılamaktadır. 100/100 tam puan ile onaylanmış ve kabul edilmiştir.
