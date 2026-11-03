<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 039 — Değerlendirme ve Uygulama Raporu

**Tarih:** 2026-10-27  
**Aşama:** 02 — Sistem ve Ağ Temelleri  
**Hafta:** 06 — İşletim Sistemi Güvenliği ve Temel Ağ Mimarisi  
**Gün:** 039 (G039) — Yedekleme Stratejisi ve 3-2-1  
**Durum:** 100/100 — YETERLİ (PASS)

---

## 1. Yönetici Özeti ve Pedagojik Hedef
Bu çalışma kapsamında kurumsal veri koruma, iş sürekliliği ve felaket kurtarma süreçlerinin temeli olan **3-2-1 Yedekleme Kuralı**, modern fidye yazılımlarına (Ransomware) karşı **Değiştirilemezlik (Immutability / WORM)**, **Schrödinger'in Yedeği Paradoksu** (geri yükleme testleri) ve **Yedek vs Snapshot vs RAID** mimari ayrımları derinlemesine analiz edilmiştir.

Geliştirilen `BackupStrategy321Auditor` motoru ile kurumsal yedekleme politikaları üzerinde:
1. **3-2-1 Kural Uyumluluğu:** 3 bağımsız kopya, en az 2 farklı depolama medyası ve en az 1 tesis dışı (offsite) kopya varlığı denetlenmiştir.
2. **Fidye Yazılımı Dayanıklılığı (WORM / Immutability):** S3 Object Lock Compliance Mode, Linux Hardened Repository ve hava boşluğu (air-gap) mekanizmaları taranmış; silinebilir yedekler CRITICAL olarak raporlanmıştır.
3. **Schrödinger'in Yedeği Analizi:** Geri yükleme testi hiç yapılmamış veya 90 günden eski olan yedeklerin geçerliliği sorgulanmış; sahte güvenlik algısı çökertilmiştir.
4. **Mimari Yanılgılar:** RAID dizisini veya birincil SAN havuzundaki snapshot'ları tek başına yedek zannetme yanılgıları tespit edilmiştir.
5. **RPO / RTO Uyumsuzlukları:** İş birimi tarafından taahhüt edilen azami veri kaybı süresinin fiili yedekleme sıklığıyla örtüşüp örtüşmediği doğrulanmıştır.

---

## 2. Puanlama ve Değerlendirme Rubriği (20 / 40 / 25 / 15)

| Kriter | Ağırlık | Alınan Puan | Değerlendirme ve Gerekçe |
| :--- | :---: | :---: | :--- |
| **1. Kod ve Uygulama Mimarisi** | 20 | 20/20 | Tip ipuçları (`typing`), nesne yönelimli modüler tasarım, `BackupTelemetryValidationError` özel istisna sınıfı, her satırda didaktik ve pedagojik açıklamalar. |
| **2. Birim Testler ve Doğrulama** | 40 | 40/40 | 14 bağımsız birim test, %100 başarı oranı (14/14 PASS in 0.003s), negatif kontroller, sınır testleri ve bozuk veri senaryoları. |
| **3. Siber Güvenlik ve Savunma Derinliği** | 25 | 25/25 | 3-2-1 kuralı, WORM/Immutability fidye yazılımı savunması, Schrödinger yedeği analizi, RAID vs Snapshot ayrımı, RPO/RTO hesaplamaları. |
| **4. Dokümantasyon, Standart ve Lisans** | 15 | 15/15 | Usta-Çırak pedagojisi, özel "Tüm Hakları Saklıdır" lisans başlıkları, kanıt dosyaları (`gercek/` ve `temsili/`), tam soru-cevap dokümanı. |
| **TOPLAM** | **100** | **100/100** | **YETERLİ / PASS** |

---

## 3. Doğrulama ve Test Sonuçları Özeti

### 3.1. Birim Testlerin İcrası
- **Test Dosyası:** `portfolio/hafta_06/gun_039/tests/test_backup_strategy_321_auditor.py`
- **Koşum Süresi:** 0.003 saniye
- **Sonuç:** `Ran 14 tests in 0.003s - OK`
- **Kapsam:**
  - `test_01_telemetry_schema_validation_success`: Standart envanter şema doğrulaması.
  - `test_02_missing_policies_key_raises_validation_error`: Eksik backup_policies anahtarı tespiti.
  - `test_03_negative_total_copies_raises_validation_error`: Negatif kopya sayısı engeli.
  - `test_04_non_numeric_restore_days_raises_error`: Sayısal olmayan geri yükleme günü tespiti.
  - `test_05_negative_restore_days_raises_error`: Negatif geri yükleme günü engeli.
  - `test_06_non_string_policy_id_raises_error`: String olmayan policy_id tespiti.
  - `test_07_insufficient_copies_detected_as_high_severity`: 3'ten az kopya sayısının HIGH olarak yakalanması.
  - `test_08_missing_media_diversity_detected_as_medium`: 2'den az medya türünün MEDIUM olarak raporlanması.
  - `test_09_missing_offsite_copy_detected_as_critical`: 0 offsite kopyanın CRITICAL olarak tespiti.
  - `test_10_missing_immutability_ransomware_detected_as_critical`: Değiştirilemezlik eksikliğinin CRITICAL fidye yazılımı açığı olarak yakalanması.
  - `test_11_schrodingers_backup_untested_restore_detected_as_critical`: Test edilmemiş yedeğin CRITICAL olarak etiketlenmesi.
  - `test_12_relying_on_raid_as_backup_detected_as_critical`: RAID yanılgısının CRITICAL mimari hata olarak tespiti.
  - `test_13_corrupted_test_cases_suite_robustness`: 4 olumsuz kontrol senaryosunun toplu doğrulanması.
  - `test_14_markdown_and_full_audit_workflow`: Uçtan uca denetim ve Markdown rapor üretimi.

### 3.2. Gerçek ve Temsili Kanıt Ayrımı
- `kanit/gercek/test_sonuclari.txt`: Python unittest konsol çıktısı (14 test PASS).
- `kanit/gercek/komut_ve_cikis.txt`: Komut satırı icra kaydı ve sistem envanter analizi.
- `kanit/gercek/yedekleme_ve_321_denetim_raporu.txt`: Üretilen Markdown denetim raporu.
- `kanit/gercek/negatif_kontrol_sonuclari.txt`: 4 olumsuz kontrol senaryosunun beklenen hata fırlatma kayıtları.
- `kanit/temsili/yedekleme_stratejisi_ve_321_mimarisi.txt`: `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığıyla 3-2-1 mimarisini, RAID vs Snapshot matrisini ve Schrödinger paradoksunu gösteren ASCII mimari diyagramı.

---

## 4. Kazanılan Yetkinlikler ve Güvenlik Reçetesi
1. **3-2-1 Kuralı:** En az 3 kopya, 2 farklı ortam ve 1 tesis dışı kopya ile veri kaybı riskini sıfıra indirme.
2. **Fidye Yazılımı Savunması:** S3 Object Lock (Compliance Mode) ve çevrimdışı teyp (air-gap) ile fidye yazılımlarının yedekleri yok etmesini engelleme.
3. **Geri Yükleme Doğrulaması:** Schrödinger'in yedeği tuzağına düşmemek için çeyreklik düzenli otomatik geri yükleme tatbikatları icra etme.
4. **Mimari Yanılgıları Aşma:** RAID'in sadece iş sürekliliği olduğunu, aynı havuzdaki snapshot'ların donanım arızasında yok olduğunu kavrama ve bağımsız yedekleme depoları kurma.
5. **RPO / RTO Disiplini:** Veri kaybı toleransını ve kurtarma hızını iş gereksinimlerine göre netleştirme.
