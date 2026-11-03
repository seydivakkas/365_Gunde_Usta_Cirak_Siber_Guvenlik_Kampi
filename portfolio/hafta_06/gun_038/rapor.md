<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 038 — Değerlendirme ve Uygulama Raporu

**Tarih:** 2026-10-27  
**Aşama:** 02 — Sistem ve Ağ Temelleri  
**Hafta:** 06 — İşletim Sistemi Güvenliği ve Temel Ağ Mimarisi  
**Gün:** 038 (G038) — Zaman Senkronizasyonu ve NTP  
**Durum:** 100/100 — YETERLİ (PASS)

---

## 1. Yönetici Özeti ve Pedagojik Hedef
Bu çalışma kapsamında kurumsal bilişim ve ağ altyapılarında zaman senkronizasyonu (Time Synchronization), Network Time Protocol (NTPv4), Chrony ve Windows Zaman Servisi (w32time) mimarileri siber güvenlik, kimlik doğrulama, adli bilişim (forensics) ve hizmet reddi (DDoS) saldırıları boyutlarıyla incelenmiştir.

Geliştirilen `NtpTimeSyncAuditor` aracı ile sistem telemetrisi üzerinde:
1. **Saat Kayması ve Kerberos Çöküşü:** 5 dakikalık (300 saniye = 300.000 ms) saat sapması eşiği incelenmiş; `KRB_AP_ERR_SKEW` kimlik doğrulama felaketi modellenmiştir.
2. **Stratum Hiyerarşisi ve Senkronizasyon:** Stratum 16 (serbest dönen saat / bağlantı kaybı) durumu CRITICAL güvenlik riski olarak yakalanmıştır.
3. **Üst Sunucu Yedekliliği (Byzantine Fault Tolerance):** Marzullo algoritmasının hatalı/sahte zaman sunucularını (false-tickers) eleyebilmesi için asgari 3-4 bağımsız zaman kaynağı gereksinimi doğrulanmıştır.
4. **NTP Amplification DDoS Koruması:** `monlist` (Mode 6) yönetim sorgularının açık bırakılmasının doğurduğu ~200 katlık UDP DDoS büyütme tehdidi tespit edilmiştir.
5. **Dağıtık Zaman Tutarlılığı ve SIEM:** İki farklı ağ segmentindeki sistemlerin zaman damgaları karşılaştırılarak adli bilişim olay çizelgesi uyuşmazlıkları analiz edilmiştir.

---

## 2. Puanlama ve Değerlendirme Rubriği (20 / 40 / 25 / 15)

| Kriter | Ağırlık | Alınan Puan | Değerlendirme ve Gerekçe |
| :--- | :---: | :---: | :--- |
| **1. Kod ve Uygulama Mimarisi** | 20 | 20/20 | Tip güvenliği (`typing`), `NtpTelemetryValidationError` özel istisna sınıfı, nesne yönelimli modüler yapı, her satırda didaktik açıklamalar. |
| **2. Birim Testler ve Doğrulama** | 40 | 40/40 | 14 bağımsız birim test, %100 başarı oranı (14/14 PASS in 0.003s), negatif kontroller, sınır testleri ve bozuk veri senaryoları. |
| **3. Siber Güvenlik ve Savunma Derinliği** | 25 | 25/25 | Kerberos 5 dk kuralı, TLS sertifika süre denetimi, Marzullo algoritması, monlist DDoS amplifikasyonu, NTS şifreleme ve SIEM korelasyonu. |
| **4. Dokümantasyon, Standart ve Lisans** | 15 | 15/15 | Usta-Çırak pedagojisi, özel "Tüm Hakları Saklıdır" lisans başlıkları, kanıt dosyaları (`gercek/` ve `temsili/`), tam soru-cevap dokümanı. |
| **TOPLAM** | **100** | **100/100** | **YETERLİ / PASS** |

---

## 3. Doğrulama ve Test Sonuçları Özeti

### 3.1. Birim Testlerin İcrası
- **Test Dosyası:** `portfolio/hafta_06/gun_038/tests/test_ntp_time_sync_auditor.py`
- **Koşum Süresi:** 0.003 saniye
- **Sonuç:** `Ran 14 tests in 0.003s - OK`
- **Kapsam:**
  - `test_01_telemetry_schema_validation_success`: Standart telemetri şema doğrulaması.
  - `test_02_missing_systems_key_raises_validation_error`: Eksik systems anahtarı tespiti.
  - `test_03_invalid_stratum_boundary_raises_error`: Negatif veya >16 Stratum değeri kontrolü.
  - `test_04_non_numeric_offset_raises_validation_error`: Sayısal olmayan saat kayması tespiti.
  - `test_05_negative_jitter_raises_validation_error`: Negatif jitter engeli.
  - `test_06_non_string_hostname_raises_error`: String olmayan hostname tespiti.
  - `test_07_kerberos_skew_threshold_exceeded_detected_as_critical`: 300 saniye üzeri Kerberos çöküşünün CRITICAL tespiti.
  - `test_08_siem_timeline_skew_detected_as_high`: 1 saniye üzeri SIEM zaman sapması tespiti.
  - `test_09_healthy_synchronized_clock_passes_skew_clean`: Sağlıklı 2.1 ms kaymanın temiz geçmesi.
  - `test_10_stratum_16_unsynchronized_detected_as_critical`: Stratum 16 senkronizasyon kaybı tespiti.
  - `test_11_insufficient_upstream_servers_detected_as_high`: 3'ten az üst sunuculu yapıda SPOF tespiti.
  - `test_12_monlist_ddos_risk_detected_as_high`: monlist DDoS açıklığının HIGH tespiti.
  - `test_13_corrupted_test_cases_suite_robustness`: 4 olumsuz kontrol senaryosunun toplu doğrulanması.
  - `test_14_markdown_and_full_audit_workflow`: Uçtan uca denetim ve Markdown rapor üretimi.

### 3.2. Gerçek ve Temsili Kanıt Ayrımı
- `kanit/gercek/test_sonuclari.txt`: Python unittest konsol çıktısı (14 test PASS).
- `kanit/gercek/komut_ve_cikis.txt`: Komut satırı icra kaydı ve sistem telemetri dökümü.
- `kanit/gercek/zaman_ve_ntp_denetim_raporu.txt`: Üretilen Markdown denetim raporu.
- `kanit/gercek/negatif_kontrol_sonuclari.txt`: 4 olumsuz kontrol senaryosunun beklenen hata fırlatma kayıtları.
- `kanit/temsili/zaman_senkronizasyonu_ve_ntp_mimarisi.txt`: `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığıyla Stratum katmanlarını, T1-T4 matematiksel gecikme modelini ve monlist DDoS akışını gösteren ASCII mimari diyagramı.

---

## 4. Kazanılan Yetkinlikler ve Güvenlik Reçetesi
1. **Kerberos & Zaman Güvenliği:** 300 saniyelik saat sapması sınırının kimlik doğrulama altyapısı için hayati önemini kavrama; `KRB_AP_ERR_SKEW` hatalarını teşhis etme.
2. **SIEM & Adli Zaman Çizelgesi:** Olay müdahalesinde neden-sonuç sırasının korunması için tüm log kaynaklarında UTC standardizasyonunu sağlama.
3. **Stratum Mimarisi:** Stratum 0'dan 16'ya uzanan hiyerarşiyi yönetme; serbest dönen donanım saatlerinin oluşturduğu riskleri engelleme.
4. **Bizans Hata Toleransı:** En az 3-4 bağımsız NTP sunucusu yapılandırarak sahte/tahrif edilmiş zaman kaynaklarına karşı sistemi koruma.
5. **DDoS Savunması:** NTP sunucularında `disable monitor` ve `noquery` direktifleri uygulayarak sistemin `monlist` amplifikasyon silahı olarak kullanılmasını önleme.
