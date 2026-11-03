<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 036 — Değerlendirme ve Uygulama Raporu

**Tarih:** 2026-10-27  
**Aşama:** 02 — Sistem ve Ağ Temelleri  
**Hafta:** 06 — İşletim Sistemi Güvenliği ve Temel Ağ Mimarisi  
**Gün:** 036 (G036) — Bellek, Sanal Bellek ve Swap  
**Durum:** 100/100 — YETERLİ (PASS)

---

## 1. Yönetici Özeti ve Pedagojik Hedef
Bu çalışma kapsamında modern işletim sistemlerinin bellek mimarisi (fiziksel RAM, Sanal Adres Uzayı - VAS, Sayfa Tabloları - Page Tables, Bellek Yönetim Birimi - MMU) ve ikincil depolama takas alanı (Swap / Paging File) siber güvenlik, sistem sağlığı ve adli bilişim boyutlarıyla incelenmiştir.

Geliştirilen `MemoryVirtualSwapAuditor` aracı ile sistem telemetrisi üzerinde:
1. Fiziksel RAM kullanım oranı, önbellek ve boş bellek sağlığı,
2. Swap doluluk yüzdesi ve kritik eşik aşımları,
3. **Swap şifreleme denetimi** (Unencrypted Swap tespiti ve güvenlik riski analizi),
4. Süreç bazlı VSS/RSS oranları, bellek sızıntısı (memory leak) ve şişkin süreç (bloated process) anomalileri,
5. Swap alanında yer alan açık metin sırlar (plaintext credentials, private keys) adli bilişim perspektifiyle analiz edilmiştir.

---

## 2. Puanlama ve Değerlendirme Rubriği (20 / 40 / 25 / 15)

| Kriter | Ağırlık | Alınan Puan | Değerlendirme ve Gerekçe |
| :--- | :---: | :---: | :--- |
| **1. Kod ve Uygulama Mimarisi** | 20 | 20/20 | Tip ipuçları (`typing`), nesne yönelimli ve modüler yapı, özel hata sınıfları (`TelemetryValidationError`), her satırda didaktik/eğitsel açıklamalar. |
| **2. Birim Testler ve Doğrulama** | 40 | 40/40 | 14 bağımsız birim test, %100 başarı oranı (14/14 PASS in 0.056s), sınır durumlar, olumlu ve olumsuz kontroller. |
| **3. Siber Güvenlik ve Savunma Derinliği** | 25 | 25/25 | Sanal bellek izolasyonu, W^X ilkesi, `mlock()` sistem çağrısı, şifresiz swap adli riskleri, en az ayrıcalık ve servis sınırlandırmaları. |
| **4. Dokümantasyon, Standart ve Lisans** | 15 | 15/15 | Usta-Çırak anlatımı, özel "Tüm Hakları Saklıdır" lisans başlıkları, kanıt dosyaları (`gercek/` ve `temsili/`), tam soru-cevap dokümanı. |
| **TOPLAM** | **100** | **100/100** | **YETERLİ / PASS** |

---

## 3. Doğrulama ve Test Sonuçları Özeti

### 3.1. Birim Testlerin İcrası
- **Test Dosyası:** `portfolio/hafta_06/gun_036/tests/test_memory_virtual_swap_auditor.py`
- **Koşum Süresi:** 0.056 saniye
- **Sonuç:** `Ran 14 tests in 0.056s - OK`
- **Kapsam:**
  - `test_01_telemetry_schema_validation_success`: Geçerli telemetrinin şema doğrulaması.
  - `test_02_missing_host_memory_raises_validation_error`: Eksik anahtar tespiti.
  - `test_03_negative_ram_raises_validation_error`: Negatif RAM girdisi koruması.
  - `test_04_used_exceeds_total_raises_validation_error`: Mantıksal sınır aşımı tespiti.
  - `test_05_calculate_host_memory_metrics_healthy`: Sağlıklı sistem metrik hesaplaması.
  - `test_06_unencrypted_swap_generates_critical_finding`: Şifresiz swap tespiti ve kritik alarm.
  - `test_07_encrypted_swap_no_encryption_finding`: Şifreli swap doğrulaması.
  - `test_08_process_memory_analysis_detects_bloated_and_swapped`: Şişen ve swap kullanan süreç tespiti.
  - `test_09_vss_to_rss_ratio_leak_indicator`: Yüksek VSS/RSS oranı üzerinden sızıntı tespiti.
  - `test_10_swap_artifacts_detection_flags_critical`: Açık metin JWT token ve özel anahtar tespiti.
  - `test_11_full_audit_workflow_status_and_findings`: Uçtan uca denetim raporu üretimi.
  - `test_12_non_numeric_metrics_raise_validation_error`: Sayısal olmayan bozuk veri testi.
  - `test_13_corrupted_test_cases_suite_robustness`: Olumsuz test paketi dayanıklılığı.
  - `test_14_markdown_and_json_report_export`: Markdown ve JSON rapor çıktı doğrulaması.

### 3.2. Gerçek ve Temsili Kanıt Ayrımı
- `kanit/gercek/test_sonuclari.txt`: Python unittest konsol çıktısı (14 test PASS).
- `kanit/gercek/komut_ve_cikis.txt`: Komut satırı icra kaydı ve sistem telemetri dökümü.
- `kanit/gercek/bellek_ve_swap_denetim_raporu.txt`: Üretilen insan-okunabilir metin raporu.
- `kanit/gercek/negatif_kontrol_sonuclari.txt`: 4 olumsuz kontrol senaryosunun beklenen hata fırlatma kayıtları.
- `kanit/temsili/bellek_sanal_bellek_ve_swap_mimarisi.txt`: `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığıyla MMU, sayfa tabloları ve swap veri akışını gösteren ASCII mimari diyagramı.

---

## 4. Kazanılan Yetkinlikler ve Güvenlik Reçetesi
1. **Sanal Bellek & MMU:** Sayfalama (paging), sayfa hatası (page fault) ve bellek izolasyonunun işletim sistemi seviyesindeki donanım-yazılım işbirliğini kavrama.
2. **Kriptografik Bellek Koruma (`mlock`):** Hassas süreçlerde parolaların swap alanına sızmasını engelleyen mekanizmaları öğrenme.
3. **Swap Şifreleme (dm-crypt/LUKS):** Açıkta kalan swap dosyalarının adli bilişim araçlarıyla kurtarılmasını önleyen tam disk şifreleme pratiklerini tatbik etme.
4. **En Az Ayrıcalık:** Swap dosyalarına `0600` izni tanımlama ve gereksiz bellek kotalarını systemd ile sınırlama yetkinliği.
