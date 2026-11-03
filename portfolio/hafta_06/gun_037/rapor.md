<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 037 — Değerlendirme ve Uygulama Raporu

**Tarih:** 2026-10-27  
**Aşama:** 02 — Sistem ve Ağ Temelleri  
**Hafta:** 06 — İşletim Sistemi Güvenliği ve Temel Ağ Mimarisi  
**Gün:** 037 (G037) — Disk Bölümleri ve Dosya Sistemleri  
**Durum:** 100/100 — YETERLİ (PASS)

---

## 1. Yönetici Özeti ve Pedagojik Hedef
Bu çalışma kapsamında modern işletim sistemlerinin depolama mimarisi (Blok Aygıtlar, MBR/GPT Bölüm Tabloları, Birimler, Dosya Sistemleri ve VFS Bağlama Mekanizmaları) siber güvenlik, sistem sertleştirme ve veri bütünlüğü perspektifleriyle incelenmiştir.

Geliştirilen `DiskPartitionFsAuditor` aracı ile sistem telemetrisi üzerinde:
1. **Bölüm Tablosu Güvenliği:** Eski MBR mimarisinin getirdiği sektör 0 bootkit riskleri ve yedek tablo eksikliği analiz edilmiş, GPT mimarisinin CRC32 bütünlük güvenceleri modellenmiştir.
2. **Dosya Sistemi İzin ve Yetki Desteği:** Sunucu ve veri disklerinde FAT32/exFAT kullanımının POSIX DAC ve Windows ACL izin yoksunluğu sebebiyle doğurduğu kritik güvenlik açıkları taranmıştır.
3. **Bağlama Bayrakları Sertleştirmesi (Mount Hardening):** `/tmp`, `/var/tmp` ve `/dev/shm` geçici dizinlerinde zararlı ikili çalıştırmayı ve yetki yükseltmeyi önleyen `noexec`, `nosuid` ve `nodev` bayrakları denetlenmiştir.
4. **Hareketsiz Veri Şifrelemesi (Data-at-Rest Encryption):** LUKS2 ve BitLocker tam disk şifreleme durumları incelenerek şifresiz birimler raporlanmıştır.
5. **Kapasite ve DoS Koruması:** %85 üzeri uyarı ve %95 üzeri kritik tükenme eşikleriyle sistem çökmesi ve günlük kaybı riskleri hesaplanmıştır.

---

## 2. Puanlama ve Değerlendirme Rubriği (20 / 40 / 25 / 15)

| Kriter | Ağırlık | Alınan Puan | Değerlendirme ve Gerekçe |
| :--- | :---: | :---: | :--- |
| **1. Kod ve Uygulama Mimarisi** | 20 | 20/20 | Tip ipuçları (`typing`), nesne yönelimli modüler tasarım, `DiskTelemetryValidationError` özel hata sınıfı, her satırda didaktik ve eğitsel açıklamalar. |
| **2. Birim Testler ve Doğrulama** | 40 | 40/40 | 14 bağımsız birim test, %100 başarı oranı (14/14 PASS in 0.003s), negatif kontroller, sınır testleri ve bozuk veri senaryoları. |
| **3. Siber Güvenlik ve Savunma Derinliği** | 25 | 25/25 | MBR bootkit tehditleri, GPT CRC32 koruması, `noexec/nosuid` fstab sertleştirmesi, FAT32 izin zaafı ve LUKS tam disk şifreleme ilkeleri. |
| **4. Dokümantasyon, Standart ve Lisans** | 15 | 15/15 | Usta-Çırak pedagojisi, özel "Tüm Hakları Saklıdır" lisans başlıkları, kanıt dosyaları (`gercek/` ve `temsili/`), tam soru-cevap dokümanı. |
| **TOPLAM** | **100** | **100/100** | **YETERLİ / PASS** |

---

## 3. Doğrulama ve Test Sonuçları Özeti

### 3.1. Birim Testlerin İcrası
- **Test Dosyası:** `portfolio/hafta_06/gun_037/tests/test_disk_partition_fs_auditor.py`
- **Koşum Süresi:** 0.003 saniye
- **Sonuç:** `Ran 14 tests in 0.003s - OK`
- **Kapsam:**
  - `test_01_telemetry_schema_validation_success`: Standart telemetri şema doğrulaması.
  - `test_02_missing_disks_key_raises_validation_error`: Eksik disks anahtarı tespiti.
  - `test_03_negative_disk_size_raises_validation_error`: Negatif disk boyutu engeli.
  - `test_04_used_space_exceeds_total_raises_validation_error`: Mantıksal kapasite aşımı tespiti.
  - `test_05_non_numeric_partition_capacity_raises_error`: Sayısal olmayan kapasite girdisi denetimi.
  - `test_06_non_string_filesystem_type_raises_error`: String olmayan dosya sistemi türü tespiti.
  - `test_07_mbr_partition_table_detected_as_medium_severity`: MBR tablosunun MEDIUM bulgu üretmesi.
  - `test_08_gpt_partition_table_passes_clean`: Modern GPT tablosunun temiz geçmesi.
  - `test_09_fat32_data_partition_detected_as_high_severity`: FAT32 veri diskinin HIGH olarak raporlanması.
  - `test_10_unencrypted_partition_detected_as_critical`: Şifresiz kök birimin CRITICAL olarak yakalanması.
  - `test_11_mount_options_missing_noexec_on_tmp_detected`: /tmp üzerinde eksik `noexec` tespiti.
  - `test_12_capacity_exhaustion_warning_and_critical_thresholds`: %85 warning ve %95 critical eşik doğrulaması.
  - `test_13_corrupted_test_cases_suite_robustness`: 4 olumsuz kontrol senaryosunun toplu doğrulanması.
  - `test_14_markdown_and_full_audit_workflow`: Uçtan uca denetim ve Markdown rapor üretimi.

### 3.2. Gerçek ve Temsili Kanıt Ayrımı
- `kanit/gercek/test_sonuclari.txt`: Python unittest konsol çıktısı (14 test PASS).
- `kanit/gercek/komut_ve_cikis.txt`: Komut satırı icra kaydı ve sistem telemetri dökümü.
- `kanit/gercek/disk_ve_dosya_sistemi_denetim_raporu.txt`: Üretilen Markdown denetim raporu.
- `kanit/gercek/negatif_kontrol_sonuclari.txt`: 4 olumsuz kontrol senaryosunun beklenen hata fırlatma kayıtları.
- `kanit/temsili/disk_bolumleri_ve_dosya_sistemi_mimarisi.txt`: `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığıyla MBR/GPT sektör haritasını ve VFS bağlama katmanını gösteren ASCII mimari diyagramı.

---

## 4. Kazanılan Yetkinlikler ve Güvenlik Reçetesi
1. **Katman Ayrımı:** Donanım (Block Device), Bölüm (Partition), Birim (Volume) ve Dosya Sistemi (Filesystem) arasındaki farkları kavrama; yanlış aygıta müdahalenin yıkıcı sonuçlarını engelleme.
2. **MBR vs GPT:** Modern UEFI sistemlerde GPT'nin CRC32 doğrulaması ve ikincil yedek başlık avantajlarını adli ve güvenlik bağlamında uygulama.
3. **Mount Sertleştirmesi:** `/tmp`, `/var/tmp` ve `/dev/shm` dizinlerine `noexec,nosuid,nodev` bayrakları tanımlayarak zararlı ikili dosyaların çalıştırılmasını önleme.
4. **Dosya Sistemi Güvenliği:** FAT32/exFAT gibi erişim kontrolü olmayan dosya sistemlerinin sunucularda kullanımını engelleme ve ext4/NTFS ACL mimarisini koruma.
5. **Veri Güvenliği (FDE):** LUKS2 ve BitLocker ile fiziksel hırsızlık ve harici USB müdahalelerine karşı tam disk şifrelemesi sağlama.
