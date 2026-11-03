# Gün 095: Güvenlik Betikleri Performans Ölçüm ve Profilleme Motoru

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![Durum](https://img.shields.io/badge/Durum-Tamamlandı%20(100%2F100)-brightgreen?style=flat-square)

Siber güvenlik işlevlerinde, SOC otomasyonlarında, kriptografik operasyonlarda ve SIEM boru hatlarında yüksek hassasiyetli zaman, CPU ve bellek profillemesi sağlayan kurumsal benchmarking ve SLA koruma motoru.

---

## 🛡️ Yetenekler ve Güvenlik Mimarisi

- **Çift Kanallı Yüksek Hassasiyetli Zaman Ölçümü:**
  - **Duvar Saati (`time.perf_counter`):** Sistem saati sapmalarından (NTP) etkilenmeyen monotonik TSC tabanlı gerçek geçen süre ölçümü.
  - **İşlemci Saati (`time.process_time`):** I/O ve bekleme sürelerinden bağımsız saf CPU çekirdek yükü analizi.
- **`tracemalloc` Bellek Profillemesi:** Fonksiyonun çalışması esnasında ulaştığı tepe bellek miktarını (`peak_memory_bytes`) bayt düzeyinde ölçer (CWE-401 Bellek Sızıntısı Koruması).
- **Isınma Döngüsü (Warmup):** İlk çalıştırma jitter ve önbellek etkilerini (L1/L2 cache miss) ölçümden izole eder.
- **Kuyruk Gecikmesi ve İstatistiksel Analiz:** Ortalama, medyan, standart sapma, min/max, p95 ve p99 persentil değerleri ile throughput (Ops/Sec) hesaplaması.
- **Güvenlik Eşiği ve SLA Kalkanı:**
  - `@profile_security_func(threshold_ms, max_memory_bytes)`: Belirlenen SLA bütçesini aşan fonksiyonlarda anında `PerformanceBudgetExceededError` (CWE-400 DoS Alarmı) veya `MemoryLimitExceededError` fırlatır.
- **Kayıtlı Güvenlik Kıyaslama Hedefleri:**
  - SHA-256 vs SHA-512 vs BLAKE2b karşılaştırması.
  - String concatenation (`+`) vs `list.join()` bellek verimliliği.
  - Önceden derlenmiş regex (`re.compile`) vs dinamik regex arama.
- **POSIX Uyumlu CLI (`benchmarker_cli.py`):** 0 (Başarılı), 1 (Bütçe İhlali / Uyarı), 2 (Hata) standart kodları ve JSON çıktısı.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_14/gun_095/
├── uygulama/
│   ├── __init__.py
│   ├── security_benchmarker.py           # Çekirdek performans ölçüm ve profilleme motoru
│   └── benchmarker_cli.py                # Terminal CLI yürütücüsü
├── tests/
│   ├── __init__.py
│   └── test_security_benchmarker.py      # 14/14 birim test seti
├── ornek_veri/
│   ├── benchmark_scenarios.json          # Kriptografik ve güvenlik iş yükü senaryoları
│   └── invalid_benchmark_inputs.json     # 9 adet negatif kontrol senaryosu
├── kanit/
│   ├── gercek/                           # Doğrulanmış test ve denetim çıktıları
│   │   ├── komut_ve_cikis.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── performans_olcum_raporu.txt
│   │   └── test_sonuclari.txt
│   └── temsili/                          # Kapsamlı mimari ASCII görselleştirmesi
│       └── performans_olcum_mimarisi.txt
├── ders.md                               # Usta-Çırak pedagojik ders anlatımı
├── soru_cevap.md                         # 4 alt başlıklı 3 mülakat soru-cevap seti
├── rapor.md                              # 100/100 rubrik değerlendirme raporu
├── sonuc.json                            # Makine tarafından okunabilir sonuç metrikleri
├── kanit_uretici.py                      # Otomatik test ve kanıt üretim orkestratörü
├── manifest.json                         # Dosya bütünlük manifestosu
└── README.md
```

---

## 🚀 Çalıştırma ve Test

Birim testleri ve kanıt üretimini başlatmak için:

```bash
# Kanıt üreticiyi çalıştır
python kanit_uretici.py

# Birim testleri doğrudan koştur
python -m unittest tests/test_security_benchmarker.py -v

# CLI ile SHA-256 algoritmasını profille
python uygulama/benchmarker_cli.py --target sha256 --iterations 20 --warmup 3

# CLI ile tüm hedefleri karşılaştırıp JSON raporu üret
python uygulama/benchmarker_cli.py --target all --iterations 15 --json
```

---

## 📜 Lisans

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
amaçlı olarak paylaşılmıştır.

YASAKLAR:
  1. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
  2. Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
  3. Alt lisanslanamaz, satılamaz veya devredilemez.
  4. Tersine mühendislik yapılamaz.

İZİN VERİLEN KULLANIM:
  - GitHub üzerinde görüntüleme ve okuma.
  - Kişisel öğrenim amacıyla kodu inceleme (kopyalamadan).

YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
İzin talepleri için: GitHub @seydivakkas
```
