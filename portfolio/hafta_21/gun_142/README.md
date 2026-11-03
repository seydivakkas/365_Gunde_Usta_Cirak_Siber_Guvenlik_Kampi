# Gün 142: CVSS Temel Metrikleri

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Tests: 15 Passed](https://img.shields.io/badge/tests-15%20passed-brightgreen?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/score-100%2F100-success?style=flat-square)
![Platform: Pure Python 3](https://img.shields.io/badge/platform-Python%203-blue?style=flat-square)

## Genel Bakış

Bu modül, **Hafta 21 (Zafiyet Yönetimi, Güvenlik Açıkları ve Otomasyon)** müfredatının 2. günüdür. Zafiyet puanlama ekosisteminin küresel referans standardı olan **FIRST CVSS v3.1 (Ortak Zafiyet Puanlama Sistemi)** temel metriklerinin matematiksel modellemesini ve vektör dizesi ayrıştırmasını gerçekleştiren kurumsal bir **CVSS Taban Metrik Motoru (`cvss_base_engine.py`)** ve **Hesaplayıcı CLI Aracı (`cvss_calculator_cli.py`)** geliştirilmiştir.

Modül; İstismar Edilebilirlik (Exploitability: AV, AC, PR, UI), Kapsam (Scope: S) ve Etki (Impact: C, I, A) metriklerini analiz eder; resmi FIRST Roundup algoritmasını işleterek taban skoru (0.0 - 10.0) ve nitel şiddet derecesini (CRITICAL, HIGH, MEDIUM, LOW, NONE) hatasız hesaplar.

---

## Dizin Yapısı

```
portfolio/hafta_21/gun_142/
├── README.md                              # Proje özeti, kullanım kılavuzu ve lisans
├── ders.md                                # Usta-Çırak pedagojisi ile derinlemesine teknik ders
├── soru_cevap.md                          # 4 alt başlıklı 3 kapsamlı derinleşme sorusu ve cevabı
├── rapor.md                               # 100/100 tam puanlı başarı karnesi ve metrikler
├── sonuc.json                             # Makine tarafından okunabilir sonuç özeti
├── manifest.json                          # Dizin dosya bütünlüğü ve SHA-256 sağlama toplamları
├── kanit_uretici.py                       # Testleri koşturan ve kanıtları üreten otomasyon aracı
├── uygulama/
│   ├── __init__.py                        # Paket başlatıcı
│   ├── cvss_base_engine.py                # FIRST CVSS v3.1 Taban Metrik Hesaplama Motoru
│   └── cvss_calculator_cli.py             # Komut satırı hesaplayıcı ve karşılaştırıcı CLI
├── tests/
│   ├── __init__.py                        # Test paketi başlatıcı
│   └── test_cvss_base_metrics.py          # 15 birim testi içeren test paketi (100% PASS)
├── ornek_veri/
│   ├── cvss_benchmark_vectors.json        # NVD doğrulamalı gerçek dünya zafiyet vektörleri
│   └── invalid_cvss_vectors.json          # 9 adet negatif ve hatalı vektör test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt             # 15 birim testinin çalışma logları
    │   ├── negatif_kontrol_sonuclari.txt  # 9 negatif senaryonun yakalanma logları
    │   ├── cvss_benchmark_analiz_raporu.json # Gerçek zafiyetlerin toplu analiz raporu
    │   ├── komut_ve_cikis.txt             # CLI yürütme çıktıları
    │   └── cvss_v31_metric_reference.json # Katsayı ve formül referans kartı
    └── temsili/
        └── cvss_mimarisi.txt              # ASCII sistem mimarisi diyagramı
```

---

## Temel Özellikler

1. **FIRST CVSS v3.1 Resmî Uyumu:** Formüller, ağırlık katsayıları ve `Roundup` fonksiyonu FIRST şartnamesi Bölüm 7.1 ile %100 uyumludur.
2. **Kapsam (Scope) Kırılması:** `S:U` ve `S:C` arasındaki matematiksel ve yapısal ayrımı tam olarak modeller (1.08 katsayısı ve üstel kuvvet).
3. **Vektör Karşılaştırma (Delta Analizi):** İki farklı zafiyet veya önlem sonrası konfigürasyon arasındaki skor ve metrik farkını (`score_diff`) hesaplar.
4. **Toplu Değerlendirme (Batch Evaluation):** Yüzlerce vektörü saniyeler içinde analiz edip ortalama skor ve şiddet dağılımı grafiği üretir.
5. **Niteliksel Şiddet Derecelendirmesi:** FIRST ölçeğine göre None (0.0), Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9) ve Critical (9.0-10.0) tespiti.

---

## Hızlı Başlangıç

### 1. Testleri ve Kanıt Üreticisini Çalıştırma
```powershell
python kanit_uretici.py
```

### 2. CLI ile Vektör Hesaplama ve Karşılaştırma
```powershell
# Vektör dizesini ayrıştır ve hesapla (Log4Shell örneği)
python uygulama/cvss_calculator_cli.py calculate "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

# İki vektörü karşılaştır (Yetki artışının skora etkisi)
python uygulama/cvss_calculator_cli.py compare "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"

# Toplu vektör dosyasını hesapla
python uygulama/cvss_calculator_cli.py batch ornek_veri/cvss_benchmark_vectors.json

# Zafiyetin izin verilen maksimum skoru aşıp aşmadığını doğrula
python uygulama/cvss_calculator_cli.py verify "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" --max-score 8.0
```

---

## Lisans

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
