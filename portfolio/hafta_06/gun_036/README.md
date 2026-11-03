<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 036 — Bellek, Sanal Bellek ve Swap Denetçisi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](https://github.com/seydivakkas)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Status: PASS (100/100)](https://img.shields.io/badge/status-PASS%20(100%2F100)-brightgreen.svg)]()
[![Stage: 02 - Week: 06](https://img.shields.io/badge/Aşama%2002-Hafta%2006-orange.svg)]()

## 📌 Genel Bakış ve Amaç
Bu proje, 365 Günlük Siber Güvenlik Müfredatı'nın **Aşama 02, Hafta 06, Gün 036** modülüdür. 
Modern işletim sistemlerinde **Fiziksel Bellek (RAM)**, **Sanal Adres Uzayı (VAS)**, **Sayfa Tabloları (Page Tables)**, **Bellek Yönetim Birimi (MMU)** ve **Swap (Takas Alanı)** mekanizmalarını siber güvenlik, sistem kararlılığı ve adli bilişim (forensics) boyutlarıyla inceler.

### 🛡️ Temel Yetenekler
- **RAM ve Swap Telemetri Analizi:** Toplam, kullanılan, boş ve önbellek bellek oranlarını hesaplar; kritik eşik aşımlarını (`%80` ve `%90`) tespit eder.
- **Swap Şifreleme Denetimi:** Takas alanının şifrelenip şifrelenmediğini denetler; şifresiz takas alanlarını **CRITICAL** bulgu olarak raporlar.
- **Süreç Bazlı Ayak İzi (VSS/RSS):** Bellek sızıntısı (memory leak) şüphesi uyandıran ve diske takas edilen (swapped-out) süreçleri belirler.
- **Swap Kalıntı Analizi (Forensic Artifacts):** Takas alanında unutulmuş açık metin sırları (API anahtarları, private key parçacıkları, token'lar) tespit eder.
- **Detaylı Raporlama:** İnsan okunabilir metin, Markdown ve makine tarafından işlenebilir JSON formatlarında çıktı üretir.

---

## 📂 Dizin Yapısı
```text
portfolio/hafta_06/gun_036/
├── ders.md                                  # Usta-Çırak pedagojisiyle teorik ve pratik anlatım
├── soru_cevap.md                            # 3 ana soru için 4 zorunlu alt başlıklı detaylı çözümler
├── rapor.md                                 # 20/40/25/15 puanlama rubriği ve değerlendirme raporu
├── README.md                                # Proje genel bakışı, çalıştırma rehberi ve lisans
├── sonuc.json                               # Standart 14 alanlı sonuç ve başarı göstergesi
├── manifest.json                            # Dosya bütünlük karmaları (SHA256)
├── uygulama/
│   ├── __init__.py                          # Paket başlatıcı
│   └── memory_virtual_swap_auditor.py       # Satır satır açıklamalı denetçi motoru
├── tests/
│   ├── __init__.py                          # Test paketi başlatıcı
│   └── test_memory_virtual_swap_auditor.py  # 14 bağımsız birim test
├── ornek_veri/
│   ├── sample_memory_telemetry.json         # Gerçekçi sistem bellek telemetrisi
│   └── corrupted_memory_telemetry_test_cases.json # Negatif kontrol ve bozuk veri testleri
└── kanit/
    ├── gercek/                              # Gerçek icra kanıtları
    │   ├── test_sonuclari.txt
    │   ├── komut_ve_cikis.txt
    │   ├── bellek_ve_swap_denetim_raporu.txt
    │   └── negatif_kontrol_sonuclari.txt
    └── temsili/                             # Temsili mimari illüstrasyonları
        └── bellek_sanal_bellek_ve_swap_mimarisi.txt
```

---

## 🚀 Hızlı Başlangıç ve Çalıştırma

### 1. Birim Testleri Koşma
```powershell
python -m unittest portfolio/hafta_06/gun_036/tests/test_memory_virtual_swap_auditor.py -v
```

### 2. Uygulamayı Telemetri Verisiyle Çalıştırma
```powershell
python portfolio/hafta_06/gun_036/uygulama/memory_virtual_swap_auditor.py --telemetry portfolio/hafta_06/gun_036/ornek_veri/sample_memory_telemetry.json
```

---

## 📜 Özel Lisans Bildirimi

```text
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
