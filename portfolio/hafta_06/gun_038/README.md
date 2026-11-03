<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 038 — Zaman Senkronizasyonu ve NTP Güvenlik Denetçisi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](https://github.com/seydivakkas)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Status: PASS (100/100)](https://img.shields.io/badge/status-PASS%20(100%2F100)-brightgreen.svg)]()
[![Stage: 02 - Week: 06](https://img.shields.io/badge/Aşama%2002-Hafta%2006-orange.svg)]()

## 📌 Genel Bakış ve Amaç
Bu proje, 365 Günlük Siber Güvenlik Müfredatı'nın **Aşama 02, Hafta 06, Gün 038** modülüdür.
Kurumsal ağlarda **Zaman Senkronizasyonu**, **Network Time Protocol (NTPv4)**, **Chrony** ve **Windows Zaman Servisi (w32time)** yapılandırmalarını; **Saat Kayması (Clock Skew)**, **Kerberos 5 Dakika Kuralı**, **SIEM Adli Bilişim Zaman Çizelgesi**, **Stratum Hiyerarşisi** ve **NTP Amplification DDoS (monlist)** tehditleri ekseninde denetler.

### 🛡️ Temel Yetenekler
- **Saat Kayması (Offset) Analizi:** Sistem saatindeki sapmaları milisaniye hassasiyetinde ölçer; Kerberos sınırını (300 saniye) ve SIEM sapmasını (1 saniye) tespit eder.
- **Stratum & Eşzamanlama Durumu:** Senkronizasyonunu kaybetmiş serbest dönen saatleri (Stratum 16) yakalar.
- **Bizans Hata Toleransı & Üst Sunucu Yedekliliği:** Marzullo algoritmasının gerektirdiği asgari 3-4 bağımsız zaman kaynağı varlığını denetler; tek hata noktasını (SPOF) engeller.
- **NTP Protokol Güvenliği (monlist & NTS):** Sunucuların DDoS yükseltme aracı olarak kullanılmasını sağlayan `monlist` zafiyetini ve şifresiz UDP risklerini raporlar.
- **Çapraz Sistem Zaman Karşılaştırması:** İki farklı ağ segmentindeki sistemlerin zaman damgalarını karşılaştırarak dağıtık korelasyon uçurumlarını açığa çıkarır.

---

## 📂 Dizin Yapısı
```text
portfolio/hafta_06/gun_038/
├── ders.md                                  # Usta-Çırak pedagojisiyle teorik ve pratik anlatım
├── soru_cevap.md                            # 3 ana soru için 4 zorunlu alt başlıklı detaylı çözümler
├── rapor.md                                 # 20/40/25/15 puanlama rubriği ve değerlendirme raporu
├── README.md                                # Proje genel bakışı, çalıştırma rehberi ve lisans
├── sonuc.json                               # Standart 14 alanlı sonuç ve başarı göstergesi
├── manifest.json                            # Dosya bütünlük karmaları (SHA256)
├── uygulama/
│   ├── __init__.py                          # Paket başlatıcı
│   └── ntp_time_sync_auditor.py             # Satır satır açıklamalı denetçi motoru
├── tests/
│   ├── __init__.py                          # Test paketi başlatıcı
│   └── test_ntp_time_sync_auditor.py        # 14 bağımsız birim test
├── ornek_veri/
│   ├── sample_ntp_telemetry.json            # Gerçekçi sistem NTP telemetrisi
│   └── corrupted_ntp_telemetry_test_cases.json # Negatif kontrol ve bozuk veri testleri
└── kanit/
    ├── gercek/                              # Gerçek icra kanıtları
    │   ├── test_sonuclari.txt
    │   ├── komut_ve_cikis.txt
    │   ├── zaman_ve_ntp_denetim_raporu.txt
    │   └── negatif_kontrol_sonuclari.txt
    └── temsili/                             # Temsili mimari illüstrasyonları
        └── zaman_senkronizasyonu_ve_ntp_mimarisi.txt
```

---

## 🚀 Hızlı Başlangıç ve Çalıştırma

### 1. Birim Testleri Koşma
```powershell
python -m unittest portfolio/hafta_06/gun_038/tests/test_ntp_time_sync_auditor.py -v
```

### 2. Uygulamayı Telemetri Verisiyle Çalıştırma
```powershell
python portfolio/hafta_06/gun_038/uygulama/ntp_time_sync_auditor.py --telemetry portfolio/hafta_06/gun_038/ornek_veri/sample_ntp_telemetry.json --output portfolio/hafta_06/gun_038/kanit/gercek/zaman_ve_ntp_denetim_raporu.txt
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
