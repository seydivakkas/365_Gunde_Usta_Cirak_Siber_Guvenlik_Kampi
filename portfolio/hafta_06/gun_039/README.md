<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 039 — Yedekleme Stratejisi ve 3-2-1 Kuralı Güvenlik Denetçisi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](https://github.com/seydivakkas)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Status: PASS (100/100)](https://img.shields.io/badge/status-PASS%20(100%2F100)-brightgreen.svg)]()
[![Stage: 02 - Week: 06](https://img.shields.io/badge/Aşama%2002-Hafta%2006-orange.svg)]()

## 📌 Genel Bakış ve Amaç
Bu proje, 365 Günlük Siber Güvenlik Müfredatı'nın **Aşama 02, Hafta 06, Gün 039** modülüdür.
Kurumsal veri koruma ve felaket kurtarma süreçlerinde **3-2-1 Yedekleme Kuralı**, **Fidye Yazılımlarına (Ransomware) Karşı Değiştirilemezlik (WORM/Immutability)**, **Schrödinger'in Yedeği Paradoksu (Geri Yükleme Testleri)** ve **Yedek vs Snapshot vs RAID** mimari ayrımlarını siber güvenlik perspektifiyle denetler.

### 🛡️ Temel Yetenekler
- **3-2-1 Kural Uyumluluğu:** 3 bağımsız kopya, en az 2 farklı depolama medyası ve en az 1 tesis dışı (offsite) kopya varlığını analiz eder.
- **Fidye Yazılımı Savunması (Immutability/WORM):** S3 Object Lock Compliance Mode, Linux Hardened Repository ve çevrimdışı teyp (air-gap) mekanizmalarını denetler.
- **Schrödinger'in Yedeği Tespiti:** Hiç geri yükleme testi yapılmamış veya 90 günden eski olan yedekleme politikalarını yakalar.
- **Mimari Yanılgı Analizi:** RAID dizilerini veya aynı havuzdaki snapshot'ları yedekleme zanneden ölümcül yapılandırma hatalarını belirler.
- **RPO / RTO Denetimi:** Taahhüt edilen veri kaybı toleransı (RPO) ile fiili yedekleme sıklığı arasındaki açıkları hesaplar.

---

## 📂 Dizin Yapısı
```text
portfolio/hafta_06/gun_039/
├── ders.md                                  # Usta-Çırak pedagojisiyle teorik ve pratik anlatım
├── soru_cevap.md                            # 3 ana soru için 4 zorunlu alt başlıklı detaylı çözümler
├── rapor.md                                 # 20/40/25/15 puanlama rubriği ve değerlendirme raporu
├── README.md                                # Proje genel bakışı, çalıştırma rehberi ve lisans
├── sonuc.json                               # Standart 14 alanlı sonuç ve başarı göstergesi
├── manifest.json                            # Dosya bütünlük karmaları (SHA256)
├── uygulama/
│   ├── __init__.py                          # Paket başlatıcı
│   └── backup_strategy_321_auditor.py       # Satır satır açıklamalı denetçi motoru
├── tests/
│   ├── __init__.py                          # Test paketi başlatıcı
│   └── test_backup_strategy_321_auditor.py  # 14 bağımsız birim test
├── ornek_veri/
│   ├── sample_backup_inventory.json         # Gerçekçi kurumsal yedekleme envanteri
│   └── corrupted_backup_inventory_test_cases.json # Negatif kontrol ve bozuk veri testleri
└── kanit/
    ├── gercek/                              # Gerçek icra kanıtları
    │   ├── test_sonuclari.txt
    │   ├── komut_ve_cikis.txt
    │   ├── yedekleme_ve_321_denetim_raporu.txt
    │   └── negatif_kontrol_sonuclari.txt
    └── temsili/                             # Temsili mimari illüstrasyonları
        └── yedekleme_stratejisi_ve_321_mimarisi.txt
```

---

## 🚀 Hızlı Başlangıç ve Çalıştırma

### 1. Birim Testleri Koşma
```powershell
python -m unittest portfolio/hafta_06/gun_039/tests/test_backup_strategy_321_auditor.py -v
```

### 2. Uygulamayı Envanter Verisiyle Çalıştırma
```powershell
python portfolio/hafta_06/gun_039/uygulama/backup_strategy_321_auditor.py --telemetry portfolio/hafta_06/gun_039/ornek_veri/sample_backup_inventory.json --output portfolio/hafta_06/gun_039/kanit/gercek/yedekleme_ve_321_denetim_raporu.txt
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
