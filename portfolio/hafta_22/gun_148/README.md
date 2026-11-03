# Gün 148: EDR, Antivirüs (AV) ve Uç Nokta Telemetri Güvenlik Motoru

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Tests: 15/15 PASS](https://img.shields.io/badge/tests-15%2F15%20PASS-brightgreen.svg)](tests/)
[![Negative Controls: 9/9 PASS](https://img.shields.io/badge/negative%20controls-9%2F9%20PASS-brightgreen.svg)](kanit/gercek/negatif_kontrol_sonuclari.txt)

---

## 📌 Genel Bakış

Bu modül, kurumsal uç nokta güvenliğinde **Geleneksel Antivirüs (AV)** statik dosya ve hash taraması ile modern **Uç Nokta Tespit ve Müdahale (EDR)** çekirdek telemetri analizini, süreç soy ağacı anomalilerini (Parent-Child ilişkisi), dosyasız zararlıları (Fileless Malware / LOLBAS), bellek enjeksiyonlarını (Process Injection), LSASS bellek dökümü girişimlerini (Credential Dumping) ve **MITRE ATT&CK** korelasyonunu işleten endüstriyel sınıf bir güvenlik motorudur.

Tüm kodlar harici kütüphane bağımlılığı olmaksızın saf Python 3 standart kütüphanesi ile geliştirilmiş, her yürütülebilir satır detaylı Türkçe öğretici yorumlarla zenginleştirilmiştir.

---

## 🏗️ Dizin Yapısı

```text
gun_148/
├── README.md                           # Proje genel tanıtımı ve kullanım kılavuzu
├── ders.md                             # Usta-Çırak derinlemesine teknik EDR ve telemetri dersi
├── soru_cevap.md                       # 3 derin teknik soru ve 4 zorunlu alt başlık
├── rapor.md                            # 100/100 PASS değerlendirme puan kartı
├── sonuc.json                          # Yapılandırılmış sonuç özeti
├── manifest.json                       # SHA-256 bütünlük ve dosya manifestosu
├── kanit_uretici.py                    # Gerçek kanıtları üreten otomasyon betiği
├── uygulama/
│   ├── __init__.py                     # Paket başlangıç dosyası
│   ├── edr_telemetry_engine.py         # Çekirdek telemetri, EDR kuralları ve AV motoru
│   └── edr_telemetry_cli.py            # Komut satırı yönetim arayüzü (CLI)
├── tests/
│   ├── __init__.py                     # Test paketi başlangıç dosyası
│   └── test_edr_telemetry.py           # 15 kapsamlı birim testi (%100 PASS)
├── ornek_veri/
│   ├── clean_system_telemetry.json     # Olağan / temiz kurumsal sistem telemetrisi
│   └── invalid_telemetry_scenarios.json# 9 negatif kontrol ve saldırı senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt          # Birim testi çıktı kanıtı (15/15 PASS)
    │   ├── negatif_kontrol_sonuclari.txt# Negatif test izolasyon kanıtı (9/9 PASS)
    │   ├── edr_telemetry_report.json   # JSON formatlı denetim raporu çıktısı
    │   ├── edr_response_remediation.ps1# Otomatik PowerShell müdahale betiği
    │   ├── edr_mitre_matrix.json       # MITRE ATT&CK taktik ve teknik haritası
    │   └── komut_ve_cikis.txt          # CLI komut çalıştırma logları
    └── temsili/
        └── edr_av_mimarisi.txt         # ASCII EDR telemetri ve müdahale şeması
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Komut Satırı Arayüzü (CLI) Yardımı
```bash
python uygulama/edr_telemetry_cli.py --help
```

### 2. Uç Nokta Telemetri Akışını Analiz Etme
```bash
python uygulama/edr_telemetry_cli.py analyze ornek_veri/clean_system_telemetry.json
```

### 3. Çıktıyı JSON Olarak Kaydetme ve Müdahale Betiği Üretme
```bash
python uygulama/edr_telemetry_cli.py analyze ornek_veri/clean_system_telemetry.json \
  --cikis-json denetim_raporu.json \
  --uret-remediation mudahale.ps1
```

### 4. Birim Testlerini Çalıştırma
```bash
python -m unittest tests/test_edr_telemetry.py -v
```

### 5. Kanıt Üreticisini Çalıştırma
```bash
python kanit_uretici.py
```

---

## 🔒 Lisans — Tüm Hakları Saklıdır

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
