# Gün 162: SQL Injection Neden Oluşur Paketi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](https://github.com/seydivakkas)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Status: 100/100 PASS](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen.svg)]()

Bu paket, 365 Günlük Siber Güvenlik Kampı **Hafta 24, Aşama 07 (Web Güvenliği)** açılış konusu olan **SQL Injection Neden Oluşur?** çalışmasını içerir. SQL enjeksiyonunun kök nedeni olan "Kod ile Veri Karışımı" (Code vs. Data Ambiguity) ilkesini, veritabanı Soyut Sözdizim Ağacı (AST) manipülasyonunu, güvensiz dinamik dize birleştirme ile güvenli parametrik sorgu (Prepared Statement) arasındaki yapısal ve protokol farklarını in-memory SQLite motoru üzerinde somutlaştırır.

---

## Dizin Yapısı

```
portfolio/hafta_24/gun_162/
├── uygulama/
│   ├── __init__.py
│   ├── sql_injection_engine.py    # SQLi tehdit sensörü, SQLite test motoru ve analiz orkestratörü
│   └── sql_injection_cli.py       # Tehdit tarama, simülasyon ve dinamik belirteç CLI aracı
├── tests/
│   ├── __init__.py
│   └── test_sql_injection.py      # 15 birim test (100% PASS, 0.005s)
├── ornek_veri/
│   ├── enterprise_db_schema.json  # Kurumsal veritabanı şeması ve SQLi önleme standartları
│   └── invalid_sqli_payloads.json # 9 negatif kontrol SQLi saldırı senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt     # 15/15 birim test icra günlüğü
│   │   ├── negatif_kontrol_sonuclari.txt # 9/9 saldırı senaryosu savunma kanıtı
│   │   ├── sqli_audit_report.json # Denetim JSON raporu
│   │   ├── sanitized_query_samples.txt   # Zafiyetli vs Parametrik sorgu karşılaştırma dökümü
│   │   └── komut_ve_cikis.txt     # CLI araçları gerçek yürütme logları
│   └── temsili/
│       └── sqli_savunma_mimarisi.txt # Zorunlu başlıklı mimari ASCII diyagramı
├── ders.md                        # Usta-Çırak derin teknik anlatımı
├── soru_cevap.md                  # 3 mülakat sorusu ve 4 zorunlu alt başlık
├── rapor.md                       # 100/100 kalite değerlendirme karnesi
├── sonuc.json                     # Standart sonuç metadatası
└── manifest.json                  # SHA-256 ve dosya bütünlük listesi
```

---

## Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Çalıştırma
```powershell
python -m unittest discover -s portfolio/hafta_24/gun_162/tests -p "test_*.py" -v
```

### 2. Girdide SQLi Tehdidi Tarama
```powershell
python portfolio/hafta_24/gun_162/uygulama/sql_injection_cli.py scan --input "admin' OR '1'='1"
```

### 3. Zafiyetli ve Güvenli Yürütmeyi Karşılaştırma
```powershell
python portfolio/hafta_24/gun_162/uygulama/sql_injection_cli.py simulate --username "admin' OR 1=1 --" --password "xyz"
```

### 4. Dinamik Belirteç Allowlist Güvenlik Testi
```powershell
python portfolio/hafta_24/gun_162/uygulama/sql_injection_cli.py dynamic-identifier --table users --sort-by balance
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
