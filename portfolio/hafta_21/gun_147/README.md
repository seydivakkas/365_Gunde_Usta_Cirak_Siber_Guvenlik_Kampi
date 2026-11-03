# Gün 147: Mini Proje 20 — Kurumsal IAM Politika Matrisi ve Güvenlik Motoru

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Tests: 15/15 PASS](https://img.shields.io/badge/tests-15%2F15%20PASS-brightgreen.svg)](tests/)
[![Negative Controls: 9/9 PASS](https://img.shields.io/badge/negative%20controls-9%2F9%20PASS-brightgreen.svg)](kanit/gercek/negatif_kontrol_sonuclari.txt)

---

## 📌 Genel Bakış

Bu proje, **Hafta 21'in Kapanış Mini Projesidir (Mini Proje 20)**. Hafta boyunca işlenen Active Directory etki alanı mimarisi, Kerberos v5 bilet mekanizmaları, Group Policy güvenlik sertleştirmesi ve IAM JML yaşam döngüsü konularını bir araya getirerek; kurumsal düzeyde **Microsoft Enterprise Access Katmanlama Modelini (Tier 0 / Tier 1 / Tier 2)**, **Kerberos Kaynak Tabanlı Kısıtlı Yetki Devrini (RBCD)**, **Görevler Ayrılığı (SoD) matrisini** ve **Sıfır Güven (Zero Trust) ABAC koşullu erişim mekanizmasını** işleten endüstriyel sınıf bir güvenlik motorudur.

Tüm kodlar harici kütüphane bağımlılığı olmaksızın saf Python 3 standart kütüphanesi ile geliştirilmiş, her yürütülebilir satır detaylı Türkçe öğretici yorumlarla zenginleştirilmiştir.

---

## 🏗️ Dizin Yapısı

```text
gun_147/
├── README.md                           # Proje genel tanıtımı ve kullanım kılavuzu
├── ders.md                             # Usta-Çırak derinlemesine teknik Mini Proje 20 dersi
├── soru_cevap.md                       # 3 derin teknik soru ve 4 zorunlu alt başlık
├── rapor.md                            # 100/100 PASS değerlendirme puan kartı
├── sonuc.json                          # Yapılandırılmış sonuç özeti
├── manifest.json                       # SHA-256 bütünlük ve dosya manifestosu
├── kanit_uretici.py                    # Gerçek kanıtları üreten otomasyon betiği
├── uygulama/
│   ├── __init__.py                     # Paket başlangıç dosyası
│   ├── iam_policy_matrix_engine.py     # Katmanlama, RBCD, SoD ve ABAC karar motoru
│   └── iam_matrix_cli.py               # Komut satırı yönetim ve simülasyon arayüzü (CLI)
├── tests/
│   ├── __init__.py                     # Test paketi başlangıç dosyası
│   └── test_iam_policy_matrix.py       # 15 kapsamlı birim testi (%100 PASS)
├── ornek_veri/
│   ├── enterprise_iam_policy_matrix.json # Kurumsal sertleştirilmiş politika matrisi
│   └── invalid_policy_matrix_scenarios.json # 9 negatif kontrol ve zafiyet senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt          # Birim testi çıktı kanıtı (15/15 PASS)
    │   ├── negatif_kontrol_sonuclari.txt# Negatif test izolasyon kanıtı (9/9 PASS)
    │   ├── iam_matrix_denetim_raporu.json # JSON formatlı denetim raporu çıktısı
    │   ├── iam_matrix_sertlestirme.ps1 # Otomatik PowerShell sertleştirme betiği
    │   ├── iam_policy_matrix_ozet.json # Kurumsal matris ve katman mimarisi özeti
    │   └── komut_ve_cikis.txt          # CLI komut çalıştırma logları
    └── temsili/
        └── iam_politika_matrisi_mimarisi.txt # ASCII Tiering ve Zero Trust kontrol şeması
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Komut Satırı Arayüzü (CLI) Yardımı
```bash
python uygulama/iam_matrix_cli.py --help
```

### 2. Kurumsal Politika Matrisini Denetleme
```bash
python uygulama/iam_matrix_cli.py audit ornek_veri/enterprise_iam_policy_matrix.json
```

### 3. Dinamik Erişim Talebini Simüle Etme (Zero Trust ABAC)
```bash
python uygulama/iam_matrix_cli.py simulate-access ornek_veri/enterprise_iam_policy_matrix.json \
  --user-id USR-T0-SEYYID \
  --resource-id RES-DC01
```

### 4. Çıktıyı JSON Olarak Kaydetme ve Sertleştirme Betiği Üretme
```bash
python uygulama/iam_matrix_cli.py audit ornek_veri/enterprise_iam_policy_matrix.json \
  --cikis-json denetim_raporu.json \
  --uret-remediation sertlestirme.ps1
```

### 5. Birim Testlerini Çalıştırma
```bash
python -m unittest tests/test_iam_policy_matrix.py -v
```

### 6. Kanıt Üreticisini Çalıştırma
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
