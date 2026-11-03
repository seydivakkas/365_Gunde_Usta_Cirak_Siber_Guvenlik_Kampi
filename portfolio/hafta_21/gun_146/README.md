# Gün 146: IAM Yaşam Döngüsü JML (Joiner, Mover, Leaver) Güvenlik Motoru

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Tests: 15/15 PASS](https://img.shields.io/badge/tests-15%2F15%20PASS-brightgreen.svg)](tests/)
[![Negative Controls: 9/9 PASS](https://img.shields.io/badge/negative%20controls-9%2F9%20PASS-brightgreen.svg)](kanit/gercek/negatif_kontrol_sonuclari.txt)

---

## 📌 Genel Bakış

Bu modül, kurumsal Kimlik ve Erişim Yönetimi (IAM) mimarisinde personel yaşam döngüsünün (**Joiner, Mover, Leaver - JML**) güvenliğini, İK otoriter veri kaynağı ile hedef sistemler arasındaki senkronizasyonu, yetki birikimini (**Privilege Creep**), görevler ayrılığı (**Separation of Duties - SoD**) zehirli kombinasyonlarını ve sahipsiz yetim hesapları (**Orphan Accounts**) denetleyen endüstriyel sınıf bir güvenlik motorudur.

Tüm kodlar harici kütüphane bağımlılığı olmaksızın saf Python 3 standart kütüphanesi ile geliştirilmiş, her yürütülebilir satır detaylı Türkçe öğretici yorumlarla zenginleştirilmiştir.

---

## 🏗️ Dizin Yapısı

```text
gun_146/
├── README.md                           # Proje genel tanıtımı ve kullanım kılavuzu
├── ders.md                             # Usta-Çırak derinlemesine teknik IAM JML dersi
├── soru_cevap.md                       # 3 derin teknik soru ve 4 zorunlu alt başlık
├── rapor.md                            # 100/100 PASS değerlendirme puan kartı
├── sonuc.json                          # Yapılandırılmış sonuç özeti
├── manifest.json                       # SHA-256 bütünlük ve dosya manifestosu
├── kanit_uretici.py                    # Gerçek kanıtları üreten otomasyon betiği
├── uygulama/
│   ├── __init__.py                     # Paket başlangıç dosyası
│   ├── iam_jml_lifecycle_engine.py     # JML yaşam döngüsü, SoD ve mutabakat motoru
│   └── iam_jml_cli.py                  # Komut satırı yönetim arayüzü (CLI)
├── tests/
│   ├── __init__.py                     # Test paketi başlangıç dosyası
│   └── test_iam_jml_lifecycle.py       # 15 kapsamlı birim testi (%100 PASS)
├── ornek_veri/
│   ├── iam_organization_directory.json # Kurumsal sertleştirilmiş IAM dizin verisi
│   └── invalid_jml_scenarios.json      # 9 negatif kontrol ve zafiyet senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt          # Birim testi çıktı kanıtı (15/15 PASS)
    │   ├── negatif_kontrol_sonuclari.txt# Negatif test izolasyon kanıtı (9/9 PASS)
    │   ├── iam_jml_audit_report.json   # JSON formatlı denetim raporu çıktısı
    │   ├── iam_jml_remediation.ps1     # Otomatik PowerShell sertleştirme betiği
    │   ├── iam_jml_matrix.json         # JML güvenlik sertleştirme ve uyumluluk matrisi
    │   └── komut_ve_cikis.txt          # CLI komut çalıştırma logları
    └── temsili/
        └── iam_jml_mimarisi.txt        # ASCII JML yaşam döngüsü ve kontrol şeması
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Komut Satırı Arayüzü (CLI) Yardımı
```bash
python uygulama/iam_jml_cli.py --help
```

### 2. Kurumsal Dizini JML ve SoD Risklerine Karşı Denetleme
```bash
python uygulama/iam_jml_cli.py audit ornek_veri/iam_organization_directory.json
```

### 3. Çıktıyı JSON Olarak Kaydetme ve Sertleştirme Betiği Üretme
```bash
python uygulama/iam_jml_cli.py audit ornek_veri/iam_organization_directory.json \
  --cikis-json denetim_raporu.json \
  --uret-remediation sertlestirme.ps1
```

### 4. Personel İşten Ayrılma (Leaver) ve Anında Hesap Kapatma
```bash
python uygulama/iam_jml_cli.py leaver ornek_veri/iam_organization_directory.json \
  --emp-id EMP-002 \
  --onaylayan hr_director@kurum.local
```

### 5. Birim Testlerini Çalıştırma
```bash
python -m unittest tests/test_iam_jml_lifecycle.py -v
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
