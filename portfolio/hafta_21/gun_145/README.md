# Gün 145: Group Policy Güvenlik Etkileri ve Denetim Motoru

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Tests: 15/15 PASS](https://img.shields.io/badge/tests-15%2F15%20PASS-brightgreen.svg)](tests/)
[![Negative Controls: 9/9 PASS](https://img.shields.io/badge/negative%20controls-9%2F9%20PASS-brightgreen.svg)](kanit/gercek/negatif_kontrol_sonuclari.txt)

---

## 📌 Genel Bakış

Bu modül, Microsoft Active Directory etki alanı mimarisinde **Group Policy (GPO)** yapılandırmalarının güvenlik etkilerini, hiyerarşik kalıtım ve öncelik kurallarını (LSDOU: Local, Site, Domain, OU), suistimal vektörlerini (GPP cpassword MS14-025, GPO ACL Hijacking, yetkisiz URA atamaları, güvensiz betik yolları) ve modern kurumsal savunma pratiklerini (LAPS, Enforced/NoOverride, Tiered Admin) denetleyen endüstriyel sınıf bir güvenlik motorudur.

Tüm kodlar harici kütüphane bağımlılığı olmaksızın saf Python 3 standart kütüphanesi ile geliştirilmiş, her yürütülebilir satır detaylı Türkçe öğretici yorumlarla zenginleştirilmiştir.

---

## 🏗️ Dizin Yapısı

```text
gun_145/
├── README.md                           # Proje genel tanıtımı ve kullanım kılavuzu
├── ders.md                             # Usta-Çırak derinlemesine teknik Group Policy dersi
├── soru_cevap.md                       # 3 derin teknik soru ve 4 zorunlu alt başlık
├── rapor.md                            # 100/100 PASS değerlendirme puan kartı
├── sonuc.json                          # Yapılandırılmış sonuç özeti
├── manifest.json                       # SHA-256 bütünlük ve dosya manifestosu
├── kanit_uretici.py                    # Gerçek kanıtları üreten otomasyon betiği
├── uygulama/
│   ├── __init__.py                     # Paket başlangıç dosyası
│   ├── gpo_security_engine.py          # LSDOU, ACL, LAPS, GPP cpassword denetim motoru
│   └── gpo_audit_cli.py                # Komut satırı yönetim arayüzü (CLI)
├── tests/
│   ├── __init__.py                     # Test paketi başlangıç dosyası
│   └── test_gpo_security.py            # 15 kapsamlı birim testi (%100 PASS)
├── ornek_veri/
│   ├── enterprise_gpo_spec.json        # Kurumsal sertleştirilmiş GPO örnek verisi
│   └── invalid_gpo_scenarios.json      # 9 negatif kontrol ve zafiyet senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt          # Birim testi çıktı kanıtı (15/15 PASS)
    │   ├── negatif_kontrol_sonuclari.txt# Negatif test izolasyon kanıtı (9/9 PASS)
    │   ├── gpo_guvenlik_raporu.json    # JSON formatlı denetim raporu çıktısı
    │   ├── gpo_sertlestirme_betigi.ps1 # Otomatik PowerShell sertleştirme betiği
    │   ├── gpo_hardening_matrix.json   # Group Policy güvenlik sertleştirme matrisi
    │   └── komut_ve_cikis.txt          # CLI komut çalıştırma logları
    └── temsili/
        └── gpo_mimarisi.txt            # ASCII GPO kalıtım ve saldırı/savunma şeması
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Komut Satırı Arayüzü (CLI) Yardımı
```bash
python uygulama/gpo_audit_cli.py --help
```

### 2. Kurumsal GPO Ortamını Denetleme
```bash
python uygulama/gpo_audit_cli.py audit ornek_veri/enterprise_gpo_spec.json
```

### 3. Belirli Bir OU İçin Etkin GPO Sırasını (LSDOU) Hesaplama
```bash
python uygulama/gpo_audit_cli.py effective-gpos ornek_veri/enterprise_gpo_spec.json --ou "OU=Workstations,DC=kurum,DC=local"
```

### 4. Çıktıyı JSON Olarak Kaydetme ve Sertleştirme Betiği Üretme
```bash
python uygulama/gpo_audit_cli.py audit ornek_veri/enterprise_gpo_spec.json \
  --cikis-json denetim_raporu.json \
  --uret-remediation sertlestirme.ps1
```

### 5. Birim Testlerini Çalıştırma
```bash
python -m unittest tests/test_gpo_security.py -v
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
