# Gün 144: Kerberos v5 Temel Bilet Akışı ve Güvenlik Motoru

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Tests: 15/15 PASS](https://img.shields.io/badge/tests-15%2F15%20PASS-brightgreen.svg)](tests/)
[![Negative Controls: 9/9 PASS](https://img.shields.io/badge/negative%20controls-9%2F9%20PASS-brightgreen.svg)](kanit/gercek/negatif_kontrol_sonuclari.txt)

---

## 📌 Genel Bakış

Bu modül, **RFC 4120 Kerberos v5** kimlik doğrulama protokolünün bilet yaşam döngüsünü (AS-REQ/AS-REP, TGS-REQ/TGS-REP, AP-REQ/AP-REP), KDC bilet üretim ve doğrulama süreçlerini, Kanıtlayıcı (Authenticator) zaman ve Replay Cache denetimlerini, PAC (Privilege Attribute Certificate) HMAC Server ve KDC çift imza bütünlüğünü ve kurumsal Kerberos saldırı vektörlerini (Golden Ticket, Silver Ticket, AS-REP Roasting, Kerberoasting, Cipher Downgrade, Replay Attack) denetleyen endüstriyel sınıf bir güvenlik motorudur.

Tüm kodlar harici kütüphane bağımlılığı olmaksızın saf Python 3 standart kütüphanesi ile geliştirilmiş, her yürütülebilir satır detaylı Türkçe öğretici yorumlarla zenginleştirilmiştir.

---

## 🏗️ Dizin Yapısı

```text
gun_144/
├── README.md                           # Proje genel tanıtımı ve kullanım kılavuzu
├── ders.md                             # Usta-Çırak derinlemesine teknik Kerberos v5 dersi
├── soru_cevap.md                       # 3 derin teknik soru ve 4 zorunlu alt başlık
├── rapor.md                            # 100/100 PASS değerlendirme puan kartı
├── sonuc.json                          # Yapılandırılmış sonuç özeti
├── manifest.json                       # SHA-256 bütünlük ve dosya manifestosu
├── kanit_uretici.py                    # Gerçek kanıtları üreten otomasyon betiği
├── uygulama/
│   ├── __init__.py                     # Paket başlangıç dosyası
│   ├── kerberos_ticket_flow_engine.py  # RFC 4120 bilet akışı ve güvenlik motoru
│   └── kerberos_flow_cli.py            # Komut satırı yönetim arayüzü (CLI)
├── tests/
│   ├── __init__.py                     # Test paketi başlangıç dosyası
│   └── test_kerberos_ticket_flow.py    # 15 kapsamlı birim testi (%100 PASS)
├── ornek_veri/
│   ├── kerberos_flow_scenario.json     # Kurumsal Kerberos bilet takas örneği
│   └── invalid_kerberos_scenarios.json # 9 negatif kontrol ve zafiyet senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt          # Birim testi çıktı kanıtı (15/15 PASS)
    │   ├── negatif_kontrol_sonuclari.txt# Negatif test izolasyon kanıtı (9/9 PASS)
    │   ├── kerberos_denetim_raporu.json# JSON formatlı denetim raporu çıktısı
    │   ├── kerberos_sertlestirme_betigi.ps1 # Otomatik PowerShell sertleştirme betiği
    │   ├── kerberos_hardening_matrix.json   # Kerberos güvenlik sertleştirme matrisi
    │   └── komut_ve_cikis.txt          # CLI komut çalıştırma logları
    └── temsili/
        └── kerberos_bilet_mimarisi.txt # ASCII Kerberos bilet yaşam döngüsü şeması
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Komut Satırı Arayüzü (CLI) Yardımı
```bash
python uygulama/kerberos_flow_cli.py --help
```

### 2. Tam Kerberos Bilet Takasını Simüle Etme
```bash
python uygulama/kerberos_flow_cli.py simulate \
  --client canan@KURUM.LOCAL \
  --spn cifs/fs01.kurum.local \
  --realm KURUM.LOCAL \
  --enc-type AES256
```

### 3. Çıktıyı JSON Olarak Kaydetme ve Sertleştirme Betiği Üretme
```bash
python uygulama/kerberos_flow_cli.py simulate \
  --client canan@KURUM.LOCAL \
  --spn cifs/fs01.kurum.local \
  --cikis-json denetim_raporu.json \
  --uret-remediation sertlestirme.ps1
```

### 4. Birim Testlerini Çalıştırma
```bash
python -m unittest tests/test_kerberos_ticket_flow.py -v
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
