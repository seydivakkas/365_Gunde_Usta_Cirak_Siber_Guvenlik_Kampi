# Gün 143: Active Directory Etki Alanı Güvenliği ve Sertleştirme Motoru

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Tests: 15/15 PASS](https://img.shields.io/badge/tests-15%2F15%20PASS-brightgreen.svg)](tests/)
[![Negative Controls: 9/9 PASS](https://img.shields.io/badge/negative%20controls-9%2F9%20PASS-brightgreen.svg)](kanit/gercek/negatif_kontrol_sonuclari.txt)

---

## 📌 Genel Bakış

Bu modül, kurumsal **Active Directory Domain Services (AD DS)** ortamlarının güvenlik olgunluğunu, etki alanı denetleyicisi (Domain Controller) sertleştirme seviyesini, FSMO rol dağılımını, Kerberos biletleme ve KDC güvenliğini, NTLM geriye dönük uyumluluk açıklarını, LDAP/SMB imzalama kurallarını ve etki alanı düzeyindeki kritik kimlik saldırı vektörlerini (Kerberoasting, AS-REP Roasting, Kısıtlanmamış Delegasyon, SID Filtering eksikliği) denetleyen endüstriyel sınıf bir güvenlik motorudur.

Tüm kodlar harici kütüphane bağımlılığı olmaksızın saf Python 3 standart kütüphanesi ile geliştirilmiş, her yürütülebilir satır detaylı Türkçe öğretici yorumlarla zenginleştirilmiştir.

---

## 🏗️ Dizin Yapısı

```text
gun_143/
├── README.md                           # Proje genel tanıtımı ve kullanım kılavuzu
├── ders.md                             # Usta-Çırak derinlemesine teknik AD DS dersi
├── soru_cevap.md                       # 3 derin teknik soru ve 4 zorunlu alt başlık
├── rapor.md                            # 100/100 PASS değerlendirme puan kartı
├── sonuc.json                          # Yapılandırılmış sonuç özeti
├── manifest.json                       # SHA-256 bütünlük ve dosya manifestosu
├── kanit_uretici.py                    # Gerçek kanıtları üreten otomasyon scripti
├── uygulama/
│   ├── __init__.py                     # Paket başlangıç dosyası
│   ├── ad_domain_security_engine.py    # AD DS denetim ve kural değerlendirme motoru
│   └── ad_domain_cli.py                # Komut satırı yönetim arayüzü (CLI)
├── tests/
│   ├── __init__.py                     # Test paketi başlangıç dosyası
│   └── test_ad_domain_security.py      # 15 kapsamlı birim testi (%100 PASS)
├── ornek_veri/
│   ├── enterprise_ad_domain_spec.json  # Kurumsal AD DS teknik konfigürasyon örneği
│   └── invalid_ad_scenarios.json       # 9 negatif kontrol ve zafiyet senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt          # Birim testi çıktı kanıtı (15/15 PASS)
    │   ├── negatif_kontrol_sonuclari.txt# Negatif test izolasyon kanıtı (9/9 PASS)
    │   ├── ad_domain_guvenlik_raporu.json # JSON denetim raporu çıktısı
    │   ├── ad_sertlestirme_gpo.ps1     # Otomatik PowerShell sertleştirme betiği
    │   ├── ad_hardening_matrix.json    # AD güvenlik sertleştirme matrisi
    │   └── komut_ve_cikis.txt          # CLI komut çalıştırma logları
    └── temsili/
        └── ad_mimarisi.txt             # ASCII AD DS güvenlik ve biletleme mimarisi
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Komut Satırı Arayüzü (CLI) Yardımı
```bash
python uygulama/ad_domain_cli.py --help
```

### 2. Kurumsal AD DS Spesifikasyonunu Denetleme
```bash
python uygulama/ad_domain_cli.py ornek_veri/enterprise_ad_domain_spec.json
```

### 3. Çıktıyı JSON Olarak Kaydetme ve Sertleştirme Betiği Üretme
```bash
python uygulama/ad_domain_cli.py ornek_veri/enterprise_ad_domain_spec.json \
  --cikis-json denetim_raporu.json \
  --uret-remediation sertlestirme.ps1
```

### 4. Birim Testlerini Çalıştırma
```bash
python -m unittest tests/test_ad_domain_security.py -v
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
