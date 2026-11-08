# Gün 160: XSS Türleri ve Savunma Paketi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](https://github.com/seydivakkas)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Status: 100/100 PASS](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen.svg)]()

Bu paket, 365 Günlük Siber Güvenlik Kampı **Hafta 23, Aşama 07 (Web Güvenliği)** kapsamında **XSS Türleri ve Savunma** konusunu ele alır. Reflected, Stored, DOM-based ve Mutation XSS vektörlerini derinlemesine inceleyerek katı allowlist HTML temizliği, bağlama duyarlı çıktı kodlama ve CSP Seviye 3 ilkeleriyle çok katmanlı savunma hattı inşa eder.

---

## Dizin Yapısı

```
portfolio/hafta_23/gun_160/
├── uygulama/
│   ├── __init__.py
│   ├── xss_defense_engine.py      # XSS algılama, DOM analiz, HTML arındırma ve CSP motoru
│   └── xss_defense_cli.py         # Komut satırı yönetim aracı (inspect, dom, sanitize, csp, encode)
├── tests/
│   ├── __init__.py
│   └── test_xss_defense.py        # 15 birim test (100% PASS)
├── ornek_veri/
│   ├── enterprise_xss_policy.json # Kurumsal XSS ve CSP Seviye 3 güvenlik politikası
│   └── invalid_xss_payloads.json  # 9 negatif kontrol saldırı senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt     # 15/15 birim test icra günlüğü
│   │   ├── negatif_kontrol_sonuclari.txt # 9/9 saldırı senaryosu savunma kanıtı
│   │   ├── xss_defense_audit_report.json # Denetim JSON raporu
│   │   ├── sanitized_xss_samples.txt     # Güvenli arındırılmış örnek çıktılar
│   │   └── komut_ve_cikis.txt     # CLI araçları gerçek yürütme logları
│   └── temsili/
│       └── xss_savunma_mimarisi.txt # Zorunlu başlıklı mimari ASCII diyagramı
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
python -m unittest discover -s portfolio/hafta_23/gun_160/tests -p "test_*.py" -v
```

### 2. CLI ile Saldırı Yükü Analizi
```powershell
python portfolio/hafta_23/gun_160/uygulama/xss_defense_cli.py inspect --payload "<script>alert(1)</script>" --context html_body
```

### 3. JavaScript DOM XSS Taint Analizi
```powershell
python portfolio/hafta_23/gun_160/uygulama/xss_defense_cli.py analyze-dom --script "let q = location.search; document.body.innerHTML = q;"
```

### 4. Nonce Tabanlı CSP Seviye 3 Başlığı Üretme
```powershell
python portfolio/hafta_23/gun_160/uygulama/xss_defense_cli.py csp --generate
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
