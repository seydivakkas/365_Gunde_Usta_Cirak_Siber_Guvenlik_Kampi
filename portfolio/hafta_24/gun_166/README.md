# Gün 166: SSRF Kavramı ve Savunma

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status: 100/100 PASS](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Aşama: 07 Web Güvenliği](https://img.shields.io/badge/a%C5%9Fama-07%20Web%20G%C3%BCvenli%C4%9Fi-blue?style=flat-square)
![Hafta: 24](https://img.shields.io/badge/hafta-24-orange?style=flat-square)

## Proje Hakkında

Bu çalışma, **365 Günde Usta-Çırak Siber Güvenlik Kampı** kapsamında **Aşama 07: Web Güvenliği / Hafta 24: Enjeksiyon ve İstek Güvenliği** altında yer alan **Gün 166: SSRF Kavramı ve Savunma** konusunun kurumsal seviyedeki savunma motorunu, birim testlerini, negatif kontrol analizlerini ve dokümantasyonunu içerir.

Sunucu Taraflı İstek Sahteciliği (Server-Side Request Forgery - SSRF / CWE-918) tehdidi incelenmiş; Yerel Döngü (Loopback), RFC 1918 özel iç ağları, Bulut Metaveri Servisi (`169.254.169.254`), tehlikeli protokol şemaları (`file://`, `gopher://`), gizlenmiş IP temsilleri (Integer, Hex, Octal, IPv4-mapped IPv6), DNS Rebinding ve HTTP Açık Yönlendirme (Open Redirect) atlatmaları simüle edilerek Pre-Request DNS çözümlemesi, IP Sabitleme (IP Pinning), güvenli yönlendirme denetimi ve çıkış filtreleme (Egress Filtering) mimarisiyle %100 oranında savunulmuştur.

## Dizin Yapısı

```
portfolio/hafta_24/gun_166/
├── uygulama/
│   ├── __init__.py
│   ├── ssrf_defense_engine.py   # SSRF savunma motoru ve güvenli istemci
│   └── ssrf_defense_cli.py      # CLI denetim ve simülasyon aracı
├── tests/
│   ├── __init__.py
│   └── test_ssrf_defense.py     # 15/15 PASS birim testleri
├── ornek_veri/
│   ├── enterprise_ssrf_policy.json   # Kurumsal SSRF güvenlik politikası
│   └── invalid_ssrf_payloads.json    # 9 negatif kontrol senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── ssrf_audit_report.json
│   │   ├── sanitized_fetch_logs.txt
│   │   └── komut_ve_cikis.txt
│   └── temsili/
│       └── ssrf_savunma_mimarisi.txt
├── kanit_uretici.py             # Otomatik kanıt üretim scripti
├── ders.md                      # Usta-Çırak derinlemesine teknik dersi
├── soru_cevap.md                # 3 mülakat sorusu ve teknik analiz
├── rapor.md                     # 100/100 PASS başarı puan kartı
├── sonuc.json                   # Günlük özet metadataları
├── manifest.json                # SHA-256 doğrulama manifestosu
└── README.md                    # Proje tanıtım ve lisans belgesi
```

## Hızlı Başlangıç

### Testleri Çalıştırma:
```bash
python -m unittest portfolio/hafta_24/gun_166/tests/test_ssrf_defense.py
```

### CLI Kullanımı:
```bash
python portfolio/hafta_24/gun_166/uygulama/ssrf_defense_cli.py --help
python portfolio/hafta_24/gun_166/uygulama/ssrf_defense_cli.py validate-url --url http://127.0.0.1:8080/admin
python portfolio/hafta_24/gun_166/uygulama/ssrf_defense_cli.py validate-url --url http://169.254.169.254/latest/meta-data/
python portfolio/hafta_24/gun_166/uygulama/ssrf_defense_cli.py parse-ip --host 2130706433
python portfolio/hafta_24/gun_166/uygulama/ssrf_defense_cli.py simulate-attack --target-url http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role
```

### Kanıtları Yeniden Üretme:
```bash
python portfolio/hafta_24/gun_166/kanit_uretici.py
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
