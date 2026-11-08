# Gün 165: CORS ile Güvenlik Sınırı

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status: 100/100 PASS](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Aşama: 07 Web Güvenliği](https://img.shields.io/badge/a%C5%9Fama-07%20Web%20G%C3%BCvenli%C4%9Fi-blue?style=flat-square)
![Hafta: 24](https://img.shields.io/badge/hafta-24-orange?style=flat-square)

## Proje Hakkında

Bu çalışma, **365 Günde Usta-Çırak Siber Güvenlik Kampı** kapsamında **Aşama 07: Web Güvenliği / Hafta 24: Enjeksiyon ve İstek Güvenliği** altında yer alan **Gün 165: CORS ile Güvenlik Sınırı** konusunun kurumsal seviyedeki savunma motorunu, birim testlerini, negatif kontrol analizlerini ve dokümantasyonunu içerir.

Aynı Köken İlkesi'nin (Same-Origin Policy - SOP) sınırları ile Siteler Arası Kaynak Paylaşımı (Cross-Origin Resource Sharing - CORS / CWE-942) mekanizması derinlemesine incelenmiş; sahada en sık yapılan Arbitrary Origin Reflection, `null` origin kabulü, gevşek regex atlatmaları ve önbellek zehirlenmesi zafiyetleri simüle edilerek katı kurumsal beyaz liste (Allowlist), Preflight (OPTIONS) kontrolü ve `Vary: Origin` mimarisiyle %100 oranında savunulmuştur.

## Dizin Yapısı

```
portfolio/hafta_24/gun_165/
├── uygulama/
│   ├── __init__.py
│   ├── cors_engine.py           # CORS savunma ve doğrulama motoru
│   └── cors_cli.py              # CLI test ve denetim aracı
├── tests/
│   ├── __init__.py
│   └── test_cors_engine.py      # 15/15 PASS birim testleri
├── ornek_veri/
│   ├── enterprise_cors_policy.json   # Kurumsal CORS güvenlik politikası
│   └── invalid_cors_payloads.json    # 9 negatif kontrol senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── cors_audit_report.json
│   │   ├── sanitized_cors_exchanges.txt
│   │   └── komut_ve_cikis.txt
│   └── temsili/
│       └── cors_guvenlik_siniri_mimarisi.txt
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
python -m unittest portfolio/hafta_24/gun_165/tests/test_cors_engine.py
```

### CLI Kullanımı:
```bash
python portfolio/hafta_24/gun_165/uygulama/cors_cli.py --help
python portfolio/hafta_24/gun_165/uygulama/cors_cli.py evaluate-origin --origin https://portal.kurum.internal
python portfolio/hafta_24/gun_165/uygulama/cors_cli.py evaluate-origin --origin https://evil-attacker.com
python portfolio/hafta_24/gun_165/uygulama/cors_cli.py test-preflight --origin https://portal.kurum.internal --request-method POST --request-headers content-type,authorization
python portfolio/hafta_24/gun_165/uygulama/cors_cli.py simulate-misconfig --attacker-origin https://evil-hacker.com
```

### Kanıtları Yeniden Üretme:
```bash
python portfolio/hafta_24/gun_165/kanit_uretici.py
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
