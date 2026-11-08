# Gün 164: CSRF ve Oturum Bağlamı

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status: 100/100 PASS](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Aşama: 07 Web Güvenliği](https://img.shields.io/badge/a%C5%9Fama-07%20Web%20G%C3%BCvenli%C4%9Fi-blue?style=flat-square)
![Hafta: 24](https://img.shields.io/badge/hafta-24-orange?style=flat-square)

## Proje Hakkında

Bu çalışma, **365 Günde Usta-Çırak Siber Güvenlik Kampı** kapsamında **Aşama 07: Web Güvenliği / Hafta 24: Enjeksiyon ve İstek Güvenliği** altında yer alan **Gün 164: CSRF ve Oturum Bağlamı** konusunun kurumsal seviyedeki savunma motorunu, birim testlerini, negatif kontrol analizlerini ve dokümantasyonunu içerir.

Tarayıcıların Ortam Yetkisi (Ambient Authority) davranışından kaynaklanan Siteler Arası İstek Sahteciliği (Cross-Site Request Forgery - CSRF / CWE-352) zafiyeti modellenmiş; duruma özel Synchronizer Token Pattern (STP), tek kullanımlık nonce ve HMAC-SHA256 imzası, katı Origin/Referer doğrulaması, SameSite çerez öznitelikleri ve kritik işlemler için Step-Up Re-Authentication mimarisiyle %100 oranında savunulmuştur.

## Dizin Yapısı

```
portfolio/hafta_24/gun_164/
├── uygulama/
│   ├── __init__.py
│   ├── csrf_engine.py           # Anti-CSRF ve oturum savunma motoru
│   └── csrf_cli.py              # CLI test ve denetim aracı
├── tests/
│   ├── __init__.py
│   └── test_csrf_engine.py      # 15/15 PASS birim testleri
├── ornek_veri/
│   ├── enterprise_csrf_policy.json   # Kurumsal Anti-CSRF güvenlik politikası
│   └── invalid_csrf_payloads.json    # 9 negatif kontrol senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── csrf_audit_report.json
│   │   ├── sanitized_http_transactions.txt
│   │   └── komut_ve_cikis.txt
│   └── temsili/
│       └── csrf_savunma_mimarisi.txt
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
python -m unittest portfolio/hafta_24/gun_164/tests/test_csrf_engine.py
```

### CLI Kullanımı:
```bash
python portfolio/hafta_24/gun_164/uygulama/csrf_cli.py --help
python portfolio/hafta_24/gun_164/uygulama/csrf_cli.py generate-token --user-id 2 --username ahmet_kaya
python portfolio/hafta_24/gun_164/uygulama/csrf_cli.py simulate-attack --method POST --origin https://evil-attacker.site --amount 2500
python portfolio/hafta_24/gun_164/uygulama/csrf_cli.py generate-cookie --session-id sess_sample_1234 --samesite Strict
```

### Kanıtları Yeniden Üretme:
```bash
python portfolio/hafta_24/gun_164/kanit_uretici.py
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
