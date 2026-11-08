# Gün 163: NoSQL ve ORM Sınırları

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status: 100/100 PASS](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Aşama: 07 Web Güvenliği](https://img.shields.io/badge/a%C5%9Fama-07%20Web%20G%C3%BCvenli%C4%9Fi-blue?style=flat-square)
![Hafta: 24](https://img.shields.io/badge/hafta-24-orange?style=flat-square)

## Proje Hakkında

Bu çalışma, **365 Günde Usta-Çırak Siber Güvenlik Kampı** kapsamında **Aşama 07: Web Güvenliği / Hafta 24: Enjeksiyon ve İstek Güvenliği** altında yer alan **Gün 163: NoSQL ve ORM Sınırları** konusunun kurumsal seviyedeki savunma motorunu, birim testlerini, negatif kontrol analizlerini ve dokümantasyonunu içerir.

NoSQL veritabanlarındaki operatör enjeksiyonları (`$ne`, `$gt`, `$regex`, `$where`, `$in`, `$exists`), nokta notasyonu manipülasyonu (`path pollution`) ile ORM katmanlarındaki Kütlesel Atama (Mass Assignment / Over-Posting) riskleri teorik ve pratik olarak simüle edilmiş; katı tip denetimi (Type Enforcement) ve DTO (Data Transfer Object) beyaz listeleri ile %100 oranında savunulmuştur.

## Dizin Yapısı

```
portfolio/hafta_24/gun_163/
├── uygulama/
│   ├── __init__.py
│   ├── nosql_orm_engine.py       # NoSQL/ORM savunma ve tespit motoru
│   └── nosql_orm_cli.py          # Etkileşimli CLI denetim aracı
├── tests/
│   ├── __init__.py
│   └── test_nosql_orm.py         # 15/15 PASS birim testleri
├── ornek_veri/
│   ├── enterprise_nosql_policy.json   # Kurumsal NoSQL ve ORM politikası
│   └── invalid_nosql_orm_payloads.json # 9 negatif kontrol senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── nosql_orm_audit_report.json
│   │   ├── sanitized_orm_samples.txt
│   │   └── komut_ve_cikis.txt
│   └── temsili/
│       └── nosql_orm_savunma_mimarisi.txt
├── kanit_uretici.py              # Otomatik kanıt üretim scripti
├── ders.md                       # Usta-Çırak derinlemesine teknik dersi
├── soru_cevap.md                 # 3 mülakat sorusu ve teknik analiz
├── rapor.md                      # 100/100 PASS başarı puan kartı
├── sonuc.json                    # Günlük özet metadataları
├── manifest.json                 # SHA-256 doğrulama manifestosu
└── README.md                     # Proje tanıtım ve lisans belgesi
```

## Hızlı Başlangıç

### Testleri Çalıştırma:
```bash
python -m unittest portfolio/hafta_24/gun_163/tests/test_nosql_orm.py
```

### CLI Kullanımı:
```bash
python portfolio/hafta_24/gun_163/uygulama/nosql_orm_cli.py --help
python portfolio/hafta_24/gun_163/uygulama/nosql_orm_cli.py inspect-nosqli --query '{"username": "admin", "password_hash": {"$ne": ""}}'
python portfolio/hafta_24/gun_163/uygulama/nosql_orm_cli.py test-mass-assignment --payload '{"full_name": "Test", "is_admin": true}'
```

### Kanıtları Yeniden Üretme:
```bash
python portfolio/hafta_24/gun_163/kanit_uretici.py
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
