# Gün 161: Mini Proje 22 - Güvenli Form Arayüzü Paketi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](https://github.com/seydivakkas)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Status: 100/100 PASS](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen.svg)]()

Bu paket, 365 Günlük Siber Güvenlik Kampı **Hafta 23, Aşama 07 (Web Güvenliği)** kapanış projesi olan **Mini Proje 22: Güvenli Form Arayüzü** çalışmasını içerir. CSRF koruması (HMAC-SHA256, TTL, Replay engeli), katı şema girdi doğrulama, Shannon bilgi entropisi ile parola denetimi, kayan pencere istek sınırlandırması (Rate Limiting) ve CSP Seviye 3 başlık üretimini uçtan uca sentezleyen kurumsal bir motor ve CLI aracı sunar.

---

## Dizin Yapısı

```
portfolio/hafta_23/gun_161/
├── uygulama/
│   ├── __init__.py
│   ├── secure_form_engine.py      # CSRF, alan doğrulama, rate limit ve form işleme ana motoru
│   └── secure_form_cli.py         # Form render, submit, CSRF yönetim CLI aracı
├── tests/
│   ├── __init__.py
│   └── test_secure_form.py        # 15 birim test (100% PASS, 0.001s)
├── ornek_veri/
│   ├── enterprise_form_schema.json# Kurumsal form şeması ve güvenlik standartları
│   └── invalid_form_payloads.json # 9 negatif kontrol ve saldırı senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt     # 15/15 birim test icra günlüğü
│   │   ├── negatif_kontrol_sonuclari.txt # 9/9 saldırı senaryosu savunma kanıtı
│   │   ├── secure_form_audit_report.json # Denetim JSON raporu
│   │   ├── rendered_form_samples.html    # Motor tarafından render edilen canlı form HTML'i
│   │   └── komut_ve_cikis.txt     # CLI araçları gerçek yürütme logları
│   └── temsili/
│       └── guvenli_form_mimarisi.txt # Zorunlu başlıklı mimari ASCII diyagramı
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
python -m unittest discover -s portfolio/hafta_23/gun_161/tests -p "test_*.py" -v
```

### 2. Canlı Form HTML Şablonunu Render Etme
```powershell
python portfolio/hafta_23/gun_161/uygulama/secure_form_cli.py render --session-id "sess_demo_user_1"
```

### 3. CLI Üzerinden Form Gönderimi Simülasyonu
```powershell
python portfolio/hafta_23/gun_161/uygulama/secure_form_cli.py submit --json-data '{\"username\":\"ahmet_bey\",\"email\":\"ahmet@kurum.com\",\"password\":\"P@ssw0rdSecure!2026\",\"amount\":\"1500.00\"}' --session-id "sess_demo_user_1"
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
