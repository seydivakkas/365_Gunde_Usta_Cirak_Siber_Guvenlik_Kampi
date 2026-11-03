# Gün 058: HTTP Yöntemleri ve Idempotency — Metot Semantiği ve Güvenlik Motoru

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Tests: 14/14 Passed](https://img.shields.io/badge/tests-14%2F14%20passed-brightgreen?style=flat-square)](kanit/gercek/test_sonuclari.txt)
[![Score: 100/100](https://img.shields.io/badge/score-100%2F100%20PASS-blue?style=flat-square)](rapor.md)

---

## 📌 Proje Genel Bakışı

Bu çalışma, **365 Gün Siber Güvenlik ve Ağ Uzmanlığı Müfredatı** kapsamında 58. gün çalışması olarak geliştirilmiştir. RFC 7231 ve RFC 5789 standartlarına tam uyumlu HTTP metot doğrulaması, Güvenli (Safe) ve Eşgüçlü (Idempotent) davranış analizi, Stripe / IETF standardında `Idempotency-Key` yaşam döngüsü, SHA-256 gövde özeti doğrulama, çifte para çekme (double charge) engelleme, HTTP Verb Tampering (Metot Atlatma) ve güvensiz GET manipülasyonlarının denetimini içerir.

---

## 📁 Dizin Yapısı

```
gun_058/
├── uygulama/
│   ├── __init__.py
│   └── http_methods_idempotency.py       # Metot semantigi, Idempotency yöneticisi ve Verb Tampering denetçisi
├── tests/
│   ├── __init__.py
│   └── test_http_methods_idempotency.py  # 14 adet birim, entegrasyon ve negatif güvenlik testi
├── ornek_veri/
│   ├── sample_http_methods.json          # Metot senaryoları, Idempotency-Key ve saldırı örnekleri
│   └── invalid_method_inputs.json        # 9 adet negatif sınır durumu ve bozuk girdi
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt            # 14/14 PASS birim test çıktıları
│   │   ├── komut_ve_cikis.txt            # Terminal çalıştırma ve exit code kaydı
│   │   ├── http_metotlari_ve_idempotency_raporu.txt # Protokol ve güvenlik analiz raporu
│   │   └── negatif_kontrol_sonuclari.txt # Sınır durumları doğrulama kayıtları
│   └── temsili/
│       └── idempotency_ve_metot_guvenlik_mimarisi.txt # Temsili ASCII akış ve mimari şeması
├── ders.md                               # Usta-Çırak pedagojik ders notu
├── soru_cevap.md                         # 3 senaryolu derinlemesine vaka analizleri (SC1-SC3)
├── rapor.md                              # 100/100 Rubrik değerlendirme ve kalite raporu
├── sonuc.json                            # 14 standart alanlı makine tarafından okunabilir sonuç
└── README.md                             # Bu tanıtım ve kullanım kılavuzu
```

---

## 🚀 Hızlı Başlangıç ve Test Çalıştırma

### Gereksinimler
- Python 3.10+
- Standart kütüphaneler (`hashlib`, `time`, `unittest`, `dataclasses`, `json`)

### Testleri Çalıştırma
```powershell
python -m unittest portfolio/hafta_09/gun_058/tests/test_http_methods_idempotency.py -v
```

---

## 🔒 Lisans ve Telif Hakkı

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
