# Gün 057: HTTP İstek ve Yanıt Yapısı — Protokol Mimarisi ve Güvenlik Denetleyicisi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Tests: 14/14 Passed](https://img.shields.io/badge/tests-14%2F14%20passed-brightgreen?style=flat-square)](kanit/gercek/test_sonuclari.txt)
[![Score: 100/100](https://img.shields.io/badge/score-100%2F100%20PASS-blue?style=flat-square)](rapor.md)

---

## 📌 Proje Genel Bakışı

Bu çalışma, **365 Gün Siber Güvenlik ve Ağ Uzmanlığı Müfredatı** kapsamında 57. gün çalışması ve **Hafta 09 (Uygulama Katmanı Protokolleri ve Web Temelleri)** başlangıcı olarak geliştirilmiştir. RFC 7230 ve RFC 7231 standartlarına tam uyumlu HTTP/1.1 İstek Satırı, Durum Satırı, Başlıklar, çift CRLF sınırlayıcıları ve mesaj gövdesi ayrıştırma/serileştirme motorunu, HTTP metot semantiğini (Safe vs Idempotent), durum kodlarını, OWASP Güvenlik Başlıkları denetimini, CRLF Enjeksiyonu ve HTTP Request Smuggling (CL.TE / TE.CL) zafiyet analizlerini içerir.

---

## 📁 Dizin Yapısı

```
gun_057/
├── uygulama/
│   ├── __init__.py
│   └── http_protocol_analyzer.py         # HTTP istek/yanıt ayrıştırıcı, serileştirici ve güvenlik denetçisi
├── tests/
│   ├── __init__.py
│   └── test_http_protocol_analyzer.py    # 14 adet birim, entegrasyon ve negatif güvenlik testi
├── ornek_veri/
│   ├── sample_http_messages.json         # Standart istekler, yanıtlar ve saldırı örnekleri
│   └── invalid_http_inputs.json          # 9 adet negatif sınır durumu ve bozuk girdi
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt            # 14/14 PASS birim test çıktıları
│   │   ├── komut_ve_cikis.txt            # Terminal çalıştırma ve exit code kaydı
│   │   ├── http_mesaj_ve_guvenlik_raporu.txt # Protokol ve güvenlik analiz raporu
│   │   └── negatif_kontrol_sonuclari.txt # Sınır durumları doğrulama kayıtları
│   └── temsili/
│       └── http_istek_yanit_ve_guvenlik_mimarisi.txt # Temsili ASCII akış ve mimari şeması
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
- Standart kütüphaneler (`re`, `urllib.parse`, `unittest`, `dataclasses`)

### Testleri Çalıştırma
```powershell
python -m unittest portfolio/hafta_09/gun_057/tests/test_http_protocol_analyzer.py -v
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
