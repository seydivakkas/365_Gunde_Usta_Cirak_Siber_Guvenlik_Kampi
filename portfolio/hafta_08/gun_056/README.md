# Gün 056: Mini Proje 7 — Protokol Haritası ve Paket Çözümleme Çalışma Kitabı

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Tests: 14/14 Passed](https://img.shields.io/badge/tests-14%2F14%20passed-brightgreen?style=flat-square)](kanit/gercek/test_sonuclari.txt)
[![Score: 100/100](https://img.shields.io/badge/score-100%2F100%20PASS-blue?style=flat-square)](rapor.md)

---

## 📌 Proje Genel Bakışı

Bu çalışma, **365 Gün Siber Güvenlik ve Ağ Uzmanlığı Müfredatı** kapsamında 56. gün çalışması ve **Hafta 08 (Taşıma ve Uygulama Katmanı Protokolleri) Kapanış Mini Projesi** olarak geliştirilmiştir. Katman-2 Ethernet, Katman-3 IPv4, Katman-4 TCP/UDP ve Katman-7 DNS/DHCP/HTTP protokollerini ikili (binary) düzeyde çözümler, ağın Protokol Dağılım Hiyerarşisini (Protocol Hierarchy) çıkarır, 5'li demet (5-tuple) iletişim akış matrisini oluşturur, TCP oturum durumlarını ve yeniden iletimlerini (retransmission) izler; Port Tarama, DNS Tünelleme ve Sahte DHCP saldırılarını otomatik tespit eder.

---

## 📁 Dizin Yapısı

```
gun_056/
├── uygulama/
│   ├── __init__.py
│   └── protocol_map_analyzer.py          # Çok katmanlı çözümleyici, akış matrisi ve tehdit avcısı
├── tests/
│   ├── __init__.py
│   └── test_protocol_map_analyzer.py     # 14 adet birim, entegrasyon ve negatif güvenlik testi
├── ornek_veri/
│   ├── sample_pcap_frames.json           # L2-L7 gerçekçi paket akışı ve anomali çerçeveleri
│   └── invalid_protocol_inputs.json      # 9 adet negatif sınır durumu ve bozuk girdi
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt            # 14/14 PASS birim test çıktıları
│   │   ├── komut_ve_cikis.txt            # Terminal çalıştırma ve exit code kaydı
│   │   ├── protokol_haritasi_ve_analiz_raporu.txt # Protokol hiyerarşisi ve akış matrisi raporu
│   │   └── negatif_kontrol_sonuclari.txt # Sınır durumları doğrulama kayıtları
│   └── temsili/
│       └── protokol_hiyerarsisi_ve_is_akisi.txt # Temsili ASCII akış ve mimari şeması
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
- Standart kütüphaneler (`struct`, `ipaddress`, `math`, `time`, `unittest`, `dataclasses`)

### Testleri Çalıştırma
```powershell
python -m unittest portfolio/hafta_08/gun_056/tests/test_protocol_map_analyzer.py -v
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
