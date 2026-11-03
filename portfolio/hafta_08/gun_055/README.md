# Gün 055: DHCP ve IP Ataması — Protokol Mimarisi ve Güvenlik Denetleyicisi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Tests: 14/14 Passed](https://img.shields.io/badge/tests-14%2F14%20passed-brightgreen?style=flat-square)](kanit/gercek/test_sonuclari.txt)
[![Score: 100/100](https://img.shields.io/badge/score-100%2F100%20PASS-blue?style=flat-square)](rapor.md)

---

## 📌 Proje Genel Bakışı

Bu çalışma, **365 Gün Siber Güvenlik ve Ağ Uzmanlığı Müfredatı** kapsamında 55. gün çalışması olarak geliştirilmiştir. RFC 2131 ve RFC 2132 standartlarına tam uyumlu 236 baytlık BOOTP başlığı + 4 bayt Magic Cookie + TLV seçeneklerinin ikili (binary) düzeyde paketlenmesi, ayrıştırılması, DORA (Discover, Offer, Request, ACK) yaşam döngüsü, IP kiralama havuzu, Sahte (Rogue) DHCP sunucusu tespiti, DHCP Starvation DoS saldırısı engelleme ve L2 DHCP Snooping kurallarını içerir.

---

## 📁 Dizin Yapısı

```
gun_055/
├── uygulama/
│   ├── __init__.py
│   └── dhcp_protocol_allocator.py        # 236B BOOTP, DORA, Rogue, Starvation & Snooping motoru
├── tests/
│   ├── __init__.py
│   └── test_dhcp_protocol_allocator.py   # 14 adet birim, entegrasyon ve negatif güvenlik testi
├── ornek_veri/
│   ├── sample_dhcp_packets.json          # DORA, Rogue ve Starvation test paketleri
│   └── invalid_dhcp_inputs.json          # 9 adet negatif sınır durumu ve bozuk girdi
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt            # 14/14 PASS birim test çıktıları
│   │   ├── komut_ve_cikis.txt            # Terminal çalıştırma ve exit code kaydı
│   │   ├── dhcp_protokol_ve_guvenlik_raporu.txt # Protokol ve güvenlik analiz raporu
│   │   └── negatif_kontrol_sonuclari.txt # Sınır durumları doğrulama kayıtları
│   └── temsili/
│       └── dhcp_dora_ve_saldiri_savunma_mimarisi.txt # Temsili ASCII akış ve mimari şeması
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
- Standart kütüphaneler (`struct`, `ipaddress`, `time`, `unittest`, `dataclasses`)

### Testleri Çalıştırma
```powershell
python -m unittest portfolio/hafta_08/gun_055/tests/test_dhcp_protocol_allocator.py -v
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
