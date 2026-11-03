# G044 — Ethernet, MAC ve Çerçeve Yapısı Analiz Laboratuvarı

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](#lisans)
[![Test Durumu](https://img.shields.io/badge/tests-14%20passed-brightgreen?style=flat-square)](#testler)
[![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)](#değerlendirme)

Bu modül, **365 Günlük Siber Güvenlik Müfredatı** kapsamında Hafta 07 / Gün 044 için hazırlanmış **"Ethernet, MAC ve Çerçeve Yapısı"** laboratuvar çalışmasını ve analiz motorunu içermektedir.

---

## 🎯 Hedefler ve Kapsam
1. **Katman 2 (Veri Bağlantısı) Anatomisi:** Standart Ethernet II ve IEEE 802.1Q VLAN etiketli çerçeve başlıklarının alan alan ayrıştırılması.
2. **MAC Adresi Bit Düzeyi Analizi:** 48-bit MAC mimarisi, I/G (Individual/Group) ve U/L (Universal/Local) bitleri, OUI üretici tescili.
3. **Kapsülleme ve Dolgulama (Padding):** Ethernet asgari 64 bayt kuralı ve 46 bayt altındaki veriler için otomatik padding mekanizması.
4. **Katman 2 Tehdit ve Savunmaları:** MAC Flooding, MAC Spoofing, Port Security (Sticky MAC), DAI ve 802.1X mekanizmaları.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_07/gun_044/
├── README.md                                         # Modül tanıtım ve kullanım rehberi
├── ders.md                                           # Usta-Çırak pedagojisiyle teorik ders anlatımı
├── soru_cevap.md                                     # G044-SC1, SC2, SC3 soruları ve detaylı çözümler
├── rapor.md                                          # 100/100 değerlendirme ve rubrik raporu
├── sonuc.json                                        # Standartlaştırılmış sonuç dosyası
├── manifest.json                                     # Dosya SHA256 bütünlük imzaları
├── uygulama/
│   ├── __init__.py                                   # Python paket tanımı
│   └── ethernet_frame_analyzer.py                    # Çerçeve ayrıştırma ve MAC analiz motoru
├── tests/
│   ├── __init__.py                                   # Python test paketi tanımı
│   └── test_ethernet_frame_analyzer.py               # 14 adet birim ve negatif test içeren test süiti
├── ornek_veri/
│   ├── sample_ethernet_frames.json                   # Unicast, Broadcast ve VLAN etiketli örnek çerçeveler
│   └── corrupted_ethernet_frames.json                # Negatif kontrol test girdileri
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                        # Unittest çıktısı (14/14 PASS)
    │   ├── komut_ve_cikis.txt                        # Terminal yürütme kaydı
    │   ├── ethernet_cerceve_analiz_raporu.txt        # Çerçeve analiz ve etiketleme raporu
    │   └── negatif_kontrol_sonuclari.txt             # Negatif testlerin doğrulama günlüğü
    └── temsili/
        └── ethernet_cerceve_mimarisi.txt             # Ethernet II ve 802.1Q çerçeve anatomisi şeması
```

---

## 🚀 Hızlı Başlangıç

### 1. Çerçeve Analiz Motorunu Çalıştırma
```powershell
python portfolio/hafta_07/gun_044/uygulama/ethernet_frame_analyzer.py --frames-input portfolio/hafta_07/gun_044/ornek_veri/sample_ethernet_frames.json
```

### 2. Raporu Dosyaya Kaydetme
```powershell
python portfolio/hafta_07/gun_044/uygulama/ethernet_frame_analyzer.py --frames-input portfolio/hafta_07/gun_044/ornek_veri/sample_ethernet_frames.json --output portfolio/hafta_07/gun_044/kanit/gercek/ethernet_cerceve_analiz_raporu.txt
```

---

## 🧪 Testler

Test süiti 14 adet birim ve negatif kontrol testini içerir:
- Geçerli çerçeve veri seti ayrıştırması
- Unicast, Broadcast (ARP) ve 802.1Q VLAN etiket doğrulamaları
- OUI üretici tescili çözümlemesi
- Asgari 64 bayt sınır ve dolgulama (padding) testleri
- Negatif Kontroller: Multicast kaynak MAC kural ihlali, geçersiz hex MAC, bozuk EtherType, cüce (runt) çerçeve.

Testleri çalıştırmak için:
```powershell
python -m unittest discover -s portfolio/hafta_07/gun_044/tests -v
```

---

## 📜 Lisans

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
