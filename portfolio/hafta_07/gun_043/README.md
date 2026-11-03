# G043 — OSI ve TCP/IP Katmanları ve Paket Kapsülleme Mimarisi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](#lisans)
[![Test Durumu](https://img.shields.io/badge/tests-14%20passed-brightgreen?style=flat-square)](#testler)
[![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)](#değerlendirme)

Bu modül, **365 Günlük Siber Güvenlik Müfredatı** kapsamında Hafta 07 / Gün 043 için hazırlanmış **"OSI ve TCP/IP Modelinin Katmanları"** laboratuvar çalışmasını ve paket denetim motorunu içermektedir. Bu gün ile birlikte **Aşama 03: Ağ Temelleri ve Ağ Güvenliği** başlamıştır.

---

## 🎯 Hedefler ve Kapsam
1. **OSI ve TCP/IP Modellerinin Eşleşmesi:** 7 katmanlı kavramsal OSI referans modeli ile 4 katmanlı pratik TCP/IP yığını arasındaki ilişkilerin analizi.
2. **Paket Kapsülleme (Encapsulation) Süreci:** Bir HTTPS isteğinin (HTTP/2 + TLS 1.3) uygulama katmanından fiziksel katmana kadar paketlenme ve başlık eklenme adımları.
3. **Denetim ve Ayrıştırma Motoru:** MAC, IP, TCP port/bayrak ve TLS şifreleme doğrulaması yapan `osi_tcpip_packet_inspector.py` uygulaması.
4. **Katman Bazlı Güvenlik Tehditleri:** L2 ARP zehirlenmesinden L7 web saldırılarına kadar her katmanın saldırı yüzeyi ve savunma mekanizmaları.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_07/gun_043/
├── README.md                                         # Modül tanıtım ve kullanım rehberi
├── ders.md                                           # Usta-Çırak pedagojisiyle teorik ders anlatımı
├── soru_cevap.md                                     # G043-SC1, SC2, SC3 soruları ve detaylı çözümler
├── rapor.md                                          # 100/100 değerlendirme ve rubrik raporu
├── sonuc.json                                        # Standartlaştırılmış sonuç dosyası
├── manifest.json                                     # Dosya SHA256 bütünlük imzaları
├── uygulama/
│   ├── __init__.py                                   # Python paket tanımı
│   └── osi_tcpip_packet_inspector.py                 # Paket denetim, doğrulama ve model eşleme motoru
├── tests/
│   ├── __init__.py                                   # Python test paketi tanımı
│   └── test_osi_tcpip_packet_inspector.py            # 14 adet birim ve negatif test içeren test süiti
├── ornek_veri/
│   ├── sample_https_encapsulation.json               # 7 katmanlı HTTPS paket kapsülleme referans verisi
│   └── corrupted_encapsulation_cases.json            # Negatif kontrol test girdileri
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                        # Unittest çıktısı (14/14 PASS)
    │   ├── komut_ve_cikis.txt                        # Terminal yürütme kaydı
    │   ├── katman_ve_paket_ayristirma_raporu.txt     # Paket ayrıştırma ve katman raporu
    │   └── negatif_kontrol_sonuclari.txt             # Negatif testlerin doğrulama günlüğü
    └── temsili/
        └── osi_tcpip_kapsulleme_mimarisi.txt         # 7 katmanlı kapsülleme akış şeması
```

---

## 🚀 Hızlı Başlangıç

### 1. Paket Denetim Motorunu Çalıştırma
```powershell
python portfolio/hafta_07/gun_043/uygulama/osi_tcpip_packet_inspector.py --packet-input portfolio/hafta_07/gun_043/ornek_veri/sample_https_encapsulation.json
```

### 2. Raporu Dosyaya Kaydetme
```powershell
python portfolio/hafta_07/gun_043/uygulama/osi_tcpip_packet_inspector.py --packet-input portfolio/hafta_07/gun_043/ornek_veri/sample_https_encapsulation.json --output portfolio/hafta_07/gun_043/kanit/gercek/katman_ve_paket_ayristirma_raporu.txt
```

---

## 🧪 Testler

Test süiti 14 adet birim ve negatif kontrol testini içerir:
- Geçerli HTTPS kapsülleme JSON doğrulaması
- 7 OSI katmanının varlık kontrolü
- 4 katmanlı TCP/IP modeli haritalandırması
- IPv4 oktet sınır kontrolleri
- MAC adresi biçim denetimi
- Port ve TCP bayrak testleri
- Negatif Kontroller: Oktet taşması, geçersiz MAC, taşan port, geçersiz TCP bayrağı, eksik katman.

Testleri çalıştırmak için:
```powershell
python -m unittest discover -s portfolio/hafta_07/gun_043/tests -v
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
