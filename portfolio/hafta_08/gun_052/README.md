# Gün 052: UDP ve Kullanım Alanları

![Lisans: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Durum: Tamamlandı](https://img.shields.io/badge/durum-Tamamland%C4%B1-brightgreen?style=flat-square)
![Puan: 100/100](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)
![Aşama: 03](https://img.shields.io/badge/a%C5%9Fama-03-orange?style=flat-square)
![Hafta: 08](https://img.shields.io/badge/hafta-08-yellow?style=flat-square)

---

## 🔒 Özel Lisans Bildirimi

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

---

## 📌 Proje Genel Bakış

Bu çalışma, **Siber Güvenlik 365 Gün Müfredatı** kapsamında 8. Haftanın 52. Günü için geliştirilmiş bağımsız, yerel çalışan bir **UDP (User Datagram Protocol) Protokol ve Kullanım Alanları Analizörüdür**.

RFC 768 standartlarına uygun olarak 8 baytlık ikili UDP başlığı paketleme, ayrıştırma, IPv4 sahte başlığı (pseudo-header) ile 16-bit birin tümleyeni sağlama toplamı (checksum) hesaplama, DNS ve NTP protokollerinin yük seviyesinde sınıflandırılması, Yansıtma / Amplifikasyon (Reflection DDoS) risk analizi, UDP Flood ve UDP Port Sweep anomali tespiti ile Kaminsky DNS Zehirleme savunması için kaynak port entropisi denetimi gerçekleştirilmektedir.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_08/gun_052/
├── README.md                                           # Proje tanıtımı ve lisans belgesi
├── ders.md                                             # Usta-Çırak pedagojisi ile kapsamlı ders notu
├── soru_cevap.md                                       # Soru bankası (G052-SC1, SC2, SC3) detaylı yanıtları
├── rapor.md                                            # 100/100 rubrik puanlı teknik inceleme raporu
├── sonuc.json                                          # Standartlaştırılmış gün sonuç verisi
├── manifest.json                                       # SHA256 bütünlük özeti
├── uygulama/
│   ├── __init__.py                                     # Paket başlatıcı
│   └── udp_protocol_analyzer.py                        # RFC 768 UDP analizör ve anomali tespit motoru
├── tests/
│   ├── __init__.py                                     # Test başlatıcı
│   └── test_udp_protocol_analyzer.py                   # 14 birim ve negatif test (%100 PASS)
├── ornek_veri/
│   ├── sample_udp_datagrams.json                       # Meşru ve amplifikasyon test paketleri
│   └── invalid_udp_inputs.json                         # 8 adet sınır aşımı ve negatif test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                          # 14/14 PASS birim test konsol çıktısı
    │   ├── komut_ve_cikis.txt                          # Komut çalıştırma ve durum kayıtları
    │   ├── udp_protokol_ve_guvenlik_raporu.txt         # Otomatik protokol sınıflandırma ve BAF raporu
    │   └── negatif_kontrol_sonuclari.txt               # 8/8 engellenen geçersiz paket kanıtları
    └── temsili/
        └── udp_datagram_amplification_ve_savunma_mimarisi.txt # Temsilî mimari ve ASCII diyagramı
```

---

## 🚀 Hızlı Başlangıç ve Çalıştırma

### 1. Birim Testleri Çalıştırma:
```bash
python -m unittest portfolio/hafta_08/gun_052/tests/test_udp_protocol_analyzer.py -v
```

### 2. Örnek Veri ile Analizör Çalıştırma:
```python
from portfolio.hafta_08.gun_052.uygulama.udp_protocol_analyzer import UDPDatagram, UDPProtocolAnalyzer

analyzer = UDPProtocolAnalyzer()
datagram = UDPDatagram.create("192.168.1.100", "8.8.8.8", 54321, 53, b"DNS_QUERY")
classification = analyzer.classify_datagram(datagram)
print(classification)
```

---

## 🛡️ Güvenlik ve Savunma Prensipleri

1. **RFC 2827 / BCP 38 (Ingress Anti-Spoofing):** IP sahteciliğini önlemek adına kenar yönlendiricilerde uRPF zorunluluğu.
2. **Response Rate Limiting (RRL):** DNS amplifikasyonuna karşı yanıt sınırlaması ve istemciyi TCP el sıkışmasına (`TC=1`) zorlama.
3. **Kritik Servis Sıkılaştırma:** NTP `monlist` ve Memcached UDP desteğinin internete tamamen kapatılması.
4. **RFC 5452 SPRs:** Kaminsky DNS zehirleme saldırılarına karşı yüksek entropili rastgele kaynak portu tahsisi.
