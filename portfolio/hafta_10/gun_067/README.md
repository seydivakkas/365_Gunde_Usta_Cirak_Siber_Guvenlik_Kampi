# G067: Paket Kaybı, Gecikme ve Jitter Ağ Performans Analiz Motoru

![Lisans: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama: 03](https://img.shields.io/badge/A%C5%9Fama-03%20A%C4%9F%20G%C3%BCvenli%C4%9Fi-blue?style=flat-square)
![Hafta: 10](https://img.shields.io/badge/Hafta-10-green?style=flat-square)
![Test: 14/14 PASS](https://img.shields.io/badge/Test-14%2F14%20PASS-brightgreen?style=flat-square)
![Not: 100/100](https://img.shields.io/badge/Not-100%2F100-success?style=flat-square)

---

## 📌 Proje Genel Bakışı

Bu proje, kurumsal ağlarda ve telekomünikasyon altyapılarında ağ performansını ve hizmet kalitesini (QoS) denetleyen; paket kaybı (Packet Loss), tek yönlü gecikme (One-Way Delay), gidiş-dönüş süresi (RTT), gecikme değişimi (Jitter - RFC 3393 / RFC 3550) ve TCP yeniden iletimlerini (Retransmissions) derinlemesine analiz eden bir performans ve güvenlik motorudur.

Sistem, VoIP/RTP ses trafiği ve TCP veri transferi telemetrilerini ayrıştırır; ITU-T G.114 standartları çerçevesinde SLA uyumluluğunu değerlendirir ve DoS saldırısı veya ağ tıkanıklığı gibi anomalileri tespit eder.

---

## 🛠️ Temel Yetenekler ve Teknik Mimarisi

- **Tek Yönlü Gecikme (OWD):** Paketin gönderim ve varış zaman damgaları arasındaki mikrosaniye hassasiyetli gecikme hesabı ($T_{recv} - T_{send}$).
- **RTT (Round Trip Time):** TCP segment gönderimi ile ACK onayının varışı arasındaki süre.
- **Jitter Analizi:**
  - RFC 3393 uyarınca Paketler Arası Gecikme Farkı (IPDV - Mean Absolute Jitter).
  - RFC 3550 standardı uyarınca düşük geçirgen filtreli smoothed jitter hesabı.
- **Paket Kaybı Tespiti:** Ardışık sıra numarası boşluklarından kayıp paket sayısı ve yüzde oranının çıkarılması.
- **TCP Retransmission Tespiti:** Tekrarlanan segmentlerin tespiti ve yeniden iletim oranı analizi.
- **QoS SLA Değerlendirmesi:** VoIP (Jitter $\le 30$ ms, Kayıp $\le 3\%$, Gecikme $\le 150$ ms) ve TCP SLA eşik ihlalleri.
- **Siber Tehdit Avcılığı:** DoS/DDoS kaynaklı aşırı paket kaybı (%40+) ve aşırı saat kayması tespiti.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_10/gun_067/
├── uygulama/
│   ├── __init__.py
│   └── network_performance_qos_analyzer.py
├── tests/
│   ├── __init__.py
│   └── test_network_performance_qos_analyzer.py
├── ornek_veri/
│   ├── sample_network_telemetry.json
│   └── invalid_qos_inputs.json
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt
│   │   ├── komut_ve_cikis.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   └── ag_performans_qos_raporu.txt
│   └── temsili/
│       └── qos_jitter_kayip_mimarisi.txt
├── ders.md
├── soru_cevap.md
├── rapor.md
├── sonuc.json
├── manifest.json
└── README.md
```

---

## 🚀 Çalıştırma ve Test

Birim testlerini ve doğrulama paketini çalıştırmak için:

```bash
python -m unittest portfolio.hafta_10.gun_067.tests.test_network_performance_qos_analyzer -v
```

---

## ⚖️ Lisans ve Kullanım Şartları

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
