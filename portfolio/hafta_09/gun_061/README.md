# G061: Proxy, NAT ve Güvenlik Duvarı

![Lisans: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama: 03 Ağ Temelleri](https://img.shields.io/badge/A%C5%9Fama-03%20A%C4%9F%20Temelleri-blue?style=flat-square)
![Hafta: 09 Web Protokolleri](https://img.shields.io/badge/Hafta-09%20Web%20Protokolleri-green?style=flat-square)
![Test Durumu: PASS](https://img.shields.io/badge/Test-14%2F14%20PASS-brightgreen?style=flat-square)

---

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

## 📖 Genel Bakış

Bu çalışma, **Siber Güvenlik 365 Gün Müfredat Paketi** kapsamındaki 61. gün çalışmasıdır. Konu: **Proxy, NAT ve Güvenlik Duvarı**.

Çalışma kapsamında RFC 793 (TCP), RFC 1918 (Özel IP), RFC 3022 (PAT/NAPT) ve RFC 7239 (Forwarded) standartları doğrultusunda; durum takipli (Stateful / Conntrack) güvenlik duvarı kural motoru, Port Adres Dönüşümü (PAT) havuzu, İleri ve Ters vekil sunucu mekanizmaları ile X-Forwarded-For IP sahteciliği ve gizli TCP tarama (SYN+FIN, Null Scan, Xmas Scan) savunmaları modellenmiştir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_09/gun_061/
├── README.md                                # Proje tanıtım ve lisans dokümanı
├── ders.md                                  # Kapsamlı hoca-çırak ders notu
├── soru_cevap.md                            # 3 derin teknik soru ve 4 alt başlıklı cevapları
├── rapor.md                                 # Günlük değerlendirme ve 100/100 rubrik raporu
├── sonuc.json                               # Standart makine tarafından okunabilir sonuç dosyası
├── manifest.json                            # SHA-256 bütünlük özeti
├── ornek_veri/
│   ├── sample_network_rules.json            # Ağ kuralları, PAT ve vekil yapılandırması
│   └── invalid_traffic_inputs.json          # 9 negatif sınır değer ve saldırı senaryosu
├── uygulama/
│   ├── __init__.py                          # Paket başlatıcı
│   └── proxy_nat_firewall_engine.py         # Conntrack, PAT ve Proxy simülasyon motoru
├── tests/
│   ├── __init__.py                          # Test başlatıcı
│   └── test_proxy_nat_firewall_engine.py    # 14 birim testten oluşan kapsamlı test paketi
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt               # 14/14 PASS birim test çalıştırma çıktısı
    │   ├── komut_ve_cikis.txt               # Ortam, komut ve dönüş kodu kanıtı
    │   ├── proxy_nat_guvenlik_duvari_raporu.txt # Protokol ve güvenlik analiz raporu
    │   └── negatif_kontrol_sonuclari.txt    # 9/9 negatif test doğrulama çıktısı
    └── temsili/
        └── proxy_nat_firewall_mimarisi.txt  # Topoloji, conntrack ve PAT mimari çizimi
```

---

## 🚀 Çalıştırma ve Doğrulama Talimatları

### Birim Testlerini Çalıştırma
```bash
python -m unittest portfolio.hafta_09.gun_061.tests.test_proxy_nat_firewall_engine -v
```

### Negatif ve Güvenlik Testlerini Doğrulama
```bash
python -c "
import json
from pathlib import Path
from portfolio.hafta_09.gun_061.uygulama.proxy_nat_firewall_engine import *
# Negatif kontroller uzerinde dogrulama
"
```

---
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
ÖZEL LİSANS — Yalnızca görüntüleme ve eğitim amaçlıdır.
