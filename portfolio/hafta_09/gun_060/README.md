# G060: HTTP/2 ve HTTP/3 Farkları

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

Bu çalışma, **Siber Güvenlik 365 Gün Müfredat Paketi** kapsamındaki 60. gün çalışmasıdır. Konu: **HTTP/2 ve HTTP/3 Farkları**.

Çalışma kapsamında RFC 7540 / RFC 9113 (HTTP/2), RFC 9000 (QUIC) ve RFC 9114 (HTTP/3) standartları doğrultusunda; 9 baytlık HTTP/2 ikili çerçeveleme (binary framing) katmanı ayrıştırılmış, TCP Hat Başı Tıkanması (TCP Head-of-Line Blocking) ile QUIC bağımsız akış mimarisi simüle edilmiş, CVE-2023-44487 Rapid Reset DDoS saldırısı tespit motoru ve RFC 9000 3x Anti-Amplification sınır denetleyicisi geliştirilmiştir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_09/gun_060/
├── README.md                                # Proje tanıtım ve lisans dokümanı
├── ders.md                                  # Kapsamlı hoca-çırak ders notu
├── soru_cevap.md                            # 3 derin teknik soru ve 4 alt başlıklı cevapları
├── rapor.md                                 # Günlük değerlendirme ve 100/100 rubrik raporu
├── sonuc.json                               # Standart makine tarafından okunabilir sonuç dosyası
├── manifest.json                            # SHA-256 bütünlük özeti
├── ornek_veri/
│   ├── sample_frames_and_quic.json          # HTTP/2 çerçeveleri ve QUIC senaryoları
│   └── invalid_h2_h3_inputs.json            # 9 negatif sınır değer ve saldırı senaryosu
├── uygulama/
│   ├── __init__.py                          # Paket başlatıcı
│   └── http2_http3_analyzer.py              # İkili çerçeveleme, HoL ve güvenlik analiz motoru
├── tests/
│   ├── __init__.py                          # Test başlatıcı
│   └── test_http2_http3_analyzer.py         # 14 birim testten oluşan kapsamlı test paketi
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt               # 14/14 PASS birim test çalıştırma çıktısı
    │   ├── komut_ve_cikis.txt               # Ortam, komut ve dönüş kodu kanıtı
    │   ├── http2_http3_karsilastirma_raporu.txt # Protokol ve güvenlik karşılaştırma raporu
    │   └── negatif_kontrol_sonuclari.txt    # 9/9 negatif test doğrulama çıktısı
    └── temsili/
        └── http2_http3_quic_mimarisi.txt    # Çoklama, HoL ve Rapid Reset mimari illüstrasyonu
```

---

## 🚀 Çalıştırma ve Doğrulama Talimatları

### Birim Testlerini Çalıştırma
```bash
python -m unittest portfolio.hafta_09.gun_060.tests.test_http2_http3_analyzer -v
```

### Negatif ve Güvenlik Testlerini Doğrulama
```bash
python -c "
import json
from pathlib import Path
from portfolio.hafta_09.gun_060.uygulama.http2_http3_analyzer import *
# Negatif kontroller uzerinde dogrulama
"
```

---
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
ÖZEL LİSANS — Yalnızca görüntüleme ve eğitim amaçlıdır.
