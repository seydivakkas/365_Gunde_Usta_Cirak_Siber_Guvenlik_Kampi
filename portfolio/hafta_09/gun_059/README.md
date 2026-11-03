# G059: HTTPS ve TLS El Sıkışması (Handshake)

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

Bu çalışma, **Siber Güvenlik 365 Gün Müfredat Paketi** kapsamındaki 59. gün çalışmasıdır. Konu: **HTTPS ve TLS El Sıkışması (TLS Handshake)**.

Çalışma kapsamında RFC 5246 (TLS 1.2), RFC 8446 (TLS 1.3), RFC 6066 (SNI) ve RFC 2818 (HTTPS) standartlarına tam uyumlu bir TLS analiz ve güvenlik motoru geliştirilmiştir. İkili (binary) düzeyde 5 baytlık TLS Record Layer başlığı ayrıştırılmış, 1-RTT ve 2-RTT gecikme farkları modellenmiş, Kusursuz İletme Gizliliği (PFS) ve RFC 8446 sürüm düşürme (downgrade) sentinel koruması hayata geçirilmiştir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_09/gun_059/
├── README.md                                # Proje tanıtım ve lisans dokümanı
├── ders.md                                  # Kapsamlı hoca-çırak ders notu
├── soru_cevap.md                            # 3 derin teknik soru ve 4 alt başlıklı cevapları
├── rapor.md                                 # Günlük değerlendirme ve 100/100 rubrik raporu
├── sonuc.json                               # Standart makine tarafından okunabilir sonuç dosyası
├── manifest.json                            # SHA-256 bütünlük özeti
├── ornek_veri/
│   ├── sample_tls_handshake.json            # 5 pozitif TLS el sıkışma ve senaryo verisi
│   └── invalid_tls_inputs.json              # 9 negatif sınır değer ve saldırı senaryosu
├── uygulama/
│   ├── __init__.py                          # Paket başlatıcı
│   └── tls_handshake_analyzer.py            # TLS Record Layer ve El Sıkışma güvenlik motoru
├── tests/
│   ├── __init__.py                          # Test başlatıcı
│   └── test_tls_handshake_analyzer.py       # 14 birim testten oluşan kapsamlı test paketi
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt               # 14/14 PASS birim test çalıştırma çıktısı
    │   ├── komut_ve_cikis.txt               # Ortam, komut ve dönüş kodu kanıtı
    │   ├── tls_el_sikisma_raporu.txt        # Detaylı protokol analiz raporu
    │   └── negatif_kontrol_sonuclari.txt    # 9/9 negatif sınır test doğrulama çıktısı
    └── temsili/
        └── tls_el_sikisma_ve_guvenlik_mimarisi.txt # TLS el sıkışma mimarisi metin illüstrasyonu
```

---

## 🚀 Çalıştırma ve Doğrulama Talimatları

### Birim Testlerini Çalıştırma
```bash
python -m unittest portfolio.hafta_09.gun_059.tests.test_tls_handshake_analyzer -v
```

### Negatif ve Sınır Değer Testlerini Doğrulama
```bash
python -c "
import json
from pathlib import Path
from portfolio.hafta_09.gun_059.uygulama.tls_handshake_analyzer import *
# Negatif test senaryolari uzerinde dogrulama
"
```

---
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
ÖZEL LİSANS — Yalnızca görüntüleme ve eğitim amaçlıdır.
