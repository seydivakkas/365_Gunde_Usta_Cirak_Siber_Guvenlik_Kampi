# Gün 021: Mini Proje 2 — İşletim Sistemi Güvenlik Envanteri (OS Security Inventory Collector)

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama](https://img.shields.io/badge/Aşama-02%20Sistem%20ve%20Ağ%20Temelleri-blue?style=flat-square)
![Hafta](https://img.shields.io/badge/Hafta-03%20İşletim%20Sistemi%20Temelleri-green?style=flat-square)
![Test Durumu](https://img.shields.io/badge/Testler-14%2F14%20PASS-brightgreen?style=flat-square)
![Puan](https://img.shields.io/badge/Puan-100%2F100-success?style=flat-square)

---

## 📖 Genel Bakış

Bu modül, Siber Güvenlik 365 Gün Müfredatı'nın **Aşama 02 / Hafta 03 / Gün 021 (Haftalık Mini Proje 2)** çalışmasıdır. CIS Control 1-2 ve NIST SP 800-53 CM-8 standartları uyarınca, Windows ve Linux işletim sistemleri üzerinde 5 temel güvenlik boyutunu (sürüm/çekirdek, donanım/depolama, hesaplar, servisler ve güncellemeler) kataloglayan, güvenlik duruşunu denetleyen ve karşılaştırmalı analitik CSV raporları üreten kapsamlı bir güvenlik aracı geliştirilmiştir.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_03/gun_021/
├── README.md                                  # Bu tanıtım ve kullanım kılavuzu
├── ders.md                                    # 7 bölümlük kapsamlı usta-çırak mini proje dersi
├── soru_cevap.md                              # 4 zorunlu alt başlıklı soru-cevap dokümanı
├── rapor.md                                   # 100/100 puanlı detaylı değerlendirme raporu
├── sonuc.json                                 # 14 standart alanlı makine tarafından okunabilir özet
├── manifest.json                              # SHA-256 bütünlük parmak izleri listesi
├── uygulama/
│   ├── __init__.py                            # Paket başlatıcı
│   └── os_security_inventory_collector.py     # Zengin açıklamalı envanter ve denetim motoru
├── tests/
│   ├── __init__.py                            # Test paketi başlatıcı
│   └── test_os_security_inventory_collector.py# 14 birim testten oluşan kapsamlı doğrulama suite
├── ornek_veri/
│   ├── os_inventory_windows_sample.json       # Windows Server 2022 örnek güvenlik envanteri
│   ├── os_inventory_linux_sample.json         # Ubuntu 24.04 LTS örnek güvenlik envanteri
│   └── os_inventory_schema.json               # CIS/NIST tabanlı şema ve karaliste kuralları
└── kanit/
    ├── gercek/
    │   ├── komut_ve_cikis.txt                 # CLI ve gerçek çalıştırma kanıtları
    │   ├── test_sonuclari.txt                 # 14/14 test pass yürütme çıktısı
    │   └── karsilastirmali_os_envanter.csv    # Üretilen 5 kolonlu karşılaştırmalı CSV matrisi
    └── temsili/
        └── os_envanter_mimarisi.txt           # Zorunlu etiketli mimari ASCII görselleştirmesi
```

---

## 🚀 Çalıştırma ve Test

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest discover -s portfolio/hafta_03/gun_021/tests -p "test_*.py" -v
```

### 2. Karşılaştırmalı CSV ve Güvenlik Raporu Üretimi (G021-SC2)
```bash
python portfolio/hafta_03/gun_021/uygulama/os_security_inventory_collector.py \
  --windows portfolio/hafta_03/gun_021/ornek_veri/os_inventory_windows_sample.json \
  --linux portfolio/hafta_03/gun_021/ornek_veri/os_inventory_linux_sample.json \
  --schema portfolio/hafta_03/gun_021/ornek_veri/os_inventory_schema.json \
  --csv portfolio/hafta_03/gun_021/kanit/gercek/karsilastirmali_os_envanter.csv
```

### 3. Canlı Sistem Envanteri Sorgulama
```bash
python portfolio/hafta_03/gun_021/uygulama/os_security_inventory_collector.py --live
```

---

## 🔒 Lisans

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
