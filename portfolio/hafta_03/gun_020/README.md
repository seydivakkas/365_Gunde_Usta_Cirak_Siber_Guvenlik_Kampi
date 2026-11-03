# Gün 020: Linux Dosya Ağacı ve FHS (Filesystem Hierarchy Standard) Güvenlik Denetimi

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama](https://img.shields.io/badge/Aşama-02%20Sistem%20ve%20Ağ%20Temelleri-blue?style=flat-square)
![Hafta](https://img.shields.io/badge/Hafta-03%20İşletim%20Sistemi%20Temelleri-green?style=flat-square)
![Test Durumu](https://img.shields.io/badge/Testler-14%2F14%20PASS-brightgreen?style=flat-square)
![Puan](https://img.shields.io/badge/Puan-100%2F100-success?style=flat-square)

---

## 📖 Genel Bakış

Bu modül, Siber Güvenlik 365 Gün Müfredatı'nın **Aşama 02 / Hafta 03 / Gün 020** çalışmasıdır. Linux dosya sistemi hiyerarşisi standardı (**FHS 3.0**), tek kök (`/`) mimarisi, çekirdek FHS dizinleri (`/etc`, `/var`, `/home`, `/tmp`, `/dev`, `/proc`), Sticky Bit (`+t`), mount sertleştirme bayrakları (`nodev`, `nosuid`, `noexec`) ve kritik sistem dosyalarının (`/etc/shadow`, `/etc/sudoers`) izin denetimlerini kapsamlı olarak inceler.

Proje kapsamında geliştirilen `linux_fhs_hierarchy_auditor.py` aracı hem canlı sistem ortamı bağlamını sorgulayabilir hem de bağımsız JSON haritaları üzerinden CIS Linux Benchmark ve NIST SP 800-53 uyumluluk denetimlerini icra eder.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_03/gun_020/
├── README.md                                  # Bu tanıtım ve kullanım dokümanı
├── ders.md                                    # 7 bölümlük kapsamlı usta-çırak ders anlatımı
├── soru_cevap.md                              # 4 zorunlu alt başlıklı soru-cevap dokümanı
├── rapor.md                                   # 100/100 puanlı detaylı değerlendirme raporu
├── sonuc.json                                 # 14 standart alanlı makine tarafından okunabilir özet
├── manifest.json                              # SHA-256 bütünlük parmak izleri listesi
├── uygulama/
│   ├── __init__.py                            # Modül tanımlayıcı
│   └── linux_fhs_hierarchy_auditor.py         # Zengin açıklamalı FHS güvenlik denetim motoru
├── tests/
│   ├── __init__.py                            # Test paketi tanımlayıcı
│   └── test_linux_fhs_hierarchy_auditor.py    # 14 birim testten oluşan kapsamlı doğrulama suite
├── ornek_veri/
│   ├── linux_fhs_sample_map.json              # 6 çekirdek dizin, mount ve dosya haritası
│   └── linux_fhs_security_baseline.json       # CIS / NIST tabanlı güvenlik kural seti
└── kanit/
    ├── gercek/
    │   ├── komut_ve_cikis.txt                 # CLI ve gerçek çalıştırma kanıtları
    │   └── test_sonuclari.txt                 # 14/14 test pass yürütme çıktısı
    └── temsili/
        └── linux_fhs_mimarisi.txt             # Zorunlu etiketli mimari ASCII görselleştirmesi
```

---

## 🚀 Çalıştırma ve Test

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest discover -s portfolio/hafta_03/gun_020/tests -p "test_*.py" -v
```

### 2. Güvenlik Denetim Aracını Çalıştırma (Örnek Veri ile)
```bash
python portfolio/hafta_03/gun_020/uygulama/linux_fhs_hierarchy_auditor.py \
  --sample portfolio/hafta_03/gun_020/ornek_veri/linux_fhs_sample_map.json \
  --baseline portfolio/hafta_03/gun_020/ornek_veri/linux_fhs_security_baseline.json
```

### 3. JSON Çıktı Modu
```bash
python portfolio/hafta_03/gun_020/uygulama/linux_fhs_hierarchy_auditor.py \
  --sample portfolio/hafta_03/gun_020/ornek_veri/linux_fhs_sample_map.json \
  --baseline portfolio/hafta_03/gun_020/ornek_veri/linux_fhs_security_baseline.json \
  --json
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
