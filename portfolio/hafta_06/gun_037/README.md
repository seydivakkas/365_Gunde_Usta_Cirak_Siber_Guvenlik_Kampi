<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
-->

# Gün 037 — Disk Bölümleri ve Dosya Sistemleri Güvenlik Denetçisi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](https://github.com/seydivakkas)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Status: PASS (100/100)](https://img.shields.io/badge/status-PASS%20(100%2F100)-brightgreen.svg)]()
[![Stage: 02 - Week: 06](https://img.shields.io/badge/Aşama%2002-Hafta%2006-orange.svg)]()

## 📌 Genel Bakış ve Amaç
Bu proje, 365 Günlük Siber Güvenlik Müfredatı'nın **Aşama 02, Hafta 06, Gün 037** modülüdür.
Modern işletim sistemlerinde **Blok Aygıtlar**, **Bölüm Tabloları (MBR vs GPT)**, **Dosya Sistemleri (ext4, NTFS, FAT32)**, **Bağlama Bayrakları (Mount Options: noexec, nosuid, nodev)** ve **Tam Disk Şifreleme (LUKS / BitLocker)** mimarilerini siber güvenlik, adli bilişim ve sistem sertleştirme (hardening) ekseninde denetler.

### 🛡️ Temel Yetenekler
- **Bölüm Tablosu Güvenlik Analizi:** Eski MBR tablolarını (bootkit/rootkit ve sektör 0 manipülasyon riski) tespit eder; modern GPT mimarisini doğrular.
- **Dosya Sistemi İzin Uyumluluğu:** Sunucu ve veri bölümlerinde yetkilendirme (DAC/ACL) desteği bulunmayan güvensiz FAT32/exFAT dosya sistemlerini raporlar.
- **Bağlama Seçenekleri Sertleştirmesi (Mount Hardening):** `/tmp`, `/var/tmp` ve `/dev/shm` geçici dizinlerinde zararlı ikili dosyaların çalıştırılmasını önleyen `noexec`, `nosuid` ve `nodev` bayraklarının varlığını denetler.
- **Tam Disk Şifreleme (FDE):** Hareketsiz verinin (Data-at-Rest) şifrelenme durumunu denetler; şifresiz birimleri **CRITICAL** / **HIGH** seviyesinde raporlar.
- **Kapasite ve DoS Koruması:** %85 üzeri uyarı ve %95 üzeri kritik tükenme eşikleriyle servis çökmesi ve denetim günlüğü kaybı riskini hesaplar.

---

## 📂 Dizin Yapısı
```text
portfolio/hafta_06/gun_037/
├── ders.md                                  # Usta-Çırak pedagojisiyle teorik ve pratik anlatım
├── soru_cevap.md                            # 3 ana soru için 4 zorunlu alt başlıklı detaylı çözümler
├── rapor.md                                 # 20/40/25/15 puanlama rubriği ve değerlendirme raporu
├── README.md                                # Proje genel bakışı, çalıştırma rehberi ve lisans
├── sonuc.json                               # Standart 14 alanlı sonuç ve başarı göstergesi
├── manifest.json                            # Dosya bütünlük karmaları (SHA256)
├── uygulama/
│   ├── __init__.py                          # Paket başlatıcı
│   └── disk_partition_fs_auditor.py         # Satır satır açıklamalı denetçi motoru
├── tests/
│   ├── __init__.py                          # Test paketi başlatıcı
│   └── test_disk_partition_fs_auditor.py    # 14 bağımsız birim test
├── ornek_veri/
│   ├── sample_disk_telemetry.json           # Gerçekçi sistem disk telemetrisi
│   └── corrupted_disk_telemetry_test_cases.json # Negatif kontrol ve bozuk veri testleri
└── kanit/
    ├── gercek/                              # Gerçek icra kanıtları
    │   ├── test_sonuclari.txt
    │   ├── komut_ve_cikis.txt
    │   ├── disk_ve_dosya_sistemi_denetim_raporu.txt
    │   └── negatif_kontrol_sonuclari.txt
    └── temsili/                             # Temsili mimari illüstrasyonları
        └── disk_bolumleri_ve_dosya_sistemi_mimarisi.txt
```

---

## 🚀 Hızlı Başlangıç ve Çalıştırma

### 1. Birim Testleri Koşma
```powershell
python -m unittest portfolio/hafta_06/gun_037/tests/test_disk_partition_fs_auditor.py -v
```

### 2. Uygulamayı Telemetri Verisiyle Çalıştırma
```powershell
python portfolio/hafta_06/gun_037/uygulama/disk_partition_fs_auditor.py --telemetry portfolio/hafta_06/gun_037/ornek_veri/sample_disk_telemetry.json --output portfolio/hafta_06/gun_037/kanit/gercek/disk_ve_dosya_sistemi_denetim_raporu.txt
```

---

## 📜 Özel Lisans Bildirimi

```text
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
