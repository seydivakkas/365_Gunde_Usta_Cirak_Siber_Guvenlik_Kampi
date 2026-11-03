# Gün 150: Disk Şifreleme ve TPM 2.0 Güvenlik Mimarisi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](#lisans)
[![Test Durumu](https://img.shields.io/badge/tests-15%2F15%20PASS-brightgreen?style=flat-square)](kanit/gercek/test_sonuclari.txt)
[![Negatif Kontrol](https://img.shields.io/badge/negatif%20kontrol-9%2F9%20PASS-brightgreen?style=flat-square)](kanit/gercek/negatif_kontrol_sonuclari.txt)
[![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)](rapor.md)

---

## 📖 Genel Bakış

Bu modül, **365 Günlük Siber Güvenlik Usta-Çırak Kampı** kapsamında, uç nokta cihazlarda hareketsiz verinin (Data at Rest) korunmasını sağlayan **Tam Disk Şifreleme (Full Disk Encryption - FDE)** ve **Güvenilir Platform Modülü (TPM 2.0)** donanım güvenlik mimarisini inceleyen derinlemesine bir mühendislik çalışmasıdır.

Çalışma kapsamında; **Windows BitLocker (XTS-AES-256)** ve **Linux LUKS2 (dm-crypt + Argon2id)** mimarileri, TPM 2.0 Platform Yapılandırma Kaydedicileri (PCR 0-23) extend zinciri, donanım mühürleme (Sealing / Unsealing) politikaları ile fiziksel temas atakları (**Evil Maid**, **SPI/LPC Bus Sniffing**, **Thunderbolt DMA Attacks**) modellenmiş, denetlenmiş ve doğrulanmıştır.

---

## 🏛️ Mimari ve Dizin Yapısı

```
portfolio/hafta_22/gun_150/
├── ders.md                              # Usta-Çırak derinlemesine teknik eğitim notları
├── soru_cevap.md                        # 3 kapsamlı senaryo ve soru-cevap analizi
├── rapor.md                             # 100/100 PASS başarı karnesi ve denetim raporu
├── README.md                            # Proje tanıtımı ve lisans beyanı
├── sonuc.json                           # Yapılandırılmış sonuç özeti
├── manifest.json                        # SHA-256 dosya bütünlük doğrulaması
├── kanit_uretici.py                     # Kanıtları üreten otomasyon betiği
├── uygulama/                            # Üretim seviyesi motor ve CLI aracı
│   ├── __init__.py
│   ├── disk_encryption_tpm_engine.py    # FDE denetim ve TPM 2.0 simülasyon motoru
│   └── disk_encryption_cli.py           # Komut satırı yönetim ve saldırı simülasyon aracı
├── tests/                               # 15 birim testi
│   ├── __init__.py
│   └── test_disk_encryption_tpm.py
├── ornek_veri/                          # Test ve profil verileri
│   ├── clean_disk_encryption_spec.json  # Sertleştirilmiş BitLocker + TPM 2.0 spesifikasyonu
│   └── invalid_encryption_scenarios.json# 9 negatif kontrol ve atak senaryosu
└── kanit/                               # Gerçek ve temsili kanıt belgeleri
    ├── gercek/
    │   ├── test_sonuclari.txt           # 15/15 birim test çıktısı
    │   ├── negatif_kontrol_sonuclari.txt# 9/9 negatif senaryo tespit çıktısı
    │   ├── disk_encryption_audit_report.json # NIST/CIS güvenlik denetim raporu
    │   ├── tpm_pcr_measurements.json    # TPM 2.0 PCR ölçüm dökümü
    │   ├── bitlocker_hardening_remediation.ps1 # Windows BitLocker sertleştirme betiği
    │   └── komut_ve_cikis.txt           # CLI konsol günlüğü
    └── temsili/
        └── tpm_fde_mimarisi.txt         # ASCII formatında temsili mimari şeması
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

### 2. Disk Şifreleme ve TPM Politikasını Denetleme
```bash
python uygulama/disk_encryption_cli.py audit --config ornek_veri/clean_disk_encryption_spec.json
```

### 3. Evil Maid ve Donanım Saldırısı Simülasyonu
```bash
# Önyükleyici manipülasyonu (PCR 4 bozulması ve TPM kilitlenmesi)
python uygulama/disk_encryption_cli.py simulate-attack --attack-type evil_maid --with-pin

# Güvenli Önyükleme kapatma (PCR 7 bozulması)
python uygulama/disk_encryption_cli.py simulate-attack --attack-type disable_secure_boot --with-pin
```

### 4. PowerShell BitLocker Sertleştirme Betiği Üretme
```bash
python uygulama/disk_encryption_cli.py generate-remediation --os-type windows --drive C:
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
