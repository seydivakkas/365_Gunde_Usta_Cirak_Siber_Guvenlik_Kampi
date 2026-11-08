# Gün 151: Yedek Doğrulama, Kurtarma Noktası (RPO/RTO) ve Değiştirilemezlik (WORM) Mimarisi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](#lisans)
[![Test Durumu](https://img.shields.io/badge/tests-15%2F15%20PASS-brightgreen?style=flat-square)](kanit/gercek/test_sonuclari.txt)
[![Negatif Kontrol](https://img.shields.io/badge/negatif%20kontrol-9%2F9%20PASS-brightgreen?style=flat-square)](kanit/gercek/negatif_kontrol_sonuclari.txt)
[![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)](rapor.md)

---

## 📖 Genel Bakış

Bu modül, **365 Günlük Siber Güvenlik Usta-Çırak Kampı** kapsamında, kurumsal iş sürekliliği ve felaket kurtarma süreçlerinde can damarı niteliğinde olan **Yedek Doğrulama**, **Kurtarma Noktası Hedefi (RPO)**, **Kurtarma Süresi Hedefi (RTO)**, **3-2-1-1-0 Standardı** ve **Değiştirilemez Depolama (Immutable Storage / WORM)** mimarisini inceleyen kapsamlı bir mühendislik çalışmasıdır.

Modül kapsamında; **NIST SP 800-209** ve **CIS Control 11** standartları uyarınca yedekleme envanteri denetimi, SHA-256 sağlama toplamı ile sessiz veri bozulması (Bit rot) tespiti, **AWS S3 Object Lock Compliance** modu koruması ve fidye yazılımlarının **Volume Shadow Copy (VSS)** silme ataklarına karşı direnci modellenmiş, test edilmiş ve doğrulanmıştır.

---

## 🏛️ Mimari ve Dizin Yapısı

```
portfolio/hafta_22/gun_151/
├── ders.md                              # Usta-Çırak derinlemesine teknik eğitim notları
├── soru_cevap.md                        # 3 kapsamlı senaryo ve soru-cevap analizi
├── rapor.md                             # 100/100 PASS başarı karnesi ve denetim raporu
├── README.md                            # Proje tanıtımı ve lisans beyanı
├── sonuc.json                           # Yapılandırılmış sonuç özeti
├── manifest.json                        # SHA-256 dosya bütünlük doğrulaması
├── kanit_uretici.py                     # Kanıtları üreten otomasyon betiği
├── uygulama/                            # Üretim seviyesi motor ve CLI aracı
│   ├── __init__.py
│   ├── backup_recovery_engine.py        # Yedek denetim, RPO/RTO ve WORM simülasyon motoru
│   └── backup_recovery_cli.py           # Komut satırı yönetim ve test aracı
├── tests/                               # 15 birim testi
│   ├── __init__.py
│   └── test_backup_recovery.py
├── ornek_veri/                          # Test ve profil verileri
│   ├── clean_backup_recovery_spec.json  # Sertleştirilmiş 3-2-1-1-0 yedek spesifikasyonu
│   └── invalid_backup_scenarios.json    # 9 negatif kontrol ve felaket senaryosu
└── kanit/                               # Gerçek ve temsili kanıt belgeleri
    ├── gercek/
    │   ├── test_sonuclari.txt           # 15/15 birim test çıktısı
    │   ├── negatif_kontrol_sonuclari.txt# 9/9 negatif senaryo tespit çıktısı
    │   ├── backup_recovery_audit_report.json # NIST/CIS güvenlik denetim raporu
    │   ├── simulated_restore_verification.json # Geri yükleme ve SLA doğrulama raporu
    │   ├── immutable_backup_remediation.ps1 # Windows VSS ve sağlama toplamı sertleştirme betiği
    │   └── komut_ve_cikis.txt           # CLI konsol günlüğü
    └── temsili/
        └── yedekleme_kurtarma_mimarisi.txt # ASCII formatında temsili mimari şeması
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

### 2. Yedekleme Mimarisi Denetimi (3-2-1 ve WORM Uyumluluğu)
```bash
python uygulama/backup_recovery_cli.py audit --config ornek_veri/clean_backup_recovery_spec.json
```

### 3. Geri Yükleme ve SLA (RPO/RTO) Simülasyonu
```bash
python uygulama/backup_recovery_cli.py simulate-restore --config ornek_veri/clean_backup_recovery_spec.json
```

### 4. Fidye Yazılımı Yedek İmha Saldırısı Simülasyonu
```bash
python uygulama/backup_recovery_cli.py simulate-ransomware --config ornek_veri/clean_backup_recovery_spec.json
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
