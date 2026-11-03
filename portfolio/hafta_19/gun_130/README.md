# Gün 130: Windows NTFS Erişim Kontrol Listeleri (ACL / DACL / SACL)

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
![Status: 100/100 PASS](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Tests: 15 Passed](https://img.shields.io/badge/tests-15%2F15%20passed-success?style=flat-square)
![Negative Controls: 9 Passed](https://img.shields.io/badge/negatives-9%2F9%20passed-blue?style=flat-square)

---

## 🔒 Lisans ve Telif Hakkı Bildirimi

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

## 📌 Proje Genel Bakışı

Bu proje; Windows NTFS dosya sistemlerinde Güvenlik Tanımlayıcıları (Security Descriptors), İsteğe Bağlı Erişim Denetim Listeleri (DACL), Sistem Erişim Denetim Listeleri (SACL) ve ACE kurallarının **CIS Microsoft Windows Server / 11 Benchmark (Section 18/19)** ve **MITRE ATT&CK T1574.009 / T1068** standartlarına göre derinlemesine teftişini, duruş analizi puanlamasını ve `icacls` / PowerShell tabanlı otomatik sertleştirmesini gerçekleştirir.

### Kapsanan Temel Güvenlik Mekanizmaları
- **DACL İzin Analizi:** Sistem ikililerinde ve `Program Files` dizinlerinde zayıf yazma/değiştirme izinleri (`CWE-732 / CWE-276`).
- **Unquoted Service Path Koruması:** Boşluklu servis yollarında yazılabilir üst dizin zaaflarının tespiti (`CWE-428 / MITRE T1574.009`).
- **Kanonik ACE Sıralaması:** Explicit Deny -> Explicit Allow -> Inherited Deny -> Inherited Allow kural sırasının denetimi (`CWE-284`).
- **Sahiplik Yönetimi:** Sistem dosyalarında standart kullanıcı sahipliğinin tespiti ve `takeown` ile Administrators grubuna devri (`CWE-284`).
- **icacls & PowerShell Reçeteleri:** Miras kırma (`/inheritance:r`), izin sıfırlama (`/grant:r`) ve yetkisiz grup temizleme (`/remove:g`).

---

## 📁 Dizin Yapısı

```
portfolio/hafta_19/gun_130/
├── uygulama/
│   ├── __init__.py
│   ├── ntfs_acl_engine.py          # Çekirdek NTFS ACL denetim ve puanlama motoru
│   └── ntfs_cli.py                 # CLI yönetim aracı (audit, remediate, ace-help)
├── tests/
│   ├── __init__.py
│   └── test_ntfs_acl.py            # 15 kapsamlı birim testi (100% PASS, 0.002s)
├── ornek_veri/
│   ├── ntfs_baseline_spec.json     # Gerçekçi kurumsal dosya sistemi yapılandırma örneği
│   └── invalid_ntfs_scenarios.json # 9 negatif zaaf senaryosu (CWE-732, 276, 428...)
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt      # 15 testin detaylı koşum çıktısı
│   │   ├── negatif_kontrol_sonuclari.txt # 9 negatif testin doğrulama kütüğü
│   │   ├── komut_ve_cikis.txt      # CLI komutları ve terminal çıktıları
│   │   └── ntfs_denetim_raporu.md  # Otomatik üretilen teftiş raporu
│   └── temsili/
│       └── ntfs_mimarisi.txt       # Temsili mimari diyagramı
├── kanit_uretici.py                # Doğrulama ve kanıt üretim orkestratörü
├── ders.md                         # Usta-Çırak / Hoca Dersi teorik anlatımı
├── soru_cevap.md                   # 3 derin teknik soru ve 4 zorunlu alt başlıklı cevapları
├── rapor.md                        # 100/100 PASS başarı karnesi
├── sonuc.json                      # Makine tarafından okunabilir sonuç özeti
├── manifest.json                   # Paket dosya listesi ve SHA-256 hash'leri
└── README.md                       # Dokümantasyon ve lisans bildirimi
```

---

## 🚀 Hızlı Kullanım (CLI)

### 1. icacls İzin Maskeleri ve Miras Bayraklarını İnceleme
```bash
python uygulama/ntfs_cli.py ace-help
```

### 2. Dosya Sistemi İzin Duruşunu Denetleme (Markdown Çıktısı)
```bash
python uygulama/ntfs_cli.py audit --spec ornek_veri/ntfs_baseline_spec.json --format markdown
```

### 3. Otomatik icacls/PowerShell Sıkılaştırma Betiği Üretme
```bash
python uygulama/ntfs_cli.py remediate --spec ornek_veri/ntfs_baseline_spec.json --out harden_ntfs.ps1
```

---

## 🧪 Birim Testler ve Kanıt Üretimi

Tüm testleri ve kanıt üretimini tek adımda çalıştırmak için:
```bash
python kanit_uretici.py
```
Testler tamamen bağımsız Python standart kütüphanesiyle (< 0.01 sn) çalışır.
