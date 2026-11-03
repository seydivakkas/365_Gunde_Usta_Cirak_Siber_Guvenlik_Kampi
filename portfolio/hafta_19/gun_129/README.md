# Gün 129: Windows Yerel Hesaplar, Gruplar ve UAC Sertleştirmesi

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

Bu proje; kurumsal Windows istemci ve sunucularında Kullanıcı Hesabı Denetimi (UAC), yerel kullanıcı hesapları (Administrator, Guest) ve hassas grup üyeliklerinin **CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 (Bölüm 2.3)** ve **MITRE ATT&CK T1548.002 / T1078.003** standartlarına göre teftişini, duruş analizi puanlamasını ve PowerShell tabanlı otomatik sertleştirmesini gerçekleştirir.

### Kapsanan Temel Güvenlik Mekanizmaları
- **Kullanıcı Hesabı Denetimi (UAC):** `EnableLUA`, `FilterAdministratorToken`, `PromptOnSecureDesktop` denetimleri (`CWE-693 / CWE-250`).
- **Onay Davranışı Politikası:** `ConsentPromptBehaviorAdmin` ve `ConsentPromptBehaviorUser` yapılandırması (`CWE-284`).
- **Yerel Hesap Sertleştirmesi:** Guest hesabı devre dışı bırakma, yerleşik SID 500 yöneticisini yeniden adlandırma (`CWE-1188`).
- **Kaba Kuvvet Koruması:** `AccountLockoutThreshold` ve süre politikaları (`CWE-307`).
- **Hassas Grup Yönetimi:** `Administrators` ve `Remote Desktop Users` gruplarındaki yetkisiz üyelerin tespiti ve temizlenmesi (`CWE-250`).
- **Windows LAPS:** Yerel yönetici parolalarının merkezi ve dinamik rotasyonu (`MITRE T1078.003`).

---

## 📁 Dizin Yapısı

```
portfolio/hafta_19/gun_129/
├── uygulama/
│   ├── __init__.py
│   ├── uac_account_security_engine.py   # Çekirdek teftiş ve sertleştirme motoru
│   └── uac_security_cli.py              # CLI yönetim aracı (audit, remediate, uac-inspect)
├── tests/
│   ├── __init__.py
│   └── test_uac_account_security.py     # 15 kapsamlı birim testi (100% PASS, 0.002s)
├── ornek_veri/
│   ├── uac_account_baseline_spec.json   # Gerçekçi kurumsal istemci yapılandırma örneği
│   └── invalid_uac_scenarios.json       # 9 negatif zaaf senaryosu (CWE-693, 250, 284...)
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt           # 15 testin detaylı koşum çıktısı
│   │   ├── negatif_kontrol_sonuclari.txt # 9 negatif testin doğrulama kütüğü
│   │   ├── komut_ve_cikis.txt           # CLI komutları ve terminal çıktıları
│   │   └── uac_denetim_raporu.md        # Otomatik üretilen teftiş raporu
│   └── temsili/
│       └── uac_mimarisi.txt             # Temsili mimari diyagramı
├── kanit_uretici.py                     # Doğrulama ve kanıt üretim orkestratörü
├── ders.md                              # Usta-Çırak / Hoca Dersi teorik anlatımı
├── soru_cevap.md                        # 3 derin teknik soru ve 4 zorunlu alt başlıklı cevapları
├── rapor.md                             # 100/100 PASS başarı karnesi
├── sonuc.json                           # Makine tarafından okunabilir sonuç özeti
├── manifest.json                        # Paket dosya listesi ve SHA-256 hash'leri
└── README.md                            # Dokümantasyon ve lisans bildirimi
```

---

## 🚀 Hızlı Kullanım (CLI)

### 1. UAC Kayıt Defteri Parametreleri Rehberini İnceleme
```bash
python uygulama/uac_security_cli.py uac-inspect
```

### 2. İstemci Hesap ve UAC Duruşunu Denetleme (Markdown Çıktısı)
```bash
python uygulama/uac_security_cli.py audit --spec ornek_veri/uac_account_baseline_spec.json --format markdown
```

### 3. Otomatik PowerShell Sıkılaştırma Betiği Üretme
```bash
python uygulama/uac_security_cli.py remediate --spec ornek_veri/uac_account_baseline_spec.json --out harden_uac.ps1
```

---

## 🧪 Birim Testler ve Kanıt Üretimi

Tüm testleri ve kanıt üretimini tek adımda çalıştırmak için:
```bash
python kanit_uretici.py
```
Testler tamamen bağımsız Python standart kütüphanesiyle (< 0.01 sn) çalışır.
