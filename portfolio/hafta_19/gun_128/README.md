# Gün 128: Windows Güvenlik Merkezi ve Defender Sertleştirme

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

Bu proje, Microsoft Defender Antivirus ve Windows Güvenlik Merkezi (Windows Security Center) bileşenlerinin **CIS Microsoft Windows 11 Benchmark v3.0.0** standartlarına göre derinlemesine teftişini, duruş analizi puanlamasını ve PowerShell tabanlı otomatik sertleştirmesini gerçekleştirir.

### Kapsanan Temel Güvenlik Mekanizmaları
- **Gerçek Zamanlı Koruma (Real-Time Protection):** `DisableRealtimeMonitoring` denetimi (`CWE-693 / MITRE T1562.001`).
- **Kurcalama Koruması (Tamper Protection):** Yerel yönetici yetkisiyle kayıt defteri manipülasyonunun önlenmesi (`CWE-693 / MITRE T1562.001`).
- **Saldırı Yüzeyi Azaltma (ASR):** 7 kritik kural (LSASS koruması, Office alt süreç engelleme, obfuscated betikler vb.) (`CWE-358`).
- **Fidye Yazılımı Koruması (Controlled Folder Access):** Yetkisiz dosya şifreleme ve tahrifat engeli (`MITRE T1486`).
- **Hariç Tutma İstismarı (Exclusion Abuse):** Aşırı geniş `C:\` veya `*.exe` hariç tutmalarının yakalanması (`CWE-732`).
- **Ağ ve Bulut Koruması:** `MAPS HighPlus` seviyesi ve zararlı C2 IP/URL bloklama (`CWE-319 / CWE-1188`).

---

## 📁 Dizin Yapısı

```
portfolio/hafta_19/gun_128/
├── uygulama/
│   ├── __init__.py
│   ├── windows_defender_engine.py   # Çekirdek denetim ve PowerShell sertleştirme motoru
│   └── defender_cli.py              # CLI yönetim aracı (audit, remediate, asr-list)
├── tests/
│   ├── __init__.py
│   └── test_windows_defender.py     # 15 kapsamlı birim testi (100% PASS, 0.002s)
├── ornek_veri/
│   ├── defender_baseline_spec.json  # Gerçekçi kurumsal istemci yapılandırma örneği
│   └── invalid_defender_scenarios.json # 9 negatif zaaf senaryosu (CWE-693, 732, 1188...)
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt       # 15 testin detaylı koşum çıktısı
│   │   ├── negatif_kontrol_sonuclari.txt # 9 negatif testin doğrulama kütüğü
│   │   ├── komut_ve_cikis.txt       # CLI komutları ve terminal çıktıları
│   │   └── defender_denetim_raporu.md # Otomatik üretilen teftiş raporu
│   └── temsili/
│       └── defender_mimarisi.txt    # Temsili mimari diyagramı
├── kanit_uretici.py                 # Doğrulama ve kanıt üretim orkestratörü
├── ders.md                          # Usta-Çırak / Hoca Dersi teorik anlatımı
├── soru_cevap.md                    # 3 derin teknik soru ve 4 zorunlu alt başlıklı cevapları
├── rapor.md                         # 100/100 PASS başarı karnesi
├── sonuc.json                       # Makine tarafından okunabilir sonuç özeti
├── manifest.json                    # Paket dosya listesi ve SHA-256 hash'leri
└── README.md                        # Dokümantasyon ve lisans bildirimi
```

---

## 🚀 Hızlı Kullanım (CLI)

### 1. Kritik ASR Kuralları Kataloğunu Listeleme
```bash
python uygulama/defender_cli.py asr-list
```

### 2. İstemci Yapılandırmasını Denetleme (Markdown Formatında)
```bash
python uygulama/defender_cli.py audit --spec ornek_veri/defender_baseline_spec.json --format markdown
```

### 3. Otomatik PowerShell Sıkılaştırma Betiği Üretme
```bash
python uygulama/defender_cli.py remediate --spec ornek_veri/defender_baseline_spec.json --out harden_defender.ps1
```

---

## 🧪 Birim Testler ve Kanıt Üretimi

Tüm testleri ve kanıt üretimini tek adımda çalıştırmak için:
```bash
python kanit_uretici.py
```
Testler bağımsız Python standart kütüphanesiyle (< 0.01 sn) çalışır ve harici bağımlılık gerektirmez.
