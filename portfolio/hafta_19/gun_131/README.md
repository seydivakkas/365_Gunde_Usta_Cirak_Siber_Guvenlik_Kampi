# Gün 131: Windows Firewall Profilleri ve Sertleştirmesi

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

Bu proje; Windows Defender Gelişmiş Güvenlikli Güvenlik Duvarı (WFAS) Domain, Private ve Public ağ profillerinin, varsayılan gelen/giden eylemlerinin, kütükleme mekanizmalarının ve riskli port kurallarının **CIS Microsoft Windows 11 / Server Benchmark (Section 9)** ve **MITRE ATT&CK T1562.004 / T1021** standartlarına göre derinlemesine teftişini, duruş analizi puanlamasını ve PowerShell / netsh tabanlı otomatik sertleştirmesini gerçekleştirir.

### Kapsanan Temel Güvenlik Mekanizmaları
- **Ağ Profili Denetimi:** Domain, Private ve Public profillerinin zorunlu etkinliği (`CWE-693 / MITRE T1562.004`).
- **Varsayılan Bloklama:** `DefaultInboundAction = Block` politikasının doğrulanması (`CWE-284`).
- **Public Profil İzolasyonu:** RDP (3389), SMB (445), WinRM (5985) portlarının genel ağlarda engellenmesi (`MITRE T1021`).
- **Kural Denetimi:** Tehlikeli Any-to-Any gelen izin kurallarının tespiti ve devre dışı bırakılması (`CWE-284`).
- **Güvenlik Kütüklemesi:** `pfirewall.log` dosyasına düşürülen paketlerin yazılması ve >= 16 MB kütük boyutu (`CWE-778`).

---

## 📁 Dizin Yapısı

```
portfolio/hafta_19/gun_131/
├── uygulama/
│   ├── __init__.py
│   ├── windows_firewall_engine.py      # Çekirdek güvenlik duvarı denetim motoru
│   └── firewall_cli.py                 # CLI yönetim aracı (audit, remediate, profiles-info)
├── tests/
│   ├── __init__.py
│   └── test_windows_firewall.py        # 15 kapsamlı birim testi (100% PASS, 0.002s)
├── ornek_veri/
│   ├── firewall_baseline_spec.json     # Gerçekçi kurumsal istemci yapılandırma örneği
│   └── invalid_firewall_scenarios.json # 9 negatif zaaf senaryosu (CWE-693, 284, 778...)
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt          # 15 testin detaylı koşum çıktısı
│   │   ├── negatif_kontrol_sonuclari.txt # 9 negatif testin doğrulama kütüğü
│   │   ├── komut_ve_cikis.txt          # CLI komutları ve terminal çıktıları
│   │   └── firewall_denetim_raporu.md  # Otomatik üretilen teftiş raporu
│   └── temsili/
│       └── firewall_mimarisi.txt       # Temsili mimari diyagramı
├── kanit_uretici.py                    # Doğrulama ve kanıt üretim orkestratörü
├── ders.md                             # Usta-Çırak / Hoca Dersi teorik anlatımı
├── soru_cevap.md                       # 3 derin teknik soru ve 4 zorunlu alt başlıklı cevapları
├── rapor.md                            # 100/100 PASS başarı karnesi
├── sonuc.json                          # Makine tarafından okunabilir sonuç özeti
├── manifest.json                       # Paket dosya listesi ve SHA-256 hash'leri
└── README.md                           # Dokümantasyon ve lisans bildirimi
```

---

## 🚀 Hızlı Kullanım (CLI)

### 1. Güvenlik Duvarı Profil Rehberini İnceleme
```bash
python uygulama/firewall_cli.py profiles-info
```

### 2. Güvenlik Duvarı Duruşunu Denetleme (Markdown Çıktısı)
```bash
python uygulama/firewall_cli.py audit --spec ornek_veri/firewall_baseline_spec.json --format markdown
```

### 3. Otomatik PowerShell/netsh Sıkılaştırma Betiği Üretme
```bash
python uygulama/firewall_cli.py remediate --spec ornek_veri/firewall_baseline_spec.json --out harden_firewall.ps1
```

---

## 🧪 Birim Testler ve Kanıt Üretimi

Tüm testleri ve kanıt üretimini tek adımda çalıştırmak için:
```bash
python kanit_uretici.py
```
Testler tamamen bağımsız Python standart kütüphanesiyle (< 0.01 sn) çalışır.
