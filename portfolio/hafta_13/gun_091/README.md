# Gün 091: Mini Proje 12 — Çok Platformlu Sistem Raporu

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![Bash](https://img.shields.io/badge/Bash-POSIX-brightgreen?style=flat-square)
![PowerShell](https://img.shields.io/badge/PowerShell-Core-blue?style=flat-square)
![Durum](https://img.shields.io/badge/Durum-Tamamlandı%20(100%2F100)-brightgreen?style=flat-square)

Hafta 13 Capstone Projesi: Windows ve Linux sunucu altyapılarından yerel betiklerle telemetri toplayan, merkezi zafiyet ve uyumluluk denetimi gerçekleştiren, çoklu formatta (Text, JSON, HTML) rapor üreten kurumsal güvenlik aracı.

---

## 🛡️ Yetenekler ve Özellikler

- **Yerel Telemetri Toplayıcılar:**
  - `windows_collector.ps1`: WMI/CIM, Event Log, Firewall ve açık port telemetrisi.
  - `linux_collector.sh`: Katı modda (`set -euo pipefail`) `/proc`, `/etc/shadow`, `systemctl` ve dinleme portları telemetrisi.
- **Çekirdek Analiz ve Güvenlik Motoru (`cross_platform_security_reporter.py`):**
  - **Zaman Standardizasyonu:** ISO-8601 UTC Zulu zorunluluğu, naive zaman damgalarının reddedilmesi (CWE-613).
  - **Hassas Veri Maskeleme:** Stderr veya log akışında açık şifre tespiti (CWE-532).
  - **DoS & Boyut Kalkanı:** 1 MB üzerindeki şişirilmiş telemetrilerin engellenmesi (CWE-400).
  - **Dizin Atlama Engeli:** Rapor çıktılarında `..` dizin atlama koruması (CWE-22).
  - **CWE Zafiyet Tespiti:** SMB 445, RDP 3389, Redis 6379, Windows Public Firewall kapalı (CWE-276), Kripto Madenci Servis (CWE-506), Linux `/etc/shadow` 0644 (CWE-732), Sudo NOPASSWD (CWE-250).
- **Kurumsal CLI Arayüzü (`reporter_cli.py`):** Karşılıklı dışlayan `--fast`/`--deep` bayrakları, POSIX çıkış kodları (0, 1, 2) ve çoklu çıktı desteği.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_13/gun_091/
├── uygulama/
│   ├── __init__.py
│   ├── cross_platform_security_reporter.py # Çekirdek raporlama ve analiz motoru
│   ├── reporter_cli.py                     # Argparse CLI arayüzü
│   ├── windows_collector.ps1               # PowerShell yerel veri toplayıcı
│   └── linux_collector.sh                  # POSIX Bash yerel veri toplayıcı
├── tests/
│   ├── __init__.py
│   └── test_cross_platform_security_reporter.py # 14/14 birim test seti
├── ornek_veri/
│   ├── sample_windows_telemetry.json       # Örnek Windows telemetrisi
│   ├── sample_linux_telemetry.json         # Örnek Linux telemetrisi
│   └── invalid_reporter_inputs.json        # 9 adet negatif kontrol senaryosu
├── kanit/
│   ├── gercek/                             # Doğrulanmış test ve denetim çıktıları
│   └── temsili/                            # Mimari ASCII görselleştirmesi
├── ders.md                                 # Kapsamlı usta-çırak ders notu
├── soru_cevap.md                           # 4 alt başlıklı 3 mülakat soru-cevap seti
├── rapor.md                                # 100/100 rubrik değerlendirme raporu
├── sonuc.json                              # Makine tarafından okunabilir sonuç metrikleri
├── kanit_uretici.py                        # Testleri çalıştırıp kanıtları toplayan otomasyon betiği
└── README.md
```

---

## 🚀 Çalıştırma ve Test

```bash
# Birim testleri çalıştırma
python -m unittest tests/test_cross_platform_security_reporter.py

# Kanıt üretici ve test paketini yürütme
python kanit_uretici.py

# Yerel toplayıcıları deneme
pwsh -File uygulama/windows_collector.ps1
bash uygulama/linux_collector.sh

# CLI aracını deneme
python uygulama/reporter_cli.py --telemetry-file ornek_veri/sample_windows_telemetry.json --fast
python uygulama/reporter_cli.py --telemetry-file ornek_veri/sample_linux_telemetry.json --deep --format json
```

---

## 📜 Lisans

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
