# Gün 023: Linux Terminali, Kabuk (Shell) Yorumlayıcısı ve Yol Güvenliği

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama](https://img.shields.io/badge/Aşama-02%20Sistem%20ve%20Ağ%20Temelleri-blue?style=flat-square)
![Hafta](https://img.shields.io/badge/Hafta-04%20Ağ%20ve%20Komut%20Satırı%20Temelleri-orange?style=flat-square)
![Test Durumu](https://img.shields.io/badge/Testler-14%2F14%20PASS-brightgreen?style=flat-square)
![Puan](https://img.shields.io/badge/Puan-100%2F100-success?style=flat-square)

---

## 📖 Genel Bakış

Bu modül, Siber Güvenlik 365 Gün Müfredatı'nın **Aşama 02 / Hafta 04 / Gün 023** çalışmasıdır. Linux terminal (TTY/PTY) ve kabuk (Bash/Sh) katman ayrımını, standart G/Ç akışlarını (stdin/stdout/stderr), POSIX temel kabuk komutlarını (`pwd`, `cd`, `ls`, `cat`, `head`), göreceli yol (relative path) tuzaklarını, dizin aşımı (CWE-22) ve güvensiz PATH ortam değişkeni (CWE-426) zafiyetlerini inceler.

Proje kapsamında geliştirilen `linux_shell_security_simulator.py` aracı, sanal bir Linux dosya sistemi üzerinde 5 temel kabuk komutunun sıralı iş akışını (G023-SC2) simüle eder ve yol güvenliği denetimlerini icra eder.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_04/gun_023/
├── README.md                                  # Bu tanıtım ve kullanım kılavuzu
├── ders.md                                    # 7 bölümlük kapsamlı usta-çırak ders dokümanı
├── soru_cevap.md                              # 4 zorunlu alt başlıklı soru-cevap dokümanı
├── rapor.md                                   # 100/100 puanlı detaylı değerlendirme raporu
├── sonuc.json                                 # 14 standart alanlı makine tarafından okunabilir özet
├── manifest.json                              # SHA-256 bütünlük parmak izleri listesi
├── uygulama/
│   ├── __init__.py                            # Paket başlatıcı
│   └── linux_shell_security_simulator.py      # Zengin açıklamalı kabuk simülasyon motoru
├── tests/
│   ├── __init__.py                            # Test paketi başlatıcı
│   └── test_linux_shell_security_simulator.py # 14 birim testten oluşan doğrulama suite
├── ornek_veri/
│   ├── shell_virtual_filesystem.json          # Sanal dosya sistemi ağacı (/etc, /var/log, /home)
│   └── shell_security_rules.json              # POSIX komut ve yol güvenliği kuralları
└── kanit/
    ├── gercek/
    │   ├── komut_ve_cikis.txt                 # CLI ve gerçek çalıştırma kanıtları
    │   ├── test_sonuclari.txt                 # 14/14 test pass yürütme çıktısı
    │   └── kabuk_komut_analiz_ciktisi.txt     # 5 adımlı G023-SC2 laboratuvar çıktısı
    └── temsili/
        └── linux_kabuk_mimarisi.txt           # Zorunlu etiketli mimari ASCII görselleştirmesi
```

---

## 🚀 Çalıştırma ve Test

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest discover -s portfolio/hafta_04/gun_023/tests -p "test_*.py" -v
```

### 2. Laboratuvar İş Akışını Çalıştırma (G023-SC2)
```bash
python portfolio/hafta_04/gun_023/uygulama/linux_shell_security_simulator.py \
  --filesystem portfolio/hafta_04/gun_023/ornek_veri/shell_virtual_filesystem.json \
  --rules portfolio/hafta_04/gun_023/ornek_veri/shell_security_rules.json \
  --lab
```

### 3. JSON Çıktı Modu
```bash
python portfolio/hafta_04/gun_023/uygulama/linux_shell_security_simulator.py \
  --filesystem portfolio/hafta_04/gun_023/ornek_veri/shell_virtual_filesystem.json \
  --rules portfolio/hafta_04/gun_023/ornek_veri/shell_security_rules.json \
  --lab --json
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
