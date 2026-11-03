# Gün 022: Komut Satırı — PowerShell Temelleri ve Nesne Boru Hattı Güvenlik Denetimi

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama](https://img.shields.io/badge/Aşama-02%20Sistem%20ve%20Ağ%20Temelleri-blue?style=flat-square)
![Hafta](https://img.shields.io/badge/Hafta-04%20Ağ%20ve%20Komut%20Satırı%20Temelleri-orange?style=flat-square)
![Test Durumu](https://img.shields.io/badge/Testler-14%2F14%20PASS-brightgreen?style=flat-square)
![Puan](https://img.shields.io/badge/Puan-100%2F100-success?style=flat-square)

---

## 📖 Genel Bakış

Bu modül, Siber Güvenlik 365 Gün Müfredatı'nın **Aşama 02 / Hafta 04 / Gün 022** çalışmasıdır. Windows dünyasının güçlü kabuğu olan PowerShell'in .NET nesne boru hattı (Object Pipeline) mimarisini, salt-okunur cmdlet felsefesini, Execution Policy kavramının sınırlarını, MITRE ATT&CK T1059.001 (PowerShell istismarı) ve CWE-428 (Tırnaksız Servis Yolu) zafiyetlerini inceler.

Geliştirilen `powershell_security_pipeline_auditor.py` aracı canlı sistemden (`--live`) veya örnek veri setlerinden süreç ve servis nesnelerini toplar; `Where-Object` benzeri güvenlik kurallarıyla süzerek CSV formatında denetim raporu üretir.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_04/gun_022/
├── README.md                                  # Bu tanıtım ve kullanım kılavuzu
├── ders.md                                    # 7 bölümlük kapsamlı usta-çırak ders dokümanı
├── soru_cevap.md                              # 4 zorunlu alt başlıklı soru-cevap dokümanı
├── rapor.md                                   # 100/100 puanlı detaylı değerlendirme raporu
├── sonuc.json                                 # 14 standart alanlı makine tarafından okunabilir özet
├── manifest.json                              # SHA-256 bütünlük parmak izleri listesi
├── uygulama/
│   ├── __init__.py                            # Paket başlatıcı
│   └── powershell_security_pipeline_auditor.py# Zengin açıklamalı denetim motoru
├── tests/
│   ├── __init__.py                            # Test paketi başlatıcı
│   └── test_powershell_security_pipeline_auditor.py # 14 birim testten oluşan doğrulama suite
├── ornek_veri/
│   ├── ps_process_samples.json                # Örnek süreç nesneleri (Bypass, Mimikatz, Explorer)
│   ├── ps_service_samples.json                # Örnek servis nesneleri (TlntSvr, CWE-428)
│   └── ps_audit_rules.json                    # Şüpheli parametre ve kaynak sınır kuralları
└── kanit/
    ├── gercek/
    │   ├── komut_ve_cikis.txt                 # CLI ve gerçek çalıştırma kanıtları
    │   ├── test_sonuclari.txt                 # 14/14 test pass yürütme çıktısı
    │   └── filtrelenmis_surec_ve_servisler.csv# Üretilen filtrelenmiş CSV raporu
    └── temsili/
        └── powershell_pipeline_mimarisi.txt   # Zorunlu etiketli mimari ASCII görselleştirmesi
```

---

## 🚀 Çalıştırma ve Test

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest discover -s portfolio/hafta_04/gun_022/tests -p "test_*.py" -v
```

### 2. Filtreleme ve CSV Raporu Üretimi (G022-SC2)
```bash
python portfolio/hafta_04/gun_022/uygulama/powershell_security_pipeline_auditor.py \
  --processes portfolio/hafta_04/gun_022/ornek_veri/ps_process_samples.json \
  --services portfolio/hafta_04/gun_022/ornek_veri/ps_service_samples.json \
  --rules portfolio/hafta_04/gun_022/ornek_veri/ps_audit_rules.json \
  --csv portfolio/hafta_04/gun_022/kanit/gercek/filtrelenmis_surec_ve_servisler.csv
```

### 3. Canlı PowerShell Nesneleri Sorgulama
```bash
python portfolio/hafta_04/gun_022/uygulama/powershell_security_pipeline_auditor.py --live
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
