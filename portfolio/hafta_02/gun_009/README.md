# GÜN 009: Windows Üzerinde Laboratuvar Hazırlığı (Windows Sandbox, Hyper-V vSwitch, WSL2 ve Defender Kalkanı)

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Durum](https://img.shields.io/badge/durum-PASS-brightgreen?style=flat-square)
![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 📖 Genel Bakış

Bu çalışma, Siber Güvenlik 365 Gün Müfredatının **2. Haftasının 2. günüdür (GÜN 009)**. Windows 11 ve 10 işletim sistemlerinde güvenli bir siber güvenlik analiz ve simülasyon ortamının nasıl kurulacağını inceler.

Kimya laboratuvarlarındaki çekerocak (Fume Hood) analojisiyle; yerleşik **Windows Sandbox (WSB)** tek kullanımlık mikro-sanallaştırması, fiziksel ağdan izole **Hyper-V vSwitch** yapılandırmaları, **WSL2** güvenli entegrasyonu ve antivirüs dışlamalarının istismarını (**Exclusion Hijacking**) önleyen katı NTFS erişim denetimi (ACL) kuralları somutlaştırılmıştır.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_02/gun_009/
├── ders.md                          # 7 aşamalı "Usta-Çırak" masterclass dersi
├── soru_cevap.md                    # 4 katı alt başlıklı kavramsal soru-cevaplar (G009-SC1, SC2, SC3)
├── rapor.md                         # 20/40/25/15 puan tablosu ve denetim raporu
├── README.md                        # Kullanım kılavuzu ve proje özeti
├── sonuc.json                       # 14 alanlı standart makine-okunabilir durum
├── manifest.json                    # SHA-256 bütünlük özeti (küçük harf, / ayracı)
├── uygulama/
│   └── windows_lab_provisioner.py   # Zengin açıklamalı Windows Lab Denetim ve WSB Üretim Motoru
├── tests/
│   └── test_windows_lab_provisioner.py # 13 birim test (pozitif/negatif kontroller)
├── ornek_veri/
│   ├── windows_lab_yapilandirmasi.json # Sertleştirilmiş ve güvensiz lab profilleri
│   └── Izole_Zararli_Inceleme.wsb    # Otomatik üretilen BSL-4 seviyesinde Windows Sandbox profili
└── kanit/
    ├── gercek/
    │   ├── komut_ve_cikis.txt       # CLI yürütme ve terminal stdout/stderr çıktısı
    │   └── test_sonuclari.txt       # 13/13 unittest başarı kaydı
    └── temsili/
        └── windows_lab_mimarisi.txt # ASCII formatında Windows lab ve Sandbox mimari şeması
```

---

## 🚀 Çalıştırma Talimatları

### 1. Windows Laboratuvar Yapılandırmalarını Denetleme (CLI)
```bash
python portfolio/hafta_02/gun_009/uygulama/windows_lab_provisioner.py --config portfolio/hafta_02/gun_009/ornek_veri/windows_lab_yapilandirmasi.json
```

Yalnızca sertleştirilmiş profili denetlemek ve güvenli `.wsb` profili üretmek için:
```bash
python portfolio/hafta_02/gun_009/uygulama/windows_lab_provisioner.py --config portfolio/hafta_02/gun_009/ornek_veri/windows_lab_yapilandirmasi.json --lab-id WIN-LAB-SEC-01 --generate-wsb --output-dir portfolio/hafta_02/gun_009/ornek_veri
```

JSON formatında makine çıktısı almak için:
```bash
python portfolio/hafta_02/gun_009/uygulama/windows_lab_provisioner.py --config portfolio/hafta_02/gun_009/ornek_veri/windows_lab_yapilandirmasi.json --format json
```

### 2. Kapsamlı Birim Testleri Çalıştırma
```bash
python -m unittest portfolio/hafta_02/gun_009/tests/test_windows_lab_provisioner.py -v
```

---

## 🛡️ Lisans ve Kullanım Şartları

Bu proje ve ilgili tüm dosyalar **Seydi Eryılmaz (@seydivakkas)** adına tescilli olup tüm hakları saklıdır. Hiçbir açık kaynak lisansına (MIT, Apache, GPL vb.) tabi değildir. Ticari veya gayriticari olarak kopyalanamaz, paylaşılamaz, türetilemez.
