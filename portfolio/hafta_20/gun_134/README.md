# Gün 134: Linux Sudo ve Ayrıcalık Devri Güvenliği

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Category](https://img.shields.io/badge/category-Linux%20Security-blue?style=flat-square)

Bu çalışma; Linux işletim sistemlerinde `/etc/sudoers` ve `/etc/sudoers.d/` yapılandırmasını, GTFOBins kabuk kaçış (shell escape) açıklarını, tehlikeli NOPASSWD kurallarını, `env_keep` paylaşımlı kütüphane enjeksiyonlarını (`LD_PRELOAD`), Defaults sıkılaştırma direktiflerini ve dosya izinlerini denetleyen üretim kalitesinde bir güvenlik paketidir.

---

## 📁 Dizin Yapısı

```text
gun_134/
├── uygulama/
│   ├── __init__.py
│   ├── linux_sudo_engine.py              # Sudoers denetim, GTFOBins analizi ve puanlama motoru
│   └── sudo_security_cli.py              # CLI yönetim, denetim ve şablon üretim aracı
├── tests/
│   ├── __init__.py
│   └── test_linux_sudo_security.py       # 15 adet kapsamlı birim test
├── ornek_veri/
│   ├── sudoers_inventory_spec.json       # Örnek kurumsal Linux sudoers envanteri
│   └── invalid_sudoers_scenarios.json    # 9 adet negatif test senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt            # Birim test çalıştırma kanıtı (15/15 PASS)
│   │   ├── negatif_kontrol_sonuclari.txt # 9/9 negatif senaryo doğrulama çıktısı
│   │   ├── sudo_guvenlik_analiz_raporu.json # JSON formatlı denetim raporu
│   │   ├── otomatik_sikilastirma.sh      # Otomatik üretilen Bash iyileştirme betiği
│   │   ├── ornek_guvenli_sudoers.conf    # Sıkılaştırılmış /etc/sudoers yapılandırma şablonu
│   │   └── komut_ve_cikis.txt            # CLI komutları ve terminal çıktıları
│   └── temsili/
│       └── sudo_mimarisi.txt             # Sudo ve ayrıcalık devri ASCII mimari diyagramı
├── kanit_uretici.py                      # Tüm kanıtları tek komutla üreten orkestrasyon betiği
├── ders.md                               # Usta-Çırak derinlemesine hoca dersi
├── soru_cevap.md                         # 3 adet derinlemesine teknik soru ve analiz
├── rapor.md                              # 100/100 tam puan skor kartı ve analiz raporu
├── sonuc.json                            # Makine tarafından okunabilir sonuç özeti
├── manifest.json                         # Paket dosya doğrulama listesi
└── README.md                             # Paket tanıtımı ve kullanım kılavuzu
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest discover tests/
```

### 2. CLI ile Sudoers Envanterini Denetleme
```bash
python uygulama/sudo_security_cli.py audit -i ornek_veri/sudoers_inventory_spec.json -o kanit/gercek/sudo_guvenlik_analiz_raporu.json
```

### 3. Otomatik Bash İyileştirme Betiği Üretme
```bash
python uygulama/sudo_security_cli.py remediate -i ornek_veri/sudoers_inventory_spec.json -o kanit/gercek/otomatik_sikilastirma.sh
```

### 4. Güvenli Sudoers Şablonu Üretme
```bash
python uygulama/sudo_security_cli.py config-template -o kanit/gercek/ornek_guvenli_sudoers.conf
```

### 5. Kanıt Üreticiyi Çalıştırma
```bash
python kanit_uretici.py
```

---

## 🔒 Güvenlik Standartları ve Kapsam

- **CWE-250 / MITRE ATT&CK T1548.003:** Şifresiz Tam Root (NOPASSWD: ALL) ve Yetki Yükseltme.
- **CWE-250 / GTFOBins:** Sudo ile izin verilen `vim`, `find`, `awk`, `python`, `less` üzerinden kabuk kaçışı.
- **CWE-426 / MITRE ATT&CK T1574.006:** `env_keep` listesinde `LD_PRELOAD` ve `LD_LIBRARY_PATH` kütüphane enjeksiyonu.
- **CWE-732 / MITRE ATT&CK T1548.003:** `/etc/sudoers` dosya izinlerinin `0440` ve `root:root` dışında olması.
- **CWE-88:** Komut argümanlarında denetimsiz joker karakter (`*`) kullanımı.
- **CIS Linux Benchmark Section 5.3:** Sudoers yapılandırması ve `visudo` zorunluluğu.

---

## Lisans

Bu projenin tüm hakları saklıdır.  
**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.  
Yalnızca GitHub üzerinde görüntüleme ve inceleme izni verilmiştir (kopyalamadan).  
Yazarın açık yazılı izni olmaksızın hiçbir ticari veya ticari olmayan projede kullanılamaz, kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya tersine mühendislik uygulanamaz.
