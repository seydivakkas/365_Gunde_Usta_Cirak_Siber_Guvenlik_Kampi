# Gün 132: Windows Hizmet Güvenliği ve Servis Sıkılaştırma

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Category](https://img.shields.io/badge/category-Windows%20Security-blue?style=flat-square)

Bu çalışma, Windows Service Control Manager (SCM - `services.exe`) mimarisini, servis erişim izinlerini (Service DACL / SDDL), tırnaksız servis yolu zafiyetlerini (Unquoted Service Path - CWE-428), zayıf binary dosya izinlerini (CWE-732), en az ayrıcalık prensibi ihlallerini (CWE-250) ve CIS Windows Benchmark kurallarını denetleyen üretim kalitesinde bir güvenlik paketidir.

---

## 📁 Dizin Yapısı

```text
gun_132/
├── uygulama/
│   ├── __init__.py
│   ├── windows_service_security_engine.py  # SCM denetim, SDDL ayrıştırma ve puanlama motoru
│   └── service_security_cli.py            # CLI yönetim, denetim ve iyileştirme aracı
├── tests/
│   ├── __init__.py
│   └── test_windows_service_security.py   # 15 adet kapsamlı birim test
├── ornek_veri/
│   ├── service_inventory_spec.json        # Örnek kurumsal servis envanteri
│   └── invalid_service_scenarios.json     # 9 adet negatif test senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt             # Birim test çalıştırma kanıtı (15/15 PASS)
│   │   ├── negatif_kontrol_sonuclari.txt  # 9/9 negatif senaryo doğrulama çıktısı
│   │   ├── servis_guvenlik_analiz_raporu.json # JSON denetim raporu
│   │   ├── otomatik_sikilastirma.ps1      # Otomatik üretilen PowerShell iyileştirme betiği
│   │   └── komut_ve_cikis.txt             # CLI komutları ve terminal çıktıları
│   └── temsili/
│       └── service_mimarisi.txt           # SCM ve güvenlik sınırları ASCII mimari diyagramı
├── kanit_uretici.py                       # Tüm kanıtları tek komutla üreten orkestrasyon betiği
├── ders.md                                # Usta-Çırak derinlemesine hoca dersi
├── soru_cevap.md                          # 3 adet derinlemesine teknik soru ve analiz
├── rapor.md                               # 100/100 tam puan skor kartı ve analiz raporu
├── sonuc.json                             # Makine tarafından okunabilir sonuç özeti
├── manifest.json                          # Paket dosya doğrulama listesi
└── README.md                              # Paket tanıtımı ve kullanım kılavuzu
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest discover tests/
```

### 2. CLI ile Servis Envanterini Denetleme
```bash
python uygulama/service_security_cli.py audit -i ornek_veri/service_inventory_spec.json -o kanit/gercek/servis_guvenlik_analiz_raporu.json
```

### 3. Otomatik PowerShell İyileştirme Betiği Üretme
```bash
python uygulama/service_security_cli.py remediate -i ornek_veri/service_inventory_spec.json -o kanit/gercek/otomatik_sikilastirma.ps1
```

### 4. Kanıt Üreticiyi Çalıştırma
```bash
python kanit_uretici.py
```

---

## 🔒 Güvenlik Standartları ve Kapsam

- **CWE-428 / MITRE ATT&CK T1574.009:** Tırnaksız Servis Yolu (Unquoted Service Path).
- **CWE-732 / MITRE ATT&CK T1543.003:** Zayıf Servis DACL İzinleri (`SERVICE_CHANGE_CONFIG`, `WRITE_DAC`, `WRITE_OWNER`).
- **CWE-732 / MITRE ATT&CK T1574.010:** Zayıf Servis İkili Dosya İzinleri (`Users` veya `Everyone` yazma yetkisi).
- **CWE-250 / MITRE ATT&CK T1078.003:** En Az Ayrıcalık İhlali (Üçüncü parti servislerin `LocalSystem` ile çalışması).
- **CWE-250 / MITRE ATT&CK T1134:** Tehlikeli Windows Ayrıcalık Talepleri (`SeDebugPrivilege` vb.).
- **CWE-16 / MITRE ATT&CK T1003.002:** CIS Benchmark uyarınca kapatılması gereken riskli servisler (`RemoteRegistry` vb.).

---

## Lisans

Bu projenin tüm hakları saklıdır.  
**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.  
Yalnızca GitHub üzerinde görüntüleme ve inceleme izni verilmiştir (kopyalamadan).  
Yazarın açık yazılı izni olmaksızın hiçbir ticari veya ticari olmayan projede kullanılamaz, kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya tersine mühendislik uygulanamaz.
