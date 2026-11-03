# Gün 133: Mini Proje 18 — Bütünleşik Windows Güvenlik Denetim ve Raporlama Platformu

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Category](https://img.shields.io/badge/category-Windows%20Security%20Mini--Project-blue?style=flat-square)

Bu proje; Hafta 19 boyunca işlenen Windows Olay Günlükleri, Defender, UAC ve Yerel Hesaplar, NTFS Erişim Kontrol Listeleri, Windows Firewall ve Windows Hizmet Güvenliği konularını tek bir çatı altında sentezleyen, kurumsal düzeyde **Bütünleşik Windows Güvenlik Denetim ve Raporlama Platformu**dur.

---

## 📁 Dizin Yapısı

```text
gun_133/
├── uygulama/
│   ├── __init__.py
│   ├── windows_audit_platform_engine.py  # 5 boyutlu denetim, puanlama ve raporlama motoru
│   └── windows_audit_cli.py              # CLI yönetim, denetim ve betik üretim aracı
├── tests/
│   ├── __init__.py
│   └── test_windows_audit_platform.py    # 15 adet kapsamlı birim test
├── ornek_veri/
│   ├── enterprise_windows_spec.json      # Örnek kurumsal uç nokta spesifikasyonu
│   └── invalid_audit_scenarios.json      # 9 adet negatif test senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt            # Birim test çalıştırma kanıtı (15/15 PASS)
│   │   ├── negatif_kontrol_sonuclari.txt # 9/9 negatif senaryo doğrulama çıktısı
│   │   ├── windows_denetim_raporu.json   # Makine tarafından okunabilir JSON denetim raporu
│   │   ├── windows_denetim_raporu.md     # Yönetici düzeyinde Markdown denetim raporu
│   │   ├── master_remediation.ps1        # Otomatik üretilen Master PowerShell sıkılaştırma betiği
│   │   └── komut_ve_cikis.txt            # CLI komutları ve terminal çıktıları
│   └── temsili/
│       └── windows_denetim_mimarisi.txt  # Bütünleşik denetim mimarisi ASCII diyagramı
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

### 2. CLI ile Bütünleşik Denetim Yürütme (JSON Çıktısı)
```bash
python uygulama/windows_audit_cli.py audit -i ornek_veri/enterprise_windows_spec.json -o kanit/gercek/windows_denetim_raporu.json
```

### 3. Yönetici Düzeyinde Markdown Raporu Üretme
```bash
python uygulama/windows_audit_cli.py report -i ornek_veri/enterprise_windows_spec.json -o kanit/gercek/windows_denetim_raporu.md
```

### 4. Master PowerShell Sıkılaştırma Betiği Oluşturma
```bash
python uygulama/windows_audit_cli.py remediate -i ornek_veri/enterprise_windows_spec.json -o kanit/gercek/master_remediation.ps1
```

### 5. Tüm Kanıtları Üretme
```bash
python kanit_uretici.py
```

---

## 🔒 Denetlenen 5 Temel Güvenlik Alanı (100.0 Puan Modeli)

1. **Windows Defender ve Uç Nokta Koruması (20 Puan):** Gerçek Zamanlı Koruma (RTP), Davranışsal İzleme, Kurcalama Koruması (Tamper Protection), PUA Koruması (CWE-693 / MITRE T1562.001).
2. **Yerel Hesaplar, Gruplar ve UAC (20 Puan):** EnableLUA Split-Token, Admin Onay Modu, Güvenli Masaüstü, Konuk (Guest) Hesabı Kısıtlamaları (CWE-250, CWE-284 / MITRE T1548.002, T1078.001).
3. **NTFS Erişim Kontrol Listeleri (20 Puan):** Sistem dizinlerinde standart kullanıcı yazma yetkileri, kalıtım bütünlüğü, SACL denetim günlüğü (CWE-732, CWE-778 / MITRE T1574.009, T1222.001).
4. **Windows Firewall Profilleri (20 Puan):** Domain, Private, Public profilleri, varsayılan gelen engelleme (Default Block), 3389 RDP ve 445 SMB maruziyeti (CWE-284 / MITRE T1562.004, T1021.001).
5. **Windows Hizmet Güvenliği (20 Puan):** Tırnaksız servis yolları, zayıf servis DACL (DC/WD) izinleri, yazılabilir servis ikili dosyaları, CIS gereksiz servisleri (CWE-428, CWE-732, CWE-16 / MITRE T1574.009, T1543.003).

---

## Lisans

Bu projenin tüm hakları saklıdır.  
**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.  
Yalnızca GitHub üzerinde görüntüleme ve inceleme izni verilmiştir (kopyalamadan).  
Yazarın açık yazılı izni olmaksızın hiçbir ticari veya ticari olmayan projede kullanılamaz, kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya tersine mühendislik uygulanamaz.
