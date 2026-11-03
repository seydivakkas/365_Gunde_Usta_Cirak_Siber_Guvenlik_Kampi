# GÜN 019: Windows Dosya Sistemi, NTFS ACL ve Dosya Bütünlüğü Güvenlik Analizörü

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Stage: 02](https://img.shields.io/badge/stage-02%20Low%20Level%20Security-blue?style=flat-square)
![Tests: 14/14 PASS](https://img.shields.io/badge/tests-14%2F14%20PASS-brightgreen?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/score-100%2F100-success?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz veya tersine mühendislik yapılamaz.

---

## 🎯 Proje ve Modül Amacı

Bu modül, Siber Güvenlik 365 Gün Müfredatı'nın **Aşama 02 (Sistem, Bellek ve Düşük Seviyeli Güvenlik)** kapsamında geliştirilmiştir. Windows işletim sistemi depolama güvenliğinin temelini oluşturan:
1. **NTFS Mimarisi ve Ana Dosya Tablosu (Master File Table - $MFT)**
2. **Erişim Denetim Listeleri (DACL/SACL) ve İzin Değerlendirme Algoritması (Deny > Allow)**
3. **Klasör İzinlerinde "Önce/Sonra" Fark Analizi (G019-SC2)**
4. **Alternatif Veri Akışları (ADS - MITRE ATT&CK T1564.004) ile Zararlı Gizleme**
5. **Dosya Uzantısı Yanılgısı ve Sihirli Baytlar (Magic Bytes - MITRE T1036) Doğrulaması**

konularını derinlemesine inceleyen, canlı dizin izinlerini `icacls` ile sorgulayan ve kurumsal dosya bütünlüğü taban çizgisini denetleyen bir araç içerir.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_03/gun_019/
├── uygulama/
│   └── ntfs_security_and_acl_analyzer.py      # Her satırı açıklamalı güvenlik analiz motoru
├── tests/
│   └── test_ntfs_security_and_acl_analyzer.py  # 14 adet kapsamlı birim testi
├── ornek_veri/
│   ├── ntfs_file_samples.json                  # Dosya, sihirli bayt, ADS ve ACL fark veri seti
│   └── ntfs_security_baseline.json             # CIS ve NIST NTFS taban çizgisi
├── kanit/
│   ├── gercek/
│   │   ├── komut_ve_cikis.txt                  # CLI yürütme terminal kanıtı
│   │   └── test_sonuclari.txt                  # 14/14 PASS unittest test raporu
│   └── temsili/
│       └── ntfs_ve_acl_mimarisi.txt            # ASCII NTFS/MFT/ACL/ADS mimari şeması
├── ders.md                                     # 7 bölümlük derin usta-çırak ders metni
├── soru_cevap.md                               # 3 adet 4 alt başlıklı soru-cevap senaryosu
├── rapor.md                                    # 100/100 değerlendirme ve kabul raporu
├── sonuc.json                                  # Makine tarafından okunabilir durum kaydı
├── manifest.json                               # Kriptografik SHA-256 doğrulama özeti
└── README.md                                   # Bu dokümantasyon dosyası
```

---

## 🚀 Kurulum ve Çalıştırma

### Gereksinimler
- Python 3.10+ (Standart kütüphane yeterlidir, harici bağımlılık gerekmez)

### 1. Canlı Dizin NTFS İzinlerini Sorgulama
```powershell
python uygulama/ntfs_security_and_acl_analyzer.py --live
```

### 2. Dosya Bütünlüğü, ADS ve ACL Fark Denetimi
```powershell
python uygulama/ntfs_security_and_acl_analyzer.py --sample ornek_veri/ntfs_file_samples.json --baseline ornek_veri/ntfs_security_baseline.json
```

### 3. Birim Testleri Yürütme
```powershell
python -m unittest tests/test_ntfs_security_and_acl_analyzer.py -v
```

---

## 🛡️ Temel Güvenlik Bulguları

- **Uzantı Bir Güvenlik Özelliği Değildir:** `.pdf` veya `.txt` uzantılı bir dosya, başlığında `4D 5A` sihirli baytlarını taşıyorsa bu bir PE çalıştırılabilir programdır ve e-posta filtrelerini atlatmayı amaçlar.
- **Alternatif Veri Akışları (ADS):** Standart Dosya Gezgini'nde görünmeyen gizli veri akışları (`dosya.txt:payload.ps1`), antivirüs taramalarından kaçmak için kullanılabilir.
- **DACL İzin Mirası ve Everyone:** Hassas klasörlerde `Everyone:FullControl` bulunması fidye yazılımları ve yerel saldırganlar için açık kapıdır; `Explicit Deny` kuralları ile sınırlandırılmalıdır.

---

## 📜 Lisans

Bu projenin tüm hakları saklıdır. Detaylı lisans şartları için üst kısımdaki lisans uyarısını inceleyiniz.
