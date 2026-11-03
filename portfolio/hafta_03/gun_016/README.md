# GÜN 016: CPU, RAM ve Depolama Ayrımı Güvenlik Analizörü

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

Bu modül, Siber Güvenlik 365 Gün Müfredatı'nın **Aşama 02 (Sistem, Bellek ve Düşük Seviyeli Güvenlik)** kapsamında geliştirilmiştir. Donanım seviyesindeki temel güvenlik sınırlarını oluşturan:
1. **CPU, RAM ve Depolama Katmanlarının Mimari Ayrımı**
2. **Uçuculuk Sıralaması (RFC 3227 Order of Volatility)**
3. **Bellek Hijyeni ve Güvenli Sıfırlama (`SecureZeroMemory` vs. `plain_free`)**
4. **RAM'den Diske Takas Sızıntıları (`pagefile.sys`, `hiberfil.sys`)**
5. **Kalıcı Depolamada Veri Kalıntısı (Data Remanence) ve Adli Dosya Kurtarma (File Carving)**

konularını derinlemesine inceleyen, canlı donanım envanteri toplayan ve CIS Benchmark / NIST standartlarına göre sistem güvenlik taban çizgisini denetleyen bir araç içerir.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_03/gun_016/
├── uygulama/
│   └── system_hardware_boundary_auditor.py      # Her satırı açıklamalı güvenlik denetim motoru
├── tests/
│   └── test_system_hardware_boundary_auditor.py  # 14 adet kapsamlı birim testi
├── ornek_veri/
│   ├── hardware_boundary_sample.json            # Simüle edilmiş donanım ve bellek nesneleri
│   └── hardware_security_baseline.json          # NIST ve CIS sertleştirme taban çizgisi
├── kanit/
│   ├── gercek/
│   │   ├── komut_ve_cikis.txt                   # CLI yürütme terminal kanıtı
│   │   └── test_sonuclari.txt                   # 14/14 PASS unittest test raporu
│   └── temsili/
│       └── cpu_ram_depolama_mimarisi.txt        # ASCII donanım sınırları diyagramı
├── ders.md                                      # 7 bölümlük derin usta-çırak ders metni
├── soru_cevap.md                                # 3 adet 4 alt başlıklı soru-cevap senaryosu
├── rapor.md                                     # 100/100 değerlendirme ve kabul raporu
├── sonuc.json                                   # Makine tarafından okunabilir durum kaydı
├── manifest.json                                # Kriptografik SHA-256 doğrulama özeti
└── README.md                                    # Bu dokümantasyon dosyası
```

---

## 🚀 Kurulum ve Çalıştırma

### Gereksinimler
- Python 3.10+ (Standart kütüphane yeterlidir, harici bağımlılık gerekmez)

### 1. Canlı Yerel Donanım Envanterini Çıkarma
```powershell
python uygulama/system_hardware_boundary_auditor.py --live
```

### 2. Donanım Taban Çizgisi ve Veri Kalıntısı Denetimini Çalıştırma
```powershell
python uygulama/system_hardware_boundary_auditor.py --sample ornek_veri/hardware_boundary_sample.json --baseline ornek_veri/hardware_security_baseline.json
```

### 3. Birim Testleri Yürütme
```powershell
python -m unittest tests/test_system_hardware_boundary_auditor.py -v
```

---

## 🛡️ Temel Güvenlik Bulguları

- **Sayfalama Temizliği (ClearPageFileAtShutdown):** Sistem kapatılırken RAM'in diske yazılan sayfalarının temizlenmemesi, disk söküldüğünde veya live USB ile açıldığında açık metin parola ve anahtarların sızmasına yol açar.
- **Güvenli Bellek Temizliği (Memory Hygiene):** Belleğin yalnızca `free()` ile serbest bırakılması durumunda verinin ram üzerinde aynen kaldığı ve adli bellek dökümüyle ele geçirilebileceği simüle edilmiştir.
- **Tam Disk Şifreleme (FDE):** İşletim sistemi çöktüğünde veya depolama çalındığında verinin okunmasını engelleyen en kritik donanım sınırı kontrolüdür.

---

## 📜 Lisans

Bu projenin tüm hakları saklıdır. Detaylı lisans şartları için üst kısımdaki lisans uyarısını inceleyiniz.
