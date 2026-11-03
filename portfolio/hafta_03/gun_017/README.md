# GÜN 017: İşletim Sistemi Çekirdeği ve Kullanıcı Modu Güvenlik Analizörü

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

Bu modül, Siber Güvenlik 365 Gün Müfredatı'nın **Aşama 02 (Sistem, Bellek ve Düşük Seviyeli Güvenlik)** kapsamında geliştirilmiştir. İşletim sistemi mimarisinin en temel güvenlik sınırı olan:
1. **Çekirdek Kipi (Kernel Mode / Ring 0) ve Kullanıcı Kipi (User Mode / Ring 3) İzolasyonu**
2. **Yönetici (Administrator / root) Yetkilerinin Sınırları ve Ring 3'te Kalması Gerçeği**
3. **Sistem Çağrısı (Syscall) Güvenlik Doğrulamaları (`ProbeForRead`, `ProbeForWrite`, SMEP/SMAP)**
4. **BYOVD (Bring Your Own Vulnerable Driver) Tehdit Analizi**
5. **HVCI, VBS ve Sürücü Engelleme Listesi (Driver Blocklist) Sertleştirmesi**

konularını derinlemesine inceleyen, canlı süreç bağlamını sorgulayan ve kurumsal çekirdek güvenlik taban çizgisini denetleyen bir araç içerir.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_03/gun_017/
├── uygulama/
│   └── kernel_user_mode_boundary_analyzer.py      # Her satırı açıklamalı güvenlik analiz motoru
├── tests/
│   └── test_kernel_user_mode_boundary_analyzer.py  # 14 adet kapsamlı birim testi
├── ornek_veri/
│   ├── kernel_user_privilege_matrix.json          # Ring 0 vs Ring 3 yetki matrisi ve BYOVD sürücüleri
│   └── kernel_security_baseline.json              # Microsoft WDAC/HVCI ve CIS çekirdek standartları
├── kanit/
│   ├── gercek/
│   │   ├── komut_ve_cikis.txt                     # CLI yürütme terminal kanıtı
│   │   └── test_sonuclari.txt                     # 14/14 PASS unittest test raporu
│   └── temsili/
│       └── cekirdek_ve_kullanici_modu_mimarisi.txt # ASCII Ring 0/Ring 3 mimari diyagramı
├── ders.md                                        # 7 bölümlük derin usta-çırak ders metni
├── soru_cevap.md                                  # 3 adet 4 alt başlıklı soru-cevap senaryosu
├── rapor.md                                       # 100/100 değerlendirme ve kabul raporu
├── sonuc.json                                     # Makine tarafından okunabilir durum kaydı
├── manifest.json                                  # Kriptografik SHA-256 doğrulama özeti
└── README.md                                      # Bu dokümantasyon dosyası
```

---

## 🚀 Kurulum ve Çalıştırma

### Gereksinimler
- Python 3.10+ (Standart kütüphane yeterlidir, harici bağımlılık gerekmez)

### 1. Canlı Süreç Yetki ve Bütünlük Bağlamını Sorgulama
```powershell
python uygulama/kernel_user_mode_boundary_analyzer.py --live
```

### 2. Çekirdek Güvenlik Taban Çizgisi ve BYOVD Denetimini Çalıştırma
```powershell
python uygulama/kernel_user_mode_boundary_analyzer.py --matrix ornek_veri/kernel_user_privilege_matrix.json --baseline ornek_veri/kernel_security_baseline.json
```

### 3. Birim Testleri Yürütme
```powershell
python -m unittest tests/test_kernel_user_mode_boundary_analyzer.py -v
```

---

## 🛡️ Temel Güvenlik Bulguları

- **Yönetici Süreçleri Ring 3'tedir:** Bir sürecin yönetici olması donanıma doğrudan erişebileceği anlamına gelmez. Tüm çekirdek talepleri sistem çağrıları (syscall) üzerinden doğrulanmak zorundadır.
- **BYOVD Tehdidi:** Yasal donanım üreticileri tarafından imzalanmış ancak zafiyet barındıran eski sürücüler (örn: `RTCore64.sys`), saldırganlar tarafından DSE imza kontrolünü atlatarak çekirdeğe sızmak için kullanılır.
- **İşaretçi Doğrulaması:** Kullanıcı modundan çekirdeğe aktarılan bellek göstericileri katı sınır kontrollerine tabi tutulmazsa, kullanıcı modu çekirdek belleğini ezerek keyfi kod çalıştırabilir.

---

## 📜 Lisans

Bu projenin tüm hakları saklıdır. Detaylı lisans şartları için üst kısımdaki lisans uyarısını inceleyiniz.
