# GÜN 018: Süreç, İş Parçacığı ve Hizmet Güvenlik Analizörü

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

Bu modül, Siber Güvenlik 365 Gün Müfredatı'nın **Aşama 02 (Sistem, Bellek ve Düşük Seviyeli Güvenlik)** kapsamında geliştirilmiştir. İşletim sistemi kaynak yönetimi ve yerel yetki yükseltme (LPE) mekanizmalarını oluşturan:
1. **Süreç (Process) İzolasyonu ve Sanal Adres Alanı (VAS) Sınırları**
2. **İş Parçacığı (Thread) Ortak Bellek Paylaşımı ve Yarış Durumları (Race Condition / TOCTOU)**
3. **Arka Plan Hizmetleri (Services/Daemons) ve Session 0 İzolasyonu**
4. **Tırnaksız Servis Yolu (Unquoted Service Path - MITRE ATT&CK T1574.009)**
5. **Zayıf Servis ve Klasör İzinleri ile SYSTEM Yetkisine Yükselme**

konularını derinlemesine inceleyen, canlı sistem süreç ve servislerini belgeleyen (G018-SC2) ve kurumsal hizmet taban çizgisini denetleyen bir araç içerir.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_03/gun_018/
├── uygulama/
│   └── process_thread_service_security_auditor.py      # Her satırı açıklamalı güvenlik analiz motoru
├── tests/
│   └── test_process_thread_service_security_auditor.py  # 14 adet kapsamlı birim testi
├── ornek_veri/
│   ├── process_thread_service_inventory.json           # Örnek süreç, hizmet ve thread veri seti
│   └── service_security_baseline.json                  # CIS ve MITRE ATT&CK hizmet kuralları
├── kanit/
│   ├── gercek/
│   │   ├── komut_ve_cikis.txt                          # CLI yürütme terminal kanıtı
│   │   └── test_sonuclari.txt                          # 14/14 PASS unittest test raporu
│   └── temsili/
│       └── surec_thread_hizmet_mimarisi.txt            # ASCII süreç/thread/hizmet mimari şeması
├── ders.md                                             # 7 bölümlük derin usta-çırak ders metni
├── soru_cevap.md                                       # 3 adet 4 alt başlıklı soru-cevap senaryosu
├── rapor.md                                            # 100/100 değerlendirme ve kabul raporu
├── sonuc.json                                          # Makine tarafından okunabilir durum kaydı
├── manifest.json                                       # Kriptografik SHA-256 doğrulama özeti
└── README.md                                           # Bu dokümantasyon dosyası
```

---

## 🚀 Kurulum ve Çalıştırma

### Gereksinimler
- Python 3.10+ (Standart kütüphane yeterlidir, harici bağımlılık gerekmez)

### 1. Canlı Süreç ve Sistem Hizmeti Envanterini Çıkarma
```powershell
python uygulama/process_thread_service_security_auditor.py --live
```

### 2. Hizmet Güvenlik Taban Çizgisi ve Zaafiyet Denetimi
```powershell
python uygulama/process_thread_service_security_auditor.py --sample ornek_veri/process_thread_service_inventory.json --baseline ornek_veri/service_security_baseline.json
```

### 3. Birim Testleri Yürütme
```powershell
python -m unittest tests/test_process_thread_service_security_auditor.py -v
```

---

## 🛡️ Temel Güvenlik Bulguları

- **Unquoted Service Path:** Servis yollarında boşluk bulunması ve çift tırnak (`"`) kullanılmaması durumunda, standart kullanıcılar `C:\Program.exe` gibi ara yollara zararlı koyarak SYSTEM yetkisi elde edebilir.
- **Zayıf Dizin İzinleri:** Standart kullanıcıların yazabildiği servis klasörlerindeki ikili dosyalar değiştirilerek tam sistem kontrolü sağlanabilir.
- **İş Parçacığı Senkronizasyonu:** Mutex kilitleri uygulanmadığında aynı bellek alanını paylaşan iş parçacıkları veri bozulmasına (Race Condition) yol açar.

---

## 📜 Lisans

Bu projenin tüm hakları saklıdır. Detaylı lisans şartları için üst kısımdaki lisans uyarısını inceleyiniz.
