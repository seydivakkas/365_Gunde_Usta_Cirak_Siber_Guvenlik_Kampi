# GÜN 122: Savunma Derinliği (Defense-in-Depth) ve Güvenlik Kontrol Tipleri

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Day: 122/365](https://img.shields.io/badge/G%C3%BCn-122%2F365-blue?style=flat-square)
![Status: 100/100 PASS](https://img.shields.io/badge/Status-100%2F100%20PASS-brightgreen?style=flat-square)

---

## ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

**YASAKLAR:**
1. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
2. Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
3. Alt lisanslanamaz, satılamaz veya devredilemez.
4. Tersine mühendislik yapılamaz.

**İZİN VERİLEN KULLANIM:**
- GitHub üzerinde görüntüleme ve okuma.
- Kişisel öğrenim amacıyla kodu inceleme (kopyalamadan).

YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.  
İzin talepleri için: GitHub @seydivakkas

---

## Proje Genel Bakışı

Bu proje, NIST SP 800-53 Rev 5 ve NSA Savunma Derinliği (Defense-in-Depth) ilkelerine tam uyumlu olarak geliştirilmiş saf Python standardında bir **7 Katmanlı Savunma Derinliği ve Kontrol Tipleri Yönetim ve Simülasyon Motoru**dur.

Sistem; 7 temel savunma katmanını (Fiziksel, Çevre, İç Ağ, Sunucu, Uygulama, Veri, Kimlik) modeller; kontrolleri fonksiyonlarına göre (Önleyici, Tespit Edici, Düzeltici, Telafi Edici, Caydırıcı) sınıflandırır; katman boşluklarını (CWE-653 Defense Gap), gözetimsiz katmanları (Blind Spot) ve tek hata noktalarını (CWE-1008 SPoF) otomatik tespit eder; siber saldırı zincirlerini (Kill Chain) çok katmanlı mimari üzerinde simüle eder.

---

## Dizin Yapısı

```
portfolio/hafta_18/gun_122/
├── uygulama/
│   ├── __init__.py
│   ├── defense_in_depth_engine.py   # Çekirdek 7 katman ve simülasyon motoru
│   └── defense_cli.py               # Komut satırı denetim ve simülasyon aracı
├── tests/
│   ├── __init__.py
│   └── test_defense_in_depth.py     # 15/15 birim test (%100 PASS)
├── ornek_veri/
│   ├── defense_architecture_config.json # 7 katmanlı kurumsal mimari ve senaryolar
│   └── invalid_defense_scenarios.json   # 9 negatif kontrol test senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── savunma_analiz_raporu.txt
│   │   └── komut_ve_cikis.txt
│   └── temsili/
│       └── savunma_mimarisi.txt     # ASCII mimari illüstrasyonu
├── kanit_uretici.py                 # Otomatik kanıt üretim ve doğrulama betiği
├── ders.md                          # Usta-Çırak interaktif ders anlatımı
├── soru_cevap.md                    # 3 derin teknik soru ve çözüm analizi
├── rapor.md                         # 100/100 tam puan değerlendirme karnesi
├── sonuc.json                       # Puan ve yeterlilik doğrulama dosyası
├── manifest.json                    # Dosya bütünlüğü ve SHA256 özetleri
└── README.md                        # Dokümantasyon ve lisans bildirimi
```

---

## Çalıştırma ve Kullanım

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest tests/test_defense_in_depth.py
```

### 2. CLI ile Savunma Derinliği Denetimi
```bash
# Mimariyi denetle ve konsol özetini gör
python uygulama/defense_cli.py audit ornek_veri/defense_architecture_config.json

# Markdown formatında kapsamlı matris raporu üret
python uygulama/defense_cli.py audit ornek_veri/defense_architecture_config.json --format markdown
```

### 3. Çok Katmanlı Saldırı Simülasyonu Koşturma
```bash
# Ransomware senaryosunu koştur
python uygulama/defense_cli.py simulate ornek_veri/defense_architecture_config.json SCN-RANSOM-01

# SQL Injection senaryosunu koştur
python uygulama/defense_cli.py simulate ornek_veri/defense_architecture_config.json SCN-SQLI-01
```

### 4. Tüm Kanıtları Yeniden Üretme
```bash
python kanit_uretici.py
```
