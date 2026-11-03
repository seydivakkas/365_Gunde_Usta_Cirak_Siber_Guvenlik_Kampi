# GÜN 120: Tehdit Modellemede STRIDE Metodolojisi ve DFD Analizi

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Day: 120/365](https://img.shields.io/badge/G%C3%BCn-120%2F365-blue?style=flat-square)
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

Bu proje, yazılım mimarisi ve altyapı tasarım aşamasında güvenlik risklerini proaktif olarak tespit etmek amacıyla geliştirilmiş saf Python standardında bir **STRIDE Tehdit Modelleme ve DFD Analiz Motoru**dur.

Sistem; Veri Akış Diyagramı (DFD) bileşenlerini (Dış Varlık, Süreç, Veri Deposu, Veri Akışı) modeller, aralarındaki güven sınırlarını (Trust Boundary) tespit eder, STRIDE matrisine göre potansiyel tehditleri otomatik türetir, DREAD yöntemiyle risk puanlaması yapar ve azaltılmamış kritik tehditler varken sistemin üretime çıkmasını engeller (CWE-1025).

---

## Dizin Yapısı

```
portfolio/hafta_18/gun_120/
├── uygulama/
│   ├── __init__.py
│   ├── stride_threat_engine.py      # DFD, STRIDE, DREAD ve analiz motoru
│   └── stride_cli.py                # Komut satırı yönetim aracı
├── tests/
│   ├── __init__.py
│   └── test_stride_threat_modeling.py # 15/15 birim test (%100 PASS)
├── ornek_veri/
│   ├── stride_model_config.json      # Örnek e-ticaret DFD mimarisi
│   └── invalid_stride_scenarios.json # 9 negatif kontrol senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── stride_analiz_raporu.txt
│   │   └── komut_ve_cikis.txt
│   └── temsili/
│       └── stride_mimarisi.txt       # ASCII mimari illüstrasyonu
├── kanit_uretici.py                  # Otomatik kanıt üretim ve doğrulama betiği
├── ders.md                           # Usta-Çırak interaktif ders anlatımı
├── soru_cevap.md                     # 3 derin teknik soru ve çözüm analizi
├── rapor.md                          # 100/100 tam puan değerlendirme karnesi
├── sonuc.json                        # Puan ve yeterlilik doğrulama dosyası
├── manifest.json                     # Dosya bütünlüğü ve SHA256 özetleri
└── README.md                         # Dokümantasyon ve lisans bildirimi
```

---

## Çalıştırma ve Kullanım

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest tests/test_stride_threat_modeling.py
```

### 2. CLI ile Tehdit Analizi Yapma
```bash
# Modeli analiz et ve özet çıktıyı gör
python uygulama/stride_cli.py model ornek_veri/stride_model_config.json

# Markdown formatında kapsamlı rapor üret
python uygulama/stride_cli.py model ornek_veri/stride_model_config.json --format markdown

# Hızlı DREAD risk skoru hesapla
python uygulama/stride_cli.py dread 8 7 9 10 5
```

### 3. Tüm Kanıtları Yeniden Üretme
```bash
python kanit_uretici.py
```
