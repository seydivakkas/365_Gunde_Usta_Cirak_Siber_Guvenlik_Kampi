# GÜN 014: Aşama 1 Kalite Özeti ve Güvenlik Temelleri Kabulü (Mini Proje 2)

![Lisans: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama: 01 Kapanış](https://img.shields.io/badge/A%C5%9Fama-01%20Kapan%C4%B1%C5%9F-blue?style=flat-square)
![Hafta: 02 Final](https://img.shields.io/badge/Hafta-02%20Final-indigo?style=flat-square)
![Durum: PASS](https://img.shields.io/badge/Durum-PASS-brightgreen?style=flat-square)
![Test Kapsamı: 100%](https://img.shields.io/badge/Test%20Kapsam%C4%B1-100%25-success?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 📌 Genel Bakış ve Hedefler

Bu çalışma; Aşama 01 (Gün 001 - Gün 013) boyunca inşa edilen temel siber güvenlik yapı taşlarını:
- CIA Triad, Tehdit-Açıklık-Risk Matrisi ve Etik RoE Sözleşmesi,
- NIST CSF 2.0'ın 6 Temel İşlevi (Govern, Identify, Protect, Detect, Respond, Recover),
- Varlık Envanteri, Veri Sınıflandırması ve STRIDE Tehdit Modellemesi,
- Sanallaştırma İzolasyonu, CIS Benchmark Taban Çizgisi, Mikro-Segmentasyon ve Conntrack,
- WORM Değişmez Yedekleme, Rollback Tatbikatı ve CRAAP Kaynak Doğrulamasını

tek bir kurumsal **Kanıt Zinciri (Chain of Evidence)** altında birleştirir ve "Bir güvenlik önlemini tek başına eksiksiz savunma sanma" (Single Measure Fallacy) ölümcül yanılgısını bilimsel olarak denetler.

---

## 📂 Dizin Yapısı

```text
portfolio/hafta_02/gun_014/
├── README.md                                   # Bu bilgilendirme ve kullanım kılavuzu
├── ders.md                                     # 7 bölümlü Usta-Çırak masterclass ders metni
├── soru_cevap.md                               # Soru bankasındaki 3 soruya derin kurumsal yanıtlar
├── rapor.md                                    # 20/40/25/15 puanlama ve doğrulama raporu
├── sonuc.json                                  # 14 zorunlu standart alanı içeren makine-okunabilir özet
├── manifest.json                               # Kriptografik SHA-256 dosya bütünlük indeks tablosu
├── uygulama/
│   └── stage1_security_auditor.py              # Aşama 1 kalite ve kabul denetim CLI motoru
├── tests/
│   └── test_stage1_security_auditor.py         # 14 birim testten oluşan kapsamlı doğrulama paketi
├── ornek_veri/
│   ├── asama_01_laboratuvar_dosyasi.json       # Altın kabul ve kusurlu laboratuvar projeleri veritabanı
│   └── csf_2_0_denetim_rubrigi.json            # NIST CSF 2.0 ve RoE kabul standartları rubriği
└── kanit/
    ├── gercek/
    │   ├── komut_ve_cikis.txt                  # Gerçek CLI yürütme çıktıları ve ortam bilgisi
    │   └── test_sonuclari.txt                  # 14/14 unittest başarı çıktısı
    └── temsili/
        └── asama_01_kalite_kabul_mimarisi.txt  # Etiketli temsilî ASCII kanıt zinciri şeması
```

---

## 🚀 Çalıştırma ve Test Rehberi

### 1. Ortam Gereksinimleri
- Python 3.10+ (Standart Kütüphane: `os`, `sys`, `json`, `hashlib`, `argparse`, `datetime`, `unittest`)
- Harici üçüncü taraf bağımlılığı yoktur.

### 2. Aşama 1 Kabul Denetimini Çalıştırma
```bash
# Tüm Aşama 1 laboratuvar projelerini topluca denetle
python portfolio/hafta_02/gun_014/uygulama/stage1_security_auditor.py --dosya portfolio/hafta_02/gun_014/ornek_veri/asama_01_laboratuvar_dosyasi.json --tumunu-denetle

# Altın kabul projesini derinlemesine denetle ve SHA-256 sertifikası üret
python portfolio/hafta_02/gun_014/uygulama/stage1_security_auditor.py --dosya portfolio/hafta_02/gun_014/ornek_veri/asama_01_laboratuvar_dosyasi.json --proje-id LAB-SEC-GOLDEN-01 --denetle
```

### 3. Birim Testleri Çalıştırma
```bash
python -m unittest portfolio/hafta_02/gun_014/tests/test_stage1_security_auditor.py -v
```

---

## 🛡️ Güvenlik ve Etik Sınırlar

- Aşama 1 kabul denetimi; yetkisiz dış ağ taramalarını, üretim sistemlerine teması ve yasal sözleşmesiz (RoE) testleri kesin olarak durdurma (`CRIT-01` / `STOP`) kuralıyla korur.
- Tüm veriler sentetiktir; gerçek kullanıcı veya sistem verisi içermez.
