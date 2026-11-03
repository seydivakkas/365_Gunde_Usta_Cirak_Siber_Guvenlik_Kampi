# GÜN 006: Tehdit Modelleme Başlangıcı (Varlık, Güven Sınırı, Saldırı Yüzeyi ve Kontrol)

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Durum](https://img.shields.io/badge/durum-PASS-brightgreen?style=flat-square)
![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 📖 Genel Bakış

Bu çalışma; sistem ve yazılım mimarilerinde **Tehdit Modelleme (Threat Modeling)** temellerini, **Veri Akış Diyagramı (DFD)** yapısını, **Güven Sınırlarını (Trust Boundaries)** ve **Microsoft STRIDE** tehdit sınıflandırmasını incelemektedir. *"Tehdit != Olay"* ilkesi doğrultusunda yerel bir not defteri uygulaması (`KriptoNot`) modellenmiş ve sınır geçiş kontrolleri denetlenmiştir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_01/gun_006/
├── ders.md                          # 7 aşamalı "Usta-Çırak" masterclass dersi
├── soru_cevap.md                    # 4 katı alt başlıklı kavramsal soru-cevaplar
├── rapor.md                         # 20/40/25/15 puan tablosu ve denetim raporu
├── README.md                        # Kullanım kılavuzu ve proje özeti
├── sonuc.json                       # 14 alanlı standart makine-okunabilir durum
├── manifest.json                    # SHA-256 bütünlük özeti (küçük harf, / ayracı)
├── uygulama/
│   └── threat_modeler.py            # Zengin açıklamalı DFD tehdit modelleme CLI motoru
├── tests/
│   └── test_threat_modeler.py       # 10 birim test (pozitif/negatif kontroller)
├── ornek_veri/
│   └── not_uygulamasi_dfd.json      # Yerel not defteri uygulaması DFD modeli
└── kanit/
    ├── gercek/
    │   ├── komut_ve_cikis.txt       # CLI yürütme ve terminal stdout/stderr çıktısı
    │   └── test_sonuclari.txt       # 10/10 unittest başarı kaydı
    └── temsili/
        └── veri_akis_diyagrami.txt  # ASCII formatında DFD Level 1 ve STRIDE şeması
```

---

## 🚀 Çalıştırma Talimatları

### 1. DFD ve Tehdit Modelleme Doğrulama Aracını Çalıştırma
```bash
python portfolio/hafta_01/gun_006/uygulama/threat_modeler.py --dfd portfolio/hafta_01/gun_006/ornek_veri/not_uygulamasi_dfd.json
```

JSON formatında makine çıktısı almak için:
```bash
python portfolio/hafta_01/gun_006/uygulama/threat_modeler.py --dfd portfolio/hafta_01/gun_006/ornek_veri/not_uygulamasi_dfd.json --format json
```

### 2. Kapsamlı Birim Testleri Çalıştırma
```bash
python -m unittest portfolio/hafta_01/gun_006/tests/test_threat_modeler.py -v
```
