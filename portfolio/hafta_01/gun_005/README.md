# GÜN 005: Varlık Envanteri ve Veri Sınıflandırması

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Durum](https://img.shields.io/badge/durum-PASS-brightgreen?style=flat-square)
![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 📖 Genel Bakış

Bu çalışma, bir kurumun siber varlıklarının (Cihaz, Uygulama, Kimlik, Veri, Ağ) envanter altına alınmasını, 4 seviyeli kurumsal veri sınıflandırması hiyerarşisini (Kamuya Açık, Dahili, Gizli, Çok Gizli/Sır), **Varlık Sahipliği (Asset Ownership)** ilkelerini ve **"Donanım Fiyatı != Varlık Değeri" (Crown Jewels Paradoksu)** mekanizmasını incelemektedir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_01/gun_005/
├── ders.md                          # 7 aşamalı "Usta-Çırak" masterclass dersi
├── soru_cevap.md                    # 4 katı alt başlıklı kavramsal soru-cevaplar
├── rapor.md                         # 20/40/25/15 puan tablosu ve denetim raporu
├── README.md                        # Kullanım kılavuzu ve proje özeti
├── sonuc.json                       # 14 alanlı standart makine-okunabilir durum
├── manifest.json                    # SHA-256 bütünlük özeti (küçük harf, / ayracı)
├── uygulama/
│   └── asset_classifier.py          # Zengin açıklamalı varlık değerlendirme CLI motoru
├── tests/
│   └── test_asset_classifier.py     # 10 birim test (pozitif/negatif kontroller)
├── ornek_veri/
│   └── varlik_envanteri.json        # 5 farklı varlık türünü içeren referans veri
└── kanit/
    ├── gercek/
    │   ├── komut_ve_cikis.txt       # CLI yürütme ve terminal stdout/stderr çıktısı
    │   └── test_sonuclari.txt       # 10/10 unittest başarı kaydı
    └── temsili/
        └── veri_siniflandirma_piramidi.txt # ASCII formatında sınıflandırma piramidi
```

---

## 🚀 Çalıştırma Talimatları

### 1. Varlık Envanteri ve Sınıflandırma Denetimini Çalıştırma
```bash
python portfolio/hafta_01/gun_005/uygulama/asset_classifier.py --envanter portfolio/hafta_01/gun_005/ornek_veri/varlik_envanteri.json
```

JSON formatında makine çıktısı almak için:
```bash
python portfolio/hafta_01/gun_005/uygulama/asset_classifier.py --envanter portfolio/hafta_01/gun_005/ornek_veri/varlik_envanteri.json --format json
```

### 2. Kapsamlı Birim Testleri Çalıştırma
```bash
python -m unittest portfolio/hafta_01/gun_005/tests/test_asset_classifier.py -v
```
