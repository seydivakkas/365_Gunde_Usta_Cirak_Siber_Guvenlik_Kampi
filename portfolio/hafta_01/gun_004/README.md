# GÜN 004: NIST CSF 2.0 İşlevleri (Govern, Identify, Protect, Detect, Respond, Recover)

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Durum](https://img.shields.io/badge/durum-PASS-brightgreen?style=flat-square)
![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 📖 Genel Bakış

Bu çalışma, **NIST Cybersecurity Framework 2.0 (CSF 2.0)** çekirdeğinde yer alan 6 temel işlevin (Govern, Identify, Protect, Detect, Respond, Recover) kurumsal siber güvenlik duruşundaki yerini, birbirini nasıl beslediğini ve tek bir fonksiyona aşırı odaklanmanın yarattığı **"Savunma Yanılsaması"nı (Protect Bias)** incelemektedir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_01/gun_004/
├── ders.md                          # 7 aşamalı "Usta-Çırak" masterclass dersi
├── soru_cevap.md                    # 4 katı alt başlıklı kavramsal soru-cevaplar
├── rapor.md                         # 20/40/25/15 puan tablosu ve denetim raporu
├── README.md                        # Kullanım kılavuzu ve proje özeti
├── sonuc.json                       # 14 alanlı standart makine-okunabilir durum
├── manifest.json                    # SHA-256 bütünlük özeti (küçük harf, / ayracı)
├── uygulama/
│   └── nist_csf_evaluator.py        # Zengin açıklamalı NIST CSF 2.0 CLI motoru
├── tests/
│   └── test_nist_csf_evaluator.py   # 9 birim test (pozitif/negatif/sınır kontroller)
├── ornek_veri/
│   └── nist_csf_matrisi.json        # 16 kategorili gerçekçi kurumsal matris
└── kanit/
    ├── gercek/
    │   ├── komut_ve_cikis.txt       # CLI yürütme ve terminal stdout/stderr çıktısı
    │   └── test_sonuclari.txt       # 9/9 unittest başarı kaydı
    └── temsili/
        └── nist_csf_dongusu.txt     # ASCII formatında CSF 2.0 döngü şeması
```

---

## 🚀 Çalıştırma Talimatları

### 1. NIST CSF 2.0 Matris Değerlendirme Aracını Çalıştırma
```bash
python portfolio/hafta_01/gun_004/uygulama/nist_csf_evaluator.py --matris portfolio/hafta_01/gun_004/ornek_veri/nist_csf_matrisi.json
```

JSON formatında makine çıktısı almak için:
```bash
python portfolio/hafta_01/gun_004/uygulama/nist_csf_evaluator.py --matris portfolio/hafta_01/gun_004/ornek_veri/nist_csf_matrisi.json --format json
```

### 2. Kapsamlı Birim Testleri Çalıştırma
```bash
python -m unittest portfolio/hafta_01/gun_004/tests/test_nist_csf_evaluator.py -v
```
