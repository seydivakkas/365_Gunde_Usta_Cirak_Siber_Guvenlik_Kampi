# GÜN 007: Mini Proje 1 — Güvenli Laboratuvar Sözleşmesi (İzolasyon, Ağ Kuralları ve Erişim Kısıtları)

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Durum](https://img.shields.io/badge/durum-PASS-brightgreen?style=flat-square)
![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 📖 Genel Bakış

Bu çalışma, Siber Güvenlik 365 Gün Müfredatının **1. Hafta Kapanış Projesidir (Milestone 1)**. Gün 001'den Gün 006'ya kadar işlenen tüm temel prensipleri (CIA üçlüsü, tehdit-açıklık-risk ilişkisi, etik yetkilendirme & angajman kuralları, NIST CSF 2.0 fonksiyonları, varlık envanteri & sınıflandırma ve DFD tabanlı tehdit modelleme) bir araya getirerek **"Karantina Altında Güvenli Zararlı Yazılım Analiz ve Simülasyon Laboratuvarı"** sözleşmesini doğrulamaktadır.

Her bir laboratuvar düğümünün ağ segmentasyonu, BSL-4 seviyesinde sızıntı önleme kalkanı, çift yönlü erişim matrisi, yetki sınırları ve acil durum protokolleri (Kill-Switch) doğrulanır.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_01/gun_007/
├── ders.md                          # 7 aşamalı "Usta-Çırak" masterclass dersi
├── soru_cevap.md                    # 4 katı alt başlıklı kavramsal soru-cevaplar
├── rapor.md                         # 20/40/25/15 puan tablosu ve denetim raporu
├── README.md                        # Kullanım kılavuzu ve proje özeti
├── sonuc.json                       # 14 alanlı standart makine-okunabilir durum
├── manifest.json                    # SHA-256 bütünlük özeti (küçük harf, / ayracı)
├── uygulama/
│   └── lab_contract_validator.py    # Zengin açıklamalı Laboratuvar Sözleşme Doğrulayıcı CLI motoru
├── tests/
│   └── test_lab_contract_validator.py # 11 birim test (pozitif/negatif kontroller)
├── ornek_veri/
│   └── laboratuvar_sozlesmesi.json  # 5 düğümlü tam yalıtımlı laboratuvar sözleşmesi
└── kanit/
    ├── gercek/
    │   ├── komut_ve_cikis.txt       # CLI yürütme ve terminal stdout/stderr çıktısı
    │   └── test_sonuclari.txt       # 11/11 unittest başarı kaydı
    └── temsili/
        └── laboratuvar_topolojisi.txt # ASCII formatında lab topolojisi ve güvenlik bölgeleri
```

---

## 🚀 Çalıştırma Talimatları

### 1. Laboratuvar Sözleşmesini Doğrulama (CLI)
```bash
python portfolio/hafta_01/gun_007/uygulama/lab_contract_validator.py --contract portfolio/hafta_01/gun_007/ornek_veri/laboratuvar_sozlesmesi.json
```

JSON formatında makine çıktısı almak için:
```bash
python portfolio/hafta_01/gun_007/uygulama/lab_contract_validator.py --contract portfolio/hafta_01/gun_007/ornek_veri/laboratuvar_sozlesmesi.json --format json
```

### 2. Kapsamlı Birim Testleri Çalıştırma
```bash
python -m unittest portfolio/hafta_01/gun_007/tests/test_lab_contract_validator.py -v
```

---

## 🛡️ Lisans ve Kullanım Şartları

Bu proje ve ilgili tüm dosyalar **Seydi Eryılmaz (@seydivakkas)** adına tescilli olup tüm hakları saklıdır. Hiçbir açık kaynak lisansına (MIT, Apache, GPL vb.) tabi değildir. Ticari veya gayriticari olarak kopyalanamaz, paylaşılamaz, türetilemez.
