# GÜN 015: İkili Gösterim, Byte ve Karakter Kodlaması Güvenlik Analizörü

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

Bu modül, Siber Güvenlik 365 Gün Müfredatı'nın **Aşama 02 (Sistem, Bellek ve Düşük Seviyeli Güvenlik)** kapsamında geliştirilmiştir. Modern web, işletim sistemi ve ağ güvenliğinde en sık istismar edilen temel yapı taşlarından olan:
1. **İkili (Bit/Byte) Gösterimi ve Hex Düzenleri**
2. **Karakter Kodlama Çeşitleri (ASCII, UTF-8, UTF-16, UTF-32)**
3. **Null Byte (`\x00`) Enjeksiyonu**
4. **Homoglyph ve IDN (Uluslararası Alan Adı) Sahteciliği**
5. **Tampon Kesilme (Buffer Truncation) ve Bayt Bölünme Açıkları**

konularını hem teorik hem de pratik/otomatize bir denetim motoru eşliğinde öğretir.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_03/gun_015/
├── uygulama/
│   └── binary_byte_encoding_inspector.py     # Her satırı açıklamalı güvenlik denetim motoru
├── tests/
│   └── test_binary_byte_encoding_inspector.py # 14 adet kapsamlı birim testi
├── ornek_veri/
│   ├── karakter_kodlama_ornekleri.json       # Farklı alfabe, null byte, emoji veri seti
│   └── encoding_security_baseline.json       # Kodlama güvenlik denetim kuralları
├── kanit/
│   ├── gercek/
│   │   ├── komut_ve_cikis.txt                # CLI yürütme terminal kanıtı
│   │   └── test_sonuclari.txt                # 14/14 PASS unittest test raporu
│   └── temsili/
│       └── ikili_ve_karakter_kodlama_mimarisi.txt # ASCII mimari şeması
├── ders.md                                   # 7 bölümlük derin usta-çırak ders metni
├── soru_cevap.md                             # 3 adet derinlemesine soru-cevap senaryosu
├── rapor.md                                  # 100/100 değerlendirme ve kabul raporu
├── sonuc.json                                # Makine tarafından okunabilir durum kaydı
├── manifest.json                             # Kriptografik SHA-256 doğrulama özeti
└── README.md                                 # Bu dokümantasyon dosyası
```

---

## 🚀 Kurulum ve Çalıştırma

### Gereksinimler
- Python 3.10+ (Standart kütüphane yeterlidir, harici bağımlılık gerekmez)

### 1. Güvenlik Denetim Aracını Çalıştırma
```powershell
python uygulama/binary_byte_encoding_inspector.py --input ornek_veri/karakter_kodlama_ornekleri.json
```

### 2. Birim Testleri Yürütme
```powershell
python -m unittest tests/test_binary_byte_encoding_inspector.py -v
```

---

## 🛡️ Güvenlik Bulguları ve Kontrolleri

- **Null Byte Algılama:** Metin akışı içerisindeki `\x00` baytları tespit edilerek C-string uyumsuzlukları ve dosya uzantısı atlatma girişimleri engellenir.
- **Homoglyph/IDN Tespiti:** Latin olmayan ve Latin karakterlerle görsel olarak ayırt edilemeyen (örn: Kiril `а`) karakterler tespit edilerek oltalama riskleri raporlanır.
- **Tampon Kesilme Simülasyonu:** Çok baytlı UTF-8 karakterlerin bayt sınırlarında bölünmesi durumunda oluşabilecek veri kaybı veya güvenlik denetimi bypass senaryoları simüle edilir.

---

## 📜 Lisans

Bu projenin tüm hakları saklıdır. Detaylı lisans şartları için üst kısımdaki lisans uyarısını inceleyiniz.
