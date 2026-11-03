# Gün 072: Değişkenler, Veri Tipleri ve Güvenli Giriş

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Stage: 04 In Progress](https://img.shields.io/badge/Stage-04%20In%20Progress-blue?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/Score-100%2F100-success?style=flat-square)
![Tests: 14/14 PASS](https://img.shields.io/badge/Tests-14%2F14%20PASS-blue?style=flat-square)
![Negative Controls: 9/9 PASS](https://img.shields.io/badge/Negative%20Controls-9%2F9%20PASS-blue?style=flat-square)

## Lisans ve Telif Hakkı

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
amaçlı olarak paylaşılmıştır.

YASAKLAR:
  1. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
  2. Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
  3. Alt lisanslanamaz, satılamaz veya devredilemez.
  4. Tersine mühendislik yapılamaz.

İZİN VERİLEN KULLANIM:
  - GitHub üzerinde görüntüleme ve okuma.
  - Kişisel öğrenim amacıyla kodu inceleme (kopyalamadan).

YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
İzin talepleri için: GitHub @seydivakkas
```

---

## Genel Bakış

Bu paket, **Siber Güvenlik 365 Gün Müfredatı** kapsamında **Aşama 04 (Siber Güvenlik için Python Geliştirme ve Otomasyon)** safhasının **Gün 072: Değişkenler, veri tipleri ve güvenli giriş** çalışmasını içerir.

### Temel Güvenlik Yetenekleri:
1. **Unicode Kanonikleştirme ve Null Byte Temizliği:** Unicode NFKC normalizasyonu ile homoglyph/fullwidth baypaslarının önlenmesi ve C tabanlı `\x00` zehirlemelerinin reddi.
2. **Tip Karmaşası (Type Confusion) Savunması:** Python'ın `bool` sınıfının `int` sınıfından kalıtım alması tuzağının (`isinstance(True, int) == True`) engellenmesi ve katı tamsayı/port doğrulaması.
3. **Komut Enjeksiyonu Koruması:** Ana makine adı ve serbest metin alanlarında kabuk metakarakterlerinin (`;|&$`><\n\r` vb.) filtrelenmesi ve katı RFC 1123 regex denetimi.
4. **Dizin Atlatma (Path Traversal) Engelleme:** `os.path.commonpath` algoritmasıyla dosya yollarının güvenli temel dizin sınırları içinde kaldığının kesin matematiksel teyidi.
5. **Katı Mantıksal Değer (Boolean) Dönüşümü:** Belirsiz değerlerin reddi, yalnızca katı boolean kümesinin (`True`, `False`, `1`, `0`, `yes`, `no`) kabul edilmesi.

---

## Dizin Yapısı

```
portfolio/hafta_11/gun_072/
├── uygulama/
│   ├── __init__.py
│   └── secure_input_and_type_validator.py   # Güvenli girdi ve tip doğrulama motoru
├── tests/
│   ├── __init__.py
│   └── test_secure_input_and_type_validator.py # 14 birim test ve 9 negatif kontrol
├── ornek_veri/
│   ├── guvenli_girdi_ornekleri.json         # Geçerli ve güvenli parametre yükleri
│   └── invalid_input_test_cases.json        # 9 negatif sınır testi senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── guvenli_girdi_dogrulama_raporu.txt # Üretilen girdi doğrulama raporu
│   │   ├── komut_ve_cikis.txt                # CLI çalıştırma komut ve konsol çıktısı
│   │   ├── negatif_kontrol_sonuclari.txt     # 9 negatif kontrol kanıt özeti
│   │   └── test_sonuclari.txt                # 14 birim test terminal çıktısı
│   └── temsili/
│       └── guvenli_girdi_ve_tip_denetim_mimarisi.txt # ASCII mimari şeması
├── ders.md                                   # Usta-Çırak güvenli girdi dersi
├── soru_cevap.md                             # 4 zorunlu alt başlıklı 3 teknik soru ve analiz
├── rapor.md                                  # 100/100 tam puanlı başarı raporu
├── README.md                                 # Dokümantasyon ve lisans bildirimi
├── sonuc.json                                # 14 standartlaştırılmış sonuç alanı
└── manifest.json                             # SHA-256 dosya bütünlük listesi
```

---

## Çalıştırma Talimatları

### Birim Testleri Koşma:
```bash
python -m unittest portfolio.hafta_11.gun_072.tests.test_secure_input_and_type_validator -v
```

### Doğrulayıcı Motorunu Çalıştırma:
```bash
python -m portfolio.hafta_11.gun_072.uygulama.secure_input_and_type_validator \
    --input portfolio/hafta_11/gun_072/ornek_veri/guvenli_girdi_ornekleri.json \
    --output-txt portfolio/hafta_11/gun_072/kanit/gercek/guvenli_girdi_dogrulama_raporu.txt
```
