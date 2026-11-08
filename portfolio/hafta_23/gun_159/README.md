# Gün 159: Girdi Doğrulama ve Bağlama Duyarlı Çıktı Kodlama Sistemi

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama](https://img.shields.io/badge/Aşama-7%20Web%20Güvenliği-blue?style=flat-square)
![Hafta](https://img.shields.io/badge/Hafta-23-orange?style=flat-square)
![Durum](https://img.shields.io/badge/Testler-15%2F15%20PASS-brightgreen?style=flat-square)

Bu modül; web uygulamalarında istemciden gelen verileri sınırda kanonikleştirerek (Unicode NFKC, recursive URL unquoting, Null byte temizliği), pozitif izin listesi (Allowlist) prensibiyle sözdizimsel ve anlamsal olarak doğrulayan; enjeksiyon saldırılarını (SQLi, XSS, Komut Enjeksiyonu, Path Traversal) tespit eden ve veriyi hedef yorumlayıcı bağlamına göre (HTML Gövdesi, HTML Özniteliği, JavaScript Değişkeni, URL Parametresi, CSS) bağlama duyarlı olarak kodlayan (**Context-Aware Output Encoding - OWASP C-03**) çift savunma hattı motorudur.

---

## 1. Dizin Yapısı

```
portfolio/hafta_23/gun_159/
├── ders.md                         # Usta-Çırak derin teknik ders notları
├── soru_cevap.md                   # 4 başlıklı 3 adet derinlemesine teknik soru & cevap
├── rapor.md                        # 100/100 PASS başarı karnesi
├── README.md                       # Proje dokümantasyonu ve özel lisans
├── sonuc.json                      # Yapılandırılmış yürütme özeti
├── manifest.json                   # 20 dosyanın SHA-256 doğrulama özeti
├── kanit_uretici.py                # Kanıt üretim ve yürütme orkestrasyon betiği
├── uygulama/
│   ├── __init__.py                 # Python modül tanımlayıcısı
│   ├── input_validator_encoder_engine.py # Doğrulama ve bağlam kodlama motoru
│   └── input_validation_cli.py     # CLI yönetim arayüzü
├── tests/
│   ├── __init__.py                 # Test paketi tanımlayıcısı
│   └── test_input_validator_encoder.py # 15 kapsamlı birim test
├── ornek_veri/
│   ├── enterprise_input_schemas.json # Kurumsal şema ve geçerli yük örneği
│   └── invalid_input_payloads.json # 9 adet negatif kontrol saldırı payload'u
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt      # 15/15 birim test çıktısı
    │   ├── negatif_kontrol_sonuclari.txt # 9 negatif senaryo engelleme çıktısı
    │   ├── validation_encoding_report.json # Şema toplu doğrulama JSON raporu
    │   ├── sanitized_output_samples.txt # Farklı bağlamlarda kodlama örnekleri
    │   └── komut_ve_cikis.txt      # CLI yürütme logları
    └── temsili/
        └── girdi_cikti_guvenlik_borusu.txt # ASCII çift savunma hattı diyagramı
```

---

## 2. Temel Yetenekler ve Özellikler

1. **Kapsamlı Kanonikleştirme (Canonicalization):**
   - Çift ve üçlü URL kodlama (%252e%252e%252f -> ../) hilelerini çözer.
   - Unicode NFKC normalizasyonu ile görsel benzeri (homoglyph/tam genişlik) karakterleri standart ASCII'ye indirger.
   - Null byte (`\x00`, `%00`) enjeksiyonlarını filtreler.
2. **Pozitif Güvenlik Modeli (Allowlist Validation):**
   - 8 temel veri tipi desteği: `TextAlpha`, `TextAlphanumeric`, `Email`, `NumericInt`, `UuidV4`, `UrlHttpHttps`, `DateIso8601`, `SafeTextMultiline`.
   - Asgari ve azami uzunluk sınırlandırması.
3. **Saldırı İmza Sensörü:**
   - SQLi (`UNION SELECT`, `' OR 1=1`), XSS (`<script`, `javascript:`, `onerror`), Command Injection (`; rm`, `| bash`) ve Path Traversal (`../`) imzalarını anında yakalar.
4. **Bağlama Duyarlı Çıktı Kodlama (Context-Aware Output Encoding):**
   - **HTML Body:** `&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`.
   - **HTML Attribute:** Alfanümerik dışı karakterlerde `&#xHH;` hex entity dönüşümü.
   - **JavaScript:** `\u00XX` unicode kaçışı.
   - **URL Parameter:** RFC 3986 percent-encoding.

---

## 3. Kurulum ve Çalıştırma

### Birim Testleri Çalıştırma:
```bash
python -m unittest portfolio/hafta_23/gun_159/tests/test_input_validator_encoder.py -v
```

### Tek Bir Girdiyi Doğrulama (CLI):
```bash
python portfolio/hafta_23/gun_159/uygulama/input_validation_cli.py validate-field --name username --value Seydi_Eryilmaz --type TextAlphanumeric
```

### Bağlama Duyarlı Çıktı Kodlama:
```bash
python portfolio/hafta_23/gun_159/uygulama/input_validation_cli.py encode-output --value "<script>alert('test')</script>" --context HtmlBody
python portfolio/hafta_23/gun_159/uygulama/input_validation_cli.py encode-output --value "'; alert(1); //" --context JavaScript
```

### JSON İstek Gövdesini Şemaya Göre Doğrulama:
```bash
python portfolio/hafta_23/gun_159/uygulama/input_validation_cli.py validate-payload --payload portfolio/hafta_23/gun_159/ornek_veri/enterprise_input_schemas.json --schema portfolio/hafta_23/gun_159/ornek_veri/enterprise_input_schemas.json
```

### Güvenlik Boru Hattı Şemasını Görüntüleme:
```bash
python portfolio/hafta_23/gun_159/uygulama/input_validation_cli.py pipeline
```

### Tüm Kanıtları Yeniden Üretme:
```bash
python portfolio/hafta_23/gun_159/kanit_uretici.py
```

---

## 4. Lisans

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
