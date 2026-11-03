# GÜN 076: METİN, REGEX VE KARAKTER KODLAMASI — SİBER GÜVENLİKTE SAVUNMACI AYRIŞTIRMA

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

---

## ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR

**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**

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
İzin talepleri için: GitHub `@seydivakkas`

---

## 📖 MODÜL GENEL BAKIŞI

Bu modül, **Aşama 04 (Python ile Güvenlik Otomasyonu ve Savunmacı Kodlama)** ve **Hafta 11 (Python Temelleri ve Güvenli Kodlama Pratikleri)** kapsamında, Python dilinde metin işleme, düzenli ifadelerde ReDoS (CWE-1333) koruması, Unicode NFKC normalizasyonu, IDN homograf saldırı tespiti, Null-Byte dize kesme ve Trojan Source (Bidi) savunmasını inceler.

### Temel Güvenlik Mekanizmaları:
1. **ReDoS (Catastrophic Backtracking) Engellemesi:** Girdi uzunluk tavanı (`MAX_INPUT_LENGTH = 4096`) ve çakışmayan açık regex desenleri ile CPU kilitleme açıklarının önlenmesi.
2. **Unicode NFKC ve IDN Homograf Analizi:** Latin ve Kiril alfabelerinin karıştırılmasıyla yapılan alan adı taklitlerinin (pаypal.com) kanonik normalizasyon ile saptanması.
3. **Null-Byte (`\x00`) Enjeksiyon Koruması:** C seviyesi dize kesme ve dosya uzantısı atlatma saldırılarının sınırda engellenmesi.
4. **Trojan Source (Bidi / CVE-2021-42574) Filtresi:** Sağdan sola yön değiştirme (`\u202E` RLO) karakterlerinin tespit edilip reddedilmesi.
5. **İsimlendirilmiş Gruplar ve Katı Bağlaçlar:** Apache/NCSA loglarının `(?P<name>...)` grupları ve `^...$` bağlaçları ile tip güvenli ve kısmi eşleşmesiz ayrıştırılması.

---

## 📂 DİZİN VE DOSYA YAPISI

```
gun_076/
├── README.md                                                  # Proje tanıtımı ve özel lisans
├── ders.md                                                    # Kapsamlı teknik eğitim dokümanı
├── soru_cevap.md                                              # 3 teknik soru, 4 zorunlu alt başlık
├── rapor.md                                                   # 100/100 tam puan değerlendirme raporu
├── sonuc.json                                                 # Standartlaştırılmış sonuç özeti
├── manifest.json                                              # Dosya SHA-256 bütünlük matrisi
├── uygulama/
│   ├── __init__.py
│   └── secure_regex_and_encoding_engine.py                    # Savunmacı metin ve regex motoru
├── tests/
│   ├── __init__.py
│   └── test_secure_regex_and_encoding_engine.py               # 14 birim test senaryosu
├── ornek_veri/
│   ├── guvenli_metin_ve_regex_ornekleri.json                  # Doğrulanmış log ve regex veri seti
│   └── invalid_text_and_regex_inputs.json                     # 9 negatif/malforme test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                                 # 14/14 test pass kanıtı
    │   ├── komut_ve_cikis.txt                                 # Terminal çalıştırma logu
    │   ├── negatif_kontrol_sonuclari.txt                      # 9 negatif kontrol doğrulama logu
    │   └── metin_ve_regex_guvenlik_raporu.txt                 # Motor doğrulama çıktısı
    └── temsili/
        └── regex_ve_karakter_kodlama_mimarisi.txt             # ASCII mimari diyagramı
```

---

## 🚀 ÇALIŞTIRMA VE DOĞRULAMA TALİMATLARI

### 1. Birim Testleri Çalıştırma:
```bash
python -m unittest tests/test_secure_regex_and_encoding_engine.py -v
```
*Beklenen Çıktı:* `Ran 14 tests in 0.001s - OK`

### 2. Güvenlik Motorunu ve Kanıt Üretimini Çalıştırma:
```bash
python uygulama/secure_regex_and_encoding_engine.py
```

---

## 📊 KABUL VE SKOR TABLOSU

| Değerlendirme Kriteri | Puan | Durum |
| :--- | :---: | :---: |
| Tasarım ve Mimari | 20 / 20 | BAŞARILI |
| Uygulama ve Fonksiyonellik | 40 / 40 | BAŞARILI |
| Test ve Doğrulama (14 Test) | 25 / 25 | BAŞARILI |
| Güvenlik ve Negatif Kontrol (9 Kontrol) | 15 / 15 | BAŞARILI |
| **TOPLAM** | **100 / 100** | **YETERLİ / PASS** |
