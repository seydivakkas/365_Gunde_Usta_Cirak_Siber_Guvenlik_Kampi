# GÜN 077: MİNİ PROJE 10 — BAĞIMSIZ GÜVENLİK LOG AYRIŞTIRICI

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

## 📖 PROJE GENEL BAKIŞI

Bu proje, **Aşama 04 (Python ile Güvenlik Otomasyonu ve Savunmacı Kodlama)** ve **Hafta 11 (Python Temelleri ve Güvenli Kodlama Pratikleri)** bitirme projesidir (Mini Proje 10).

Hafta boyunca işlenen tüm savunmacı programlama tekniklerini sentezleyerek; heterojen kurumsal ağ ve sistem loglarını (Web Access, Linux SSHD Auth, Netfilter/iptables Firewall) tek bir hatta güvenle ayrıştıran, ReDoS, Null-Byte ve Trojan Bidi saldırılarını savuşturan, brute-force kaba kuvvet girişimlerini kilit altına alan ve sıfır yanlış pozitif ile adli analiz raporu üreten bağımsız bir motordur.

### Temel Yetenekler:
1. **Çok Formatlı Savunmacı Regex:** Web (Combined), SSHD ve Firewall kayıtlarını `(?P<name>...)` grupları ve katı bağlaçlarla ayrıştırma.
2. **Kanonikleştirilmiş Saldırı Taraması:** `urllib.parse.unquote_plus()` ile `%20` ve URL-encoding atlatmalarını aşarak SQL Injection ve Path Traversal tespiti.
3. **Kayan Pencere (Sliding Window) Brute-Force Kilit:** 60 saniyede 5 hatalı giriş yapan kaynakları tespit edip dinamik kilit havuzuna alma.
4. **Küme Cebri ile Beyaz Liste Bastırması:** Bilinen IoC listesinde olsa dahi beyaz listedeki IP'lerin (`8.8.8.8`) alarmlarını bastırarak yanlış alarmı (False Positive) önleme.
5. **ReDoS ve Enjeksiyon Savunması:** 4096 karakter tavanı, Null-byte ve Trojan Source Bidi filtreleri.

---

## 📂 DİZİN VE DOSYA YAPISI

```
gun_077/
├── README.md                                                  # Proje tanıtımı ve özel lisans
├── ders.md                                                    # Kapsamlı teknik eğitim dokümanı
├── soru_cevap.md                                              # 3 teknik soru, 4 zorunlu alt başlık
├── rapor.md                                                   # 100/100 tam puan değerlendirme raporu
├── sonuc.json                                                 # Standartlaştırılmış sonuç özeti
├── manifest.json                                              # Dosya SHA-256 bütünlük matrisi
├── uygulama/
│   ├── __init__.py
│   └── standalone_security_log_parser.py                     # Bağımsız güvenlik log ayrıştırıcı motor
├── tests/
│   ├── __init__.py
│   └── test_standalone_security_log_parser.py                # 14 birim test senaryosu
├── ornek_veri/
│   ├── mixed_security_event_stream.log                       # Çok formatlı gerçekçi log akışı
│   ├── threat_intel_and_whitelist_rules.json                 # Tehdit istihbaratı ve kural politikaları
│   └── invalid_log_parser_inputs.json                         # 9 negatif/malforme test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                                 # 14/14 test pass kanıtı
    │   ├── komut_ve_cikis.txt                                 # Terminal çalıştırma logu
    │   ├── negatif_kontrol_sonuclari.txt                      # 9 negatif kontrol doğrulama logu
    │   ├── mini_proje_10_ayristirma_raporu.json               # Yapılandırılmış adli rapor çıktısı
    │   └── mini_proje_10_adli_ozet_raporu.txt                 # İnsan-okunabilir adli özet raporu
    └── temsili/
        └── bagimsiz_log_ayristirici_mimarisi.txt              # ASCII mimari diyagramı
```

---

## 🚀 ÇALIŞTIRMA VE DOĞRULAMA TALİMATLARI

### 1. Birim Testleri Çalıştırma:
```bash
python -m unittest tests/test_standalone_security_log_parser.py -v
```
*Beklenen Çıktı:* `Ran 14 tests in 0.004s - OK`

### 2. Log Ayrıştırıcıyı ve Adli Rapor Üretimini Çalıştırma:
```bash
python uygulama/standalone_security_log_parser.py
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
