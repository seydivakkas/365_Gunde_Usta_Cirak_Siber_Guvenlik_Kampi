# GÜN 074: FONKSİYONLAR VE TEMİZ KOD — SİBER GÜVENLİKTE MODÜLER MİMARİ

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

Bu modül, **Aşama 04 (Python ile Güvenlik Otomasyonu ve Savunmacı Kodlama)** ve **Hafta 11 (Python Temelleri ve Güvenli Kodlama Pratikleri)** kapsamında, Python dilinde temiz kod (Clean Code), saf fonksiyonlar (Pure Functions), değişmezlik (Immutability), tip güvenliği ve sözleşmeye dayalı tasarımı (Design by Contract) inceler.

### Temel Güvenlik Mekanizmaları:
1. **Değiştirilebilir Varsayılan Argüman İzolasyonu (CWE-670):** Fonksiyon parametrelerinde `tags=None` deseni ile çok kiracılı sistemlerde oturum ve veri sızıntısının engellenmesi.
2. **Saf Fonksiyonlar ile Tehdit Skorlama:** Global duruma ve I/O yan etkilerine bağımlı olmayan, %100 deterministik ve adli bilişim standartlarında puanlama.
3. **Tek Sorumluluk İlkesi (SRP) Boru Hattı:** Büyük log işleme fonksiyonunun mikro yardımcı fonksiyonlara bölünerek güvenlik denetlenebilirliğinin sağlanması.
4. **Değişmezlik ve Savunmacı Kopyalama:** Güvenlik kurallarının yerinde (in-place) mutasyonunu engelleyen derin kopyalama (`deepcopy`) mimarisi.
5. **Sözleşmeye Dayalı Tasarım (DbC):** Kriptografik özet doğrulamasında katı ön koşul (`precondition`) ve son koşul (`postcondition`) garantileri.

---

## 📂 DİZİN VE DOSYA YAPISI

```
gun_074/
├── README.md                                                  # Proje tanıtımı ve özel lisans
├── ders.md                                                    # Kapsamlı teknik eğitim dokümanı
├── soru_cevap.md                                              # 3 teknik soru, 4 zorunlu alt başlık
├── rapor.md                                                   # 100/100 tam puan değerlendirme raporu
├── sonuc.json                                                 # Standartlaştırılmış sonuç özeti
├── manifest.json                                              # Dosya SHA-256 bütünlük matrisi
├── uygulama/
│   ├── __init__.py
│   └── clean_functions_and_security_modularizer.py            # Savunmacı fonksiyonel güvenlik motoru
├── tests/
│   ├── __init__.py
│   └── test_clean_functions_and_security_modularizer.py       # 14 birim test senaryosu
├── ornek_veri/
│   ├── guvenlik_fonksiyonlari_ornek_verisi.json               # Doğrulanmış örnek veri seti
│   └── invalid_function_call_inputs.json                      # 9 negatif/malforme test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                                 # 14/14 test pass kanıtı
    │   ├── komut_ve_cikis.txt                                 # Terminal çalıştırma logu
    │   ├── negatif_kontrol_sonuclari.txt                      # 9 negatif kontrol doğrulama logu
    │   └── temiz_kod_guvenlik_raporu.txt                      # Motor doğrulama çıktısı
    └── temsili/
        └── fonksiyonlar_ve_temiz_kod_mimarisi.txt             # ASCII mimari diyagramı
```

---

## 🚀 ÇALIŞTIRMA VE DOĞRULAMA TALİMATLARI

### 1. Birim Testleri Çalıştırma:
```bash
python -m unittest tests/test_clean_functions_and_security_modularizer.py -v
```
*Beklenen Çıktı:* `Ran 14 tests in 0.001s - OK`

### 2. Güvenlik Motorunu ve Kanıt Üretimini Çalıştırma:
```bash
python uygulama/clean_functions_and_security_modularizer.py
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
