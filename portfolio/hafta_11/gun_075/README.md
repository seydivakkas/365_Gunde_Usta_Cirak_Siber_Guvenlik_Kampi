# GÜN 075: LİSTELER, SÖZLÜKLER VE KÜMELER — SİBER GÜVENLİKTE VERİ YAPILARI

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

Bu modül, **Aşama 04 (Python ile Güvenlik Otomasyonu ve Savunmacı Kodlama)** ve **Hafta 11 (Python Temelleri ve Güvenli Kodlama Pratikleri)** kapsamında, Python dilinde listeler (`list`), sözlükler (`dict`) ve kümelerin (`set`) siber savunma odaklı algoritmik ve mimari kullanımını inceler.

### Temel Güvenlik Mekanizmaları:
1. **$O(1)$ vs $O(N)$ Zaman Karmaşıklığı ve Hat Hızında Eşleştirme:** Tehdit göstergelerinin (IoC) küme karma tabloları ile sabit zamanlı aranması, CPU tükenmesi DoS açıklarının önlenmesi.
2. **Küme Cebri ile Tehdit İstihbaratı Korelasyonu:** Kesişim (`&`), fark (`-`) ve birleşim (`|`) operatörleri ile bağımsız kaynakların korelasyonu ve beyaz liste yanlış pozitiflerinin temizlenmesi.
3. **Güvenli Derin Sözlük Gezintisi (`safe_deep_dict_get`):** İç içe geçmiş konfigürasyonlarda `KeyError` ve `AttributeError` çökmelerine karşı savunmacı okuma.
4. **İterasyonda In-Place Liste Silme Koruması:** `List comprehension` ile eleman atlama (skipping elements) mantık zafiyetlerinin giderilmesi.
5. **Bellek Tavanı ve DoS Koruması:** Koleksiyon boyutlarında üst sınır (`MAX_COLLECTION_LIMIT = 50.000`) ile bellek tükenmesi saldırılarının engellenmesi.

---

## 📂 DİZİN VE DOSYA YAPISI

```
gun_075/
├── README.md                                                  # Proje tanıtımı ve özel lisans
├── ders.md                                                    # Kapsamlı teknik eğitim dokümanı
├── soru_cevap.md                                              # 3 teknik soru, 4 zorunlu alt başlık
├── rapor.md                                                   # 100/100 tam puan değerlendirme raporu
├── sonuc.json                                                 # Standartlaştırılmış sonuç özeti
├── manifest.json                                              # Dosya SHA-256 bütünlük matrisi
├── uygulama/
│   ├── __init__.py
│   └── security_data_structures_engine.py                     # Savunmacı veri yapıları analiz motoru
├── tests/
│   ├── __init__.py
│   └── test_security_data_structures_engine.py                # 14 birim test senaryosu
├── ornek_veri/
│   ├── tehdit_istihbarat_veri_yapilari.json                   # Doğrulanmış CTI ve kural veri seti
│   └── invalid_data_structure_inputs.json                     # 9 negatif/malforme test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                                 # 14/14 test pass kanıtı
    │   ├── komut_ve_cikis.txt                                 # Terminal çalıştırma logu
    │   ├── negatif_kontrol_sonuclari.txt                      # 9 negatif kontrol doğrulama logu
    │   └── veri_yapilari_guvenlik_raporu.txt                  # Motor doğrulama çıktısı
    └── temsili/
        └── veri_yapilari_ve_kume_cebri_mimarisi.txt           # ASCII mimari diyagramı
```

---

## 🚀 ÇALIŞTIRMA VE DOĞRULAMA TALİMATLARI

### 1. Birim Testleri Çalıştırma:
```bash
python -m unittest tests/test_security_data_structures_engine.py -v
```
*Beklenen Çıktı:* `Ran 14 tests in 0.002s - OK`

### 2. Güvenlik Motorunu ve Kanıt Üretimini Çalıştırma:
```bash
python uygulama/security_data_structures_engine.py
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
