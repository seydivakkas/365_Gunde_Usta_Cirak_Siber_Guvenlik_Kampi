# GÜN 073: KOŞULLAR VE DÖNGÜLER — SİBER GÜVENLİKTE SAVUNMACI KONTROL AKIŞI

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

Bu modül, **Aşama 04 (Python ile Güvenlik Otomasyonu ve Savunmacı Kodlama)** ve **Hafta 11 (Python Temelleri ve Güvenli Kodlama Pratikleri)** kapsamında, Python dilindeki koşul yapıları (`if/elif/else`), döngüler (`for`, `while`) ve kontrol mekanizmalarının siber savunma odaklı kullanımını inceler.

### Temel Güvenlik Mekanizmaları:
1. **Varsayılan Olarak Engelle (Fail-Closed / Default Deny):** Güvenlik duvarı kural tablolarında eşleşme olmaması durumunda `for ... else` bloğu ile katı engelleme.
2. **Döngüsel DoS ve Sonsuz Döngü Koruması (CWE-835):** Paket başlıklarındaki işaretçi atlamalarında (DNS Compression loop, Zip Bomb) $O(1)$ küme tabanlı ziyaret takibi ve sert iterasyon limiti (`max_iterations = 1000`).
3. **Kısa Devre (Short-Circuit) Optimizasyonu:** Kuralların ucuzdan pahalıya sıralanarak CPU tüketiminin optimize edilmesi.
4. **Kayan Pencere Hız Sınırlama (Rate Limiting):** Brute-force saldırılarına karşı zaman tabanlı girişim kümeleme ve kilit mekanizması.

---

## 📂 DİZİN VE DOSYA YAPISI

```
gun_073/
├── README.md                                          # Proje tanıtımı ve özel lisans
├── ders.md                                            # Kapsamlı teknik eğitim dokümanı
├── soru_cevap.md                                      # 3 teknik soru, 4 zorunlu alt başlık
├── rapor.md                                           # 100/100 tam puan değerlendirme raporu
├── sonuc.json                                         # Standartlaştırılmış sonuç özeti
├── manifest.json                                      # Dosya SHA-256 bütünlük matrisi
├── uygulama/
│   ├── __init__.py
│   └── security_control_flow_engine.py                # Savunmacı kontrol akış motoru
├── tests/
│   ├── __init__.py
│   └── test_security_control_flow_engine.py           # 14 birim test senaryosu
├── ornek_veri/
│   ├── guvenlik_kurallari_ve_donguler.json            # Pozitif kural ve imza veri seti
│   └── invalid_control_flow_inputs.json               # 9 negatif/malforme test girdisi
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                         # 14/14 test pass kanıtı
    │   ├── komut_ve_cikis.txt                         # Terminal çalıştırma logu
    │   ├── negatif_kontrol_sonuclari.txt              # 9 negatif kontrol doğrulama logu
    │   └── kontrol_akisi_guvenlik_raporu.txt          # Motor doğrulama çıktısı
    └── temsili/
        └── kosullar_ve_donguler_guvenlik_mimarisi.txt # ASCII mimari diyagramı
```

---

## 🚀 ÇALIŞTIRMA VE DOĞRULAMA TALİMATLARI

### 1. Birim Testleri Çalıştırma:
```bash
python -m unittest tests/test_security_control_flow_engine.py -v
```
*Beklenen Çıktı:* `Ran 14 tests in 0.001s - OK`

### 2. Güvenlik Motorunu ve Kanıt Üretimini Çalıştırma:
```bash
python uygulama/security_control_flow_engine.py
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
