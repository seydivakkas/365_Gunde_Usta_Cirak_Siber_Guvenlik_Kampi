<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# Gün 002: Tehdit, Zafiyet, Olay ve Risk
### Tehlike Kavramlarının Ayrımı, 5x5 Risk Matrisi ve Artık Risk Analizi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_002/README.md#lisans)
[![Test Durumu](https://img.shields.io/badge/tests-8%2F8%20passed-brightgreen?style=flat-square)](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_002/kanit/gercek/test_sonuclari.txt)
[![Puan](https://img.shields.io/badge/skor-100%2F100-blue?style=flat-square)](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_002/rapor.md)

---

## 📖 Genel Bakış

Bu modül, siber güvenlik eğitiminin 2. gününde **Tehdit, Zafiyet, Güvenlik Olayı ve Risk** kavramları arasındaki hayati farkları, 5x5 risk matrisi matematiğini ve önlemler sonrası geriye kalan **Artık Risk (Residual Risk)** kavramını Usta-Çırak / Hoca Dersi pedagojisiyle ele alır.

---

## 📂 Dizin Yapısı

- [`ders.md`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_002/ders.md): 7 bölümlük kapsamlı Hoca Dersi anlatımı (Çöl Evi Zihinsel Modeli, Teori, Saldırı vs Savunma, Kodlar, Ölümcül Hatalar, Pratik Görev, Soru Odası).
- [`uygulama/risk_matrix_evaluator.py`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_002/uygulama/risk_matrix_evaluator.py): NIST CSF / ISO 27005 uyumlu 5x5 risk matrisi ve senaryo değerlendirme motoru.
- [`tests/test_risk_matrix_evaluator.py`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_002/tests/test_risk_matrix_evaluator.py): 8 adet pozitif ve negatif birim test.
- [`ornek_veri/senaryolar.json`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_002/ornek_veri/senaryolar.json): Hastane, E-Ticaret ve Muhasebe senaryolarını içeren veri seti.
- [`soru_cevap.md`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_002/soru_cevap.md): Excel Soru Bankası'ndaki 3 kritik sorunun hoca gözüyle derin analizleri.
- [`rapor.md`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_002/rapor.md): 100/100 PASS kararı ve ölçüm raporu.
- [`kanit/gercek/`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_002/kanit/gercek/): Gerçek terminal ve test çıktıları.
- [`kanit/temsili/`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_002/kanit/temsili/): 5x5 risk matrisi şeması.

---

## 🚀 Çalıştırma Talimatları

### 1. Risk Matrisi Değerlendirmesini Çalıştırma
```powershell
python portfolio/hafta_01/gun_002/uygulama/risk_matrix_evaluator.py --eval
```

### 2. Birim Testleri Çalıştırma
```powershell
python -m unittest portfolio/hafta_01/gun_002/tests/test_risk_matrix_evaluator.py
```

### 3. Belirli Bir Senaryoyu Ayrıntılı İnceleme
```powershell
python portfolio/hafta_01/gun_002/uygulama/risk_matrix_evaluator.py --scenario SCN-01
```

---

## 📜 Lisans

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
