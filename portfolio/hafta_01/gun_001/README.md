<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# Gün 001: Siber Güvenlik Nedir ve Neyi Korur?
### Varlık, Tehdit, Zafiyet, Risk ve CIA Üçlüsü

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_001/README.md#lisans)
[![Test Durumu](https://img.shields.io/badge/tests-10%2F10%20passed-brightgreen?style=flat-square)](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_001/kanit/gercek/test_sonuclari.txt)
[![Puan](https://img.shields.io/badge/skor-100%2F100-blue?style=flat-square)](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_001/rapor.md)

---

## 📖 Genel Bakış

Bu modül, siber güvenlik eğitiminin 1. gününde **Siber Güvenliğin 3 Temel Direği (Gizlilik, Bütünlük, Erişilebilirlik - CIA Triad)**, **Varlık-Tehdit-Zafiyet-Risk** ilişkisi ve savunma/saldırı mekanizmalarını sıfırdan uzmanlık seviyesine aktaran bir Usta-Çırak / Hoca Dersi laboratuvarıdır.

---

## 📂 Dizin Yapısı

- [`ders.md`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_001/ders.md): 7 bölümlük kapsamlı Hoca Dersi anlatımı (Zihinsel Model, Teori, Saldırı vs Savunma, Kodlar, Ölümcül Hatalar, Pratik Görev, Soru Odası).
- [`uygulama/cia_triad_lab.py`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_001/uygulama/cia_triad_lab.py): Okul bilgi sistemi üzerinden CIA kontrollerini çalıştıran CLI güvenlik uygulaması.
- [`tests/test_cia_triad_lab.py`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_001/tests/test_cia_triad_lab.py): Pozitif ve negatif kontrolleri doğrulayan 10 adet birim test.
- [`ornek_veri/okul_not_sistemi.txt`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_001/ornek_veri/okul_not_sistemi.txt): Gerçek formatta hazırlanmış örnek öğrenci not kütüğü.
- [`soru_cevap.md`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_001/soru_cevap.md): Excel Soru Bankası'ndaki 3 kritik sorunun hoca gözüyle derin analizleri.
- [`rapor.md`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_001/rapor.md): 100/100 PASS kararı ve ölçüm raporu.
- [`kanit/gercek/`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_001/kanit/gercek/): Gerçek terminal çalıştırma ve birim test çıktıları.
- [`kanit/temsili/`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_001/kanit/temsili/): CIA üçlüsü kavramsal zihin haritası.

---

## 🚀 Çalıştırma Talimatları

### 1. Tam Sistem CIA Denetimini Çalıştırma
```powershell
python portfolio/hafta_01/gun_001/uygulama/cia_triad_lab.py --audit
```

### 2. Birim Testleri Çalıştırma
```powershell
python -m unittest portfolio/hafta_01/gun_001/tests/test_cia_triad_lab.py
```

### 3. Özel Senaryoları Deneme
- **Gizlilik Testi (Öğretmen Okuması):**
  ```powershell
  python portfolio/hafta_01/gun_001/uygulama/cia_triad_lab.py --read --role OGRETMEN
  ```
- **Gizlilik Testi (Öğrenci Kendi Notu):**
  ```powershell
  python portfolio/hafta_01/gun_001/uygulama/cia_triad_lab.py --read --role OGRENCI --student-id 101
  ```
- **Bütünlük Tahrifat Simülasyonu:**
  ```powershell
  python portfolio/hafta_01/gun_001/uygulama/cia_triad_lab.py --tamper-demo
  ```
- **Erişilebilirlik DoS Simülasyonu:**
  ```powershell
  python portfolio/hafta_01/gun_001/uygulama/cia_triad_lab.py --dos-demo
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
