<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# Gün 003: Etik, Yasal Yetki ve Test Kapsamı
### Angajman Kuralları (RoE), TCK 243/244 ve Kapsam Doğrulama Kapısı

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_003/README.md#lisans)
[![Test Durumu](https://img.shields.io/badge/tests-10%2F10%20passed-brightgreen?style=flat-square)](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_003/kanit/gercek/test_sonuclari.txt)
[![Puan](https://img.shields.io/badge/skor-100%2F100-blue?style=flat-square)](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_003/rapor.md)

---

## 📖 Genel Bakış

Bu modül, siber güvenlik eğitiminin 3. gününde **Etik Hackleme Prensipleri, Yasal Yetkilendirme (TCK 243/244, CFAA), Sızma Testi Angajman Kuralları (Rules of Engagement - RoE)** ve **Kapsam İçi / Kapsam Dışı Hedef Ayrımı** mekanizmalarını Usta-Çırak / Hoca Dersi pedagojisiyle işler.

---

## 📂 Dizin Yapısı

- [`ders.md`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_003/ders.md): 7 bölümlük kapsamlı Hoca Dersi anlatımı (Çilingir Analojisi, Teori, Saldırı vs Savunma, Kodlar, Ölümcül Hatalar, Pratik Görev, Soru Odası).
- [`uygulama/scope_validator.py`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_003/uygulama/scope_validator.py): Yasal kapsamı ve eylemleri denetleyen RoE kapı bekçisi CLI uygulaması.
- [`tests/test_scope_validator.py`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_003/tests/test_scope_validator.py): 10 adet pozitif ve negatif birim/entegrasyon testi.
- [`ornek_veri/kapsam_belgesi.json`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_003/ornek_veri/kapsam_belgesi.json): Kurumsal sızma testi angajman kuralları (RoE) veri belgesi.
- [`soru_cevap.md`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_003/soru_cevap.md): Excel Soru Bankası'ndaki 3 kritik sorunun derin analizi.
- [`rapor.md`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_003/rapor.md): 100/100 PASS kararı ve ölçüm raporu.
- [`kanit/gercek/`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_003/kanit/gercek/): Gerçek çalıştırma ve test çıktıları.
- [`kanit/temsili/`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_003/kanit/temsili/): Yasal yetki ve kapsam sınırları kavramsal şeması.

---

## 🚀 Çalıştırma Talimatları

### 1. Kapsam ve Angajman Kuralları Denetimini Çalıştırma
```powershell
python portfolio/hafta_01/gun_003/uygulama/scope_validator.py --audit
```

### 2. Birim Testleri Çalıştırma
```powershell
python -m unittest portfolio/hafta_01/gun_003/tests/test_scope_validator.py
```

### 3. Belirli Bir Hedef ve Eylemi Doğrulama
- **İzinli Hedef Sorgusu:**
  ```powershell
  python portfolio/hafta_01/gun_003/uygulama/scope_validator.py --check --target 192.168.10.50 --action PORT_SCAN
  ```
- **Yasaklı Hedef Sorgusu:**
  ```powershell
  python portfolio/hafta_01/gun_003/uygulama/scope_validator.py --check --target 8.8.8.8 --action RECONNAISSANCE
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
