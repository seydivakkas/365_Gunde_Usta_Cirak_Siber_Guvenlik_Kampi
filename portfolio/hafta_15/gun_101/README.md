# Gün 101: Kriptografik Hash Fonksiyonları ve Çakışma Dinamikleri

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Stage](https://img.shields.io/badge/stage-05%20Cryptography-blue?style=flat-square)
![Week](https://img.shields.io/badge/week-15-orange?style=flat-square)

Bu modül, **Aşama 5: Kriptografi ve Ağ Güvenliği Temelleri** (Hafta 15) kapsamında **Kriptografik Hash Fonksiyonları**, **İlk Ön Görüntü**, **İkinci Ön Görüntü**, **Çakışma Direnci (Collision Resistance)**, **Doğum Günü Paradoksu (Birthday Paradox)** ve **Çığ Etkisi (Avalanche Effect)** prensiplerini saf Python standart kütüphanesiyle modelleyen kurumsal analiz motorudur.

---

## 🔒 Lisans ve Telif Hakkı

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

## 📂 Dizin Yapısı

```
portfolio/hafta_15/gun_101/
├── README.md                      # Modül tanıtım ve kullanım kılavuzu
├── ders.md                        # Usta-Çırak Hash ve Çakışma derin ders notu
├── soru_cevap.md                  # 3 soru ve 4 zorunlu alt başlıklı teknik analiz
├── rapor.md                       # 100/100 tam puan değerlendirme raporu
├── sonuc.json                     # Otomasyon çıktı metrikleri ve test sonuçları
├── kanit_uretici.py               # Gerçek kanıtları üreten otomasyon betiği
├── uygulama/
│   ├── __init__.py                # Uygulama paketi başlatıcı
│   ├── hash_collision_engine.py   # Çekirdek hash, çığ etkisi ve çakışma motoru
│   └── hash_cli.py                # Standart POSIX çıkış kodlu CLI arayüzü
├── tests/
│   ├── __init__.py                # Test paketi başlatıcı
│   └── test_hash_collision.py     # 15 adet birim ve negatif test paketi
├── ornek_veri/
│   ├── collision_samples.json     # Hash ve çığ etkisi örnek veri seti
│   └── invalid_hash_inputs.json   # 9 adet negatif senaryo veri seti
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt     # 15/15 birim test geçiş kanıtı
    │   ├── negatif_kontrol_sonuclari.txt # 9/9 negatif senaryo yakalama kanıtı
    │   ├── hash_cakisma_analiz_raporu.txt # Detaylı karne raporu
    │   └── komut_ve_cikis.txt     # CLI yürütme çıktıları ve çıkış kodları
    └── temsili/
        └── hash_cakisma_mimarisi.txt # Zorunlu banner'lı ASCII mimari şeması
```

---

## 🚀 Kullanım Talimatları

### 1. SHA-256 Güvenli Özet Hesaplama
```bash
python uygulama/hash_cli.py -s "SiberGuvenlik2026" -a sha256
```

### 2. Çığ Etkisi (Avalanche Effect) Analizi
```bash
python uygulama/hash_cli.py --avalanche
```

### 3. Doğum Günü Paradoksu Çakışma Simülasyonu (16-Bit)
```bash
python uygulama/hash_cli.py --birthday-sim 16
```

### 4. Sabit Zamanlı Bütünlük Doğrulaması
```bash
python uygulama/hash_cli.py -s "abc" --verify "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
```

### 5. Birim Testlerin Çalıştırılması
```bash
python -m unittest tests/test_hash_collision.py -v
```

---

## 🛡️ Güvenlik ve CWE Karşılıkları
- **CWE-328 (Use of Weak Hash):** MD5 ve SHA-1 kırılmış hash fonksiyonlarının kullanımı engellenir.
- **CWE-327 (Broken Crypto):** Çakışmalı algoritmalar elenir, SHA-256 ve BLAKE2b zorunlu kılınır.
- **CWE-208 (Timing Attacks):** `hmac.compare_digest` ile sabit zamanlı eşlik kontrolü yapılır.
- **CWE-158 (Null Byte Injection):** Parametrelerdeki `\x00` baytları temizlenir.
- **CWE-400 (Resource Exhaustion):** 1 MB tavan tampon boyutu korunur.
