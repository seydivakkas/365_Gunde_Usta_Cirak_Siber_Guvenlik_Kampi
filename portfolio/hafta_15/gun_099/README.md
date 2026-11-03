# Gün 099: CIA Triad ve Temel Güvenlik Özellikleri Tekrarı

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Stage](https://img.shields.io/badge/stage-05%20Cryptography%20%26%20Network-blue?style=flat-square)
![Week](https://img.shields.io/badge/week-15-orange?style=flat-square)

Bu modül, **Aşama 5: Kriptografi ve Ağ Güvenliği Temelleri** (Hafta 15) kapsamında **Gizlilik (Confidentiality)**, **Bütünlük (Integrity)**, **Erişilebilirlik (Availability)** ve **İnkar Edilemezlik (Non-Repudiation)** niteliklerini saf Python standart kütüphanesiyle modelleyen, doğrulayan ve tahrifat/DoS testlerini simüle eden kurumsal güvenlik motorudur.

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
portfolio/hafta_15/gun_099/
├── README.md                      # Modül tanıtım ve kullanım kılavuzu
├── ders.md                        # Usta-Çırak CIA Triad derin ders notu
├── soru_cevap.md                  # 3 soru ve 4 zorunlu alt başlıklı teknik analiz
├── rapor.md                       # 100/100 tam puan değerlendirme raporu
├── sonuc.json                     # Otomasyon çıktı metrikleri ve test sonuçları
├── kanit_uretici.py               # Gerçek kanıtları üreten otomasyon betiği
├── uygulama/
│   ├── __init__.py                # Uygulama paketi başlatıcı
│   ├── cia_triad_engine.py        # Çekirdek CIA Triad motoru ve koruyucuları
│   └── cia_evaluator_cli.py       # Standart POSIX çıkış kodlu CLI arayüzü
├── tests/
│   ├── __init__.py                # Test paketi başlatıcı
│   └── test_cia_triad_engine.py   # 15 adet birim ve negatif test paketi
├── ornek_veri/
│   ├── sample_transaction.json    # Örnek finansal işlem verisi
│   └── invalid_cia_inputs.json    # 9 adet negatif senaryo veri seti
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt     # 15/15 birim test geçiş kanıtı
    │   ├── negatif_kontrol_sonuclari.txt # 9/9 negatif senaryo yakalama kanıtı
    │   ├── cia_guvenlik_degerlendirme_raporu.txt # Detaylı karne raporu
    │   └── komut_ve_cikis.txt     # CLI yürütme çıktıları ve çıkış kodları
    └── temsili/
        └── cia_triad_mimarisi.txt # Zorunlu banner'lı ASCII mimari şeması
```

---

## 🚀 Kullanım Talimatları

### 1. İşlem Dosyası CIA Değerlendirmesi
```bash
python uygulama/cia_evaluator_cli.py -f ornek_veri/sample_transaction.json
```

### 2. Tahrifat (Bit-Flip) Saldırı Simülasyonu
```bash
python uygulama/cia_evaluator_cli.py --tamper-test
```

### 3. DoS Hız Sınırlayıcı Savunma Testi
```bash
python uygulama/cia_evaluator_cli.py --dos-test
```

### 4. İnkar Edilemezlik Denetim Zinciri Bütünlük Doğrulaması
```bash
python uygulama/cia_evaluator_cli.py --audit-chain
```

### 5. Birim Testlerin Çalıştırılması
```bash
python -m unittest tests/test_cia_triad_engine.py -v
```

---

## 🛡️ Güvenlik ve CWE Karşılıkları
- **CWE-311 (Missing Encryption):** Açık metin hassas kart ve parola sızıntısı tespiti.
- **CWE-345 / CWE-353 (Integrity Verification):** HMAC-SHA256 dijital mühür doğrulama.
- **CWE-208 (Timing Attacks):** `hmac.compare_digest` ile sabit zamanlı eşlik.
- **CWE-770 (Rate Limiting):** Token bucket kayan pencere algoritmasıyla DoS koruması.
- **CWE-400 (Resource Exhaustion):** 1 MB tavan bellek sınırı.
- **CWE-778 (Audit Logging):** Blokzincir tarzı hash-zincirli (hash-chained) denetim kaydı.
- **CWE-326 (Key Length):** En az 128-bit (16 bayt) kriptografik anahtar zorunluluğu.
