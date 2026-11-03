# Gün 100: Kriptografide Entropi ve Rastgelelik Prensipleri

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Stage](https://img.shields.io/badge/stage-05%20Cryptography-blue?style=flat-square)
![Milestone](https://img.shields.io/badge/milestone-Day%20100%20Celebration-gold?style=flat-square)

Bu modül, **Aşama 5: Kriptografi ve Ağ Güvenliği Temelleri** (Hafta 15) kapsamında bilgi teorisi, **Shannon Entropisi**, **Min-Entropi**, **Ki-Kare uygunluk testi**, **NIST SP 800-22 Monobit frekans testi** ve **CSPRNG vs PRNG** karşılaştırmasını saf Python standart kütüphanesiyle gerçekleştiren kurumsal analiz motorudur.

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
portfolio/hafta_15/gun_100/
├── README.md                      # Modül tanıtım ve kullanım kılavuzu
├── ders.md                        # Usta-Çırak Entropi ve Rastgelelik derin ders notu
├── soru_cevap.md                  # 3 soru ve 4 zorunlu alt başlıklı teknik analiz
├── rapor.md                       # 100/100 tam puan değerlendirme raporu
├── sonuc.json                     # Otomasyon çıktı metrikleri ve test sonuçları
├── kanit_uretici.py               # Gerçek kanıtları üreten otomasyon betiği
├── uygulama/
│   ├── __init__.py                # Uygulama paketi başlatıcı
│   ├── entropy_randomness_engine.py # Matematiksel entropi ve CSPRNG motoru
│   └── entropy_cli.py             # Standart POSIX çıkış kodlu CLI arayüzü
├── tests/
│   ├── __init__.py                # Test paketi başlatıcı
│   └── test_entropy_randomness.py # 15 adet birim ve negatif test paketi
├── ornek_veri/
│   ├── entropy_test_samples.json  # Entropi test örnekleri
│   └── invalid_entropy_inputs.json# 9 adet negatif senaryo veri seti
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt     # 15/15 birim test geçiş kanıtı
    │   ├── negatif_kontrol_sonuclari.txt # 9/9 negatif senaryo yakalama kanıtı
    │   ├── entropi_analiz_raporu.txt # Detaylı istatistiksel karne raporu
    │   └── komut_ve_cikis.txt     # CLI yürütme çıktıları ve çıkış kodları
    └── temsili/
        └── entropi_rastgelelik_mimarisi.txt # Zorunlu banner'lı ASCII mimari şeması
```

---

## 🚀 Kullanım Talimatları

### 1. Kriptografik Güvenli Anahtar Üretimi (256-Bit CSPRNG)
```bash
python uygulama/entropy_cli.py -g
```

### 2. PRNG (Mersenne Twister) vs CSPRNG Karşılaştırma Testi
```bash
python uygulama/entropy_cli.py --compare-prng
```

### 3. Dosya Entropisi Analizi
```bash
python uygulama/entropy_cli.py -f ornek_veri/entropy_test_samples.json
```

### 4. Doğrudan Metin Entropisi Analizi
```bash
python uygulama/entropy_cli.py -s "SuperSecretPassword123456789!"
```

### 5. Birim Testlerin Çalıştırılması
```bash
python -m unittest tests/test_entropy_randomness.py -v
```

---

## 🛡️ Güvenlik ve CWE Karşılıkları
- **CWE-338 (Weak PRNG):** Kriptografide `random` (MT19937) modülünün kullanımı engellenir.
- **CWE-331 (Insufficient Entropy):** 7.0 bit/baytın altındaki zayıf anahtarlar reddedilir.
- **CWE-337 (Predictable Seed):** Sistem saati (`time.time()`) gibi tohumlar yasaklanır.
- **CWE-334 (Small Entropy Space):** 64 bitten küçük anahtarlar reddedilir.
- **CWE-158 (Null Byte Injection):** Parametrelerdeki `\x00` baytları temizlenir.
- **CWE-400 (Resource Exhaustion):** 1 MB tavan tampon boyutu korunur.
