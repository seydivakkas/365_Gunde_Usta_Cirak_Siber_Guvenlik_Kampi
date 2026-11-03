# Gün 126: Aşama 5 Kalite Özeti — Kriptografi ve Güvenlik Mimarisi

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Stage 5 Quality Score](https://img.shields.io/badge/Stage_5_Quality_Score-100%2F100-brightgreen?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-15%20Passed-success?style=flat-square)
![Negative Controls](https://img.shields.io/badge/Negative_Controls-9%2F9%20Passed-success?style=flat-square)
![Stage Decision](https://img.shields.io/badge/Stage_5_Decision-ACCEPTED%20(PASS)-success?style=flat-square)

Bu proje, **365 Günlük Siber Güvenlik Müfredatı** bünyesindeki **Aşama 5: Kriptografi ve Güvenlik Mimarisi** aşamasının resmi kalite özeti ve kabul değerlendirmesidir (Quality Gate). Simetrik/asimetrik kriptografi, özet fonksiyonları, KDF, anahtar yönetimi, STRIDE tehdit modelleme, risk skorlama, savunma derinliği, Saltzer-Schroeder Fail-Safe ve Fail-Secure ilkeleri ile sırlar yönetiminin tüm kuramsal ve pratik kazanımlarını bağımsız bir denetim motoru ile teftiş eder.

---

## 🔒 Lisans ve Telif Hakkı Bildirimi

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

## 🌟 Aşama 5 Kalite ve Kabul Kriterleri

1. **NIST SP 800-131A & SP 800-57 Uyumluluğu:**
   - Eski ve kırık algoritmalar (MD5, SHA-1, DES, 3DES, RC4, AES-ECB) sıfır toleransla elenir (`CWE-327`).
   - RSA için en az 2048-bit (`CWE-326`), PBKDF2 için en az 100.000 iterasyon (`CWE-916`), CSPRNG zorunluluğu (`CWE-338`).
2. **Saltzer-Schroeder & NIST SP 800-160 Mimarisi:**
   - Varsayılan Ret (Default-Deny) zorunluluğu (`CWE-1188`).
   - Altyapı kesintilerinde kilitlenme (Fail-Secure / Fail-Closed) zorunluluğu (`CWE-636`).
   - Statik Görevler Ayrılığı (Maker-Checker SoD) denetimi (`CWE-863`).
   - En Az Yetki İlkesi (PoLP) ve normal rollere joker (*) yasağı (`CWE-250`).
3. **Yönetişim ve Kanıt Güvencesi:**
   - Denetim kütüklerinde sır maskelemesi (`CWE-532`).
   - Yerel çalıştırılabilir 15 birim test ve 9 negatif sınır testi güvencesi.

---

## 📁 Proje Dizin Yapısı

```
gun_126/
├── uygulama/
│   ├── __init__.py
│   ├── stage5_quality_engine.py      # Aşama 5 Kalite ve Kabul Denetçisi
│   └── stage5_cli.py                 # CLI denetim ve sorgu aracı
├── tests/
│   ├── __init__.py
│   └── test_stage5_quality.py        # 15 Birim test (100% PASS)
├── ornek_veri/
│   ├── sample_crypto_architecture_spec.json # Kurumsal Aşama 5 mimari şartnamesi
│   └── invalid_stage5_scenarios.json # 9 Negatif hata enjeksiyon senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt        # Birim test koşu kanıtı
│   │   ├── negatif_kontrol_sonuclari.txt # 9 Negatif kontrol kanıtı
│   │   ├── asama5_kalite_denetim_raporu.json # JSON denetim raporu
│   │   └── komut_ve_cikis.txt        # CLI etkileşim kanıtı
│   └── temsili/
│       └── asama5_kalite_mimarisi.txt # Zorunlu banner'lı ASCII mimari şeması
├── ders.md                           # Usta-Çırak Aşama 5 Kalite Özeti dersi
├── soru_cevap.md                     # 3 Derinlemesine teknik soru & cevap
├── rapor.md                          # 100/100 Başarı değerlendirme raporu
├── sonuc.json                        # Yapılandırılmış değerlendirme sonucu
├── manifest.json                     # Dosya bütünlük ve sağlama listesi
├── kanit_uretici.py                  # Otomatik kanıt üretim betiği
└── README.md                         # Proje genel belgesi
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Koşma
```bash
python -m unittest tests/test_stage5_quality.py
```

### 2. Tüm Kanıtları Otomatik Üretme
```bash
python kanit_uretici.py
```

### 3. CLI Denetim Aracını Çalıştırma
```bash
# Algoritma parametre doğrulaması
python uygulama/stage5_cli.py verify-crypto --algorithm AES-256-GCM --key-bits 256 --mode GCM

# Tam Aşama 5 mimari şartname denetimi
python uygulama/stage5_cli.py audit ornek_veri/sample_crypto_architecture_spec.json --format markdown
```
