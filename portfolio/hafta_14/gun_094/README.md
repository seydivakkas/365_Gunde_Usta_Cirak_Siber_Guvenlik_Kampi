# Gün 094: Regex ile Kişisel Veri Maskeleme ve DLP Motoru

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![Durum](https://img.shields.io/badge/Durum-Tamamlandı%20(100%2F100)-brightgreen?style=flat-square)

Siber güvenlik operasyonlarında, telemetri loglarında ve veri tabanı akışlarında KVKK, GDPR ve PCI-DSS uyumluluğu sağlayan kurumsal seviyede iki aşamalı veri sızıntısı önleme (Data Loss Prevention - DLP) ve kişisel veri (PII) maskeleme motoru.

---

## 🛡️ Yetenekler ve Güvenlik Mimarisi

- **İki Aşamalı Hassas Filtreleme (Sıfır Yanlış Pozitif):**
  - **Aşama 1 (Kaba Arama):** ReDoS korumalı ve optimize edilmiş düzenli ifadeler ile metin içerisindeki muhtemel PII adaylarını yakalar.
  - **Aşama 2 (Matematiksel Teyit):** Adayların gerçekten geçerli olup olmadığını algoritmik olarak doğrular:
    - **Kredi Kartı (PAN):** ISO/IEC 7812 Luhn (Mod-10) algoritması denetimi.
    - **T.C. Kimlik Numarası (TCKN):** 10. ve 11. basamak algoritmik modül 10 kontrolü ve sıfırla başlama engeli.
    - **TR IBAN:** ISO 7064 MOD-97 doğrulama algoritması.
- **Çok Yönlü Maskeleme Stratejileri:**
  - `MASK`: Destek ve operasyonel ekipler için format koruyucu kısmi yıldızlama (`123******50`, `453201******0366`).
  - `REDACT`: Dış denetim ve açık veri setleri için tam karartma (`[REDACTED_TCKN]`, `[REDACTED_CARD]`).
  - `HASH`: Analitik, fraud tespiti ve SIEM korelasyonu için tuzlu SHA-256 pseudonymization (`TCKN#a8f10c...`).
- **Gelişmiş Zafiyet Kalkanları:**
  - **CWE-1333 (ReDoS Koruması):** Katastrofik geri izleme (catastrophic backtracking) yaratmayan lineer zamanlı desenler ve kötücül şablon tespiti.
  - **CWE-158 (Null-Byte Zehirlemesi Koruması):** C tabanlı log sistemlerini hedefleyen `\x00` enjeksiyonlarını anında tespit edip engeller.
  - **CWE-400 (DoS ve Bellek Tavanı):** Girdi boyutunu 1 MB ile sınırlandırarak bellek tükenmesini önler.
  - **CWE-843 (Type Confusion Koruması):** Tip uyuşmazlıklarını çalışma anında tespit eder.
  - **CWE-532 & CWE-359:** Loglara ve yetkisiz aktörlere hassas veri sızmasını tamamen engeller.
- **POSIX Uyumlu CLI (`masker_cli.py`):** Standart Linux boru hatları ve PowerShell komut dizileri için 0 (Başarılı), 1 (Güvenlik Engeli), 2 (Girdi Hatası) çıkış kodları ve JSON telemetri çıktısı.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_14/gun_094/
├── uygulama/
│   ├── __init__.py
│   ├── pii_masker.py                     # Çekirdek PII maskeleme ve algoritmik doğrulama motoru
│   └── masker_cli.py                     # Terminal CLI yürütücüsü
├── tests/
│   ├── __init__.py
│   └── test_pii_masker.py                # 14/14 birim test seti
├── ornek_veri/
│   ├── raw_telemetry_logs.log            # Hassas veriler içeren örnek telemetri kütüğü
│   ├── sample_gdpr_records.json          # Yapılandırılmış JSON test verisi
│   └── invalid_pii_inputs.json           # 9 adet negatif kontrol senaryosu
├── kanit/
│   ├── gercek/                           # Doğrulanmış test ve denetim çıktıları
│   │   ├── kisisel_veri_maskeleme_raporu.txt
│   │   ├── komut_ve_cikis.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   └── test_sonuclari.txt
│   └── temsili/                          # Kapsamlı mimari ASCII görselleştirmesi
│       └── kisisel_veri_maskeleme_mimarisi.txt
├── ders.md                               # Usta-Çırak pedagojik ders anlatımı
├── soru_cevap.md                         # 4 alt başlıklı 3 mülakat soru-cevap seti
├── rapor.md                              # 100/100 rubrik değerlendirme raporu
├── sonuc.json                            # Makine tarafından okunabilir sonuç metrikleri
├── kanit_uretici.py                      # Otomatik test ve kanıt üretim orkestratörü
├── manifest.json                         # Dosya bütünlük manifestosu
└── README.md
```

---

## 🚀 Çalıştırma ve Test

Birim testleri ve kanıt üretimini başlatmak için:

```bash
# Kanıt üreticiyi çalıştır
python kanit_uretici.py

# Birim testleri doğrudan koştur
python -m unittest tests/test_pii_masker.py -v

# CLI ile doğrudan metin maskeleme
python uygulama/masker_cli.py --text "Kullanici tckn=12345678950 pan=4532015112830366" --style MASK

# CLI ile dosya maskeleme ve JSON rapor üretme
python uygulama/masker_cli.py --file ornek_veri/raw_telemetry_logs.log --style REDACT --json
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
