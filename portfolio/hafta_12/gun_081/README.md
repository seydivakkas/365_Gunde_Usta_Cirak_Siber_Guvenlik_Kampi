# GÜN 081: PYTHON LOGGING MODÜLÜ (GÜVENLİ SIEM VE DENETİM BORU HATTI)

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

## 📖 PROJE GENEL BAKIŞI

Bu proje, **Aşama 04 (Python ile Güvenlik Otomasyonu ve Savunmacı Kodlama)** ve **Hafta 12 (Python ile Sistem ve Dosya Güvenliği)** kapsamında geliştirilmiştir.

Uygulamanın temel amacı; kurumsal güvenlik operasyonlarında ve araçlarında `print()` gibi denetimsiz metotlar yerine, Python'un standart `logging` modülünü kurumsal bir **Savunmacı SIEM Boru Hattına** dönüştürmektir. Modül; **Log Enjeksiyonunu (CWE-117)**, **Hassas Veri İfşasını (CWE-532 / CWE-359)** ve **Disk Doygunluğu DoS (CWE-400)** tehditlerini mimari seviyede engelleyerek yapılandırılmış JSON logları üretir.

### Temel Yetenekler:
1. **CRLF ve Null-Byte Nötralizasyonu (CWE-117):** Loglara enjekte edilen `\r`, `\n` ve `\x00` karakterlerini boşlukla değiştirerek sahte denetim satırı üretimini engelleme.
2. **Otomatik Hassas Veri Maskeleme (CWE-532 / CWE-359):** Parolalar (`password=[REDACTED]`), API anahtarları, Bearer JWT belirteçleri ve 16 haneli kredi kartı numaralarını (`****-****-****-4444`) otomatik gizleme.
3. **ANSI Kaçış Kodu Temizliği:** Terminal izleyicilerini yanıltabilecek kaçış dizilerini arındırma.
4. **Yapılandırılmış SIEM JSON Biçimlendirici:** UTC ISO-8601 mikrosaniye zaman damgalı, makine tarafından milisaniyede dizinlenebilir JSON nesneleri üretme.
5. **Disk Doygunluğu ve DoS Koruması (CWE-400):** Mesaj uzunluk tavanı (`max_message_length = 4096`) ve izolasyon (`propagate = False`) kuralları.

---

## 📂 DİZİN VE DOSYA YAPISI

```
gun_081/
├── README.md                                                  # Proje tanıtımı ve özel lisans
├── ders.md                                                    # Kapsamlı teknik eğitim dokümanı
├── soru_cevap.md                                              # 3 teknik soru, 4 zorunlu alt başlık
├── rapor.md                                                   # 100/100 tam puan değerlendirme raporu
├── sonuc.json                                                 # Standartlaştırılmış sonuç özeti
├── manifest.json                                              # Dosya SHA-256 bütünlük matrisi
├── uygulama/
│   ├── __init__.py
│   └── secure_logger_and_audit_engine.py                      # Güvenli loglama ve denetim motoru
├── tests/
│   ├── __init__.py
│   └── test_secure_logger_and_audit_engine.py                 # 14 birim test senaryosu
├── ornek_veri/
│   └── invalid_logging_inputs.json                            # 9 negatif güvenlik kontrol senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                                 # 14 birim test doğrulama çıktısı
    │   ├── komut_ve_cikis.txt                                 # Terminal yürütme logları
    │   ├── negatif_kontrol_sonuclari.txt                      # 9 negatif kontrol doğrulama çıktısı
    │   └── guvenli_loglama_raporu.txt                         # Üretilen adli log analiz raporu
    └── temsili/
        └── logging_ve_denetim_mimarisi.txt                    # ASCII akış ve savunma mimarisi
```

---

## 🚀 ÇALIŞTIRMA VE TEST TALİMATLARI

### 1. Birim Testleri Çalıştırma:
```powershell
python -m unittest portfolio.hafta_12.gun_081.tests.test_secure_logger_and_audit_engine -v
```

### 2. Uygulamayı Bağımsız Çalıştırma:
```powershell
python portfolio/hafta_12/gun_081/uygulama/secure_logger_and_audit_engine.py
```

### 3. Negatif Güvenlik Kontrollerini Çalıştırma:
```powershell
python -c "
import json
from pathlib import Path
from portfolio.hafta_12.gun_081.uygulama.secure_logger_and_audit_engine import SecureAuditLoggerManager

fixtures = Path('portfolio/hafta_12/gun_081/ornek_veri/invalid_logging_inputs.json')
with open(fixtures, 'r', encoding='utf-8') as f:
    cases = json.load(f)['negatif_testler']

print(f'Yüklenen Negatif Test Senaryosu Sayısı: {len(cases)}')
for c in cases:
    print(f'  [SENARYO] {c[\"test_id\"]} -> {c[\"aciklama\"]}')
"
```
