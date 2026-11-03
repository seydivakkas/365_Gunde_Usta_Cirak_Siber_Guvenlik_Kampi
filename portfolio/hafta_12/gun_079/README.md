# GÜN 079: CSV VE JSON VERİ İŞLEME (GÜVENLİ VE SAVUNMACI AYRIŞTIRMA MOTORU)

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

Uygulamanın temel amacı; kurumsal güvenlik operasyonlarında sıklıkla tüketilen ve üretilen CSV ve JSON verilerini; **Formül Enjeksiyonu (CWE-1236 / DDE Execution)**, **Mükerrer Anahtar Çarpışması (JSON Hijacking / Parser Differential)**, **JSON Bombası (Derin Özyinelemeli DoS)**, **Null-Byte Zehirlenmesi** ve **Bellek Taşması** saldırılarına karşı korumak, doğrulamak ve güvenle adli analiz raporları üretmektir.

### Temel Yetenekler:
1. **CSV Formül Nötralizasyonu:** `=`, `+`, `-`, `@`, `\t`, `\r` ile başlayan hücrelerin başına tek tırnak (`'`) ekleyerek Excel/Calc üzerinde uzaktan komut yürütülmesini engelleme.
2. **Sütun Sayısı ve Alan Boyutu Tavanı:** Katı satır uzunluğu ve sütun sayısı denetimi ile format manipülasyonlarının ve DoS girişimlerinin önlenmesi.
3. **Mükerrer JSON Anahtar Kancası:** `object_pairs_hook` ile aynı anahtarın birden fazla geçmesi durumunda yetki aşımını önlemek için işlemi anında kesme.
4. **Özyinelemeli Derinlik Sınırı:** Çağrı yığını tükenmesini (`RecursionError`) önleyen yapısal derinlik tavanı (`max_depth = 15`).
5. **Katı Şema Doğrulaması:** JSON sözlüklerinde veri tiplerini ve zorunlu alanları denetleme.
6. **Entegre Üst Düzey Motor (Façade):** Tehdit beslemelerini ve güvenlik olaylarını tek bir noktadan analiz edip adli rapor sunma.

---

## 📂 DİZİN VE DOSYA YAPISI

```
gun_079/
├── README.md                                                  # Proje tanıtımı ve özel lisans
├── ders.md                                                    # Kapsamlı teknik eğitim dokümanı
├── soru_cevap.md                                              # 3 teknik soru, 4 zorunlu alt başlık
├── rapor.md                                                   # 100/100 tam puan değerlendirme raporu
├── sonuc.json                                                 # Standartlaştırılmış sonuç özeti
├── manifest.json                                              # Dosya SHA-256 bütünlük matrisi
├── uygulama/
│   ├── __init__.py
│   └── secure_csv_json_processor.py                           # Güvenli CSV ve JSON işleme motoru
├── tests/
│   ├── __init__.py
│   └── test_secure_csv_json_processor.py                      # 14 birim test senaryosu
├── ornek_veri/
│   ├── sample_threat_feed.csv                                 # Örnek meşru tehdit beslemesi CSV
│   ├── sample_security_events.json                            # Örnek güvenlik olayları JSON
│   └── invalid_csv_json_inputs.json                           # 9 negatif güvenlik kontrol senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                                 # 14 birim test doğrulama çıktısı
    │   ├── komut_ve_cikis.txt                                 # Terminal yürütme logları
    │   ├── negatif_kontrol_sonuclari.txt                      # 9 negatif kontrol doğrulama çıktısı
    │   └── guvenli_veri_isleme_raporu.txt                     # Üretilen veri analiz raporu
    └── temsili/
        └── csv_json_guvenlik_mimarisi.txt                     # ASCII akış ve savunma mimarisi
```

---

## 🚀 ÇALIŞTIRMA VE TEST TALİMATLARI

### 1. Birim Testleri Çalıştırma:
```powershell
python -m unittest portfolio.hafta_12.gun_079.tests.test_secure_csv_json_processor -v
```

### 2. Uygulamayı Bağımsız Çalıştırma:
```powershell
python portfolio/hafta_12/gun_079/uygulama/secure_csv_json_processor.py
```

### 3. Negatif Güvenlik Kontrollerini Çalıştırma:
```powershell
python -c "
import json
from pathlib import Path
from portfolio.hafta_12.gun_079.uygulama.secure_csv_json_processor import SecureCsvProcessor, SecureJsonProcessor

fixtures = Path('portfolio/hafta_12/gun_079/ornek_veri/invalid_csv_json_inputs.json')
with open(fixtures, 'r', encoding='utf-8') as f:
    cases = json.load(f)['negatif_testler']

print(f'Yüklenen Negatif Test Senaryosu Sayısı: {len(cases)}')
for c in cases:
    print(f'  [SENARYO] {c[\"test_id\"]} -> {c[\"aciklama\"]}')
"
```
