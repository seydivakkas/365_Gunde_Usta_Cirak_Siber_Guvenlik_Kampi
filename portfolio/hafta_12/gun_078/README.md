# GÜN 078: DOSYA OKUMA VE PATHLIB (GÜVENLİ DOSYA ERİŞİM VE İZOLASYON MOTORU)

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

Uygulamanın temel amacı; kurumsal güvenlik operasyonlarında ve araçlarında zafiyetlere en açık alanlardan biri olan dosya sistemi işlemlerini (okuma, akış işleme, dizin tarama ve yazma) kum havuzu (sandbox) prensibiyle izole etmek, Path Traversal (`../`), mutlak yol enjeksiyonu (`/etc/passwd`), Symlink kaçışı ve bellek tükenmesi (DoS / OOM) saldırılarını matematiksel kesinlikle engellemektir.

### Temel Yetenekler:
1. **Kum Havuzu (Sandbox) Sınır Denetimi:** Modern `pathlib.Path.resolve()` ve `is_relative_to()` ile tüm dosya işlemlerinin belirlenen kök dizin içinde kalmasını sağlama.
2. **Akış Tabanlı Güvenli Okuma (`Streaming Generator`):** Milyonlarca satırlık dev log dosyalarını tek seferde belleğe almadan, satır satır `yield` eden jeneratör mimarisi.
3. **Satır ve Dosya Boyutu Tavanı:** Bellek şişirme saldırılarına karşı `max_file_size` ve `max_line_length` sınırları.
4. **Veri Zehirlenmesi ve Karakter Güvenliği:** Katı UTF-8 kodlaması ve satır içi Null-Byte (`\x00`) tespit mekanizması.
5. **Atomik Dosya Güncelleme:** Geçici dosya, bellek-disk senkronizasyonu (`flush` + `os.fsync`) ve atomik yer değiştirme (`os.replace`) ile sıfır baytlık yarım dosya riskinin yok edilmesi.

---

## 📂 DİZİN VE DOSYA YAPISI

```
gun_078/
├── README.md                                                  # Proje tanıtımı ve özel lisans
├── ders.md                                                    # Kapsamlı teknik eğitim dokümanı
├── soru_cevap.md                                              # 3 teknik soru, 4 zorunlu alt başlık
├── rapor.md                                                   # 100/100 tam puan değerlendirme raporu
├── sonuc.json                                                 # Standartlaştırılmış sonuç özeti
├── manifest.json                                              # Dosya SHA-256 bütünlük matrisi
├── uygulama/
│   ├── __init__.py
│   └── secure_file_and_path_manager.py                        # Güvenli dosya ve pathlib motoru
├── tests/
│   ├── __init__.py
│   └── test_secure_file_and_path_manager.py                   # 14 birim test senaryosu
├── ornek_veri/
│   ├── invalid_file_and_path_inputs.json                      # 9 adet negatif güvenlik kontrol senaryosu
│   └── guvenli_dosya_deposu/                                  # Meşru kum havuzu test deposu
│       ├── config.json
│       ├── security_audit.log
│       └── sample_policy.yaml
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                                 # 14 birim test doğrulama çıktısı
    │   ├── komut_ve_cikis.txt                                 # Terminal yürütme logları
    │   ├── negatif_kontrol_sonuclari.txt                      # 9 negatif kontrol doğrulama çıktısı
    │   └── dosya_guvenlik_raporu.txt                          # Üretilen dosya analiz raporu
    └── temsili/
        └── pathlib_ve_dosya_guvenlik_mimarisi.txt             # ASCII kum havuzu mimari şeması
```

---

## 🚀 ÇALIŞTIRMA VE TEST TALİMATLARI

### 1. Birim Testleri Çalıştırma:
```powershell
python -m unittest tests/test_secure_file_and_path_manager.py -v
```

### 2. Uygulamayı Bağımsız Çalıştırma:
```powershell
python uygulama/secure_file_and_path_manager.py
```

### 3. Negatif Güvenlik Kontrollerini Çalıştırma:
```powershell
python -c "
import json
from pathlib import Path
from uygulama.secure_file_and_path_manager import SecureFileAndPathManager

sandbox = Path('ornek_veri/guvenli_dosya_deposu').resolve()
manager = SecureFileAndPathManager(sandbox, max_file_size_bytes=1024*1024, max_line_length=8192)
with open('ornek_veri/invalid_file_and_path_inputs.json', 'r', encoding='utf-8') as f:
    cases = json.load(f)['negatif_testler']

for case in cases:
    print(f'Test: {case[\"test_id\"]} - {case[\"aciklama\"]}')
"
```
