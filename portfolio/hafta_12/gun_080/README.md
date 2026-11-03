# GÜN 080: HATA YÖNETİMİ VE ÖZEL DURUMLAR (GÜVENLİ İSTİSNA VE FAİL-CLOSED MİMARİSİ)

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

Uygulamanın temel amacı; kurumsal güvenlik operasyonlarında ve yazılımlarında hataların **Fail-Closed (Hata Anında Kesin Ret)** prensibiyle yönetilmesini, yığın izi (stack trace) sızıntılarının (**CWE-209**) engellenmesini, log zehirlenmesi ve sahte log üretiminin (**CWE-117**) önlenmesini ve kritik kaynak kilitlerinin (`try-finally` ve Context Manager) deterministik olarak temizlenmesini sağlamaktır.

### Temel Yetenekler:
1. **Özel Güvenlik İstisna Hiyerarşisi:** `SecurityException` temel sınıfından türetilen 5 domain-odaklı güvenlik istisnası (`AuthenticationFailureException`, `AuthorizationDeniedException`, `InputSanitizationException`, `RateLimitExceededException`, `SecurityResourceException`).
2. **Fail-Closed Güvenlik Geçidi (`DefensiveSecurityGateway`):** En ufak bir hata veya belirsizlikte erişimi kesinlikle reddeden mimari.
3. **Yığın İzi İfşası Koruması (CWE-209):** Dış dünyaya iç kod, dosya yolları ve kütüphane sürümlerini ifşa etmeyen, yalnızca steril mesaj ve benzersiz `SEC-ERR-<UUID>` referans kodu sunan yanıt katmanı.
4. **Log Tahrifatı Koruması (CWE-117):** Hata mesajlarındaki CRLF (`\r`, `\n`) ve ANSI kontrol kodlarını temizleyerek sahte log üretimini imkansız kılan mekanizma.
5. **Deterministik Kaynak Güvencesi (`SecureResourceContext`):** İşlem sırasında donanım veya yazılım çökmesi olsa dahi kilitleri serbest bırakan bağlam yöneticisi.

---

## 📂 DİZİN VE DOSYA YAPISI

```
gun_080/
├── README.md                                                  # Proje tanıtımı ve özel lisans
├── ders.md                                                    # Kapsamlı teknik eğitim dokümanı
├── soru_cevap.md                                              # 3 teknik soru, 4 zorunlu alt başlık
├── rapor.md                                                   # 100/100 tam puan değerlendirme raporu
├── sonuc.json                                                 # Standartlaştırılmış sonuç özeti
├── manifest.json                                              # Dosya SHA-256 bütünlük matrisi
├── uygulama/
│   ├── __init__.py
│   └── secure_exception_and_error_handler.py                  # Güvenli hata ve istisna yönetim motoru
├── tests/
│   ├── __init__.py
│   └── test_secure_exception_and_error_handler.py             # 14 birim test senaryosu
├── ornek_veri/
│   └── invalid_exception_inputs.json                          # 9 negatif güvenlik kontrol senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                                 # 14 birim test doğrulama çıktısı
    │   ├── komut_ve_cikis.txt                                 # Terminal yürütme logları
    │   ├── negatif_kontrol_sonuclari.txt                      # 9 negatif kontrol doğrulama çıktısı
    │   └── hata_yonetimi_guvenlik_raporu.txt                  # Üretilen adli analiz raporu
    └── temsili/
        └── hata_ve_istisna_mimarisi.txt                       # ASCII akış ve savunma mimarisi
```

---

## 🚀 ÇALIŞTIRMA VE TEST TALİMATLARI

### 1. Birim Testleri Çalıştırma:
```powershell
python -m unittest portfolio.hafta_12.gun_080.tests.test_secure_exception_and_error_handler -v
```

### 2. Uygulamayı Bağımsız Çalıştırma:
```powershell
python portfolio/hafta_12/gun_080/uygulama/secure_exception_and_error_handler.py
```

### 3. Negatif Güvenlik Kontrollerini Çalıştırma:
```powershell
python -c "
import json
from pathlib import Path
from portfolio.hafta_12.gun_080.uygulama.secure_exception_and_error_handler import DefensiveSecurityGateway

fixtures = Path('portfolio/hafta_12/gun_080/ornek_veri/invalid_exception_inputs.json')
with open(fixtures, 'r', encoding='utf-8') as f:
    cases = json.load(f)['negatif_testler']

print(f'Yüklenen Negatif Test Senaryosu Sayısı: {len(cases)}')
for c in cases:
    print(f'  [SENARYO] {c[\"test_id\"]} -> {c[\"aciklama\"]}')
"
```
