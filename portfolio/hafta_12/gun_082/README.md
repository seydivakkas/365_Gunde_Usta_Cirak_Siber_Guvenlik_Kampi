# GÜN 082: PYTEST İLE BİRİM TESTLERİ (GÜVENLİK TEST MÜHENDİSLİĞİ ALTYAPISI)

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

Uygulamanın temel amacı; kurumsal güvenlik araçlarında ve kural motorlarında yazılan savunma fonksiyonlarının (parola karmaşıklığı, tehdit puanlaması, alan adı temizliği ve güvenlik duvarı kural doğrulaması) **`pytest`** çerçevesi kullanılarak; **Fikstürler (Fixtures)**, **Parametrik Saldırı Matrisleri (`@pytest.mark.parametrize`)**, **Sınır Değer Analizleri (Boundary Value Analysis)** ve **`pytest.raises`** mekanizmalarıyla %100 kapsayıcılıkla test edilmesidir.

### Temel Yetenekler:
1. **İzole pytest Fikstürleri:** `policy_enforcer` ve `valid_firewall_payload` fikstürleri ile testler arasında durum kirliliğini (state pollution) sıfırlama.
2. **Parametrik Saldırı Matrisi:** Tek bir test fonksiyonunda onlarca zararlı girdi ve sınır değer varyasyonunu bağımsız senaryolar olarak koşturma.
3. **Parola Politikası Denetimi:** 12-64 karakter, 4 karakter sınıfı ve sözlük kara listesi engeli (`banned_passwords`).
4. **Sınır Değer Analizi:** 0-100 aralığında tehdit puanlarının sınır geçiş noktalarını (39-40, 69-70, 89-90) ve sınır dışı değerleri doğrulama.
5. **Alan Adı Sanitizasyonu:** Protokol önekleri (`http://`, `https://`), yol geçişleri (`/`, `\`, `..`) ve null-byte (`\x00`) saldırılarını temizleme.
6. **Güvenlik Duvarı Kural Doğrulayıcı:** IPv4 geçerliliği ve 1-65535 port sınırları denetimi.

---

## 📂 DİZİN VE DOSYA YAPISI

```
gun_082/
├── README.md                                                  # Proje tanıtımı ve özel lisans
├── ders.md                                                    # Kapsamlı teknik eğitim dokümanı
├── soru_cevap.md                                              # 3 teknik soru, 4 zorunlu alt başlık
├── rapor.md                                                   # 100/100 tam puan değerlendirme raporu
├── sonuc.json                                                 # Standartlaştırılmış sonuç özeti
├── manifest.json                                              # Dosya SHA-256 bütünlük matrisi
├── uygulama/
│   ├── __init__.py
│   └── security_policy_enforcer.py                            # Güvenlik politikası ve kural motoru
├── tests/
│   ├── __init__.py
│   ├── conftest.py                                            # pytest işaretleyici yapılandırması
│   └── test_security_policy_enforcer.py                       # 14 test fonksiyonu (39 parametrik senaryo)
├── ornek_veri/
│   └── invalid_pytest_inputs.json                             # 9 negatif güvenlik kontrol senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                                 # 39 pytest testi doğrulama çıktısı
    │   ├── komut_ve_cikis.txt                                 # Terminal yürütme logları
    │   ├── negatif_kontrol_sonuclari.txt                      # 9 negatif kontrol doğrulama çıktısı
    │   └── politika_denetim_raporu.txt                        # Üretilen denetim raporu
    └── temsili/
        └── pytest_ve_guvenlik_mimarisi.txt                    # ASCII akış ve test mimarisi
```

---

## 🚀 ÇALIŞTIRMA VE TEST TALİMATLARI

### 1. pytest ile Testleri Çalıştırma:
```powershell
python -m pytest portfolio/hafta_12/gun_082/tests/test_security_policy_enforcer.py -v
```

### 2. Uygulamayı Bağımsız Çalıştırma:
```powershell
python portfolio/hafta_12/gun_082/uygulama/security_policy_enforcer.py
```

### 3. Negatif Güvenlik Kontrollerini Çalıştırma:
```powershell
python -c "
import json
from pathlib import Path
from portfolio.hafta_12.gun_082.uygulama.security_policy_enforcer import SecurityPolicyEnforcer

fixtures = Path('portfolio/hafta_12/gun_082/ornek_veri/invalid_pytest_inputs.json')
with open(fixtures, 'r', encoding='utf-8') as f:
    cases = json.load(f)['negatif_testler']

print(f'Yüklenen Negatif Test Senaryosu Sayısı: {len(cases)}')
for c in cases:
    print(f'  [SENARYO] {c[\"test_id\"]} -> {c[\"aciklama\"]}')
"
```
