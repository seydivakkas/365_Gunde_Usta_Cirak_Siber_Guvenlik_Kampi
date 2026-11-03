# Hafta 17 / Gün 113: Kimlik Doğrulama ile Yetkilendirme (AuthN vs. AuthZ Engine)

[![Lisans: Tüm Hakları Saklıdır](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg?style=flat-square)](https://www.python.org/)
[![Güvenlik: NIST SP 800-63B & OWASP A01/A07](https://img.shields.io/badge/security-NIST_800--63B_%26_OWASP-green.svg?style=flat-square)](https://pages.nist.gov/800-63-3/sp800-63b.html)
[![Test Durumu: 15/15 PASS](https://img.shields.io/badge/tests-15%2F15_PASS-brightgreen.svg?style=flat-square)](tests/)
[![Puan: 100/100](https://img.shields.io/badge/score-100%2F100_YETERLİ-success.svg?style=flat-square)](rapor.md)

---

## 🔒 Lisans Bildirimi

```text
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

## 📌 Proje Genel Bakışı

Bu proje, kurumsal siber güvenlik mimarilerinde **Kimlik Doğrulama (Authentication — AuthN)** ile **Yetkilendirme (Authorization — AuthZ)** arasındaki kritik sınırları somutlaştıran, saldırılara karşı dirençli bir referans IAM motorudur.

Sistem, iki kademeli geçit (Dual-Gate PEP) mimarisini uygular:
1. **AuthN Katmanı:** Kullanıcının kim olduğunu doğrular (PBKDF2-HMAC-SHA256, 16-bayt kriptografik tuz, `secrets.compare_digest` ile CWE-208 zamanlama saldırısı savunması, CWE-307 kaba kuvvet hesap kilitleme, CWE-384 oturum sabitleme koruması ve CWE-613 oturum zaman aşımı).
2. **AuthZ Katmanı:** Kimliği doğrulanmış öznenin ne yapabileceğini denetler (Açık Red / Default Deny ilkesi, RBAC/ABAC rol-izin kontrolleri, CWE-284 kiracı izolasyonu ve CWE-639 IDOR nesne sahipliği denetimi).

Tamamen Python standart kütüphanesiyle sıfır dış bağımlılık prensibine göre inşa edilmiştir.

---

## 🛡️ Kapsanan Güvenlik Standartları ve CWE Eşleşmeleri

| Zafiyet Kodu | Açıklama | Motordaki Savunma Mekanizması |
|---|---|---|
| **CWE-287** | Improper Authentication | PBKDF2-HMAC-SHA256, rastgele tuz ve güvenli doğrulama |
| **CWE-208** | Observable Timing Discrepancy | `secrets.compare_digest` ile sabit zamanlı karşılaştırma |
| **CWE-307** | Excessive Authentication Attempts | 3-5 başarısız denemede otomatik hesap dondurma |
| **CWE-384** | Session Fixation | Yeni girişte önceki tüm belirteçleri iptal etme |
| **CWE-613** | Insufficient Session Expiration | Katı TTL ve kayan süre aşımı kontrolü |
| **CWE-306** | Missing Authentication | Belirteçsiz isteklerin anında 401 ile kesilmesi |
| **CWE-285** | Improper Authorization | Açık Red (Default Deny / Whitelist) prensibi |
| **CWE-862** | Missing Authorization | Eylem düzeyinde rol-izin matrisi zorunluluğu |
| **CWE-639** | Insecure Direct Object References (IDOR) | Nesne düzeyinde kullanıcı sahiplik denetimi (`owner_username`) |
| **CWE-284** | Improper Access Control | Çok kiracılı (multi-tenant) tam izolasyon |

---

## 📂 Dizin Yapısı

```
portfolio/hafta_17/gun_113/
├── ders.md                        # Usta-Çırak pedagojik ders anlatımı
├── soru_cevap.md                  # 3 derin teknik soru ve 4 zorunlu alt başlık
├── rapor.md                       # 100/100 PASS kalite ve denetim karne raporu
├── README.md                      # Bu dosya (kapsam, lisans, kurulum ve kullanım)
├── sonuc.json                     # Günlük standart puanlama ve başarı özeti
├── kanit_uretici.py               # Otomatik test ve kanıt koşturucu betik
├── manifest.json                  # SHA-256 dosya bütünlük listesi
├── uygulama/
│   ├── __init__.py
│   ├── authn_authz_engine.py      # Temel AuthN ve AuthZ motoru
│   └── iam_cli.py                 # Yönetim ve doğrulama CLI arayüzü
├── tests/
│   ├── __init__.py
│   └── test_authn_authz.py        # 15/15 PASS kapsamlı birim test paketi
├── ornek_veri/
│   ├── iam_sample_environment.json   # Örnek kiracı, kullanıcı ve kaynak ortamı
│   └── invalid_iam_inputs.json       # 9 negatif kontrol test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt
    │   ├── negatif_kontrol_sonuclari.txt
    │   ├── iam_guvenlik_analiz_raporu.txt
    │   └── komut_ve_cikis.txt
    └── temsili/
        └── iam_guvenlik_mimarisi.txt
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Çalıştırma
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

### 2. Kanıtları ve Raporları Üretme
```powershell
python kanit_uretici.py
```

### 3. IAM CLI ile Örnek Akış
```powershell
# Kullanıcı girişi yap ve oturum belirteci al:
python uygulama/iam_cli.py giris --kullanici alice --parola AliceGizliParola!2026

# Korumalı kaynağa erişim talebinde bulun (AuthN + AuthZ):
python uygulama/iam_cli.py eris --belirtec <OTURUM_BELIRTECI> --kaynak finans_raporu_2026 --eylem read

# Denetim günlüklerini incele:
python uygulama/iam_cli.py denetim
```

---

## 📊 Kalite Güvencesi ve Test Sonuçları
- **Birim Testleri:** 15/15 PASS (%100 Başarı)
- **Negatif Kontroller:** 9/9 PASS (Tüm saldırı vektörleri engellendi)
- **Dış Bağımlılık:** Sıfır (Tamamen Python Standart Kütüphanesi)
- **Genel Not:** 100/100 (YETERLİ - MÜKEMMEL)
