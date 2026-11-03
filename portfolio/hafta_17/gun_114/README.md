# Hafta 17 / Gün 114: MFA Yöntemleri ve Oltalama (Phishing) Direnci

[![Lisans: Tüm Hakları Saklıdır](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg?style=flat-square)](https://www.python.org/)
[![Standart: RFC 6238 & W3C WebAuthn](https://img.shields.io/badge/standard-RFC_6238_%26_WebAuthn-green.svg?style=flat-square)](https://www.w3.org/TR/webauthn-2/)
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

Bu proje, modern siber güvenlik mimarilerinde kullanılan Çok Faktörlü Kimlik Doğrulama (MFA) yöntemlerinin (RFC 6238 TOTP, SMS/E-posta OTP, Mobil Push Onayı ve FIDO2 / WebAuthn) güvenlik sınırlarını, Ters Vekil (AiTM / Adversary-in-the-Middle — Evilginx2) oltalama saldırılarına karşı direnç seviyelerini ve **Kriptografik Menşe Bağlama (Cryptographic Origin Binding)** teknolojisini somutlaştıran referans motordur.

Proje, %100 saf Python standart kütüphanesiyle inşa edilmiş olup:
1. **RFC 6238 TOTP Motoru:** Base32 gizli anahtar çözümleme, HMAC-SHA1 dinamik kırpma ve tekrar kullanım (replay) korumasını sunar.
2. **FIDO2 / WebAuthn Simülatörü:** Asimetrik imzalama, tek kullanımlık meydan okuma (challenge), klonlama tespiti (sign_count) ve en önemlisi menşe (origin) doğrulamasını içerir.
3. **AiTM Phishing Simülatörü:** TOTP'nin ters vekil karşısında neden zafiyet verdiğini ve FIDO2'nin bu saldırıyı nasıl matematiksel kesinlikle engellediğini gösterir.

---

## 🛡️ Kapsanan Güvenlik Standartları ve CWE Eşleşmeleri

| Zafiyet Kodu | Açıklama | Motordaki Savunma Mekanizması |
|---|---|---|
| **CWE-287** | Improper Authentication | RFC 6238 HMAC-SHA1 dinamik kırpma ve doğrulama |
| **CWE-346** | Origin Validation Error | FIDO2 Cryptographic Origin Binding (`clientDataJSON.origin`) |
| **CWE-294** | Authentication Bypass by Capture-replay | TOTP `last_used_step` ve FIDO2 tek kullanımlık challenge nonce |
| **CWE-347** | Improper Verification of Cryptographic Signature | FIDO2 RSA-SHA256 asimetrik imza doğrulama |
| **CWE-347** | Clone Detection (Donanım Klonlama) | FIDO2 `sign_count` monotonik artış ve gerileme kontrolü |
| **CWE-307** | MFA Fatigue / Push Spamming | Sayı eşleştirme ve hız limiti (rate-limiting) modeli |
| **CWE-208** | Observable Timing Discrepancy | Sabit zamanlı kod ve özet karşılaştırması |

---

## 📂 Dizin Yapısı

```
portfolio/hafta_17/gun_114/
├── ders.md                        # Usta-Çırak pedagojik ders anlatımı
├── soru_cevap.md                  # 3 derin teknik soru ve 4 zorunlu alt başlık
├── rapor.md                       # 100/100 PASS kalite ve denetim karne raporu
├── README.md                      # Bu dosya (kapsam, lisans, kurulum ve kullanım)
├── sonuc.json                     # Günlük standart puanlama ve başarı özeti
├── kanit_uretici.py               # Otomatik test ve kanıt koşturucu betik
├── manifest.json                  # SHA-256 dosya bütünlük listesi
├── uygulama/
│   ├── __init__.py
│   ├── mfa_phishing_resistant_engine.py  # TOTP, FIDO2 ve AiTM simülasyon motoru
│   └── mfa_cli.py                 # MFA üretim, doğrulama ve saldırı CLI aracı
├── tests/
│   ├── __init__.py
│   └── test_mfa_phishing_resistance.py   # 15/15 PASS kapsamlı birim test paketi
├── ornek_veri/
│   ├── mfa_sample_credentials.json       # Örnek MFA kimlik ve karşılaştırma matrisi
│   └── invalid_mfa_inputs.json           # 9 negatif kontrol test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt
    │   ├── negatif_kontrol_sonuclari.txt
    │   ├── mfa_phishing_analiz_raporu.txt
    │   └── komut_ve_cikis.txt
    └── temsili/
        └── mfa_phishing_mimarisi.txt
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

### 3. MFA CLI ile Test ve Saldırı Simülasyonu
```powershell
# 1. TOTP Kodu Üret:
python uygulama/mfa_cli.py totp-uret --kullanici seydi_admin

# 2. TOTP Kodunu Doğrula:
python uygulama/mfa_cli.py totp-dogrula --kullanici seydi_admin --kod <6_HANELI_KOD>

# 3. AiTM Ters Vekil (Evilginx) Oltalama Simülasyonunu Çalıştır:
python uygulama/mfa_cli.py simulasyon-saldiri
```

---

## 📊 Kalite Güvencesi ve Test Sonuçları
- **Birim Testleri:** 15/15 PASS (%100 Başarı)
- **Negatif Kontroller:** 9/9 PASS (Tüm saldırı vektörleri engellendi)
- **Dış Bağımlılık:** Sıfır (Tamamen Python Standart Kütüphanesi)
- **Genel Not:** 100/100 (YETERLİ - MÜKEMMEL)
