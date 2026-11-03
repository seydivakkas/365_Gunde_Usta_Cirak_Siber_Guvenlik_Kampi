# Hafta 17 / Gün 116: JWT Yapısı ve Doğrulama Referans Güvenlik Motoru

[![Lisans: Tüm Hakları Saklıdır](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg?style=flat-square)](https://www.python.org/)
[![Standart: RFC 7519 & RFC 7515 JWS](https://img.shields.io/badge/standard-RFC_7519_%26_JWS-green.svg?style=flat-square)](https://datatracker.ietf.org/doc/html/rfc7519)
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

Bu proje, modern web servislerinde, API Gateway'lerde ve mikroservis iletişimlerinde kullanılan **JSON Web Token (JWT - RFC 7519)** ve **JSON Web Signature (JWS - RFC 7515)** standartlarını, en katı savunma mimarisiyle sıfırdan (saf Python kütüphanesi ile) uygulayan referans güvenlik motorudur.

Sistem şu temel güvenlik bileşenlerini ve savunma kalkanlarını içerir:
1. **RFC 7519 & RFC 7515 Uyumluluğu:** Base64URL kodlama/kod çözme, HS256 (HMAC-SHA256) ve RS256 (RSA-SHA256 PKCS#1 v1.5) ile kriptografik imzalama ve doğrulama.
2. **`alg: none` Tavizsiz Engellemesi (CWE-347):** Başlıkta `none` veya varyasyonları görüldüğü anda imzasız belirteçler derhal engellenir.
3. **Algorithm Confusion (Anahtar Karışıklığı - CWE-327) Koruması:** Asimetrik anahtar beklenen doğrulayıcıların, simetrik HMAC token'ları ile kandırılması katı algoritma beyaz listesi ile önlenir.
4. **Zaman Kısıtlamaları ve Saat Sapması (Clock Skew - CWE-298/613):** `exp` (Expiration Time) ve `nbf` (Not Before) parametreleri yapılandırılabilir saat sapması toleransı (`leeway`) ile tam denetlenir.
5. **Audience & Issuer İzolasyonu (CWE-287):** `iss` ve `aud` sınırları doğrulanarak belirteçlerin başka alan adlarında veya servislerde yetkisiz kullanımı engellenir.
6. **Stateful Revocation ve Kara Liste (`jti` - CWE-294):** Durumsuz (stateless) yapının doğurduğu iptal edilememe zafiyeti, tekil `jti` kimlikleri ve kara liste mekanizması ile giderilmiştir.
7. **Sabit Zamanlı Doğrulama (CWE-208):** İmzaların kıyaslanmasında zamanlama yan kanal saldırılarını (timing attack) önlemek amacıyla `secrets.compare_digest` kullanılmıştır.

---

## 🛡️ Kapsanan Güvenlik Standartları ve CWE Eşleşmeleri

| Zafiyet Kodu | Açıklama | Motordaki Savunma Mekanizması |
|---|---|---|
| **CWE-347** | Improper Verification of Cryptographic Signature (`alg: none`) | Başlıkta `none` algoritması görüldüğü an token reddedilir |
| **CWE-327** | Use of a Broken or Risky Cryptographic Algorithm (Algorithm Confusion) | RS256 beklenen yerde HS256 kullanımı katı beyaz liste ile engellenir |
| **CWE-347** | Tampered Signature Verification Failure | Bozuk veya tahrif edilmiş imzalar matematiksel olarak saptanır |
| **CWE-613** | Insufficient Session Expiration (`exp`) | Süresi dolan token derhal geçersiz kılınır |
| **CWE-298** | Improper Validation of Certificate Expiration Time (`nbf`) | Erken kullanım token'ları engellenir |
| **CWE-287** | Improper Authentication (`iss` / `aud` Mismatch) | Yayıncı veya hedef kitle uyuşmazlığında erişim engellenir |
| **CWE-294** | Authentication Bypass by Capture-replay (`jti` Revocation) | Kara listeye alınan veya yinelenen `jti` belirteçleri durdurulur |
| **CWE-208** | Observable Timing Discrepancy (Timing Attack) | `secrets.compare_digest` ile sabit zamanlı imza doğrulaması |

---

## 📂 Dizin Yapısı

```
portfolio/hafta_17/gun_116/
├── ders.md                        # Usta-Çırak pedagojik ders anlatımı
├── soru_cevap.md                  # 3 derin teknik soru ve 4 zorunlu alt başlık
├── rapor.md                       # 100/100 PASS kalite ve denetim karne raporu
├── README.md                      # Bu dosya (kapsam, lisans, kurulum ve kullanım)
├── sonuc.json                     # Günlük standart puanlama ve başarı özeti
├── kanit_uretici.py               # Otomatik test ve kanıt koşturucu betik
├── manifest.json                  # SHA-256 dosya bütünlük listesi
├── uygulama/
│   ├── __init__.py
│   ├── jwt_security_engine.py     # RFC 7519/7515 motoru, HS256/RS256, jti kara liste
│   └── jwt_cli.py                 # JWT üretim, doğrulama, analiz ve kara liste CLI aracı
├── tests/
│   ├── __init__.py
│   └── test_jwt_security.py       # 15/15 PASS kapsamlı birim test paketi
├── ornek_veri/
│   ├── jwt_sample_tokens.json     # Örnek konfigürasyon, HS256/RS256 anahtarları ve token'lar
│   └── invalid_jwt_inputs.json    # 9 negatif kontrol test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt
    │   ├── negatif_kontrol_sonuclari.txt
    │   ├── jwt_guvenlik_analiz_raporu.txt
    │   └── komut_ve_cikis.txt
    └── temsili/
        └── jwt_guvenlik_mimarisi.txt
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Çalıştırma
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

### 2. Kanıt Üretici ve Doğrulama Koşturma
```powershell
python kanit_uretici.py
```

### 3. CLI ile Token Üretme ve Doğrulama
```powershell
# HS256 Token Üretimi
python uygulama/jwt_cli.py issue --sub "user_101" --role "engineer" --exp-sec 3600 --key "guclu_ve_gizli_anahtar"

# Token Doğrulama
python uygulama/jwt_cli.py verify --token "<TOKEN>" --key "guclu_ve_gizli_anahtar" --aud "https://api.kurum.gov.tr" --iss "https://auth.kurum.gov.tr"

# Token İptali (Revoke)
python uygulama/jwt_cli.py revoke --token "<TOKEN>"
```
