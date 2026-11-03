# Hafta 17 / Gün 115: OAuth 2.0 ve OpenID Connect (OIDC) Referans Güvenlik Motoru

[![Lisans: Tüm Hakları Saklıdır](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg?style=flat-square)](https://www.python.org/)
[![Standart: RFC 6749 & RFC 7636 PKCE](https://img.shields.io/badge/standard-RFC_6749_%26_PKCE-green.svg?style=flat-square)](https://datatracker.ietf.org/doc/html/rfc7636)
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

Bu proje, modern mikroservis mimarilerinde ve web/mobil ekosistemlerinde **Yetki Devri (Delegated Authorization — OAuth 2.0)** ve **Federatif Kimlik Doğrulama (Federated Authentication — OpenID Connect / OIDC)** standartlarını, en katı güvenlik gereksinimleriyle (RFC 7636 PKCE, CSRF korumalı state parametresi, Open Redirector engellemesi ve JWT doğrulama) hayata geçiren referans motordur.

Sistem şu ana bileşenleri içerir:
1. **OAuth 2.0 Yetkilendirme Sunucusu (IdP / Authorization Server):** `/authorize` ve `/token` uç noktaları, PKCE S256 zorunluluğu, `redirect_uri` beyaz liste kontrolü ve tek kullanımlık yetkilendirme kodları.
2. **OpenID Connect Kimlik Katmanı:** RFC 7519 uyumlu HS256 imzalı `id_token` üretimi, `nonce` replay koruması ve claim yönetimi.
3. **Kaynak Sunucusu (Resource Server):** Bearer erişim belirteçleri ve kapsam (scope) tabanlı izin kontrolü.
4. **İstemci / Güvenen Taraf Doğrulayıcısı (Relying Party):** State ve nonce doğrulaması.

---

## 🛡️ Kapsanan Güvenlik Standartları ve CWE Eşleşmeleri

| Zafiyet Kodu | Açıklama | Motordaki Savunma Mekanizması |
|---|---|---|
| **CWE-601** | URL Redirection to Untrusted Site ('Open Redirector') | `redirect_uri` katı beyaz liste (exact matching) denetimi |
| **CWE-287** | Improper Authentication (Code Interception) | RFC 7636 PKCE S256 (`code_verifier` vs `code_challenge`) |
| **CWE-294** | Authentication Bypass by Capture-replay | Tek kullanımlık `authorization_code` ve OIDC `nonce` teyidi |
| **CWE-352** | Cross-Site Request Forgery (CSRF) | İstemci tarafında kriptografik rastgele `state` parametresi denetimi |
| **CWE-347** | Improper Verification of Cryptographic Signature | OIDC ID Token HS256 HMAC-SHA256 dijital imza kontrolü |
| **CWE-285** | Improper Authorization (Insufficient Scope) | Kaynak Sunucusu (Resource Server) belirteç `scope` denetimi |
| **CWE-287** | Invalid / Expired Bearer Token | Erişim belirteci TTL ve veritabanı doğrulama kontrolü |

---

## 📂 Dizin Yapısı

```
portfolio/hafta_17/gun_115/
├── ders.md                        # Usta-Çırak pedagojik ders anlatımı
├── soru_cevap.md                  # 3 derin teknik soru ve 4 zorunlu alt başlık
├── rapor.md                       # 100/100 PASS kalite ve denetim karne raporu
├── README.md                      # Bu dosya (kapsam, lisans, kurulum ve kullanım)
├── sonuc.json                     # Günlük standart puanlama ve başarı özeti
├── kanit_uretici.py               # Otomatik test ve kanıt koşturucu betik
├── manifest.json                  # SHA-256 dosya bütünlük listesi
├── uygulama/
│   ├── __init__.py
│   ├── oauth2_oidc_engine.py      # IdP, Kaynak Sunucusu, PKCE ve JWT motoru
│   └── oauth_cli.py               # Yetkilendirme ve token takası CLI aracı
├── tests/
│   ├── __init__.py
│   └── test_oauth2_oidc.py        # 15/15 PASS kapsamlı birim test paketi
├── ornek_veri/
│   ├── oauth_sample_clients.json  # Örnek kayıtlı istemciler ve IdP konfigürasyonu
│   └── invalid_oauth_inputs.json  # 9 negatif kontrol test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt
    │   ├── negatif_kontrol_sonuclari.txt
    │   ├── oauth_oidc_analiz_raporu.txt
    │   └── komut_ve_cikis.txt
    └── temsili/
        └── oauth_oidc_mimarisi.txt
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

### 3. OAuth CLI ile Akış Simülasyonu
```powershell
# 1. PKCE ve State Parametrelerini Başlat:
python uygulama/oauth_cli.py akisi-baslat --client-id finans_portal_app

# 2. Uçtan Uca PKCE ve OIDC Takasını Çalıştır:
python uygulama/oauth_cli.py tam-akis --kullanici seydi_kullanici
```

---

## 📊 Kalite Güvencesi ve Test Sonuçları
- **Birim Testleri:** 15/15 PASS (%100 Başarı)
- **Negatif Kontroller:** 9/9 PASS (Tüm saldırı vektörleri engellendi)
- **Dış Bağımlılık:** Sıfır (Tamamen Python Standart Kütüphanesi)
- **Genel Not:** 100/100 (YETERLİ - MÜKEMMEL)
