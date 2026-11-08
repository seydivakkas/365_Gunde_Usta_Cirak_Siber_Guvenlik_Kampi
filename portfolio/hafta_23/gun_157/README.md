# Gün 157: HTTP Cookies ve Güvenlik Bayrakları Denetim Sistemi

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama](https://img.shields.io/badge/Aşama-7%20Web%20Güvenliği-blue?style=flat-square)
![Hafta](https://img.shields.io/badge/Hafta-23-orange?style=flat-square)
![Durum](https://img.shields.io/badge/Testler-15%2F15%20PASS-brightgreen?style=flat-square)

Bu modül; web uygulamaları ve API servislerinin HTTP `Set-Cookie` yanıt başlıklarını RFC 6265bis, OWASP ASVS ve modern tarayıcı güvenlik sözleşmelerine göre denetleyen, güvenlik puanı hesaplayan ve zafiyetli çerezleri otomatik olarak **`Secure`**, **`HttpOnly`**, **`SameSite=Strict/Lax`**, **`__Host-`** ve **`__Secure-`** önekleriyle sertleştiren üretim kalitesinde bir güvenlik motorudur.

---

## 1. Dizin Yapısı

```
portfolio/hafta_23/gun_157/
├── ders.md                         # Usta-Çırak derin teknik ders notları
├── soru_cevap.md                   # 4 başlıklı 3 adet derinlemesine teknik soru & cevap
├── rapor.md                        # 100/100 PASS başarı karnesi
├── README.md                       # Proje dokümantasyonu ve özel lisans
├── sonuc.json                      # Yapılandırılmış yürütme özeti
├── manifest.json                   # 20 dosyanın SHA-256 doğrulama özeti
├── kanit_uretici.py                # Kanıt üretim ve yürütme orkestrasyon betiği
├── uygulama/
│   ├── __init__.py                 # Python modül tanımlayıcısı
│   ├── cookie_security_engine.py   # Çerez denetim ve sertleştirme motoru
│   └── cookie_security_cli.py      # CLI komut satırı arayüzü
├── tests/
│   ├── __init__.py                 # Test paketi tanımlayıcısı
│   └── test_cookie_security.py     # 15 kapsamlı birim test
├── ornek_veri/
│   ├── enterprise_cookie_spec.json # Standartlara tam uyumlu kurumsal çerez envanteri
│   └── invalid_cookie_scenarios.json # 9 adet negatif kontrol ve zafiyet senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt      # 15/15 birim test çıktısı
    │   ├── negatif_kontrol_sonuclari.txt # 9 negatif senaryo doğrulama çıktısı
    │   ├── cookie_audit_report.json # Kurumsal filonun JSON denetim raporu
    │   ├── hardened_cookies.txt    # Zafiyetli çerezlerin otomatik sertleştirilmiş başlıkları
    │   └── komut_ve_cikis.txt      # CLI yürütme logları
    └── temsili/
        └── cookie_guvenlik_bayraklari.txt # ASCII mimari ve bayrak diyagramı
```

---

## 2. Temel Yetenekler ve Özellikler

1. **Çok Boyutlu Çerez Güvenlik Denetimi:**
   - **`Secure` Bayrağı:** MITM dinlemelerini önleyerek çerezin yalnızca TLS üzerinden iletilmesini zorunlu kılar.
   - **`HttpOnly` Bayrağı:** JavaScript (`document.cookie`) erişimini yasaklayarak XSS kaynaklı oturum hırsızlığını engeller.
   - **`SameSite` Politikası:** `Strict` ve `Lax` modlarıyla CSRF saldırılarını tarayıcı seviyesinde durdurur; `None` durumunda `Secure` şartını denetler.
   - **RFC 6265bis Güvenlik Önekleri:** `__Host-` (Secure, Path=/, Domain yasak) ve `__Secure-` sözleşmelerini doğrular.
   - **Domain ve Path İzolasyonu:** Geniş wildcard domain (`.company.com`) risklerini cezalandırır.
   - **Ömür ve Veri Güvenliği:** 14 günü aşan oturum ömürlerini ve çerez içi düz metin hassas verileri (`role=admin`, parola) tespit eder.

2. **Otomatik Çerez Sertleştirme (Auto-Hardening):**
   - Zafiyetli bir Set-Cookie başlığını alır, eksik bayrakları tamamlar, domain kapsamını daraltır ve en yüksek güvenlikli `__Host-` başlığına dönüştürür.

---

## 3. Kurulum ve Çalıştırma

### Birim Testleri Çalıştırma:
```bash
python -m unittest portfolio/hafta_23/gun_157/tests/test_cookie_security.py -v
```

### Tek Bir Set-Cookie Başlığını Denetleme (CLI):
```bash
python portfolio/hafta_23/gun_157/uygulama/cookie_security_cli.py audit-header --header "session=abc; Path=/; Secure"
```

### Kurumsal Çerez Envanterini Denetleme (CLI):
```bash
python portfolio/hafta_23/gun_157/uygulama/cookie_security_cli.py audit-spec --spec portfolio/hafta_23/gun_157/ornek_veri/enterprise_cookie_spec.json
```

### Zafiyetli Başlığı Otomatik Sertleştirme:
```bash
python portfolio/hafta_23/gun_157/uygulama/cookie_security_cli.py harden --header "auth_token=xyz; Path=/; Domain=.example.com"
```

### Standartlara Uyumlu Yeni Set-Cookie Başlığı Üretme:
```bash
python portfolio/hafta_23/gun_157/uygulama/cookie_security_cli.py generate-set-cookie --name auth_token --value secure_random_token_val
```

### Tüm Kanıtları Yeniden Üretme:
```bash
python portfolio/hafta_23/gun_157/kanit_uretici.py
```

---

## 4. Lisans

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
