# Gün 156: OWASP Top 10 Haritası ve Web Zafiyet Değerlendirme Sistemi

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama](https://img.shields.io/badge/Aşama-7%20Web%20Güvenliği-blue?style=flat-square)
![Hafta](https://img.shields.io/badge/Hafta-23-orange?style=flat-square)
![Durum](https://img.shields.io/badge/Testler-15%2F15%20PASS-brightgreen?style=flat-square)

Bu modül; kurumsal web uygulamalarını, mikroservis mimarilerini ve REST/GraphQL API servislerini **OWASP Top 10:2025** güvenlik standartları ve ilgili **CWE (Common Weakness Enumeration)** taksonomileri üzerinden otomatik denetleyen, uyumluluk puanı hesaplayan ve önceliklendirilmiş zafiyet iyileştirme yol haritaları (Remediation Roadmap) üreten üretim kalitesinde bir güvenlik motorudur.

---

## 1. Dizin Yapısı

```
portfolio/hafta_23/gun_156/
├── ders.md                         # Usta-Çırak derin teknik ders notları
├── soru_cevap.md                   # 4 başlıklı 3 adet derinlemesine teknik soru & cevap
├── rapor.md                        # 100/100 PASS başarı karnesi
├── README.md                       # Proje dokümantasyonu ve özel lisans
├── sonuc.json                      # Yapılandırılmış yürütme özeti
├── manifest.json                   # 20 dosyanın SHA-256 doğrulama özeti
├── kanit_uretici.py                # Kanıt üretim ve yürütme orkestrasyon betiği
├── uygulama/
│   ├── __init__.py                 # Python modül tanımlayıcısı
│   ├── owasp_mapper_engine.py      # OWASP Top 10 değerlendirme motoru ve CWE haritası
│   └── owasp_mapper_cli.py         # CLI komut satırı arayüzü
├── tests/
│   ├── __init__.py                 # Test paketi tanımlayıcısı
│   └── test_owasp_mapper.py        # 15 kapsamlı birim test
├── ornek_veri/
│   ├── enterprise_web_app_spec.json # 10/10 kategoriyi geçen kurumsal uygulama şartnamesi
│   └── invalid_owasp_scenarios.json # 9 adet negatif kontrol ve zafiyet senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt      # 15/15 birim test çıktısı
    │   ├── negatif_kontrol_sonuclari.txt # 9 negatif senaryo doğrulama çıktısı
    │   ├── owasp_top10_mapping_report.json # Kurumsal uygulamanın tam JSON karnesi
    │   ├── owasp_remediation_roadmap.md    # Otomatik üretilen Markdown iyileştirme haritası
    │   └── komut_ve_cikis.txt      # CLI yürütme logları
    └── temsili/
        └── owasp_top10_haritasi.txt # Çok katmanlı ASCII mimari diyagramı
```

---

## 2. Temel Yetenekler ve Özellikler

1. **Tam Kapsamlı OWASP Top 10:2025 Değerlendirmesi:**
   - **A01: Broken Access Control:** RBAC ara katmanı ve IDOR kontrolleri.
   - **A02: Cryptographic Failures:** TLS 1.3 sürümü, Argon2/bcrypt parola özetleme, veri tabanı şifreleme.
   - **A03: Injection:** Parametreli SQL sorguları (Prepared Statements), bağlamsal XSS çıktı kodlama.
   - **A04: Insecure Design:** Tehdit modelleme (Threat Modeling) ve hız sınırlama (Rate Limiting).
   - **A05: Security Misconfiguration:** Üretimde açık debug modu, varsayılan kimlik bilgileri, güvenlik başlıkları.
   - **A06: Vulnerable Components:** Güncel olmayan CVE'li paketler ve otomatik SCA taraması.
   - **A07: Identification and Auth Failures:** Yönetici hesaplarında MFA, brute-force hesap kilitleme.
   - **A08: Software and Data Integrity Failures:** Güvensiz nesne serileştirme (deserialization), imzasız CI/CD.
   - **A09: Security Logging & Monitoring Failures:** Merkezi denetim günlüğü, 15 dakikanın altında olay alarm gecikmesi.
   - **A10: Server-Side Request Forgery (SSRF):** URL beyaz listesi, AWS/GCP bulut metadata (`169.254.169.254`) bloklama.

2. **CWE Zafiyet Taksonomisi Köprüsü:**
   - CWE-89 (SQLi), CWE-79 (XSS), CWE-639 (IDOR), CWE-327 (Zayıf Kripto), CWE-918 (SSRF), CWE-287 (Kimlik Doğrulama), CWE-502 (Deserialization), CWE-16 (Yapılandırma), CWE-778 (Loglama), CWE-1104 (Eski Bileşenler) eşleştirmeleri.

3. **Otomatik İyileştirme Yol Haritası (Remediation Roadmap):**
   - Tespit edilen açıkları önem derecesine göre önceliklendirir ve doğrudan yazılım geliştiricinin uygulayabileceği somut aksiyon adımlarına dönüştürür.

---

## 3. Kurulum ve Çalıştırma

### Birim Testleri Çalıştırma:
```bash
python -m unittest portfolio/hafta_23/gun_156/tests/test_owasp_mapper.py -v
```

### Kurumsal Uygulama Güvenlik Değerlendirmesi (CLI):
```bash
python portfolio/hafta_23/gun_156/uygulama/owasp_mapper_cli.py map-app --spec portfolio/hafta_23/gun_156/ornek_veri/enterprise_web_app_spec.json
```

### Belirli Bir CWE'yi OWASP Kategorisine Eşleştirme:
```bash
python portfolio/hafta_23/gun_156/uygulama/owasp_mapper_cli.py map-cwe --cwe 89
python portfolio/hafta_23/gun_156/uygulama/owasp_mapper_cli.py map-cwe --cwe 918
```

### İyileştirme Yol Haritası Üretme:
```bash
python portfolio/hafta_23/gun_156/uygulama/owasp_mapper_cli.py generate-roadmap --spec portfolio/hafta_23/gun_156/ornek_veri/enterprise_web_app_spec.json
```

### Tüm Kanıtları Yeniden Üretme:
```bash
python portfolio/hafta_23/gun_156/kanit_uretici.py
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
