# Gün 168: Mini Proje 23 — Güvenli Dosya Servisi ve İndirme Ağ Geçidi

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status: 100/100 PASS](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Aşama: 07 Web Güvenliği](https://img.shields.io/badge/a%C5%9Fama-07%20Web%20G%C3%BCvenli%C4%9Fi-blue?style=flat-square)
![Hafta: 24](https://img.shields.io/badge/hafta-24-orange?style=flat-square)

## Proje Hakkında

Bu çalışma, **365 Günde Usta-Çırak Siber Güvenlik Kampı** kapsamında **Aşama 07: Web Güvenliği / Hafta 24: Enjeksiyon ve İstek Güvenliği** modülünün haftalık sentez kapanış projesidir (**Gün 168: Mini Proje 23: Güvenli Dosya Servisi**).

Web uygulamalarının en kritik saldırı yüzeylerinden olan dosya yükleme, depolama ve indirme mekanizmaları ele alınmış; Zararlı Dosya Yükleme (CWE-434), Dizin Atlama (CWE-22), Kırık Nesne Seviyesinde Yetkilendirme (BOLA/IDOR - CWE-639) ve Sunucu Taraflı İstek Sahteciliği (SSRF - CWE-918) risklerine karşı uçtan uca savunma sağlayan bir depolama ve ağ geçidi motoru (`SecureFileService`) geliştirilmiştir.

Uygulanan temel güvenlik mekanizmaları:
- **Dosya Adı ve Girdi Normalizasyonu:** Null byte (`%00`, `\x00`), çok geçişli URL kod çözme (`%252e%252e%252f`), alfanümerik beyaz liste ve çift uzantı (`.pdf.php`) engeli.
- **Sihirli Bayt (Magic Bytes) Doğrulaması:** İstemci beyanına güvenmeyip dosya başlangıç baytlarının (`%PDF-`, `\x89PNG`, `\xff\xd8\xff`, `PK\x03\x04`) uzantı ile uyuşmasının zorunlu kılınması.
- **Polyglot ve Webshell Statik Taraması:** Dosya içerisindeki gömülü PHP, JSP, ASP, JavaScript veya komut kabuğu imzalarının taranması.
- **İndirekt Nesne Referansı (UUIDv4):** Fiziksel dosyaların diske rastgele UUIDv4 ile kaydedilmesi ve metaverilerin ayrı veritabanında saklanması.
- **Kanonik Hapishane (Chroot Jail):** `os.path.realpath` ve `os.path.commonpath` ile sembolik bağ ve mutlak yol sıçramalarının engellenmesi.
- **Kiracı İzolasyonu ve RBAC:** BOLA/IDOR saldırılarını önleyen kurum ve kullanıcı sahipliği doğrulaması.
- **Güvenli İndirme HTTP Başlıkları:** `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, `sandbox CSP` ile Stored XSS'in engellenmesi.
- **SSRF-Güvenli Uzak Getirme:** Loopback (`127.0.0.1`), RFC 1918 ve Bulut Metaveri (`169.254.169.254`) IP bloklarının filtrelenmesi.

## Dizin Yapısı

```
portfolio/hafta_24/gun_168/
├── uygulama/
│   ├── __init__.py
│   ├── secure_file_service_engine.py   # Güvenli dosya servisi ve ağ geçidi motoru
│   └── secure_file_service_cli.py      # CLI yönetim ve denetim aracı
├── tests/
│   ├── __init__.py
│   └── test_secure_file_service.py     # 15/15 PASS birim testleri
├── ornek_veri/
│   ├── enterprise_file_service_policy.json # Kurumsal dosya servisi politikası
│   └── invalid_service_payloads.json   # 9 negatif kontrol senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── file_service_audit_report.json
│   │   ├── sanitized_service_transactions.txt
│   │   └── komut_ve_cikis.txt
│   └── temsili/
│       └── guvenli_dosya_servisi_mimarisi.txt
├── kanit_uretici.py             # Otomatik kanıt üretim scripti
├── ders.md                      # Usta-Çırak derinlemesine teknik dersi
├── soru_cevap.md                # 3 mülakat sorusu ve teknik analiz
├── rapor.md                     # 100/100 PASS başarı puan kartı
├── sonuc.json                   # Günlük özet metadataları
├── manifest.json                # SHA-256 doğrulama manifestosu
└── README.md                    # Proje tanıtım ve lisans belgesi
```

## Hızlı Başlangıç

### Testleri Çalıştırma:
```bash
python -m unittest portfolio/hafta_24/gun_168/tests/test_secure_file_service.py
```

### CLI Kullanımı:
```bash
python portfolio/hafta_24/gun_168/uygulama/secure_file_service_cli.py --help
python portfolio/hafta_24/gun_168/uygulama/secure_file_service_cli.py scan --filename "safe_report.pdf" --content "%PDF-1.4 Data %%EOF"
python portfolio/hafta_24/gun_168/uygulama/secure_file_service_cli.py upload --filename "report.pdf" --content "%PDF-1.4 Financials %%EOF" --user-id "user_1" --tenant-id "tenant_alpha"
python portfolio/hafta_24/gun_168/uygulama/secure_file_service_cli.py fetch-remote --url "http://169.254.169.254/latest/meta-data/"
python portfolio/hafta_24/gun_168/uygulama/secure_file_service_cli.py audit-report
```

### Kanıtları Yeniden Üretme:
```bash
python portfolio/hafta_24/gun_168/kanit_uretici.py
```

---

## Lisans

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
