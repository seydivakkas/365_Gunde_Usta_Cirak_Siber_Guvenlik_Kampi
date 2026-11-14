# Gün 167: Path Traversal ve Dosya Erişimi

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status: 100/100 PASS](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Aşama: 07 Web Güvenliği](https://img.shields.io/badge/a%C5%9Fama-07%20Web%20G%C3%BCvenli%C4%9Fi-blue?style=flat-square)
![Hafta: 24](https://img.shields.io/badge/hafta-24-orange?style=flat-square)

## Proje Hakkında

Bu çalışma, **365 Günde Usta-Çırak Siber Güvenlik Kampı** kapsamında **Aşama 07: Web Güvenliği / Hafta 24: Enjeksiyon ve İstek Güvenliği** altında yer alan **Gün 167: Path Traversal ve Dosya Erişimi** konusunun kurumsal seviyedeki savunma motorunu, birim testlerini, negatif kontrol analizlerini ve dokümantasyonunu içerir.

Dizin Atlama (Path Traversal / Directory Traversal - CWE-22) tehdidi incelenmiş; `os.path.join` mutlak yol birleştirme zaafiyeti, sembolik bağlar (symlink), tek geçişli temizleme filtrelerini atlatabilen iç içe geçmiş dizgiler (`....//`), çok katmanlı URL kodlama (Double Encoding), Null Byte (`%00`) manipülasyonu ve uzantı baypasları simüle edilmiştir. Çok geçişli normalizasyon, kanonik hapishane denetleyicisi (`os.path.realpath` ve `os.path.commonpath`), alfanümerik beyaz liste ve Dolaylı Nesne Referansı (UUID/Token bazlı dosya soyutlama) mimarisiyle %100 oranında savunulmuştur.

## Dizin Yapısı

```
portfolio/hafta_24/gun_167/
├── uygulama/
│   ├── __init__.py
│   ├── path_traversal_engine.py   # Path traversal savunma motoru ve sanal depolama
│   └── path_traversal_cli.py      # CLI dosya okuma ve güvenlik denetim aracı
├── tests/
│   ├── __init__.py
│   └── test_path_traversal.py     # 15/15 PASS birim testleri
├── ornek_veri/
│   ├── enterprise_storage_policy.json   # Kurumsal dosya saklama politikası
│   └── invalid_traversal_payloads.json  # 9 negatif kontrol senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── path_traversal_audit_report.json
│   │   ├── sanitized_file_reads.txt
│   │   └── komut_ve_cikis.txt
│   └── temsili/
│       └── path_traversal_savunma_mimarisi.txt
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
python -m unittest portfolio/hafta_24/gun_167/tests/test_path_traversal.py
```

### CLI Kullanımı:
```bash
python portfolio/hafta_24/gun_167/uygulama/path_traversal_cli.py --help
python portfolio/hafta_24/gun_167/uygulama/path_traversal_cli.py validate-filename --filename "report_2026.pdf"
python portfolio/hafta_24/gun_167/uygulama/path_traversal_cli.py validate-filename --filename "../../../../etc/passwd"
python portfolio/hafta_24/gun_167/uygulama/path_traversal_cli.py audit-file --filename "%252e%252e%252fetc/passwd"
python portfolio/hafta_24/gun_167/uygulama/path_traversal_cli.py read-file --filename "contracts.pdf" --mode secure
```

### Kanıtları Yeniden Üretme:
```bash
python portfolio/hafta_24/gun_167/kanit_uretici.py
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
