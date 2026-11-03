# Gün 34: Dosya Türleri, Metadata ve MIME

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
![Status: Pass](https://img.shields.io/badge/status-PASS-brightgreen?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/score-100%2F100-blue?style=flat-square)
![Stage: 02](https://img.shields.io/badge/stage-02--System--and--Network-orange?style=flat-square)
![Week: 05](https://img.shields.io/badge/week-05-purple?style=flat-square)

---

### Lisans Bildirimi
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

---

## 1. Genel Bakış ve Amaç
Bu çalışma modülü; dosya adı uzantılarının yüzeysel aldatmacasını ortadan kaldırarak dosyaların başlık baytlarındaki Sihirli Baytları (Magic Bytes / File Signatures) ve MIME türlerini derinlemesine inceleyen bağımsız bir denetim motoru (`FileMetadataMimeAnalyzer`) sunar.

Dosya uzantısının dosya içeriğini belirlemediği, metadata ve zaman damgalarının (Timestomping) saldırganlarca manipüle edilebildiği (G034-SC1) ilkesi pedagojik olarak incelenmiş; PE ikilisi içeren sahte PDF'ler, ELF ikilisi içeren sahte JPEG'ler ve çift uzantılı dosyalar tespit edilmiştir.

---

## 2. Klasör ve Dosya Hiyerarşisi
```
portfolio/hafta_05/gun_034/
├── README.md                                    # Bu dokümantasyon
├── ders.md                                      # Kapsamlı Usta-Çırak teorik ve pratik ders notu
├── soru_cevap.md                                # G034-SC1, SC2, SC3 detaylı 4 başlıklı soru-cevap
├── rapor.md                                     # 20/40/25/15 puanlamalı 100/100 teknik rapor
├── sonuc.json                                   # Standart 14 alanlı makine tarafından okunabilir özet
├── manifest.json                                # SHA-256 bütünlük karmaları
├── uygulama/
│   ├── __init__.py                              # Paket başlatıcı ve lisans
│   └── file_metadata_mime_analyzer.py           # Satır satır açıklamalı imza ve MIME analizcisi
├── tests/
│   ├── __init__.py                              # Test paketi başlatıcı ve lisans
│   └── test_file_metadata_mime_analyzer.py      # 14 birim testi içeren test paketi
├── ornek_veri/
│   ├── sample_file_type_inventory.json          # 7 gerçekçi dosya ve beyan edilen MIME manifestosu
│   ├── corrupted_metadata_test_cases.json       # Negatif kontrol bozuk metadata veri seti
│   └── sample_files/                            # Meşru ve manipüle edilmiş test ikilileri
│       ├── sample_document.pdf
│       ├── sample_image.png
│       ├── sample_archive.zip
│       ├── sample_text.txt
│       ├── fake_invoice.pdf                     # PDF görünümlü PE executable (CRITICAL)
│       ├── disguised_photo.jpg                  # JPG görünümlü ELF binary (CRITICAL)
│       ├── urgent_bill.pdf.exe                  # Çift uzantı saldırısı (HIGH)
│       └── empty_zero_byte.bin                  # Boş dosya uç durum testi
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                   # Unittest 14/14 PASS terminal çıktısı
    │   ├── komut_ve_cikis.txt                   # CLI yürütme dökümü
    │   ├── metadata_ve_mime_denetim_raporu.txt  # Ayrıntılı ASCII imza denetim çıktısı
    │   └── negatif_kontrol_sonuclari.txt        # Bozuk veri yakalama raporu
    └── temsili/
        └── dosya_imzalari_ve_mime_mimarisi.txt  # 'TEMSİLÎ — AI İLLÜSTRASYONU' mimari şeması
```

---

## 3. Hızlı Başlangıç ve Kullanım

### A. Birim Testleri Çalıştırma
```bash
python -m unittest portfolio/hafta_05/gun_034/tests/test_file_metadata_mime_analyzer.py -v
```

### B. Analiz Uygulamasını Çalıştırma
```bash
python portfolio/hafta_05/gun_034/uygulama/file_metadata_mime_analyzer.py
```

---

## 4. Temel Yetenekler
- **Sihirli Bayt (Magic Bytes) Tespiti:** İlk 32 baytı okuyarak PE (`MZ`), ELF (`\x7fELF`), PDF (`%PDF-`), PNG, JPEG, ZIP ve metin biçimlerini kesin olarak saptar.
- **Uzantı-İmza Uyuşmazlığı (Extension Mismatch):** Masum doküman uzantısı taşıyan ancak çalıştırılabilir ikili olan dosyaları yakalar (MITRE T1036.008).
- **Çift Uzantı Koruması (Double Extension):** `.pdf.exe` gibi gizleme girişimlerini tespit eder (MITRE T1036.007).
- **Uç Durum ve Boş Dosya Yönetimi:** 0 baytlık boş dosyaları ve bozuk manifest kayıtlarını güvenle işler.
