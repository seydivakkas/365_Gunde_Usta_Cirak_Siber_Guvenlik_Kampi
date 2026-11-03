# Gün 33: Dosya Hash ve Bütünlük

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
Bu çalışma modülü; kriptografik özetleme fonksiyonlarını (SHA-256, MD5) ve Dosya Bütünlüğü İzleme (File Integrity Monitoring - FIM) mimarisini ele alan bağımsız bir denetim motoru (`FileIntegrityHashChecker`) sunar.

SHA-256 gibi özetlerin dosya değişimini saptadığı, fakat hash değerinin tek başına bir dosyanın güvenilir (trusted) olduğunu asla söylemediği (G033-SC1) ilkesi pedagojik olarak incelenmiş ve Çığ Etkisi (Avalanche Effect) Hamming mesafesiyle matematiksel olarak ispatlanmıştır.

---

## 2. Klasör ve Dosya Hiyerarşisi
```
portfolio/hafta_05/gun_033/
├── README.md                                    # Bu dokümantasyon
├── ders.md                                      # Kapsamlı Usta-Çırak teorik ve pratik ders notu
├── soru_cevap.md                                # G033-SC1, SC2, SC3 detaylı 4 başlıklı soru-cevap
├── rapor.md                                     # 20/40/25/15 puanlamalı 100/100 teknik rapor
├── sonuc.json                                   # Standart 14 alanlı makine tarafından okunabilir özet
├── manifest.json                                # SHA-256 bütünlük karmaları
├── uygulama/
│   ├── __init__.py                              # Paket başlatıcı ve lisans
│   └── file_integrity_hash_checker.py           # Satır satır açıklamalı FIM ve hash uygulaması
├── tests/
│   ├── __init__.py                              # Test paketi başlatıcı ve lisans
│   └── test_file_integrity_hash_checker.py      # 14 birim testi içeren test paketi
├── ornek_veri/
│   ├── sample_baseline_manifest.json            # Yetkili taban çizgisi (baseline) JSON
│   ├── corrupted_hash_test_cases.json           # Negatif kontrol bozuk hash veri seti
│   └── sample_files/                            # Orijinal, tahrifli ve yetkisiz test dosyaları
│       ├── config.json
│       ├── tampered_config.json
│       ├── security_policy.txt
│       ├── authorized_tool.py
│       └── malicious_payload.sh
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                   # Unittest 14/14 PASS terminal çıktısı
    │   ├── komut_ve_cikis.txt                   # CLI yürütme dökümü
    │   ├── butunluk_denetim_raporu.txt          # Ayrıntılı ASCII bütünlük denetim çıktısı
    │   └── negatif_kontrol_sonuclari.txt        # Bozuk veri yakalama raporu
    └── temsili/
        └── kriptografik_ozet_ve_butunluk_mimarisi.txt # 'TEMSİLÎ — AI İLLÜSTRASYONU' mimari şeması
```

---

## 3. Hızlı Başlangıç ve Kullanım

### A. Birim Testleri Çalıştırma
```bash
python -m unittest portfolio/hafta_05/gun_033/tests/test_file_integrity_hash_checker.py -v
```

### B. Denetleyici Uygulamasını Çalıştırma
```bash
python portfolio/hafta_05/gun_033/uygulama/file_integrity_hash_checker.py
```

---

## 4. Temel Yetenekler
- **64 KB Bloklu Akış (Streaming Chunking):** Bellek tüketmeden büyük dosyaların SHA-256 / MD5 özetlerini hesaplar.
- **Çığ Etkisi İspatı (Avalanche Effect):** Orijinal dosyadaki tek parametre değişiminin 122/256 bitlik (%47.66) değişim yarattığını doğrular.
- **Dosya Bütünlüğü İzleme (FIM):** Taban çizgisiyle kıyaslayarak tahrif edilmiş (`INTEGRITY_COMPROMISED`), silinmiş (`FILE_MISSING`) ve yabancı (`NEW_UNAUTHORIZED_FILE`) dosyaları saptar.
- **Güvenilirlik Değerlendirmesi:** Hash'in güvenilirlik değil bütünlük kanıtladığını açıklayan didaktik motor içerir.
