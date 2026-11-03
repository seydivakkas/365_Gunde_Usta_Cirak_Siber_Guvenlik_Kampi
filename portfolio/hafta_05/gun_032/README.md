# Gün 32: Başlangıç Uygulamaları ve Hizmet Yönetimi

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
Bu çalışma modülü; Windows ve Linux sistemlerde başlangıç noktalarını (Startup / Run Keys), servis yöneticilerini (SCM / systemd) ve kalıcılık mekanizmalarını güvenlik perspektifinden inceleyen bağımsız bir denetim motoru (`StartupServiceAuditor`) sunar.

Otomatik başlayan her uygulamanın ve servisin saldırı yüzeyini büyüttüğü, fakat bağımlılıkları bilinmeksizin gelişigüzel kapatılan hizmetlerin sistemi kararsızlaştırıp güvenlik kontrollerini körleştirdiği gerçeği pedagojik bir dille işlenmiştir.

---

## 2. Klasör ve Dosya Hiyerarşisi
```
portfolio/hafta_05/gun_032/
├── README.md                                    # Bu dokümantasyon
├── ders.md                                      # Kapsamlı Usta-Çırak teorik ve pratik ders notu
├── soru_cevap.md                                # G032-SC1, SC2, SC3 detaylı 4 başlıklı soru-cevap
├── rapor.md                                     # 20/40/25/15 puanlamalı 100/100 teknik rapor
├── sonuc.json                                   # Standart 14 alanlı makine tarafından okunabilir özet
├── manifest.json                                # SHA-256 bütünlük karmaları
├── uygulama/
│   ├── __init__.py                              # Paket başlatıcı ve lisans
│   └── startup_service_auditor.py               # Satır satır açıklamalı denetleyici uygulaması
├── tests/
│   ├── __init__.py                              # Test paketi başlatıcı ve lisans
│   └── test_startup_service_auditor.py          # 14 birim testi içeren test paketi
├── ornek_veri/
│   ├── sample_startup_service_inventory.json    # 14 gerçekçi servis ve başlangıç kaydı
│   └── corrupted_startup_service_test.json      # Negatif kontrol bozuk veri seti
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                   # Unittest 14/14 PASS terminal çıktısı
    │   ├── komut_ve_cikis.txt                   # CLI yürütme dökümü
    │   ├── baslangic_ve_servis_denetim_raporu.txt # Ayrıntılı ASCII denetim çıktısı
    │   └── negatif_kontrol_sonuclari.txt        # Bozuk veri yakalama raporu
    └── temsili/
        └── baslangic_ve_hizmet_mimarisi.txt     # 'TEMSİLÎ — AI İLLÜSTRASYONU' mimari şeması
```

---

## 3. Hızlı Başlangıç ve Kullanım

### A. Birim Testleri Çalıştırma
```bash
python -m unittest portfolio/hafta_05/gun_032/tests/test_startup_service_auditor.py -v
```

### B. Denetleyici Uygulamasını Çalıştırma
```bash
python portfolio/hafta_05/gun_032/uygulama/startup_service_auditor.py
```

---

## 4. Temel Yetenekler
- **Tırnaksız Servis Yolu Analizi (Unquoted Service Path - MITRE T1574.009):** Boşluk içeren ve tırnak içine alınmamış yolları saptayarak yerel yetki yükseltme (LPE) riskini raporlar ve `sc.exe config` iyileştirme komutunu üretir.
- **Şüpheli Dizin Tespiti (Suspicious Paths - MITRE T1547.001):** `%TEMP%`, `%APPDATA%`, `Public` klasörlerinden çalışan başlangıç öğelerini yakalar.
- **İsim Sahteciliği (Masquerading - MITRE T1036):** `svch0st`, `lsasss` gibi meşru sistem isimlerini taklit eden veya System32 haricinde konumlanan ikilileri alarm seviyesine çıkarır.
- **Savunma Tahrifatı (Impair Defenses - MITRE T1562.001):** Windows Defender veya Güvenlik Duvarı servislerinin durdurulmasını veya devre dışı bırakılmasını tespit eder.
- **Risk Skoru:** Bulguların ağırlıklarına göre 0-100 arası sistem tehdit puanı hesaplar.
