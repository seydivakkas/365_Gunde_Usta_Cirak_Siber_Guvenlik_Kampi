# G041 — Mini Proje 5: Windows ve Linux Karşılaştırmalı Güvenlik Raporu

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](#lisans)
[![Test Durumu](https://img.shields.io/badge/tests-14%20passed-brightgreen?style=flat-square)](#testler)
[![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)](#değerlendirme)

Bu modül, **365 Günlük Siber Güvenlik Müfredatı** kapsamında Hafta 06 / Gün 041 için hazırlanmış **"Mini Proje 5: Windows/Linux Karşılaştırmalı Rapor"** laboratuvar çalışmasını ve otomasyon motorunu içermektedir.

---

## 🎯 Hedefler ve Kapsam
1. **10 Standart Güvenlik Göstergesi:** Kimlik doğrulama, erişim denetimi, ayrıcalık yönetimi, çekirdek koruması, servis izolasyonu, güvenlik duvarı, disk şifreleme, olay denetimi, yama yönetimi ve EDR savunması.
2. **Objektif Karşılaştırma:** Windows Server 2022 ve Ubuntu 22.04 LTS işletim sistemlerinin güvenlik duruşunu CIS Benchmarks ve NIST CSF çerçevesinde nesnelleştirmek.
3. **Denetim ve Puanlama Motoru:** Tip güvenli, doğrulanmış ve negatif testlere dayanıklı `windows_linux_security_comparator.py` uygulamasının geliştirilmesi.
4. **Savunma Stratejileri:** LAPS v2, UAC, VBS/HVCI, systemd kum havuzlama, AppArmor, auditd ve Sysmon ile pratik sıkılaştırma.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_06/gun_041/
├── README.md                                         # Modül tanıtım ve kullanım rehberi
├── ders.md                                           # Usta-Çırak pedagojisiyle teorik ders anlatımı
├── soru_cevap.md                                     # G041-SC1, SC2, SC3 soruları ve detaylı çözümler
├── rapor.md                                          # 100/100 değerlendirme ve rubrik raporu
├── sonuc.json                                        # Standartlaştırılmış sonuç dosyası
├── manifest.json                                     # Dosya SHA256 bütünlük imzaları
├── uygulama/
│   ├── __init__.py                                   # Python paket tanımı
│   └── windows_linux_security_comparator.py          # 10 göstergeli denetim ve karşılaştırma motoru
├── tests/
│   ├── __init__.py                                   # Python test paketi tanımı
│   └── test_windows_linux_security_comparator.py     # 14 adet birim ve negatif test içeren test süiti
├── ornek_veri/
│   ├── baseline_windows_linux_10_indicators.json      # 10 göstergeli referans karşılaştırma matrisi
│   └── corrupted_comparison_test_cases.json          # Negatif kontrol test girdileri
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                        # Unittest çıktısı (14/14 PASS)
    │   ├── komut_ve_cikis.txt                        # Terminal yürütme kaydı
    │   ├── windows_linux_karsilastirma_raporu.txt    # Karşılaştırma denetim raporu
    │   └── negatif_kontrol_sonuclari.txt             # Negatif testlerin doğrulama günlüğü
    └── temsili/
        └── windows_linux_guvenlik_mimarisi.txt       # Karşılaştırmalı mimari diyagramı
```

---

## 🚀 Hızlı Başlangıç

### 1. Karşılaştırma Motorunu Çalıştırma
```powershell
python portfolio/hafta_06/gun_041/uygulama/windows_linux_security_comparator.py --matrix portfolio/hafta_06/gun_041/ornek_veri/baseline_windows_linux_10_indicators.json
```

### 2. Raporu Dosyaya Kaydetme
```powershell
python portfolio/hafta_06/gun_041/uygulama/windows_linux_security_comparator.py --matrix portfolio/hafta_06/gun_041/ornek_veri/baseline_windows_linux_10_indicators.json --output portfolio/hafta_06/gun_041/kanit/gercek/windows_linux_karsilastirma_raporu.txt
```

---

## 🧪 Testler

Test süiti 14 adet birim ve negatif kontrol testini içerir:
- Geçerli 10 göstergeli matrisin doğrulanması
- Tüm IND-01..IND-10 kimliklerinin kontrolü
- Windows ve Linux metrik hesaplamaları
- Puan farkı (differential) hesaplaması
- Markdown rapor biçim denetimi
- Negatif Kontroller: Eksik gösterge, taşan puan, negatif puan, geçersiz tip, bozuk JSON.

Testleri çalıştırmak için:
```powershell
python -m unittest discover -s portfolio/hafta_06/gun_041/tests -v
```

---

## 📜 Lisans

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
