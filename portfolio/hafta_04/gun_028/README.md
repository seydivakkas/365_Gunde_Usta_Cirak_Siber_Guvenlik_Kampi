# Gün 028: Mini Proje 3 — Komut Satırı Çalışma Defteri Motoru (Runbook Engine)

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Stage: 02 - Sistem ve Ag Guvenligi](https://img.shields.io/badge/stage-02--Sistem%20ve%20A%C4%9F%20G%C3%BCvenli%C4%9Fi-blue?style=flat-square)
![Week: 04](https://img.shields.io/badge/week-04-blue?style=flat-square)
![Project: MP-04](https://img.shields.io/badge/project-MP--04-orange?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/score-100%2F100-brightgreen?style=flat-square)
![Tests: 14 Passed](https://img.shields.io/badge/tests-14%20passed-brightgreen?style=flat-square)

Bu çalışma, **Siber Güvenlik 365 Gün Standart ve Müfredat Paketi** kapsamında, Aşama 02 (Sistem ve Ağ Güvenliği Temelleri) Hafta 04'ün haftalık mini projesi (**MP-04**) olarak geliştirilmiştir. Proje, işletim sistemi güvenlik denetimlerinde kullanılan salt-okunur keşif komutlarını doğrular, filtreler, kriptografik SHA-256 bütünlük mühürleriyle çalıştırır ve açıklamalı bir **Markdown Çalışma Defteri (Runbook)** üretir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_04/gun_028/
├── ders.md                 # 7 bölümlük usta-çırak pedagojik ders anlatımı
├── soru_cevap.md           # G028-SC1, SC2, SC3 senaryoları ve 4 başlıklı analizleri
├── rapor.md                # 20/40/25/15 kriter puanlama tablosu ve 100/100 sonuç raporu
├── README.md               # Proje genel bakışı, kullanım kılavuzu ve lisans
├── sonuc.json              # 14 standart alanlı makine tarafından okunabilir sonuç dosyası
├── manifest.json           # Dizin içeriği ve SHA256 bütünlük hash listesi
├── uygulama/
│   ├── __init__.py
│   └── command_line_notebook_engine.py  # Çalışma defteri üretim ve güvenlik motoru
├── tests/
│   ├── __init__.py
│   └── test_command_line_notebook_engine.py # 14 kapsamlı birim test
├── ornek_veri/
│   ├── safe_command_catalog.json        # 12 adet salt-okunur güvenli komut kataloğu
│   └── prohibited_commands_test.json    # Negatif kontrol için 8 yıkıcı komut veri kümesi
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                 # Unittest yürütme çıktısı (14/14 PASS)
    │   ├── komut_ve_cikis.txt                 # CLI --audit çalıştırma dökümü
    │   ├── calisma_defteri_ornek.md           # 380 satırlık üretilen nihai çalışma defteri
    │   └── guvenlik_engelleme_kaydi.txt       # 8 yıkıcı komutun engellenme günlüğü
    └── temsili/
        └── komut_satiri_gozlem_mimarisi.txt   # Gözlem ve güvenlik kapısı mimari şeması
```

---

## 🚀 Kullanım Kılavuzu

### 1. Komut Kataloğu Güvenlik Denetimi (`--audit`)
Katalogdaki komutları inceler, güvenlik kapısından geçirir ve terminalde özet tablosu sunar:
```bash
python portfolio/hafta_04/gun_028/uygulama/command_line_notebook_engine.py --catalog portfolio/hafta_04/gun_028/ornek_veri/safe_command_catalog.json --audit
```

### 2. Açıklamalı Markdown Çalışma Defteri Üretimi (`--generate-notebook`)
En az 10 (varsayılan 12) salt-okunur komutu çalıştırarak detaylı analiz kartları ve SHA-256 izleri içeren Markdown defterini oluşturur:
```bash
python portfolio/hafta_04/gun_028/uygulama/command_line_notebook_engine.py --catalog portfolio/hafta_04/gun_028/ornek_veri/safe_command_catalog.json --generate-notebook portfolio/hafta_04/gun_028/kanit/gercek/calisma_defteri_ornek.md
```

### 3. Negatif Kontrol ve Güvenlik Duvarı Testi (`--test-prohibited`)
Yıkıcı ve tehlikeli komutları motorun güvenlik filtresine tabi tutarak hepsinin engellendiğini kanıtlar:
```bash
python portfolio/hafta_04/gun_028/uygulama/command_line_notebook_engine.py --test-prohibited portfolio/hafta_04/gun_028/ornek_veri/prohibited_commands_test.json
```

### 4. Canlı Sistem Modu (`--live`)
Desteklenen platformlarda güvenli komutları yerel işletim sistemi üzerinde alt süreç olarak canlı koşturur:
```bash
python portfolio/hafta_04/gun_028/uygulama/command_line_notebook_engine.py --catalog portfolio/hafta_04/gun_028/ornek_veri/safe_command_catalog.json --live --audit
```

---

## 🧪 Birim Testlerin Çalıştırılması

Tüm testler Python standart kütüphanesi (`unittest`) kullanılarak izole ortamda çalıştırılır:
```bash
python -m unittest discover -s portfolio/hafta_04/gun_028/tests -p "test_*.py" -v
```

---

## 📄 Lisans

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
