# Gün 029: Windows Event Viewer'a Giriş ve Adli Olay Analiz Motoru

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Stage: 02 - Sistem ve Ag Guvenligi](https://img.shields.io/badge/stage-02--Sistem%20ve%20A%C4%9F%20G%C3%BCvenli%C4%9Fi-blue?style=flat-square)
![Week: 05](https://img.shields.io/badge/week-05-blue?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/score-100%2F100-brightgreen?style=flat-square)
![Tests: 14 Passed](https://img.shields.io/badge/tests-14%20passed-brightgreen?style=flat-square)

Bu çalışma, **Siber Güvenlik 365 Gün Standart ve Müfredat Paketi** kapsamında, Aşama 02 (Sistem ve Ağ Güvenliği Temelleri) Hafta 05 bünyesinde geliştirilmiş Windows Olay Günlüğü ayrıştırma, adli alan doğrulama, bağlamsal korelasyon ve SHA-256 bütünlük mühürleme motorunu içermektedir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_05/gun_029/
├── ders.md                 # 7 bölümlük usta-çırak pedagojik ders anlatımı
├── soru_cevap.md           # G029-SC1, SC2, SC3 senaryoları ve 4 başlıklı analizleri
├── rapor.md                # 20/40/25/15 kriter puanlama tablosu ve 100/100 sonuç raporu
├── README.md               # Proje genel bakışı, kullanım kılavuzu ve lisans
├── sonuc.json              # 14 standart alanlı makine tarafından okunabilir sonuç dosyası
├── manifest.json           # Dizin içeriği ve SHA256 bütünlük hash listesi
├── uygulama/
│   ├── __init__.py
│   └── windows_event_viewer_analyzer.py  # Olay günlüğü analiz ve korelasyon motoru
├── tests/
│   ├── __init__.py
│   └── test_windows_event_viewer_analyzer.py # 14 kapsamlı birim test
├── ornek_veri/
│   ├── sample_system_events.json        # 3 adet gizli veri içermeyen sistem olayı
│   ├── corrupted_events_test.json       # Negatif kontrol için 4 bozuk olay kaydı
│   └── security_event_catalog.json      # Olay kimlikleri ve MITRE ATT&CK rehberi
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                 # Unittest yürütme çıktısı (14/14 PASS)
    │   ├── komut_ve_cikis.txt                 # CLI --analyze çalıştırma dökümü
    │   ├── sistem_olay_analiz_kaydi.txt       # 3 sistem olayının ayrıntılı adli dökümü
    │   └── negatif_kontrol_sonuclari.txt      # 4 bozuk kaydın reddedilme izi
    └── temsili/
        └── windows_event_log_mimarisi.txt     # EVTX ve ETW mimari şeması
```

---

## 🚀 Kullanım Kılavuzu

### 1. Sistem Olaylarının Adli Analizi (`--analyze`)
Örnek veri kümesindeki 3 sistem olayını inceler, bağlamsal analizini yapar ve terminale raporlar:
```bash
python portfolio/hafta_05/gun_029/uygulama/windows_event_viewer_analyzer.py --events portfolio/hafta_05/gun_029/ornek_veri/sample_system_events.json --analyze
```

### 2. Negatif Kontrol ve Bozuk Veri Doğrulama Testi (`--test-corrupted`)
Bozuk, eksik veya tahrif edilmiş olay kayıtlarını güvenlik filtresine tabi tutarak hepsinin reddedildiğini doğrular:
```bash
python portfolio/hafta_05/gun_029/uygulama/windows_event_viewer_analyzer.py --test-corrupted portfolio/hafta_05/gun_029/ornek_veri/corrupted_events_test.json
```

### 3. Windows Üzerinde Canlı Olay Sorgusu (`--query-live`)
Windows işletim sistemlerinde `Get-WinEvent` komutunu kullanarak canlı sistem kanalından son olayları güvenle çeker:
```bash
python portfolio/hafta_05/gun_029/uygulama/windows_event_viewer_analyzer.py --query-live
```

---

## 🧪 Birim Testlerin Çalıştırılması

Tüm testler Python standart kütüphanesi (`unittest`) kullanılarak izole ortamda çalıştırılır:
```bash
python -m unittest discover -s portfolio/hafta_05/gun_029/tests -p "test_*.py" -v
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
