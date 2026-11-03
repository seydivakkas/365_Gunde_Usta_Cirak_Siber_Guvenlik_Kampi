# Gün 031: Process Explorer ve Süreç Ağacı Analiz Motoru

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Stage: 02 - Sistem ve Ag Guvenligi](https://img.shields.io/badge/stage-02--Sistem%20ve%20A%C4%9F%20G%C3%BCvenli%C4%9Fi-blue?style=flat-square)
![Week: 05](https://img.shields.io/badge/week-05-blue?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/score-100%2F100-brightgreen?style=flat-square)
![Tests: 14 Passed](https://img.shields.io/badge/tests-14%20passed-brightgreen?style=flat-square)

Bu çalışma, **Siber Güvenlik 365 Gün Standart ve Müfredat Paketi** kapsamında, Aşama 02 (Sistem ve Ağ Güvenliği Temelleri) Hafta 05 bünyesinde geliştirilmiş Windows süreç hiyerarşisi oluşturma (PPID -> PID), ASCII süreç ağacı şemalaştırma, döngüsel süreç tespiti (Cycle Detection) ve süreç taklidi (Masquerading - T1036) analiz motorunu içermektedir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_05/gun_031/
├── ders.md                 # 7 bölümlük usta-çırak pedagojik ders anlatımı
├── soru_cevap.md           # G031-SC1, SC2, SC3 senaryoları ve 4 başlıklı analizleri
├── rapor.md                # 20/40/25/15 kriter puanlama tablosu ve 100/100 sonuç raporu
├── README.md               # Proje genel bakışı, kullanım kılavuzu ve lisans
├── sonuc.json              # 14 standart alanlı makine tarafından okunabilir sonuç dosyası
├── manifest.json           # Dizin içeriği ve SHA256 bütünlük hash listesi
├── uygulama/
│   ├── __init__.py
│   └── process_tree_explorer_analyzer.py  # Süreç ağacı analiz ve hiyerarşi motoru
├── tests/
│   ├── __init__.py
│   └── test_process_tree_explorer_analyzer.py # 14 kapsamlı birim test
├── ornek_veri/
│   ├── sample_process_inventory.json     # Meşru ve zararlı 16 süreçlik test envanteri
│   └── corrupted_process_tree_test.json  # Negatif kontrol için döngüsel/bozuk vakalar
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                 # Unittest yürütme çıktısı (14/14 PASS)
    │   ├── komut_ve_cikis.txt                 # CLI --tree ve --audit çalıştırma dökümü
    │   ├── surec_agaci_semasi.txt             # ASCII süreç ağacı şeması dökümü
    │   └── negatif_kontrol_sonuclari.txt      # 4 bozuk vakanın reddedilme izi
    └── temsili/
        └── surec_agaci_ve_tehdit_mimarisi.txt # Süreç hiyerarşisi ve tehdit şeması
```

---

## 🚀 Kullanım Kılavuzu

### 1. Hiyerarşik Süreç Ağacı Şemalaştırma (`--tree`)
Süreç listesindeki ebeveyn-çocuk bağlarını çözerek ASCII formatında ağaç grafını ekrana basar:
```bash
python portfolio/hafta_05/gun_031/uygulama/process_tree_explorer_analyzer.py --inventory portfolio/hafta_05/gun_031/ornek_veri/sample_process_inventory.json --tree
```

### 2. Süreç Ağacı Güvenlik ve Anomali Denetimi (`--audit`)
Ağaçtaki şüpheli yürütme zincirlerini (Ofis kabuk başlatma, sahte svchost, Temp ikilileri) denetler ve MITRE ATT&CK eşleştirmeleriyle raporlar:
```bash
python portfolio/hafta_05/gun_031/uygulama/process_tree_explorer_analyzer.py --inventory portfolio/hafta_05/gun_031/ornek_veri/sample_process_inventory.json --audit
```

### 3. Negatif Kontrol ve Döngü Doğrulama Testi (`--test-corrupted`)
Döngüsel süreç ilişkileri (A -> B -> A), negatif PID ve mükerrer kayıtları denetim filtresine tabi tutarak hepsinin engellendiğini kanıtlar:
```bash
python portfolio/hafta_05/gun_031/uygulama/process_tree_explorer_analyzer.py --test-corrupted portfolio/hafta_05/gun_031/ornek_veri/corrupted_process_tree_test.json
```

---

## 🧪 Birim Testlerin Çalıştırılması

Tüm testler Python standart kütüphanesi (`unittest`) kullanılarak izole ortamda çalıştırılır:
```bash
python -m unittest discover -s portfolio/hafta_05/gun_031/tests -p "test_*.py" -v
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
