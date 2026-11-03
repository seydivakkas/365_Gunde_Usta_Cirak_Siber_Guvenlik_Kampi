# Gün 030: Linux journalctl ve Günlük Dizinleri Denetim Motoru

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Stage: 02 - Sistem ve Ag Guvenligi](https://img.shields.io/badge/stage-02--Sistem%20ve%20A%C4%9F%20G%C3%BCvenli%C4%9Fi-blue?style=flat-square)
![Week: 05](https://img.shields.io/badge/week-05-blue?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/score-100%2F100-brightgreen?style=flat-square)
![Tests: 14 Passed](https://img.shields.io/badge/tests-14%20passed-brightgreen?style=flat-square)

Bu çalışma, **Siber Güvenlik 365 Gün Standart ve Müfredat Paketi** kapsamında, Aşama 02 (Sistem ve Ağ Güvenliği Temelleri) Hafta 05 bünyesinde geliştirilmiş Linux `systemd-journald` günlüklerini ayrıştırma, kalıcılık (persistent vs volatile) denetimi, saat dilimi korelasyonu (UTC vs Yerel Saat) ve SHA-256 bütünlük mühürleme motorunu içermektedir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_05/gun_030/
├── ders.md                 # 7 bölümlük usta-çırak pedagojik ders anlatımı
├── soru_cevap.md           # G030-SC1, SC2, SC3 senaryoları ve 4 başlıklı analizleri
├── rapor.md                # 20/40/25/15 kriter puanlama tablosu ve 100/100 sonuç raporu
├── README.md               # Proje genel bakışı, kullanım kılavuzu ve lisans
├── sonuc.json              # 14 standart alanlı makine tarafından okunabilir sonuç dosyası
├── manifest.json           # Dizin içeriği ve SHA256 bütünlük hash listesi
├── uygulama/
│   ├── __init__.py
│   └── linux_journalctl_log_auditor.py  # journalctl analiz ve filtreleme motoru
├── tests/
│   ├── __init__.py
│   └── test_linux_journalctl_log_auditor.py # 14 kapsamlı birim test
├── ornek_veri/
│   ├── sample_journal_logs.json         # VM export formatında örnek journal kayıtları
│   ├── sample_journald_conf_baseline.ini# Kurumsal kalıcı journald.conf referansı
│   └── corrupted_journal_test.json      # Negatif kontrol için 4 bozuk journal kaydı
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                 # Unittest yürütme çıktısı (14/14 PASS)
    │   ├── komut_ve_cikis.txt                 # CLI --audit çalıştırma dökümü
    │   ├── journal_filtreleme_ve_zaman_kaydi.txt # sshd filtreleme ve UTC/Yerel saat izi
    │   └── negatif_kontrol_sonuclari.txt      # 4 bozuk kaydın reddedilme izi
    └── temsili/
        └── linux_journald_ve_log_mimarisi.txt # systemd-journald mimari şeması
```

---

## 🚀 Kullanım Kılavuzu

### 1. Tam Sistem Günlüğü ve Yapılandırma Denetimi (`--audit`)
Journal kayıtlarını ve `journald.conf` dosyasını inceler; kalıcılık ve saat dilimi analizini terminale basar:
```bash
python portfolio/hafta_05/gun_030/uygulama/linux_journalctl_log_auditor.py --logs portfolio/hafta_05/gun_030/ornek_veri/sample_journal_logs.json --conf portfolio/hafta_05/gun_030/ornek_veri/sample_journald_conf_baseline.ini --audit
```

### 2. Belirli Bir systemd Birimine Göre Filtreleme (`--unit`)
Yalnızca hedeflenen servise (örn: `sshd`) ait kayıtları ayıklar ve zaman damgalarını karşılaştırır:
```bash
python portfolio/hafta_05/gun_030/uygulama/linux_journalctl_log_auditor.py --logs portfolio/hafta_05/gun_030/ornek_veri/sample_journal_logs.json --unit sshd --audit
```

### 3. Öncelik Seviyesine Göre Filtreleme (`--priority`)
Yalnızca belirtilen seviye ve altındaki (örn: 4 -> warning, err, crit, alert, emerg) kayıtları listeler:
```bash
python portfolio/hafta_05/gun_030/uygulama/linux_journalctl_log_auditor.py --logs portfolio/hafta_05/gun_030/ornek_veri/sample_journal_logs.json --priority 4 --audit
```

### 4. Negatif Kontrol ve Bozuk Veri Doğrulama Testi (`--test-corrupted`)
Bozuk veya geçici bellek kullanan kayıtları denetim filtresine tabi tutarak hepsinin reddedildiğini doğrular:
```bash
python portfolio/hafta_05/gun_030/uygulama/linux_journalctl_log_auditor.py --test-corrupted portfolio/hafta_05/gun_030/ornek_veri/corrupted_journal_test.json
```

---

## 🧪 Birim Testlerin Çalıştırılması

Tüm testler Python standart kütüphanesi (`unittest`) kullanılarak izole ortamda çalıştırılır:
```bash
python -m unittest discover -s portfolio/hafta_05/gun_030/tests -p "test_*.py" -v
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
