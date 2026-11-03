# Gün 026: PATH ve Ortam Değişkenleri Güvenlik Mimarisi

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-blue)
![Security Standard](https://img.shields.io/badge/standard-CIS%20Benchmark%205.4.4%20%7C%20NIST%20800--53-orange)
![Tests](https://img.shields.io/badge/tests-14%2F14%20PASS-brightgreen)

## Lisans ve Telif Hakkı

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

## Genel Bakış

Bu çalışma, 365 Günlük Siber Güvenlik Müfredatı kapsamında **Aşama 02 / Hafta 04 / Gün 026** ("PATH ve ortam değişkenleri") modülü için geliştirilmiştir.

Modülün temel amacı; işletim sistemlerinde `$PATH` arama sırası çözümleme mantığını (soldan sağa), bağıl yol (`.`) ve boş ayraçların (`::`) oluşturduğu CWE-426 zafiyetini, dünyaya yazılabilir dizinlerin (`/tmp`) oluşturduğu CWE-427 ikili gölgeleme (Binary Hijacking) ve yetki yükseltme tehditlerini, `LD_PRELOAD` gibi tehlikeli dinamik bağlayıcı enjeksiyonlarını (CWE-114) ve ortam değişkenlerinde saklanan açık parola sızıntılarını (CWE-526) uygulamalı ve teorik olarak öğretmektir.

---

## Proje Yapısı

```
portfolio/hafta_04/gun_026/
│
├── uygulama/
│   ├── __init__.py
│   └── path_environment_security_auditor.py  # Canlı PATH ve ortam denetleyicisi
│
├── tests/
│   ├── __init__.py
│   └── test_path_environment_security_auditor.py # 14 birim test
│
├── ornek_veri/
│   ├── path_security_baseline_rules.json     # CIS/NIST tabanlı kurallar
│   └── sample_environment_profiles.json      # Örnek ortam profilleri
│
├── kanit/
│   ├── gercek/
│   │   ├── yerel_path_guvenlik_incelemesi.txt # G026-SC2 salt-okunur inceleme
│   │   ├── test_sonuclari.txt                 # 14/14 test pass çıktısı
│   │   └── komut_ve_cikis.txt                 # CLI çalışma ve denetim çıktıları
│   └── temsili/
│       └── path_ve_arama_sirasi_mimarisi.txt  # Temsili mimari şema
│
├── ders.md                                    # Kapsamlı didaktik usta-çırak dersi
├── soru_cevap.md                              # 3 senaryo ve 4 zorunlu alt başlık
├── rapor.md                                   # 100/100 başarım ve değerlendirme
├── sonuc.json                                 # 14 standart alan
└── manifest.json                              # Dosya bütünlük SHA-256 özeti
```

---

## Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest discover -s portfolio/hafta_04/gun_026/tests -p "test_*.py" -v
```

### 2. Canlı PATH Değerini Salt-Okunur İnceleme (G026-SC2)
```bash
python portfolio/hafta_04/gun_026/uygulama/path_environment_security_auditor.py --live-path
python portfolio/hafta_04/gun_026/uygulama/path_environment_security_auditor.py --live-path --json
```

### 3. Ortam Profillerini Güvenlik Kurallarına Göre Denetleme
```bash
python portfolio/hafta_04/gun_026/uygulama/path_environment_security_auditor.py --audit --profile-name guvensiz_gelistirici_profili
python portfolio/hafta_04/gun_026/uygulama/path_environment_security_auditor.py --audit --profile-name guvenli_sunucu_profili
```
