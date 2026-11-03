# Gün 071: Python Ortamı, Sanal Ortam (venv) ve Paket Sürümleri

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Stage: 04 In Progress](https://img.shields.io/badge/Stage-04%20In%20Progress-blue?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/Score-100%2F100-success?style=flat-square)
![Tests: 14/14 PASS](https://img.shields.io/badge/Tests-14%2F14%20PASS-blue?style=flat-square)
![Negative Controls: 9/9 PASS](https://img.shields.io/badge/Negative%20Controls-9%2F9%20PASS-blue?style=flat-square)

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

Bu paket, **Siber Güvenlik 365 Gün Müfredatı** kapsamında **Aşama 04 (Siber Güvenlik için Python Geliştirme ve Otomasyon)** safhasının ilk günü olan **Gün 071: Python ortamı, venv ve paket sürümleri** çalışmasını içerir.

### Temel Güvenlik Yetenekleri:
1. **Sanal Ortam (venv) Yalıtım Denetimi:** `pyvenv.cfg` ayrıştırma, `include-system-site-packages = false` yalıtım kuralı teyidi ve asgari Python sürümü ($\ge 3.10$) kontrolü.
2. **Kesin Sürüm Sabitleme (Pinning):** `requirements.txt` dosyalarında değişken/kayan (`>=`, `~=`) sürüm risklerinin engellenmesi, tam deterministik (`==`) sabitleme denetimi.
3. **Kriptografik Bütünlük (SHA-256 Hashes):** Pip hash pinning mekanizması ile paketlerin tam 64 karakterlik SHA-256 özetleriyle mühürlenmesi ve Ortadaki Adam (MitM) risklerinin bertaraf edilmesi.
4. **Tedarik Zinciri ve Typosquatting Tespiti:** Popüler siber güvenlik kütüphanelerine (`scapy`, `requests`, `cryptography`, `paramiko` vb.) yönelik harf taklitlerinin dinamik Levenshtein düzenleme uzaklığı algoritmasıyla tespiti.
5. **Yerel CVE Güvenlik Zafiyeti Taraması:** Bilinen zafiyetli kütüphane sürümlerinin (CVE-2023-45803, CVE-2023-32681, vb.) statik analizi.

---

## Dizin Yapısı

```
portfolio/hafta_11/gun_071/
├── uygulama/
│   ├── __init__.py
│   └── python_env_and_dependency_auditor.py  # Ortam ve bağımlılık güvenlik denetleyicisi
├── tests/
│   ├── __init__.py
│   └── test_python_env_and_dependency_auditor.py # 14 birim test ve 9 negatif sınır kontrolü
├── ornek_veri/
│   ├── pyvenv.cfg                            # Örnek izole sanal ortam konfigürasyonu
│   ├── guvenli_requirements.txt              # SHA-256 mühürlü güvenli bağımlılık dosyası
│   └── invalid_env_inputs.json               # 9 negatif sınır testi senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── bagimlilik_guvenlik_raporu.txt   # Üretilen kurumsal denetim raporu
│   │   ├── komut_ve_cikis.txt                # CLI çalıştırma komutu ve çıktısı
│   │   ├── negatif_kontrol_sonuclari.txt     # 9 negatif kontrol kanıt özeti
│   │   └── test_sonuclari.txt                # 14 birim test terminal çıktısı
│   └── temsili/
│       └── python_env_ve_tedarik_zinciri_mimarisi.txt # ASCII mimari şeması
├── ders.md                                   # Usta-Çırak ortam güvenliği dersi
├── soru_cevap.md                             # 4 zorunlu alt başlıklı 3 teknik soru ve analiz
├── rapor.md                                  # 100/100 tam puanlı başarı raporu
├── README.md                                 # Dokümantasyon ve lisans bildirimi
├── sonuc.json                                # 14 standartlaştırılmış sonuç alanı
└── manifest.json                             # SHA-256 dosya bütünlük listesi
```

---

## Çalıştırma Talimatları

### Birim Testleri Koşma:
```bash
python -m unittest portfolio.hafta_11.gun_071.tests.test_python_env_and_dependency_auditor -v
```

### Denetleyici Motorunu Çalıştırma:
```bash
python -m portfolio.hafta_11.gun_071.uygulama.python_env_and_dependency_auditor \
    --pyvenv-cfg portfolio/hafta_11/gun_071/ornek_veri/pyvenv.cfg \
    --requirements portfolio/hafta_11/gun_071/ornek_veri/guvenli_requirements.txt \
    --output-txt portfolio/hafta_11/gun_071/kanit/gercek/bagimlilik_guvenlik_raporu.txt
```
