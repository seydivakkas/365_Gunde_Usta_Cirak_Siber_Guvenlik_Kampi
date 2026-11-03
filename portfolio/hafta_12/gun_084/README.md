# Gün 084: Mini Proje 11: Test Edilen Güvenlik Log Aracı (Capstone)

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![pytest: 26 Passed](https://img.shields.io/badge/pytest-26%20passed-brightgreen?style=flat-square)
![Negative Controls: 9 Passed](https://img.shields.io/badge/negative%20tests-9%20passed-blue?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/score-100%2F100-success?style=flat-square)

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
```

---

## 📌 Genel Bakış ve Kapsam

Bu modül, Hafta 12'nin haftalık mini projesi (Capstone) olarak geliştirilmiş; dosya güvenliği (`pathlib`), güvenli veri işleme (JSON/CSV), fail-closed hata yönetimi, log enjeksiyonu önleme, hassas veri maskeleme ve `pytest` birim testlerini endüstriyel kalitede birleştiren **Test Edilen Güvenlik Log Aracıdır (`TestedSecurityLogTool`)**.

### Temel Güvenlik ve Analiz Yetenekleri
- **Güvenli Dosya Yolu Çözümleme (CWE-22 / CWE-59):** Temel dizin sınırlandırması (`resolve()`, `relative_to()`) ve sembolik bağ (symlink) denetimi.
- **Log Enjeksiyonu ve CRLF Nötralizasyonu (CWE-117):** CRLF karakterlerinin tek satıra indirgenmesi veya katı modda reddedilmesi.
- **Otomatik Hassas Veri Maskeleme (CWE-532 / CWE-359):** Kredi kartı PAN, parola, AWS erişim anahtarı ve JWT Bearer tokenlarının maskelenmesi.
- **Kaba Kuvvet (Brute Force) Tespiti (CWE-307):** Eşik değeri aşan ardışık başarısız oturum denemelerinin tespiti ve CRITICAL alarm üretimi.
- **SQL Injection Tespiti (CWE-89):** `UNION SELECT`, `OR 1=1`, `--` gibi zararlı enjeksiyon kalıplarının yakalanması.
- **Kötü Niyetli Tarayıcı Tespiti:** `sqlmap`, `nikto`, `nmap` User-Agent imzalarının tespiti.
- **DoS ve Bellek Tükenmesi Koruması (CWE-400):** Satır uzunluğu ve JSON derinlik sınırlandırmaları.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_12/gun_084/
├── README.md                                  # Proje tanıtım ve kullanım kılavuzu
├── ders.md                                    # Usta-çırak pedagojisiyle Capstone dersi
├── soru_cevap.md                              # 3 senaryo ve 4 zorunlu alt başlıklı Soru-Cevap
├── rapor.md                                   # 100/100 tam puanlı teknik denetim raporu
├── sonuc.json                                 # Makine tarafından okunabilir yürütme özeti
├── manifest.json                              # SHA-256 doğrulama özeti
├── ornek_veri/
│   ├── raw_access_logs.jsonl                  # Örnek gerçekçi erişim logları
│   └── invalid_log_tool_inputs.json           # 9 adet negatif güvenlik kontrol senaryosu
├── uygulama/
│   ├── __init__.py                            # Paket tanımlayıcı
│   └── tested_security_log_tool.py            # Log analiz motoru (her satır Türkçe açıklamalı)
├── tests/
│   ├── __init__.py                            # Test paketi tanımlayıcı
│   ├── conftest.py                            # pytest fikstürleri ve işaretçileri
│   └── test_tested_security_log_tool.py       # 26 parametrik test (her satır Türkçe açıklamalı)
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                 # pytest yürütme logları (26/26 PASS)
    │   ├── komut_ve_cikis.txt                 # CLI komut ve çıktı dökümü
    │   ├── negatif_kontrol_sonuclari.txt      # 9 negatif kontrolün yürütme kanıtı
    │   └── log_araci_denetim_raporu.txt       # Gerçek analiz ve metrik çıktısı
    └── temsili/
        └── log_araci_ve_guvenlik_mimarisi.txt # TEMSİLÎ etiketli ASCII mimari diyagramı
```

---

## 🚀 Çalıştırma ve Doğrulama

### pytest Birim Testlerini Çalıştırma
```bash
python -m pytest portfolio/hafta_12/gun_084/tests -v
```

### Negatif Güvenlik Testlerini Çalıştırma
```bash
python -c "
import json
from pathlib import Path
from portfolio.hafta_12.gun_084.uygulama.tested_security_log_tool import TestedSecurityLogTool
base_dir = Path('portfolio/hafta_12/gun_084')
with open(base_dir / 'ornek_veri/invalid_log_tool_inputs.json', 'r', encoding='utf-8') as f:
    data = json.load(f)
print(f'Toplam {len(data[\"negatif_testler\"])} negatif senaryo hazir.')
"
```
