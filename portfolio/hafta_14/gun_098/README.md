# Gün 098: Aşama 4 Kalite Özeti — Siber Güvenlik Otomasyonu ve Yönetişim

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Stage](https://img.shields.io/badge/stage-04%20Automation-blue?style=flat-square)
![ARL](https://img.shields.io/badge/ARL-Level%204%20Production-success?style=flat-square)

Bu modül, **Aşama 4: Siber Güvenlik Otomasyonu** (Gün 071-098) kapsamında geliştirilen tüm betiklerin ve araçların kod güvenliğini, mimari standartlarını, hata yönetimi direncini ve kurumsal uyumluluğunu denetleyen **Soyut Sözdizimi Ağacı (AST)** tabanlı statik kalite denetim motorudur.

---

## 🔒 Lisans ve Telif Hakkı

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

## 📂 Dizin Yapısı

```
portfolio/hafta_14/gun_098/
├── README.md                      # Modül tanıtım ve kullanım kılavuzu
├── ders.md                        # Usta-Çırak Aşama 4 Kalite Özeti ders notu
├── soru_cevap.md                  # 3 soru ve 4 zorunlu alt başlıklı derin teknik analiz
├── rapor.md                       # 100/100 tam puan değerlendirme ve karne raporu
├── sonuc.json                     # Otomasyon çıktı metrikleri ve test sonuçları
├── kanit_uretici.py               # Gerçek kanıtları üreten otomasyon betiği
├── uygulama/
│   ├── __init__.py                # Uygulama paketi başlatıcı
│   ├── stage4_quality_auditor.py  # Çekirdek AST ve statik denetim motoru
│   └── auditor_cli.py             # POSIX standart çıkış kodlu CLI arayüzü
├── tests/
│   ├── __init__.py                # Test paketi başlatıcı
│   └── test_stage4_quality_auditor.py # 15 adet birim ve negatif test paketi
├── ornek_veri/
│   ├── sample_compliant_script.py # ARL-4 uyumlu örnek kurumsal betik
│   ├── sample_vulnerable_script.py# ARL-1 zafiyetli örnek betik
│   └── invalid_audit_inputs.json  # 9 adet negatif senaryo veri seti
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt     # 15/15 birim test geçiş kanıtı
    │   ├── negatif_kontrol_sonuclari.txt # 9/9 negatif senaryo yakalama kanıtı
    │   ├── asama4_kalite_denetim_raporu.txt # Örnek betikler denetim tablosu
    │   └── komut_ve_cikis.txt     # CLI yürütme çıktıları ve çıkış kodları
    └── temsili/
        └── asama4_kalite_mimarisi.txt # Zorunlu banner'lı ASCII mimari şeması
```

---

## 🚀 Kullanım Talimatları

### 1. Tekil Dosya Denetimi
```bash
python uygulama/auditor_cli.py -f ornek_veri/sample_compliant_script.py
```

### 2. Dizin Taraması ve Toplu Karne Tablosu
```bash
python uygulama/auditor_cli.py -d ornek_veri/
```

### 3. CI/CD Otomasyonu İçin JSON Çıktısı
```bash
python uygulama/auditor_cli.py -f ornek_veri/sample_compliant_script.py --json
```

### 4. Sıkı Modda Çalıştırma (Kritik Açıklarda Exit Code 1)
```bash
python uygulama/auditor_cli.py -f ornek_veri/sample_vulnerable_script.py --strict
```

### 5. Birim Testlerin Çalıştırılması
```bash
python -m unittest tests/test_stage4_quality_auditor.py -v
```

---

## 🛡️ Güvenlik ve CWE Karşılıkları
- **CWE-95 (Eval Injection):** Dinamik kod yürütme (`eval`/`exec`) çağrıları AST düzeyinde engellenir.
- **CWE-798 (Hardcoded Credentials):** Kaynak koddaki sabit anahtar ve parolalar regex motoruyla yakalanır.
- **CWE-391 (Unchecked Error):** Çıplak `except:` blokları AST tespiti ile elenir.
- **CWE-158 (Null Byte Injection):** Girdi yollarında `\x00` baytları temizlenir.
- **CWE-400 (Resource Exhaustion):** 1 MB tavan boyutuyla bellek tüketimi sınırlandırılır.
- **CWE-16 (Configuration):** Kurumsal Özel Lisans başlığı doğrulanır.
