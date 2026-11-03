# GÜN 121: Risk Skorlama, Kontrol Seçimi ve ROSI Analizi

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Day: 121/365](https://img.shields.io/badge/G%C3%BCn-121%2F365-blue?style=flat-square)
![Status: 100/100 PASS](https://img.shields.io/badge/Status-100%2F100%20PASS-brightgreen?style=flat-square)

---

## ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

**YASAKLAR:**
1. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
2. Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
3. Alt lisanslanamaz, satılamaz veya devredilemez.
4. Tersine mühendislik yapılamaz.

**İZİN VERİLEN KULLANIM:**
- GitHub üzerinde görüntüleme ve okuma.
- Kişisel öğrenim amacıyla kodu inceleme (kopyalamadan).

YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.  
İzin talepleri için: GitHub @seydivakkas

---

## Proje Genel Bakışı

Bu proje, NIST SP 800-30 ve ISO 27005 standartlarına tam uyumlu kurumsal bir **Risk Skorlama, Kontrol Seçimi ve ROSI (Return on Security Investment)** motorudur.

Sistem; hem nitel (5x5 olasılık-etki matrisi) hem de nicel finansal (SLE, ARO, ALE) metrikleri işletir; NIST SP 800-53 Rev 5 ve CIS Controls v8 güvenlik kontrollerini eşleştirir; savunma derinliği (Defense-in-Depth) çerçevesinde bağımsız birleşik kontrol etkinliğini hesaplar; güvenlik harcamasının şirkete getirisini (ROSI) modeller ve risk iştahını aşan onaysız kabulleri (CWE-1025) engelleyerek kurumsal yönetişimi garanti altına alır.

---

## Dizin Yapısı

```
portfolio/hafta_18/gun_121/
├── uygulama/
│   ├── __init__.py
│   ├── risk_control_engine.py       # Çekirdek risk, kontrol ve ROSI motoru
│   └── risk_cli.py                  # Komut satırı değerlendirme ve analiz aracı
├── tests/
│   ├── __init__.py
│   └── test_risk_control.py         # 15/15 birim test (%100 PASS)
├── ornek_veri/
│   ├── risk_assessment_config.json  # Kurumsal risk kütüğü ve kontrol kataloğu
│   └── invalid_risk_scenarios.json  # 9 negatif kontrol test senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── risk_analiz_raporu.txt
│   │   └── komut_ve_cikis.txt
│   └── temsili/
│       └── risk_mimarisi.txt        # ASCII mimari illüstrasyonu
├── kanit_uretici.py                 # Otomatik kanıt üretim ve doğrulama betiği
├── ders.md                          # Usta-Çırak interaktif ders anlatımı
├── soru_cevap.md                    # 3 derin teknik soru ve çözüm analizi
├── rapor.md                         # 100/100 tam puan değerlendirme karnesi
├── sonuc.json                       # Puan ve yeterlilik doğrulama dosyası
├── manifest.json                    # Dosya bütünlüğü ve SHA256 özetleri
└── README.md                        # Dokümantasyon ve lisans bildirimi
```

---

## Çalıştırma ve Kullanım

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest tests/test_risk_control.py
```

### 2. CLI ile Risk Değerlendirmesi Yapma
```bash
# Modeli değerlendir ve konsol özetini gör
python uygulama/risk_cli.py evaluate ornek_veri/risk_assessment_config.json

# Markdown formatında yönetici raporu üret
python uygulama/risk_cli.py evaluate ornek_veri/risk_assessment_config.json --format markdown

# Hızlı finansal kayıp ve ROSI hesapla
python uygulama/risk_cli.py rosi --asset-value 500000 --ef 0.6 --aro 0.8 --cost 30000 --effectiveness 0.85
```

### 3. Tüm Kanıtları Yeniden Üretme
```bash
python kanit_uretici.py
```
