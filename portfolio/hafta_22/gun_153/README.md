# Gün 153: Mini Proje 21 — Uç Nokta Risk Panosu ve Güvenlik Duruşu Yönetimi (Endpoint Posture Management)

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status: 100/100 PASS](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Tests: 15/15 Passed](https://img.shields.io/badge/tests-15%2F15%20Passed-success?style=flat-square)
![Negative Controls: 9/9 Passed](https://img.shields.io/badge/negative%20controls-9%2F9%20Passed-blue?style=flat-square)

---

## 📌 Genel Bakış

Bu modül, **Aşama 6 (Uç Nokta ve Kimlik Güvenliği)** kapsamında geliştirilen tüm güvenlik bileşenlerini (EDR/Telemetri, Uygulama Kontrolü/Sandbox, Disk Şifreleme/TPM, Değiştirilemez Yedekleme ve CIS Yapılandırma Sapması) tek bir çatı altında birleştiren **Mini Proje 21: Kurumsal Uç Nokta Risk Panosu ve Duruş Yönetimi (ESPM)** motorunu içerir.

Sistem, heterojen işletim sistemlerinden (Windows, Linux, macOS) toplanan telemetrileri 6 ağırlıklı güvenlik vektöründe analiz eder, kritik varlık çarpanıyla iş etkisini hesaba katar, filo seviyesinde ısı haritaları üretir ve yüksek riskli uç noktalar için otomatik PowerShell iyileştirme betikleri sunar.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_22/gun_153/
├── README.md                                # Proje genel tanıtımı ve kullanım kılavuzu
├── ders.md                                  # Usta-Çırak derin teknik ders notu
├── soru_cevap.md                            # 3 derin teknik soru ve 4 zorunlu alt başlıklı cevaplar
├── rapor.md                                 # 100/100 başarı ve değerlendirme raporu
├── sonuc.json                               # Yapılandırılmış sonuç özeti
├── manifest.json                            # 20 dosyanın SHA-256 bütünlük özetleri
├── kanit_uretici.py                         # Kanıtları üreten otomasyon betiği
├── uygulama/
│   ├── __init__.py                          # Python paket başlatıcısı
│   ├── endpoint_risk_dashboard.py           # Çekirdek çok vektörlü risk analizi ve filo motoru
│   └── endpoint_risk_cli.py                 # Komut satırı yönetim arayüzü
├── tests/
│   ├── __init__.py                          # Test paketi başlatıcısı
│   └── test_endpoint_risk_dashboard.py      # 15/15 birim test paketi
├── ornek_veri/
│   ├── enterprise_fleet_inventory.json      # 10 kurumsal uç noktanın telemetri envanteri
│   └── invalid_fleet_scenarios.json         # 9 adet negatif kontrol senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt               # 15/15 PASS birim test kanıtı
    │   ├── negatif_kontrol_sonuclari.txt    # 9/9 PASS negatif senaryo kanıtı
    │   ├── fleet_risk_dashboard.json        # JSON formatında filo analiz raporu
    │   ├── executive_risk_report.txt        # Yönetici seviyesi ASCII risk panosu
    │   ├── top_priority_remediation.ps1     # Öncelikli PowerShell düzeltme betiği
    │   └── komut_ve_cikis.txt               # CLI konsol yürütme günlüğü
    └── temsili/
        └── uc_nokta_risk_panosu_mimarisi.txt # ASCII mimari diyagramı
```

---

## 🚀 Kullanım ve Çalıştırma

### 1. Birim Testleri Çalıştırma
```powershell
python -m unittest portfolio/hafta_22/gun_153/tests/test_endpoint_risk_dashboard.py -v
```

### 2. Kurumsal Filoyu Tarama ve Pano Üretme
```powershell
python portfolio/hafta_22/gun_153/uygulama/endpoint_risk_cli.py scan-fleet \
    --fleet portfolio/hafta_22/gun_153/ornek_veri/enterprise_fleet_inventory.json \
    --output portfolio/hafta_22/gun_153/kanit/gercek/fleet_risk_dashboard.json
```

### 3. Tek Bir Uç Noktanın Derinlemesine Analizi
```powershell
python portfolio/hafta_22/gun_153/uygulama/endpoint_risk_cli.py host-detail \
    --fleet portfolio/hafta_22/gun_153/ornek_veri/enterprise_fleet_inventory.json \
    --host CONTR-LAP-09
```

### 4. Acil Öncelikli PowerShell İyileştirme Betiği Üretme
```powershell
python portfolio/hafta_22/gun_153/uygulama/endpoint_risk_cli.py export-remediation \
    --fleet portfolio/hafta_22/gun_153/ornek_veri/enterprise_fleet_inventory.json \
    --output-script portfolio/hafta_22/gun_153/kanit/gercek/top_priority_remediation.ps1
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
