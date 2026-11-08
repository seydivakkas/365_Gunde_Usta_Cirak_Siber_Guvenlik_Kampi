# Gün 152: Güvenli Yapılandırma Sapması (Configuration Drift) ve Otomatik İyileştirme

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status: 100/100 PASS](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Tests: 15/15 Passed](https://img.shields.io/badge/tests-15%2F15%20Passed-success?style=flat-square)
![Negative Controls: 9/9 Passed](https://img.shields.io/badge/negative%20controls-9%2F9%20Passed-blue?style=flat-square)

---

## 📌 Genel Bakış

Bu modül, uç nokta ve sunucu sistemlerinde **Yapılandırma Sapmasını (Configuration Drift)** tespit eden ve sistemi onaylanmış güvenli referans durumuna (Hardened Baseline) geri döndüren **Otomatik İyileştirme (Auto-Remediation / Self-Healing)** motorunu sunar.

CIS Benchmarks, DISA STIG ve Microsoft Security Compliance Toolkit standartları esas alınarak geliştirilen motor; Kayıt Defteri (Registry), Sistem Servisleri (Services), Güvenlik Duvarı (Firewall Profiles), Yerel Yönetici Grupları (Local Administrators) ve Linux Çekirdek Parametreleri (Sysctl) üzerinde anlık sapma analizi yapar.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_22/gun_152/
├── README.md                                # Proje genel tanıtımı ve kullanım kılavuzu
├── ders.md                                  # Usta-Çırak pedagojik derin teknik ders notu
├── soru_cevap.md                            # 3 derin teknik soru ve 4 zorunlu alt başlıklı cevaplar
├── rapor.md                                 # 100/100 başarı ve değerlendirme raporu
├── sonuc.json                               # Yapılandırılmış sonuç özeti
├── manifest.json                            # 20 dosyanın SHA-256 bütünlük özetleri
├── kanit_uretici.py                         # Kanıtları üreten otomasyon betiği
├── uygulama/
│   ├── __init__.py                          # Python paket başlatıcısı
│   ├── config_drift_engine.py               # Çekirdek sapma ve otomatik iyileştirme motoru
│   └── config_drift_cli.py                  # Komut satırı yönetim arayüzü
├── tests/
│   ├── __init__.py                          # Test paketi başlatıcısı
│   └── test_config_drift.py                 # 15/15 birim test paketi
├── ornek_veri/
│   ├── clean_endpoint_baseline.json         # Sıkılaştırılmış referans uç nokta durumu
│   └── invalid_drift_scenarios.json         # 9 adet negatif kontrol sapma senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt               # 15/15 PASS birim test kanıtı
    │   ├── negatif_kontrol_sonuclari.txt    # 9/9 PASS negatif senaryo kanıtı
    │   ├── config_drift_audit_report.json   # JSON denetim raporu
    │   ├── remediated_endpoint_state.json   # İyileştirilmiş sistem durum raporu
    │   ├── config_drift_auto_remediation.ps1 # Otomatik üretilen PowerShell düzeltme betiği
    │   └── komut_ve_cikis.txt               # CLI konsol yürütme günlüğü
    └── temsili/
        └── yapilandirma_sapmasi_mimarisi.txt # ASCII mimari diyagramı
```

---

## 🚀 Kullanım ve Çalıştırma

### 1. Birim Testleri Çalıştırma
```powershell
python -m unittest portfolio/hafta_22/gun_152/tests/test_config_drift.py -v
```

### 2. Canlı Uç Noktayı Baseline ile Denetleme (Audit)
```powershell
python portfolio/hafta_22/gun_152/uygulama/config_drift_cli.py audit \
    --baseline portfolio/hafta_22/gun_152/ornek_veri/clean_endpoint_baseline.json \
    --current portfolio/hafta_22/gun_152/ornek_veri/clean_endpoint_baseline.json
```

### 3. Sapmayı Otomatik İyileştirme (Auto-Remediate)
```powershell
python portfolio/hafta_22/gun_152/uygulama/config_drift_cli.py remediate \
    --baseline portfolio/hafta_22/gun_152/ornek_veri/clean_endpoint_baseline.json \
    --current portfolio/hafta_22/gun_152/kanit/gercek/drifted_state.json \
    --output portfolio/hafta_22/gun_152/kanit/gercek/remediated_state.json
```

### 4. PowerShell Düzeltme Betiği Üretme
```powershell
python portfolio/hafta_22/gun_152/uygulama/config_drift_cli.py generate-remediation \
    --baseline portfolio/hafta_22/gun_152/ornek_veri/clean_endpoint_baseline.json \
    --current portfolio/hafta_22/gun_152/kanit/gercek/drifted_state.json \
    --output-script portfolio/hafta_22/gun_152/kanit/gercek/fix_drift.ps1
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
