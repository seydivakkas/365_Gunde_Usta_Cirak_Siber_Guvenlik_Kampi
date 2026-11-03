# Gün 141: Yama Yönetimi ve CVE

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Tests: 15 Passed](https://img.shields.io/badge/tests-15%20passed-brightgreen?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/score-100%2F100-success?style=flat-square)
![Platform: Pure Python 3](https://img.shields.io/badge/platform-Python%203-blue?style=flat-square)

## Genel Bakış

Bu modül, **Hafta 21 (Zafiyet Yönetimi, Güvenlik Açıkları ve Otomasyon)** müfredatının ilk günüdür. Sistemlerdeki Ortak Güvenlik Açıkları ve Maruz Kalmaların (CVE) tespit edilmesini, CVSS v3.1 puanlama sistemine, CISA KEV (Known Exploited Vulnerabilities) aktif istismar kataloğuna ve EPSS tahmin olasılığına göre önceliklendirilmesini (triyaj) gerçekleştiren kurumsal bir **Yama Yönetimi ve CVE Motoru (`patch_cve_engine.py`)** ve **CLI Aracı (`cve_patch_cli.py`)** geliştirilmiştir.

Modül; kurumsal SLA sürelerini (EMERGENCY için 72 saat, CRITICAL için 7 gün, HIGH için 14 gün) denetler, SLA aşımlarını raporlar, aşamalı otomatik yama betikleri (`otomatik_yama_plani.sh`) ve olası regresyonlara karşı acil durum geri alma betikleri (`acil_geri_alma.sh`) üretir.

---

## Dizin Yapısı

```
portfolio/hafta_21/gun_141/
├── README.md                              # Proje özeti, kullanım kılavuzu ve lisans
├── ders.md                                # Usta-Çırak pedagojisi ile derinlemesine teknik ders
├── soru_cevap.md                          # 4 alt başlıklı 3 kapsamlı derinleşme sorusu ve cevabı
├── rapor.md                               # 100/100 tam puanlı başarı karnesi ve metrikler
├── sonuc.json                             # Makine tarafından okunabilir sonuç özeti
├── manifest.json                          # Dizin dosya bütünlüğü ve SHA-256 sağlama toplamları
├── kanit_uretici.py                       # Testleri koşturan ve kanıtları üreten otomasyon aracı
├── uygulama/
│   ├── __init__.py                        # Paket başlatıcı
│   ├── patch_cve_engine.py                # CVSS, KEV, EPSS ve SLA tabanlı Yama & CVE Motoru
│   └── cve_patch_cli.py                   # Komut satırı arayüzü (scan, plan, rollback-plan, verify)
├── tests/
│   ├── __init__.py                        # Test paketi başlatıcı
│   └── test_patch_cve_management.py       # 15 birim testi içeren test paketi (100% PASS)
├── ornek_veri/
│   ├── package_inventory_cve_spec.json    # Örnek paket ve CVE zafiyet envanteri
│   └── invalid_cve_scenarios.json         # 9 adet negatif zafiyet ve format ihlali senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt             # 15 birim testinin çalışma logları
    │   ├── negatif_kontrol_sonuclari.txt  # 9 negatif senaryonun yakalanma logları
    │   ├── cve_yama_analiz_raporu.json    # JSON formatında sistem zafiyet raporu
    │   ├── otomatik_yama_plani.sh         # Aşamalı yama dağıtım Bash betiği
    │   ├── acil_geri_alma.sh              # Acil durum geri alma (rollback) Bash betiği
    │   ├── komut_ve_cikis.txt             # CLI yürütme çıktıları
    │   └── kurumsal_yama_politikasi_sla.json # NIST SP 800-40 uyumlu yama politikası
    └── temsili/
        └── yama_ve_cve_mimarisi.txt       # ASCII sistem mimarisi diyagramı
```

---

## Temel Özellikler

1. **CISA KEV ve EPSS Tehdit İstihbaratı:** Yalnızca teorik CVSS taban skoruna değil, vahşi doğada aktif istismar edilen açıklara öncelik veren modern triyaj yaklaşımı.
2. **Katı SLA İhlal Denetimi:** Zafiyet yayınından bu yana geçen süreyi takip ederek geciken yamaları tespit eder ve alarmlar üretir.
3. **Aşamalı Dağıtım (Phased Rollout):** Acil/Kritik yamaları, standart güncellemeleri ve `unattended-upgrades` yapılandırmasını sıralı aşamalarla icra eder.
4. **Otomatik Geri Alma (Rollback):** Bir güncelleme sistemde regresyona yol açtığında saniyeler içinde eski kararlı sürüme dönülmesini sağlayan `--allow-downgrades` komutlarını otomatik hazırlar.
5. **Yama Hijyen Puanı:** Sistemin genel yama sağlığını ve risk seviyesini 0-100 arasında derecelendirir.

---

## Hızlı Başlangıç

### 1. Testleri ve Kanıt Üreticisini Çalıştırma
```powershell
python kanit_uretici.py
```

### 2. CLI ile Zafiyet Taraması ve Triyaj
```powershell
# Envanteri tara ve triyaj tablosunu gör
python uygulama/cve_patch_cli.py scan ornek_veri/package_inventory_cve_spec.json

# Belirli bir tarihe göre SLA ihlallerini kontrol et
python uygulama/cve_patch_cli.py scan ornek_veri/package_inventory_cve_spec.json --date 2026-11-20

# Aşamalı yama uygulama betiği üret
python uygulama/cve_patch_cli.py plan ornek_veri/package_inventory_cve_spec.json --output kanit/gercek/otomatik_yama_plani.sh

# Acil durum geri alma betiği üret
python uygulama/cve_patch_cli.py rollback-plan ornek_veri/package_inventory_cve_spec.json --output kanit/gercek/acil_geri_alma.sh
```

---

## Lisans

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
