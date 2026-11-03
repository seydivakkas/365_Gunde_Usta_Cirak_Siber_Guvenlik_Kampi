# Gün 127: Uç Nokta Tehdit Modeli (Endpoint Threat Model)

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Stage](https://img.shields.io/badge/Stage-06%20Endpoint%20Security-blue?style=flat-square)
![Threat Score](https://img.shields.io/badge/Threat_Score-0.0%2F100%20(Hardened)-brightgreen?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-15%20Passed-success?style=flat-square)
![Negative Controls](https://img.shields.io/badge/Negative_Controls-9%2F9%20Passed-success?style=flat-square)

Bu proje, **365 Günlük Siber Güvenlik Müfredatı** bünyesindeki **Hafta 19 / Aşama 6 (Uç Nokta Güvenliği ve Sertleştirme)** modülünün ilk günüdür. Windows ve Linux işletim sistemleri üzerinde çalışan uç noktaların (Workstation, Server, Domain Controller) saldırı yüzeyini modeller; LSASS bellek dökümü, tırnaksız servis yolları, Linux SUID zafiyetleri, EDR kurcalama koruması, telemetri kör noktaları ve güvensiz portları MITRE ATT&CK ve CWE taksonomileriyle analiz ederek CIS Benchmark uyumlu sıkılaştırma yol haritası üretir.

---

## 🔒 Lisans ve Telif Hakkı Bildirimi

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

## 🌟 Öne Çıkan Mimari Yetenekler

1. **Çoklu İşletim Sistemi ve Rol Desteği:** Windows, Linux ve macOS sistemleri için Workstation, Sunucu, Database ve Domain Controller rollerine özel risk katsayıları (DC için 1.5x, DB için 1.3x).
2. **Kimlik Belleği Koruması:** LSASS bellek alanında RunAsPPL ve Credential Guard denetimi (`CWE-311` / `MITRE T1003.001`).
3. **Yetki Yükseltme Taraması:** Tırnaksız servis yolları (`CWE-428` / `MITRE T1574.009`) ve Linux SUID/SGID zafiyetleri (`CWE-250` / `MITRE T1548.001`).
4. **Savunma Atlatma Analizi:** EDR ajanı ve Kurcalama Koruması (Tamper Protection) denetimi (`CWE-693` / `MITRE T1562.001`).
5. **Telemetri ve Görünürlük:** Sysmon ve Auditd süreç izleme telemetrisi kontrolü (`CWE-778` / `MITRE T1070`).
6. **Ağ ve Kalıcılık Güvenliği:** Açık SMBv1/RDP portları (`CWE-319`) ve zayıf izinli Run kayıtları (`CWE-732`).
7. **CIS & Microsoft Uyumlu Yol Haritası:** Önceliklendirilmiş adımlarla uç nokta sertleştirme rehberi.

---

## 📁 Proje Dizin Yapısı

```
gun_127/
├── uygulama/
│   ├── __init__.py
│   ├── endpoint_threat_model_engine.py # Çekirdek uç nokta tehdit modelleme motoru
│   └── endpoint_threat_cli.py          # Komut satırı yönetim ve sorgu aracı
├── tests/
│   ├── __init__.py
│   └── test_endpoint_threat_model.py   # 15 Birim test (100% PASS)
├── ornek_veri/
│   ├── endpoint_baseline_spec.json     # Kurumsal uç nokta örnek şartnamesi
│   └── invalid_endpoint_scenarios.json # 9 Negatif sınır ve zafiyet senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt          # Birim test koşu kanıtı
│   │   ├── negatif_kontrol_sonuclari.txt # 9 Negatif senaryo kanıtı
│   │   ├── uc_nokta_tehdit_analiz_raporu.json # JSON analiz raporu
│   │   └── komut_ve_cikis.txt          # CLI etkileşim kanıtı
│   └── temsili/
│       └── uc_nokta_tehdit_mimarisi.txt # Zorunlu banner'lı ASCII mimari şeması
├── ders.md                             # Usta-Çırak Uç Nokta Tehdit Modeli dersi
├── soru_cevap.md                       # 3 Derinlemesine teknik soru & cevap
├── rapor.md                            # 100/100 Başarı değerlendirme raporu
├── sonuc.json                          # Yapılandırılmış değerlendirme sonucu
├── manifest.json                       # Dosya bütünlük ve sağlama listesi
├── kanit_uretici.py                    # Otomatik kanıt üretim betiği
└── README.md                           # Proje genel belgesi
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest tests/test_endpoint_threat_model.py
```

### 2. Tüm Kanıtları Otomatik Üretme
```bash
python kanit_uretici.py
```

### 3. CLI Tehdit Modelleme Aracını Kullanma
```bash
# Hızlı parametrik denetim
python uygulama/endpoint_threat_cli.py quick-check --name Test-WS --os WINDOWS --role WORKSTATION --edr --tamper-protection --credential-guard --disk-encryption

# Şartname dosyasını modelleme ve Markdown rapor alma
python uygulama/endpoint_threat_cli.py model ornek_veri/endpoint_baseline_spec.json --format markdown
```
