# Gün 136: Linux Servisleri ve Systemd Güvenliği

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Category](https://img.shields.io/badge/category-Linux%20Security-blue?style=flat-square)

Bu çalışma; Linux işletim sistemlerinde PID 1 `systemd` servis mimarisini, servis birim dosyalarını (`.service`), sandboxing direktiflerini (`NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`), Linux Capabilities sınırlandırmalarını (`CapabilityBoundingSet`), dosya sistemi izinlerini ve CIS Linux Benchmark uyarınca gereksiz/tehlikeli servisleri denetleyen kurumsal seviyede bir güvenlik motoru ve CLI yönetim aracı sunar.

---

## 📁 Dizin Yapısı

```text
gun_136/
├── uygulama/
│   ├── __init__.py
│   ├── linux_systemd_engine.py           # Systemd denetim, sandboxing analizi ve puanlama motoru
│   └── systemd_security_cli.py           # CLI denetim, raporlama, şablon ve Bash betiği üreticisi
├── tests/
│   ├── __init__.py
│   └── test_linux_systemd_security.py    # 15 adet kapsamlı birim test (100% PASS)
├── ornek_veri/
│   ├── systemd_inventory_spec.json       # Örnek kurumsal Linux servis envanteri
│   └── invalid_systemd_scenarios.json    # 9 adet negatif sınır durum test senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt            # Birim test çalıştırma kanıtı (15/15 PASS)
│   │   ├── negatif_kontrol_sonuclari.txt # 9/9 negatif senaryo doğrulama çıktısı
│   │   ├── systemd_guvenlik_analiz_raporu.json # JSON formatlı detaylı denetim raporu
│   │   ├── otomatik_sikilastirma.sh      # Otomatik üretilen Bash iyileştirme betiği
│   │   ├── ornek_guvenli_servis.service  # CIS uyumlu örnek güvenli servis birim şablonu
│   │   └── komut_ve_cikis.txt            # CLI komutları ve terminal çıktıları
│   └── temsili/
│       └── systemd_mimarisi.txt          # Systemd servis ve sandboxing ASCII mimari diyagramı
├── kanit_uretici.py                      # Tüm kanıtları tek komutla üreten orkestrasyon betiği
├── ders.md                               # Usta-Çırak derinlemesine hoca dersi
├── soru_cevap.md                         # 3 adet derinlemesine teknik soru ve analiz
├── rapor.md                              # 100/100 tam puan skor kartı ve analiz raporu
├── sonuc.json                            # Makine tarafından okunabilir sonuç özeti
├── manifest.json                         # Paket dosya doğrulama listesi
└── README.md                             # Paket tanıtımı ve kullanım kılavuzu
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest discover tests/
```

### 2. CLI ile Systemd Servis Envanterini Denetleme
```bash
python uygulama/systemd_security_cli.py audit -i ornek_veri/systemd_inventory_spec.json -o kanit/gercek/systemd_guvenlik_analiz_raporu.json
```

### 3. Otomatik Bash İyileştirme (Hardening) Betiği Üretme
```bash
python uygulama/systemd_security_cli.py remediate -i ornek_veri/systemd_inventory_spec.json -o kanit/gercek/otomatik_sikilastirma.sh
```

### 4. CIS Uyumlu Güvenli Servis Şablonu Oluşturma
```bash
python uygulama/systemd_security_cli.py template -n backend-api.service -e /usr/local/bin/api-server -u apiuser -o kanit/gercek/ornek_guvenli_servis.service
```

### 5. Kanıt Üreticiyi Çalıştırma
```bash
python kanit_uretici.py
```

---

## 🔒 Güvenlik Standartları ve Kapsam

- **CWE-732 / MITRE ATT&CK T1543.002:** Servis birim dosyalarında (`/etc/systemd/system/`) yetkisiz yazma izinleri (`chmod 0644`, `chown root:root`).
- **CWE-250 / MITRE ATT&CK T1548:** Alt süreçlerin SUID ikili dosyalar üzerinden yetki yükseltmesini engelleyen `NoNewPrivileges=yes` direktifi (`prctl PR_SET_NO_NEW_PRIVS`).
- **CWE-732 / MITRE ATT&CK T1565.001:** Dosya sistemini (`/usr`, `/boot`, `/etc`) salt-okunur bağlayan `ProtectSystem=strict` koruması.
- **CWE-200 / MITRE ATT&CK T1005:** Kullanıcı ana dizinlerini (`/home`, `/root`) gizleyen `ProtectHome=yes` izolasyonu.
- **CWE-377 / CWE-379:** Ortak `/tmp` yarış koşulları ve sembolik bağ saldırılarını engelleyen `PrivateTmp=yes` mount namespace'i.
- **CWE-250 / MITRE ATT&CK T1548:** Linux çekirdek yeteneklerini (`CapabilityBoundingSet`) asgariye indirme ve `CAP_SYS_ADMIN` gibi tehlikeli yetenekleri düşürme.
- **CIS Linux Benchmark Section 2.1 & 2.2:** Telnet, RSH, TFTP, Avahi, CUPS gibi gereksiz ve güvensiz servislerin durdurulması ve maskelenmesi (`systemctl mask`).

---

## Lisans

Bu projenin tüm hakları saklıdır.  
**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.  
Yalnızca GitHub üzerinde görüntüleme ve inceleme izni verilmiştir (kopyalamadan).  
Yazarın açık yazılı izni olmaksızın hiçbir ticari veya ticari olmayan projede kullanılamaz, kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya tersine mühendislik uygulanamaz.
