# Gün 138: Linux Güvenlik Duvarı: nftables ve UFW Kavramı

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Category](https://img.shields.io/badge/category-Linux%20Security-blue?style=flat-square)

Bu çalışma; Linux işletim sistemlerinde modern paket filtreleme mimarisi olan `nftables` ve kullanıcı dostu `UFW` (Uncomplicated Firewall) yapılandırmalarını, varsayılan reddetme politikasını (Default Deny), durum denetimli paket analizini (`ct state established,related accept`, `ct state invalid drop`), loopback izolasyonunu, anti-spoofing kurallarını ve açık port zafiyetlerini CIS Linux Benchmark Section 3.4 ve 3.5 standartlarına göre denetleyen kurumsal seviyede bir güvenlik motoru ve CLI yönetim aracı sunar.

---

## 📁 Dizin Yapısı

```text
gun_138/
├── uygulama/
│   ├── __init__.py
│   ├── linux_firewall_engine.py          # Güvenlik duvarı denetim, stateful analiz ve kural üretim motoru
│   └── firewall_security_cli.py          # CLI denetim, raporlama, nft/ufw şablon ve Bash betiği üreticisi
├── tests/
│   ├── __init__.py
│   └── test_linux_firewall_security.py   # 15 adet kapsamlı birim test (100% PASS)
├── ornek_veri/
│   ├── firewall_inventory_spec.json      # Örnek kurumsal Linux güvenlik duvarı kural envanteri
│   └── invalid_firewall_scenarios.json   # 9 adet negatif sınır durum test senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt            # Birim test çalıştırma kanıtı (15/15 PASS)
│   │   ├── negatif_kontrol_sonuclari.txt # 9/9 negatif senaryo doğrulama çıktısı
│   │   ├── firewall_guvenlik_analiz_raporu.json # JSON formatlı detaylı denetim raporu
│   │   ├── otomatik_sikilastirma.sh      # Otomatik üretilen Bash iyileştirme betiği
│   │   ├── ornek_guvenli_nftables.conf   # CIS uyumlu örnek kurumsal /etc/nftables.conf şablonu
│   │   ├── ornek_guvenli_ufw.sh          # CIS uyumlu örnek UFW yapılandırma betiği
│   │   └── komut_ve_cikis.txt            # CLI komutları ve terminal çıktıları
│   └── temsili/
│       └── firewall_mimarisi.txt         # Netfilter hook akışı ve filtreleme katmanları ASCII diyagramı
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

### 2. CLI ile Güvenlik Duvarı Envanterini Denetleme
```bash
python uygulama/firewall_security_cli.py audit -i ornek_veri/firewall_inventory_spec.json -o kanit/gercek/firewall_guvenlik_analiz_raporu.json
```

### 3. Otomatik Bash İyileştirme (Hardening) Betiği Üretme
```bash
python uygulama/firewall_security_cli.py remediate -i ornek_veri/firewall_inventory_spec.json -o kanit/gercek/otomatik_sikilastirma.sh
```

### 4. CIS 3.4 Uyumlu Güvenli nftables.conf Şablonu Oluşturma
```bash
python uygulama/firewall_security_cli.py nft-template -o kanit/gercek/ornek_guvenli_nftables.conf
```

### 5. CIS 3.5 Uyumlu UFW Sertleştirme Betiği Oluşturma
```bash
python uygulama/firewall_security_cli.py ufw-template -o kanit/gercek/ornek_guvenli_ufw.sh
```

### 6. Kanıt Üreticiyi Çalıştırma
```bash
python kanit_uretici.py
```

---

## 🔒 Güvenlik Standartları ve Kapsam

- **CWE-284 / MITRE ATT&CK T1562.004:** Güvenlik duvarının aktif ve kalıcı olması (`systemctl enable --now nftables` veya `ufw enable`).
- **CWE-284 / MITRE ATT&CK T1046:** Varsayılan Giriş (INPUT) politikasının `DROP`/`DENY` olması (CIS 3.4.3 & 3.5.2).
- **CWE-284:** Yönlendirme (FORWARD) politikasının `DROP` olması (CIS 3.4.3 & 3.5.2).
- **CWE-693 / MITRE ATT&CK T1059:** Durum denetimli (conntrack) filtreleme (`ct state established,related accept`, `ct state invalid drop`).
- **CWE-290 / MITRE ATT&CK T1584.004:** Loopback trafiğinin kabul edilmesi ve `127.0.0.0/8` anti-spoofing kuralının işletilmesi.
- **CWE-250 / MITRE ATT&CK T1046:** Telnet (23), SMB (445), RDP (3389) gibi tehlikeli portların açık olmasının engellenmesi.
- **CWE-778:** Düşürülen paketlerin loglanması (`ufw logging on` / nftables log prefix).
- **NIST SP 800-41 Rev. 1:** Kurumsal güvenlik duvarı mimarisi ve ilkeleri yönergeleri.

---

## Lisans

Bu projenin tüm hakları saklıdır.  
**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.  
Yalnızca GitHub üzerinde görüntüleme ve inceleme izni verilmiştir (kopyalamadan).  
Yazarın açık yazılı izni olmaksızın hiçbir ticari veya ticari olmayan projede kullanılamaz, kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya tersine mühendislik uygulanamaz.
