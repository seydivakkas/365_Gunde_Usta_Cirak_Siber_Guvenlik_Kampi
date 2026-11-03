# Gün 137: Linux SSH Anahtar Güvenliği ve Sunucu Sertleştirmesi

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Category](https://img.shields.io/badge/category-Linux%20Security-blue?style=flat-square)

Bu çalışma; Linux işletim sistemlerinde Güvenli Kabuk (SSH) mimarisini, asimetrik anahtar algoritmalarını (Ed25519, RSA, DSA), özel ve açık anahtar dosya/dizin izinlerini (`0600`, `0700`), `authorized_keys` yetkilendirme kısıtlamalarını ve OpenSSH sunucu (`sshd_config`) yapılandırmasını CIS Linux Benchmark Section 5.2 standartlarına göre denetleyen kurumsal seviyede bir güvenlik motoru ve CLI yönetim aracı sunar.

---

## 📁 Dizin Yapısı

```text
gun_137/
├── uygulama/
│   ├── __init__.py
│   ├── linux_ssh_engine.py               # SSH anahtar denetim, kriptografik analiz ve sshd_config motoru
│   └── ssh_security_cli.py               # CLI denetim, raporlama, şablon ve Bash betiği üreticisi
├── tests/
│   ├── __init__.py
│   └── test_linux_ssh_security.py        # 15 adet kapsamlı birim test (100% PASS)
├── ornek_veri/
│   ├── ssh_inventory_spec.json           # Örnek kurumsal Linux SSH anahtar ve sunucu envanteri
│   └── invalid_ssh_scenarios.json        # 9 adet negatif sınır durum test senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt            # Birim test çalıştırma kanıtı (15/15 PASS)
│   │   ├── negatif_kontrol_sonuclari.txt # 9/9 negatif senaryo doğrulama çıktısı
│   │   ├── ssh_guvenlik_analiz_raporu.json # JSON formatlı detaylı denetim raporu
│   │   ├── otomatik_sikilastirma.sh      # Otomatik üretilen Bash iyileştirme betiği
│   │   ├── ornek_guvenli_sshd_config     # CIS uyumlu örnek güvenli OpenSSH sunucu şablonu
│   │   └── komut_ve_cikis.txt            # CLI komutları ve terminal çıktıları
│   └── temsili/
│       └── ssh_mimarisi.txt              # SSH kimlik doğrulama ve sunucu sertleştirme ASCII diyagramı
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

### 2. CLI ile SSH Envanterini Denetleme
```bash
python uygulama/ssh_security_cli.py audit -i ornek_veri/ssh_inventory_spec.json -o kanit/gercek/ssh_guvenlik_analiz_raporu.json
```

### 3. Otomatik Bash İyileştirme (Hardening) Betiği Üretme
```bash
python uygulama/ssh_security_cli.py remediate -i ornek_veri/ssh_inventory_spec.json -o kanit/gercek/otomatik_sikilastirma.sh
```

### 4. CIS Uyumlu Güvenli sshd_config Şablonu Oluşturma
```bash
python uygulama/ssh_security_cli.py sshd-config -o kanit/gercek/ornek_guvenli_sshd_config
```

### 5. Kanıt Üreticiyi Çalıştırma
```bash
python kanit_uretici.py
```

---

## 🔒 Güvenlik Standartları ve Kapsam

- **CWE-732 / MITRE ATT&CK T1552.004:** Özel anahtar (Private Key) dosya izinlerinin sıkılaştırılması (`chmod 0600`).
- **CWE-732 / MITRE ATT&CK T1098.004:** `authorized_keys` dosya izinlerinin korunması ve yetkisiz açık anahtar enjeksiyonunun engellenmesi.
- **CWE-327 / CWE-326:** Kırılmış 1024-bit DSA ve zayıf RSA anahtarlarının tespiti, modern Ed25519 geçişinin zorunlu kılınması.
- **CWE-250 / MITRE ATT&CK T1078.003:** Doğrudan root girişinin yasaklanması (`PermitRootLogin no` - CIS 5.2.5).
- **CWE-307 / MITRE ATT&CK T1110.001:** Parola kimlik doğrulamasının kapatılması (`PasswordAuthentication no` - CIS 5.2.9) ve kaba kuvvet sınırlandırılması (`MaxAuthTries 3` - CIS 5.2.7).
- **CWE-258 / MITRE ATT&CK T1078:** Boş şifreli hesapların engellenmesi (`PermitEmptyPasswords no` - CIS 5.2.11).
- **CWE-613:** Hareketsiz SSH oturum zaman aşımı (`ClientAliveInterval 300` - CIS 5.2.16).
- **NIST SP 800-131A & NIST SP 800-123:** Kriptografik anahtar yönetimi ve genel sunucu güvenliği yönergeleri.

---

## Lisans

Bu projenin tüm hakları saklıdır.  
**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.  
Yalnızca GitHub üzerinde görüntüleme ve inceleme izni verilmiştir (kopyalamadan).  
Yazarın açık yazılı izni olmaksızın hiçbir ticari veya ticari olmayan projede kullanılamaz, kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya tersine mühendislik uygulanamaz.
