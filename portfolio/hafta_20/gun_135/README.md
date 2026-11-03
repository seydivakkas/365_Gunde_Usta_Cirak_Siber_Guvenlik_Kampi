# Gün 135: Linux PAM ve Oturum Politikası Güvenliği

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Category](https://img.shields.io/badge/category-Linux%20Security-blue?style=flat-square)

Bu çalışma; Linux işletim sistemlerinde Pluggable Authentication Modules (PAM) altyapısını, `/etc/pam.d/` ve `/etc/security/` yapılandırmalarını, hesap kilitleme (`pam_faillock`), parola karmaşıklığı (`pam_pwquality`), parola geçmişi (`pam_pwhistory`), boş parola engelleme (`nullok`), oturum zaman aşımı (`TMOUT`) ve dosya izinlerini denetleyen kurumsal seviyede bir güvenlik motoru ve CLI aracı sunar.

---

## 📁 Dizin Yapısı

```text
gun_135/
├── uygulama/
│   ├── __init__.py
│   ├── linux_pam_security_engine.py      # PAM ve oturum politikası denetim, puanlama ve iyileştirme motoru
│   └── pam_security_cli.py               # CLI denetim, raporlama ve Bash iyileştirme betiği üreticisi
├── tests/
│   ├── __init__.py
│   └── test_linux_pam_security.py        # 15 adet kapsamlı birim test
├── ornek_veri/
│   ├── pam_inventory_spec.json           # Örnek kurumsal Linux PAM ve oturum envanteri
│   └── invalid_pam_scenarios.json        # 9 adet negatif test senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt            # Birim test çalıştırma kanıtı (15/15 PASS)
│   │   ├── negatif_kontrol_sonuclari.txt # 9/9 negatif senaryo doğrulama çıktısı
│   │   ├── pam_guvenlik_analiz_raporu.json # JSON formatlı detaylı denetim raporu
│   │   ├── otomatik_sikilastirma.sh      # Otomatik üretilen Bash iyileştirme betiği
│   │   └── komut_ve_cikis.txt            # CLI komutları ve terminal çıktıları
│   └── temsili/
│       └── pam_mimarisi.txt              # PAM yığın mimarisi ve kontrol akışı ASCII diyagramı
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

### 2. CLI ile PAM Envanterini Denetleme
```bash
python uygulama/pam_security_cli.py audit -i ornek_veri/pam_inventory_spec.json -o kanit/gercek/pam_guvenlik_analiz_raporu.json
```

### 3. Otomatik Bash İyileştirme Betiği Üretme
```bash
python uygulama/pam_security_cli.py remediate -i ornek_veri/pam_inventory_spec.json -o kanit/gercek/otomatik_sikilastirma.sh
```

### 4. Kanıt Üreticiyi Çalıştırma
```bash
python kanit_uretici.py
```

---

## 🔒 Güvenlik Standartları ve Kapsam

- **CWE-307 / MITRE ATT&CK T1110.001:** Kaba kuvvet saldırılarına karşı `pam_faillock` hesap kilitleme mekanizması denetimi.
- **CWE-521 / MITRE ATT&CK T1201:** Zayıf parola politikalarına karşı `pam_pwquality` minimum uzunluk ve karakter sınıfı kontrolleri.
- **CWE-258 / MITRE ATT&CK T1078:** Boş parola ile sisteme giriş imkanı tanıyan `nullok` direktifi denetimi.
- **CWE-262 / MITRE ATT&CK T1201:** Parola geçmişi denetimi (`pam_pwhistory remember>=5`).
- **CWE-613 / MITRE ATT&CK T1078:** Başında kimse olmayan terminallerin istismarını önleyen `TMOUT` oturum zaman aşımı denetimi.
- **CWE-732 / MITRE ATT&CK T1548:** `/etc/pam.d/` ve `/etc/security/` dosyalarında yetkisiz yazma izinleri (`chmod 0644`, `chown root:root`).
- **CIS Linux Benchmark Section 5.4:** Kimlik doğrulama ve parola politikaları sertleştirme gereksinimleri.

---

## Lisans

Bu projenin tüm hakları saklıdır.  
**Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.  
Yalnızca GitHub üzerinde görüntüleme ve inceleme izni verilmiştir (kopyalamadan).  
Yazarın açık yazılı izni olmaksızın hiçbir ticari veya ticari olmayan projede kullanılamaz, kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya tersine mühendislik uygulanamaz.
