# GÜN 010: Linux Sanal Makinesine Güvenli Başlangıç (SSH Sertleştirmesi, Sudoers, Shadow İzinleri ve UFW Kalkanı)

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Durum](https://img.shields.io/badge/durum-PASS-brightgreen?style=flat-square)
![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 📖 Genel Bakış

Bu çalışma, Siber Güvenlik 365 Gün Müfredatının **2. Haftasının 3. günüdür (GÜN 010)**. Linux sanal makinelerinde (Debian, Ubuntu, Kali Linux) ilk kurulumdan itibaren güvenlik taban çizgisinin (Security Baseline) nasıl oluşturulacağını inceler.

Mücevher dükkanı kilit analojisiyle; **OpenSSH** sunucusunda parola kaba kuvvet saldırılarının engellenmesi (`PermitRootLogin no`, `PasswordAuthentication no`), `/etc/sudoers` dosyasındaki ölümcül **NOPASSWD** zafiyetlerinin önlenmesi, `/etc/shadow` ve `/etc/passwd` dosya izinlerinin kilitlenmesi, **umask 027** politikası ve **UFW** güvenlik duvarı ile varsayılan engelleme (`default deny incoming`) kuralları CIS Benchmark Seviye 1 standartlarında somutlaştırılmıştır.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_02/gun_010/
├── ders.md                          # 7 aşamalı "Usta-Çırak" masterclass dersi
├── soru_cevap.md                    # 4 katı alt başlıklı kavramsal soru-cevaplar (G010-SC1, SC2, SC3)
├── rapor.md                         # 20/40/25/15 puan tablosu ve denetim raporu
├── README.md                        # Kullanım kılavuzu ve proje özeti
├── sonuc.json                       # 14 alanlı standart makine-okunabilir durum
├── manifest.json                    # SHA-256 bütünlük özeti (küçük harf, / ayracı)
├── uygulama/
│   └── linux_baseline_auditor.py    # Zengin açıklamalı Linux Sertleştirme ve Denetim Motoru
├── tests/
│   └── test_linux_baseline_auditor.py # 13 birim test (pozitif/negatif kontroller)
├── ornek_veri/
│   ├── linux_vm_yapilandirmasi.json # Sertleştirilmiş ve güvensiz Linux sistem profilleri
│   ├── sshd_config_hardened         # Otomatik üretilen CIS Seviye 1 OpenSSH yapılandırması
│   └── sudoers_hardened             # Otomatik üretilen güvenli /etc/sudoers.d/ yapılandırması
└── kanit/
    ├── gercek/
    │   ├── komut_ve_cikis.txt       # CLI yürütme ve terminal stdout/stderr çıktısı
    │   └── test_sonuclari.txt       # 13/13 unittest başarı kaydı
    └── temsili/
        └── linux_guvenlik_mimarisi.txt # ASCII formatında Linux taban çizgisi ve yetki şeması
```

---

## 🚀 Çalıştırma Talimatları

### 1. Linux Taban Çizgisini Denetleme (CLI)
```bash
python portfolio/hafta_02/gun_010/uygulama/linux_baseline_auditor.py --profile portfolio/hafta_02/gun_010/ornek_veri/linux_vm_yapilandirmasi.json
```

Yalnızca sertleştirilmiş profili denetlemek ve güvenli `sshd_config` / `sudoers` dosyaları üretmek için:
```bash
python portfolio/hafta_02/gun_010/uygulama/linux_baseline_auditor.py --profile portfolio/hafta_02/gun_010/ornek_veri/linux_vm_yapilandirmasi.json --system-id LINUX-SEC-01 --generate-sshd portfolio/hafta_02/gun_010/ornek_veri/sshd_config_hardened --generate-sudoers portfolio/hafta_02/gun_010/ornek_veri/sudoers_hardened
```

JSON formatında makine çıktısı almak için:
```bash
python portfolio/hafta_02/gun_010/uygulama/linux_baseline_auditor.py --profile portfolio/hafta_02/gun_010/ornek_veri/linux_vm_yapilandirmasi.json --format json
```

### 2. Kapsamlı Birim Testleri Çalıştırma
```bash
python -m unittest portfolio/hafta_02/gun_010/tests/test_linux_baseline_auditor.py -v
```

---

## 🛡️ Lisans ve Kullanım Şartları

Bu proje ve ilgili tüm dosyalar **Seydi Eryılmaz (@seydivakkas)** adına tescilli olup tüm hakları saklıdır. Hiçbir açık kaynak lisansına (MIT, Apache, GPL vb.) tabi değildir. Ticari veya gayriticari olarak kopyalanamaz, paylaşılamaz, türetilemez.
