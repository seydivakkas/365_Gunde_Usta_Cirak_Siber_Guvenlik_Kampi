# Gün 140: Mini Proje 19 — Bütünleşik Linux Sertleştirme ve Denetim Çerçevesi

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Tests: 15 Passed](https://img.shields.io/badge/tests-15%20passed-brightgreen?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/score-100%2F100-success?style=flat-square)
![Platform: Pure Python 3](https://img.shields.io/badge/platform-Python%203-blue?style=flat-square)

## Genel Bakış

Bu proje, **Hafta 20 (Linux Güvenliği ve Sertleştirme)** modülünün kapanış projesidir (Mini Proje 19). Hafta boyunca incelenen tüm kritik Linux güvenlik bileşenlerini (Sudo Ayrıcalık Devri, PAM ve Oturum Güvenliği, Systemd Servis İzolasyonu, SSH Anahtar ve Daemon Güvenliği, Netfilter/nftables Güvenlik Duvarı, Auditd ve Journald Kurcalanamaz Günlükleme) bütünleşik bir **Linux Sertleştirme ve Denetim Çerçevesi (Linux Hardening Compliance & Audit Framework)** altında birleştirir.

Geliştirilen denetim motoru (`linux_hardening_audit_engine.py`) ve CLI yönetim aracı (`hardening_audit_cli.py`), hedef sistemlerin güvenlik durumunu CIS Linux Benchmark v2.0.0 standartlarında değerlendirir, 100 üzerinden ağırlıklı uyumluluk notu verir ve tespit edilen açıkları otomatik olarak onaran üretim düzeyinde bir Bash sıkılaştırma betiği (`otomatik_sikilastirma.sh`) üretir.

---

## Dizin Yapısı

```
portfolio/hafta_20/gun_140/
├── README.md                              # Proje özeti, kullanım kılavuzu ve lisans
├── ders.md                                # Usta-Çırak pedagojisi ile kapsamlı kapanış dersi
├── soru_cevap.md                          # 4 alt başlıklı 3 kapsamlı derinleşme sorusu ve cevabı
├── rapor.md                               # 100/100 tam puanlı başarı karnesi ve metrikler
├── sonuc.json                             # Makine tarafından okunabilir sonuç özeti
├── manifest.json                          # Dizin dosya bütünlüğü ve SHA-256 sağlama toplamları
├── kanit_uretici.py                       # Testleri koşturan ve kanıtları üreten otomasyon aracı
├── uygulama/
│   ├── __init__.py                        # Paket başlatıcı
│   ├── linux_hardening_audit_engine.py    # 6 Domainli Bütünleşik Denetim ve Sıkılaştırma Motoru
│   └── hardening_audit_cli.py             # CLI yönetim arayüzü (audit, verify, generate-remediation)
├── tests/
│   ├── __init__.py                        # Test paketi başlatıcı
│   └── test_linux_hardening_audit.py      # 15 birim testi içeren test paketi (100% PASS)
├── ornek_veri/
│   ├── enterprise_linux_audit_inventory.json # CIS uyumlu referans kurumsal envanter
│   └── invalid_hardening_scenarios.json   # 9 adet negatif zafiyet senaryosu (100% yakalama)
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt             # 15 birim testinin çalışma logları
    │   ├── negatif_kontrol_sonuclari.txt  # 9 negatif senaryonun yakalanma logları
    │   ├── linux_hardening_analiz_raporu.json # JSON formatında konsolide denetim raporu
    │   ├── otomatik_sikilastirma.sh       # Üretilen otomatik Bash onarım betiği
    │   ├── komut_ve_cikis.txt             # CLI yürütme günlükleri
    │   ├── cis_linux_hardening_matrix.json# CIS Benchmark kural haritası
    │   └── hardening_quick_reference.txt  # 6 güvenlik alanı hızlı başvuru kartı
    └── temsili/
        └── hardening_mimarisi.txt         # ASCII sistem mimarisi diyagramı
```

---

## 6 Temel Güvenlik Alanı (Scope)

1. **Sudo ve Ayrıcalık Devri (CIS 1.3 / 5.3):** Sudoers izinleri (0440), `env_reset`, `secure_path`, GTFOBins kabuk komutlarına (`/bin/bash`, `vim`, `find`) parolasız yetki engeli.
2. **PAM ve Oturum Disiplini (CIS 5.4 / 5.5):** Parola minimum uzunluğu (>= 14), 4 sınıf karakter çeşitliliği, `pam_faillock` (deny <= 5, unlock_time >= 900s), `TMOUT <= 900s`.
3. **Systemd Servis İzolasyonu (CIS 2.1 / 2.2):** Yasaklanmış servislerin engellenmesi (`telnet`, `vsftpd`), `NoNewPrivileges=yes` (PR_SET_NO_NEW_PRIVS), `ProtectSystem=strict`, `PrivateTmp=yes`.
4. **SSH ve Kriptografi Güvenliği (CIS 5.2):** `PermitRootLogin no`, `PasswordAuthentication no`, `MaxAuthTries <= 4`, özel anahtar dosya izinleri (`0600`).
5. **Güvenlik Duvarı ve Ağ Süzgeci (CIS 3.4 / 3.5):** nftables/UFW durumu, varsayılan `DROP` politikası, durumlu conntrack, açık tehlikeli port kontrolü.
6. **Adli Bütünlük ve Denetim (CIS 4.1 / 4.2):** `auditd -e 2` değiştirilemezlik modu, kritik dosya/syscall izleme, `systemd-journald` Forward Secure Sealing (FSS).

---

## Hızlı Başlangıç

### 1. Testleri ve Kanıt Üreticisini Çalıştırma
```powershell
python kanit_uretici.py
```

### 2. CLI ile Denetim Gerçekleştirme
```powershell
# Envanter dosyasını denetle
python uygulama/hardening_audit_cli.py audit ornek_veri/enterprise_linux_audit_inventory.json

# Uyumluluk durumunu hızlıca doğrula (Exit code 0 veya 1)
python uygulama/hardening_audit_cli.py verify ornek_veri/enterprise_linux_audit_inventory.json

# Otomatik sıkılaştırma betiği üret
python uygulama/hardening_audit_cli.py generate-remediation ornek_veri/enterprise_linux_audit_inventory.json --output kanit/gercek/otomatik_sikilastirma.sh
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
