# Gün 149: Uygulama İzinleri ve Sandbox Güvenlik Mimarisi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](#lisans)
[![Test Durumu](https://img.shields.io/badge/tests-15%2F15%20PASS-brightgreen?style=flat-square)](kanit/gercek/test_sonuclari.txt)
[![Negatif Kontrol](https://img.shields.io/badge/negatif%20kontrol-9%2F9%20PASS-brightgreen?style=flat-square)](kanit/gercek/negatif_kontrol_sonuclari.txt)
[![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)](rapor.md)

---

## 📖 Genel Bakış

Bu modül, **365 Günlük Siber Güvenlik Usta-Çırak Kampı** kapsamında, modern işletim sistemlerinde (Linux ve Windows) çalışan uygulamaların en az ayrıcalık (Least Privilege) ve kum havuzu (Sandbox) prensiplerine göre izole edilmesini inceleyen kapsamlı bir mühendislik çalışmasıdır.

Modül kapsamında; Linux çekirdeğinin sunduğu **Seccomp-BPF sistem çağrısı filtrelemesi**, **Linux Yetenekleri (Capabilities)**, **Ad Alanları (Namespaces)**, **cgroups v2** kaynak sınırlandırmaları, **VFS salt-okunur dosya sistemi izolasyonu** ile Windows tarafında **Zorunlu Bütünlük Kontrolü (Mandatory Integrity Control - MIC)** ve **AppContainer** mimarileri modellenmiş, denetlenmiş ve doğrulanmıştır.

---

## 🏛️ Mimari ve Dizin Yapısı

```
portfolio/hafta_22/gun_149/
├── ders.md                              # Usta-Çırak derinlemesine teknik eğitim notları
├── soru_cevap.md                        # 3 kapsamlı senaryo ve soru-cevap analizi
├── rapor.md                             # 100/100 PASS başarı karnesi ve denetim raporu
├── README.md                            # Proje tanıtımı ve lisans beyanı
├── sonuc.json                           # Yapılandırılmış sonuç özeti
├── manifest.json                        # SHA-256 dosya bütünlük doğrulaması
├── kanit_uretici.py                     # Kanıtları üreten otomasyon betiği
├── uygulama/                            # Üretim seviyesi motor ve CLI aracı
│   ├── __init__.py
│   ├── app_sandbox_engine.py            # Sandbox güvenlik ve simülasyon motoru
│   └── app_sandbox_cli.py               # Komut satırı yönetim ve test aracı
├── tests/                               # 15 birim testi
│   ├── __init__.py
│   └── test_app_sandbox.py
├── ornek_veri/                          # Test ve profil verileri
│   ├── clean_sandbox_specs.json         # Sertleştirilmiş temiz sandbox profili
│   └── invalid_sandbox_scenarios.json   # 9 negatif kontrol ve kaçış senaryosu
└── kanit/                               # Gerçek ve temsili kanıt belgeleri
    ├── gercek/
    │   ├── test_sonuclari.txt           # 15/15 birim test çıktısı
    │   ├── negatif_kontrol_sonuclari.txt# 9/9 negatif senaryo tespit çıktısı
    │   ├── app_sandbox_audit_report.json# CIS/NIST güvenlik denetim raporu
    │   ├── oci_seccomp_profile.json     # OCI standart Seccomp-BPF profili
    │   ├── app_sandbox_remediation.ps1  # Windows AppContainer sertleştirme betiği
    │   └── komut_ve_cikis.txt           # CLI konsol günlüğü
    └── temsili/
        └── sandbox_mimarisi.txt         # ASCII formatında temsili mimari şeması
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Çalıştırma
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

### 2. Sandbox Profilini Güvenlik Denetiminden Geçirme
```bash
python uygulama/app_sandbox_cli.py audit --config ornek_veri/clean_sandbox_specs.json
```

### 3. İşlem Simülasyonu Koşturma
```bash
# ptrace sistem çağrısı denemesi (Engellenmeli)
python uygulama/app_sandbox_cli.py simulate --config ornek_veri/clean_sandbox_specs.json --action syscall --target ptrace

# Salt-okunur kök sisteme yazma denemesi (Engellenmeli)
python uygulama/app_sandbox_cli.py simulate --config ornek_veri/clean_sandbox_specs.json --action filesystem --target /etc/shadow --fs-mode read
```

### 4. OCI Seccomp JSON Profili Üretme
```bash
python uygulama/app_sandbox_cli.py export-oci --config ornek_veri/clean_sandbox_specs.json --output seccomp_hardened.json
```

---

## 🔒 Lisans

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
