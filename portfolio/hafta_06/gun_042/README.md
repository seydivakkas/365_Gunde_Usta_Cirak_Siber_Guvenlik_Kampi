# G042 — Aşama 2 Kalite Özeti ve Kapanışı: İşletim Sistemi Temelleri

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](#lisans)
[![Test Durumu](https://img.shields.io/badge/tests-14%20passed-brightgreen?style=flat-square)](#testler)
[![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)](#değerlendirme)
[![Aşama 2 Durumu](https://img.shields.io/badge/A%C5%9Fama%2002-STAGE__02__PASS-success?style=flat-square)](#aşama-2-kapanışı)

Bu modül, **365 Günlük Siber Güvenlik Müfredatı** kapsamında Hafta 06 / Gün 042 için hazırlanmış **"Aşama 2 Kalite Özeti ve Kapanışı"** laboratuvar çalışmasını ve kabul motorunu içermektedir. Bu gün ile birlikte **Aşama 02 (İşletim Sistemi Temelleri - Gün 29-42)** resmi olarak tamamlanmıştır.

---

## 🎯 Hedefler ve 6 Temel Kabul Sütunu
1. **Süreç Hijyeni:** Unprivileged arka plan servisleri, kum havuzlama ve sıfır yetkisiz süreç.
2. **Dosya İzinleri ve Umask:** 0027 umask zorlaması, `/etc/shadow` (0640), `/etc/sudoers` (0440) ve hassas dosya yetkileri.
3. **Olay Günlükleme:** `systemd-journald` kalıcılığı, `auditd` çekirdek takibi ve merkezi SIEM TLS aktarımı.
4. **Bütünlük Karmaları:** Kritik ikililer için SHA-256 taban çizgisi ve değişiklik algılama.
5. **Yedekleme Stratejisi:** 3-2-1 kuralı, değişmez depolama ve başarılı geri yükleme tatbikatı.
6. **Servis Hardening:** Miras servis yasağı (telnet, rsh vb.) ve parola engelli SSH anahtar zorunluluğu.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_06/gun_042/
├── README.md                                         # Modül tanıtım ve kullanım rehberi
├── ders.md                                           # Usta-Çırak pedagojisiyle teorik aşama kapanış dersi
├── soru_cevap.md                                     # G042-SC1..SC3, W06-SC1..SC3, A02-KALİTE soru ve çözümleri
├── rapor.md                                          # 100/100 değerlendirme ve Aşama 2 kapanış raporu
├── sonuc.json                                        # Standartlaştırılmış sonuç dosyası
├── manifest.json                                     # Dosya SHA256 bütünlük imzaları
├── uygulama/
│   ├── __init__.py                                   # Python paket tanımı
│   └── stage2_os_foundations_auditor.py              # 6 sütunlu kabul motoru ve denetim aracı
├── tests/
│   ├── __init__.py                                   # Python test paketi tanımı
│   └── test_stage2_os_foundations_auditor.py         # 14 adet birim ve negatif test içeren test süiti
├── ornek_veri/
│   ├── stage2_acceptance_inventory.json              # 6 sütunlu referans kabul envanteri
│   └── corrupted_stage2_cases.json                   # Negatif kontrol test senaryoları
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                        # Unittest çıktısı (14/14 PASS)
    │   ├── komut_ve_cikis.txt                        # Terminal yürütme kaydı
    │   ├── stage2_kalite_kabul_raporu.txt            # Aşama 2 kabul raporu (STAGE_02_PASS)
    │   └── negatif_kontrol_sonuclari.txt             # Negatif testlerin doğrulama günlüğü
    └── temsili/
        └── stage2_os_temelleri_mimarisi.txt          # 6 sütunlu kabul mimarisi şeması
```

---

## 🚀 Hızlı Başlangıç

### 1. Aşama 2 Kabul Motorunu Çalıştırma
```powershell
python portfolio/hafta_06/gun_042/uygulama/stage2_os_foundations_auditor.py --inventory portfolio/hafta_06/gun_042/ornek_veri/stage2_acceptance_inventory.json
```

### 2. Raporu Dosyaya Kaydetme
```powershell
python portfolio/hafta_06/gun_042/uygulama/stage2_os_foundations_auditor.py --inventory portfolio/hafta_06/gun_042/ornek_veri/stage2_acceptance_inventory.json --output portfolio/hafta_06/gun_042/kanit/gercek/stage2_kalite_kabul_raporu.txt
```

---

## 🧪 Testler

Test süiti 14 adet birim ve negatif kontrol testini içerir:
- Envanter şema doğrulaması
- 6 sütunun temiz durum testleri (processes, permissions, logging, hashes, backups, services)
- Genel STAGE_02_PASS kabul kararı testi
- Markdown rapor biçim denetimi
- Negatif Kontroller: Eksik sütun, hatalı sekizli izin, bozuk SHA-256, negatif PID, bozuk JSON.

Testleri çalıştırmak için:
```powershell
python -m unittest discover -s portfolio/hafta_06/gun_042/tests -v
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
