# G040 — Güvenli Uzaktan Yönetim Başlangıcı

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](#lisans)
[![Test Durumu](https://img.shields.io/badge/tests-14%20passed-brightgreen?style=flat-square)](#testler)
[![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)](#değerlendirme)

Bu modül, **365 Günlük Siber Güvenlik Müfredatı** kapsamında Hafta 06 / Gün 040 için hazırlanmış **"Güvenli Uzaktan Yönetim Başlangıcı"** laboratuvar çalışmasını ve otomasyon motorunu içermektedir.

---

## 🎯 Hedefler ve Kapsam
1. **Uzaktan Yönetim Protokollerinin Güvenliği:** SSH, RDP, WinRM ve Telnet servislerinin güvenlik açıklarının ve sıkılaştırma adımlarının incelenmesi.
2. **Üçlü Güvenlik Sacayağı:** Kimlik doğrulama (Ed25519, MFA, NLA), Ağ Sınırı (Bastion Host, VLAN, CIDR kısıtlama) ve Günlükleme (merkezi Syslog, Event Log).
3. **Erişim Matrisi Denetim Motoru:** Girdi doğrulama, sınır kontrolleri, negatif test senaryoları ve risk puanlaması yapan `secure_remote_management_auditor.py` uygulaması.
4. **Savunma Stratejileri:** En az ayrıcalık, geri alınabilir yapılandırma (rollback), atlatma sunucusu (Bastion) mimarisi.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_06/gun_040/
├── README.md                                         # Modül tanıtım ve hızlı başlangıç rehberi
├── ders.md                                           # Usta-Çırak pedagojisiyle teorik ders anlatımı
├── soru_cevap.md                                     # G040-SC1, SC2, SC3 soruları ve detaylı çözümler
├── rapor.md                                          # 100/100 değerlendirme ve rubrik raporu
├── sonuc.json                                        # Standartlaştırılmış makine tarafından okunabilir sonuç dosyası
├── manifest.json                                     # Dosya SHA256 bütünlük imzaları
├── uygulama/
│   ├── __init__.py                                   # Python paket tanımı
│   └── secure_remote_management_auditor.py           # Uzaktan yönetim matrisi denetim ve risk analiz motoru
├── tests/
│   ├── __init__.py                                   # Python test paketi tanımı
│   └── test_secure_remote_management_auditor.py      # 14 adet birim ve negatif test içeren test süiti
├── ornek_veri/
│   ├── sample_remote_access_matrix.json              # Örnek geçerli ve hatalı servis matrisi
│   └── corrupted_remote_access_matrix_test_cases.json # Negatif kontrol test girdileri
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                        # Unittest çalıştırma çıktısı (14/14 PASS)
    │   ├── komut_ve_cikis.txt                        # Terminal yürütme kaydı
    │   ├── uzaktan_yonetim_denetim_raporu.txt        # Denetim motoru tarafından üretilen rapor
    │   └── negatif_kontrol_sonuclari.txt             # Negatif testlerin doğrulama günlüğü
    └── temsili/
        └── guvenli_uzaktan_yonetim_mimarisi.txt      # Bastion ve ağ sınırı mimari diyagramı
```

---

## 🚀 Hızlı Başlangıç

### 1. Denetim Motorunu Çalıştırma
```powershell
python portfolio/hafta_06/gun_040/uygulama/secure_remote_management_auditor.py --matrix portfolio/hafta_06/gun_040/ornek_veri/sample_remote_access_matrix.json
```

### 2. Raporu Dosyaya Kaydetme
```powershell
python portfolio/hafta_06/gun_040/uygulama/secure_remote_management_auditor.py --matrix portfolio/hafta_06/gun_040/ornek_veri/sample_remote_access_matrix.json --output portfolio/hafta_06/gun_040/kanit/gercek/uzaktan_yonetim_denetim_raporu.txt
```

---

## 🧪 Testler

Test süiti 14 adet kapsamlı birim ve negatif test senaryosunu içerir:
- Geçerli SSH yapılandırması uyumluluk doğrulaması
- Güvensiz Telnet protokolü tespiti ve kritik ceza puanı
- İnternete doğrudan açık RDP ve NLA eksikliği denetimi
- Negatif port (-1), sıfır port (0) ve port aşımı (65536) sınır kontrolleri
- Eksik anahtar ve bozuk tip kontrolleri

Testleri çalıştırmak için:
```powershell
python -m unittest discover -s portfolio/hafta_06/gun_040/tests -v
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
