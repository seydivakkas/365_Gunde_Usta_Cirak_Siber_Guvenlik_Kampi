# Gün 125: Mini Proje 17 — Güvenli Kimlik ve Rol Prototipi (Capstone)

![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Security Score](https://img.shields.io/badge/Security_Score-100%2F100-brightgreen?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-15%20Passed-success?style=flat-square)
![Negative Controls](https://img.shields.io/badge/Negative_Controls-9%2F9%20Passed-success?style=flat-square)

Bu proje, **365 Günlük Siber Güvenlik Müfredatı** bünyesindeki **Hafta 18 (Güvenlik Mimarisi ve Tasarım Prensipleri)** modülünün bitirme projesidir (Capstone). Tehdit modelleme (STRIDE), risk skorlama, savunma derinliği (Defense-in-Depth), güvenli varsayılanlar (Default-Deny), arıza anında güvenli kalma (Fail-Secure) ve sırlar yönetiminin tüm kuramsal ilkelerini kurumsal düzeyde çalışan tek bir prototip motorda sentezler.

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

## 🌟 Öne Çıkan Mimari Özellikler

1. **Güçlü Kimlik Doğrulama (PBKDF2-HMAC-SHA256):** 100.000 iterasyon, 16-byte kriptografik tuz, `hmac.compare_digest` ile sabit zamanlı doğrulama (CWE-208 / CWE-521).
2. **Kaba Kuvvet Koruması:** 5 ardışık başarısız girişte otomatik hesap kilitleme (`AccountLockedError` - CWE-307).
3. **Kısa Ömürlü Oturum Belirteçleri (TTL):** Kriptografik 32-byte urlsafe token'lar, süre aşımı denetimi (`SessionExpiredError` - CWE-613).
4. **Hiyerarşik RBAC:** Yönlü Asiklik Graf (DAG) tabanlı izin kalıtımı ve döngü engelleme (`CircularRoleHierarchyError` - CWE-674).
5. **Statik Görevler Ayrılığı (Static SoD):** Hazırlayıcı ve onaylayıcı (Maker-Checker) çatışan rol kombinasyonlarının engellenmesi (`SeparationOfDutyConflictError` - CWE-863).
6. **Step-Up Çok Faktörlü Doğrulama (MFA):** Kritik operasyonlarda zorunlu 2FA denetimi (CWE-308).
7. **Saltzer-Schroeder Fail-Secure / Default-Deny:** Tanımsız izinlerin reddi ve altyapı çöküşlerinde kapıların otomatik kilitlenmesi (CWE-636).
8. **Denetim Günlüğü Maskelemesi:** Kütüklerde parolaların ve token'ların dinamik sansürlenmesi (CWE-532).

---

## 📁 Proje Dizin Yapısı

```
gun_125/
├── uygulama/
│   ├── __init__.py
│   ├── secure_identity_role_engine.py  # Çekirdek kimlik ve rol güvenlik motoru
│   └── identity_cli.py                 # Komut satırı yönetim aracı
├── tests/
│   ├── __init__.py
│   └── test_secure_identity_role.py    # 15 Birim test (100% PASS)
├── ornek_veri/
│   ├── identity_prototype_config.json  # Kurumsal rol, kural ve kullanıcı yapılandırması
│   └── invalid_identity_scenarios.json # 9 Negatif hata enjeksiyon senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt          # Birim test koşu kanıtı
│   │   ├── negatif_kontrol_sonuclari.txt # 9 Negatif senaryo kanıtı
│   │   ├── kimlik_rol_analiz_raporu.json # JSON mimari denetim raporu
│   │   └── komut_ve_cikis.txt          # CLI etkileşim kanıtı
│   └── temsili/
│       └── identity_mimarisi.txt       # Zorunlu banner'lı ASCII mimari şeması
├── ders.md                             # Usta-Çırak Capstone ders anlatımı
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
python -m unittest tests/test_secure_identity_role.py
```

### 2. Tüm Kanıtları Otomatik Üretme
```bash
python kanit_uretici.py
```

### 3. CLI Yönetim Aracını Kullanma
```bash
# Mimari raporu alma
python uygulama/identity_cli.py report ornek_veri/identity_prototype_config.json

# Kimlik doğrulama
python uygulama/identity_cli.py auth ornek_veri/identity_prototype_config.json --username denetci_merve --password MerveStrongPassword2026!#

# Yetkilendirme talebi (Default-Deny denetimi)
python uygulama/identity_cli.py authorize ornek_veri/identity_prototype_config.json --username denetci_merve --password MerveStrongPassword2026!# --resource-id system --action reboot
```
