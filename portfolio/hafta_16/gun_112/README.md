# Hafta 16 / Gün 112: Mini Proje 15 — İmzalı Yapılandırma Konsepti (Signed Configuration Engine)

[![Lisans: Tüm Hakları Saklıdır](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg?style=flat-square)](https://www.python.org/)
[![Güvenlik: RFC 8785 JCS & RSA-SHA256](https://img.shields.io/badge/security-RFC_8785_JCS_%26_RSA--SHA256-green.svg?style=flat-square)](https://datatracker.ietf.org/doc/html/rfc8785)
[![Test Durumu: 15/15 PASS](https://img.shields.io/badge/tests-15%2F15_PASS-brightgreen.svg?style=flat-square)](tests/)
[![Puan: 100/100](https://img.shields.io/badge/score-100%2F100_YETERLİ-success.svg?style=flat-square)](rapor.md)

---

## 🔒 Lisans Bildirimi

```text
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

## 📌 Proje Genel Bakışı

Bu proje, dağıtık üretim sistemlerinde, Kubernetes cluster'larında, IoT ağlarında ve mikroservis mimarilerinde kritik yapılandırma parametrelerinin (örneğin veritabanı bağlantı adresleri, güvenlik duvarı kuralları, feature-flag'ler, şifreleme politikaları) yetkisiz manipülasyonunu, kurcalanmasını (tampering), sahteciliğini ve zaman aşımı/geri sarma (rollback) saldırılarını kriptografik olarak engelleyen **İmzalı Yapılandırma Motoru (Signed Configuration Concept Engine)** prototipidir.

Sistem, RFC 8785 JSON Canonicalization Scheme (JCS) deterministik serileştirme standardını, asimetrik RSA-SHA256 dijital imzalama mekanizmasını, monolitik ve dağıtık M-of-N çoklu onay (Dual/Multi-Signing) mimarisini, monontonik epoch kontrolüyle sürüm geri sarma (anti-rollback) savunmasını ve yerel güven deposu (Trust Store Pinning) teyidini %100 saf Python standart kütüphanesiyle sunar.

---

## 🛡️ Kapsanan Güvenlik Açıkları ve Savunma Standartları

| Zafiyet / Standart Kodu | Açıklama | Motordaki Savunma Mekanizması |
|---|---|---|
| **CWE-353** | Missing Support for Integrity Check (Bütünlük Kontrolü Eksikliği) | RFC 8785 JCS deterministik özet çıkarma ve RSA dijital imza doğrulaması |
| **CWE-347** | Improper Verification of Cryptographic Signature (Geçersiz İmza Doğrulama) | Yetkili kök anahtar ile kriptografik imza matematiksel kontrolü |
| **CWE-294** | Authentication Bypass by Capture-replay (Sürüm Geri Sarma / Rollback) | Monotonik artan `epoch_version` kontrolü; eski yapılandırmalar derhal reddedilir |
| **CWE-298** | Improper Validation of Certificate Expiration (Süresi Dolan Yapılandırma) | UTC tabanlı katı `expires_at` denetimi |
| **CWE-285** | Improper Authorization (Yetersiz Yetkilendirme / Çoklu Onay) | Kritik ortamlarda (PROD) M-of-N (ör. 2-of-2) eşik imza zorunluluğu |
| **CWE-327** | Use of a Broken or Risky Cryptographic Algorithm (Zayıf Algoritma) | Algoritma downgrade saldırılarına karşı yalnızca `RS256` zorunluluğu |
| **CWE-295** | Improper Certificate Validation (Bilinmeyen İmzalayıcı) | Trust Store içinde pinlenmemiş bilinmeyen imzalayıcı kimliklerinin engellenmesi |

---

## 📂 Dizin Yapısı

```
portfolio/hafta_16/gun_112/
├── ders.md                        # Usta-Çırak pedagojik ders anlatımı
├── soru_cevap.md                  # 3 derin teknik soru ve 4 zorunlu alt başlık
├── rapor.md                       # 100/100 PASS kalite ve denetim karne raporu
├── README.md                      # Bu dosya (kapsam, lisans, kurulum ve kullanım)
├── sonuc.json                     # Günlük standart puanlama ve başarı özeti
├── kanit_uretici.py               # Otomatik test ve kanıt koşturucu
├── manifest.json                  # SHA-256 dosya bütünlük listesi
├── uygulama/
│   ├── signed_config_engine.py    # Temel imzalı yapılandırma motoru (RFC 8785 + RSA)
│   └── signed_config_cli.py       # Yönetim ve doğrulama CLI arayüzü
├── tests/
│   ├── __init__.py
│   └── test_signed_config.py      # 15/15 PASS kapsamlı birim test paketi
├── ornek_veri/
│   ├── gecerli_yapilandirma.json  # Örnek geçerli ve imzalı yapılandırma zarfı
│   └── invalid_signed_config_inputs.json # 9 negatif kontrol test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt
    │   ├── negatif_kontrol_sonuclari.txt
    │   ├── imzali_yapilandirma_analiz_raporu.txt
    │   └── komut_ve_cikis.txt
    └── temsili/
        └── imzali_yapilandirma_mimarisi.txt
```

---

## 🚀 Hızlı Başlangıç ve Kullanım

### 1. Birim Testleri Çalıştırma
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

### 2. Gerçek Kanıtları Üretme
```powershell
python kanit_uretici.py
```

### 3. CLI Arayüzü ile İmzalı Yapılandırma Doğrulama
```powershell
python uygulama/signed_config_cli.py dogrula --zarf ornek_veri/gecerli_yapilandirma.json --mevcut-epoch 2 --guven-deposu ornek_veri/trust_store.json
```

---

## 📊 Kalite Güvencesi ve Test Sonuçları
- **Birim Testleri:** 15/15 PASS (%100 Başarı)
- **Negatif Kontroller:** 9/9 PASS (Tüm saldırı vektörleri engellendi)
- **Dış Bağımlılık:** Sıfır (Tamamen Python Standart Kütüphanesi)
- **Genel Not:** 100/100 (YETERLİ - MÜKEMMEL)
