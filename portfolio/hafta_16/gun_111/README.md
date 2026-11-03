# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 111: Anahtar Yönetimi ve Rotasyon (Key Management and Rotation)

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Durum](https://img.shields.io/badge/durum-TAMAMLANDI%20(PASS)-brightgreen?style=flat-square)
![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)
![Standartlar](https://img.shields.io/badge/standartlar-NIST%20SP%20800--57%20%7C%20FIPS%20140--3-orange?style=flat-square)

---

## Genel Bakış

Bu çalışma; NIST SP 800-57 standartlarına tam uyumlu olarak kriptografik anahtarların yaşam döngüsü yönetimini, Zarf Şifreleme (Envelope Encryption - KEK vs DEK) mimarisini, devasa verileri kopyalamadan saniyeler içinde anahtar rotasyonu sağlayan Re-wrapping prensibini, Çift Kontrol (Dual Control / Split Knowledge) sistemini ve Kriptografik Sıfırlamayı (Zeroization / Crypto-Shredding) inceleyen bağımsız bir güvenlik mühendisliği paketidir.

Tamamen harici bağımlılıksız (Pure Python) olarak geliştirilmiştir.

---

## Zarf Şifreleme ve Yaşam Döngüsü Mimarisi

```
  [ HSM / KMS Güvenli Bellek ]
  +-------------------------------------------------------+
  | KEK (Master Anahtar: 256-bit AES)                    |
  +-------------------------------------------------------+
                |
     (Key Wrapping / AEAD)
                v
       [ Wrapped DEK + Tag ]
                |
  [ Veri ]      +-----------------------------------------+
  +----------------------------------------------------+  |
  | DEK (Geçici Veri Anahtarı: 256-bit AES)            |  |
  +----------------------------------------------------+  |
                | (Hızlı Şifreleme)                       |
                v                                         v
       +---------------------------------------------------------------+
       | ZARF PAKETİ = [ Wrapped DEK ] + [ Şifreli Veri (Petabayt) ]    |
       +---------------------------------------------------------------+
       (Re-wrapping ile O(1) sürede devasa veri taşınmadan rotasyon!)
```

---

## Proje Dizin Yapısı

```
portfolio/hafta_16/gun_111/
├── README.md                           # Proje genel tanıtım ve kullanım kılavuzu
├── ders.md                             # Usta-Çırak derinlemesine teknik ders anlatımı
├── soru_cevap.md                       # 4 alt başlıklı 3 kapsamlı mülakat ve teknik soru
├── rapor.md                            # 100/100 tam puanlı teknik değerlendirme karnesi
├── sonuc.json                          # Makine tarafından okunabilir sonuç özeti
├── kanit_uretici.py                    # Birim testleri, negatif senaryoları ve kanıtları üreten betik
├── uygulama/
│   ├── __init__.py                     # Paket tanımlayıcısı
│   ├── key_management_engine.py        # KMS, Zarf Şifreleme, Re-wrapping ve Zeroization motoru
│   └── keymgmt_cli.py                  # Anahtar yönetimi ve rotasyon CLI aracı
├── tests/
│   ├── __init__.py                     # Test paketi tanımlayıcısı
│   └── test_key_management.py          # 15 kapsamlı birim testi (15/15 PASS)
├── ornek_veri/
│   ├── key_management_config_sample.json # Örnek NIST SP 800-57 yapılandırması
│   └── invalid_keymgmt_inputs.json     # 9 adet negatif güvenlik kontrol senaryosu
└── kanit/
    ├── gercek/                         # Gerçek yerel yürütme kanıtları
    │   ├── test_sonuclari.txt          # 15 birim test çalıştırma günlüğü
    │   ├── negatif_kontrol_sonuclari.txt # 9 negatif kontrol engelleme günlüğü
    │   ├── komut_ve_cikis.txt          # CLI yürütme çıktısı
    │   └── anahtar_yonetimi_analiz_raporu.txt # Güvenlik analiz raporu
    └── temsili/
        └── anahtar_yonetimi_mimarisi.txt # Etiketli ASCII mimari diyagramı
```

---

## Kurulum ve Çalıştırma

Harici hiçbir bağımlılık gerekmez (Pure Python):

```bash
# 1. Anahtar yaşam döngüsü ve zarf şifreleme simülasyonunu çalıştırma:
python uygulama/keymgmt_cli.py

# 2. JSON formatında çıktı alma:
python uygulama/keymgmt_cli.py --json

# 3. Birim testleri yürütme (15 Test):
python -m unittest tests/test_key_management.py

# 4. Tüm kanıtları otomatik üretme ve doğrulama:
python kanit_uretici.py
```

---

## Kapsanan Güvenlik Zafiyetleri (CWE Savunmaları)

- **CWE-320:** Kriptoperiyodu dolmuş veya sızmış (COMPROMISED) anahtarlarla işlem engellendi; DEPRECATED anahtarların yeni şifreleme yapması yasaklandı.
- **CWE-326:** 128 bit altındaki yetersiz simetrik anahtarlar engellendi (256-bit AES standardı uygulandı).
- **CWE-329:** Aynı anahtarla yapılabilecek azami işlem sınırı getirilerek Nonce tükenmesi/çarpışması önlendi.
- **CWE-353:** Zarf şifreleme yüklerinde DEK bütünlüğü AEAD kimlik doğrulama etiketiyle sağlandı.
- **CWE-226:** 3 geçişli Kriptografik Sıfırlama (Zeroization) ile RAM ve disk artık veri (remanence) sızıntıları önlendi.
- **CWE-321:** Sabit, sıfırlardan oluşan veya tahmin edilebilir sabit anahtarlar engellendi.
