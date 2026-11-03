# GÜN 102: SALT, PEPPER VE KDF TABANLI GÜVENLİ PAROLA SAKLAMA
![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status: 100/100 PASS](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Stage: 05 Kriptografi Temelleri](https://img.shields.io/badge/stage-05%20Kriptografi%20Temelleri-blue?style=flat-square)

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

## 📖 GENEL BAKIŞ
Bu modül; kurumsal seviyede güvenli parola saklama, anahtar türetme fonksiyonları (KDF), kriptografik tuz (salt), donanımsal/izole biber (pepper) ve sabit zamanlı doğrulama mimarisini sunar. NIST SP 800-132 ve OWASP ilkeleri temel alınarak geliştirilmiştir.

### Temel Özellikler
1. **PBKDF2-HMAC-SHA256 Anahtar Türetimi:** Minimum 100.000 iterasyon ile GPU tabanlı çevrimdışı kaba kuvvet saldırılarına karşı yüksek işlem gücü direnci (`CWE-916`).
2. **Kriptografik Rastgele Tuz (Salt):** `secrets.token_bytes(16)` ile üretilen 128-bit eşsiz tuz ile gökkuşağı tablolarının (Rainbow Tables) tamamen imkansız kılınması (`CWE-759`, `CWE-760`).
3. **İzole Sistem Biberi (Pepper):** Veritabanı dışında (HSM/KMS) saklanan gizli sistem biberi ile veritabanı sızıntısı durumunda çevrimdışı sözlük saldırılarına karşı tam koruma.
4. **Sabit Zamanlı Doğrulama:** `hmac.compare_digest` ile zamanlama saldırılarına (Timing Attacks) karşı tam bağışıklık (`CWE-208`).
5. **Eski Hash Tespiti:** Tuzsuz MD5, SHA-1 ve düz SHA-256 hashlerinin otomatik tespiti ve risk analizi.

---

## 📂 DİZİN YAPISI

```
gun_102/
├── README.md                      # Modül tanıtımı ve özel lisans
├── ders.md                        # Usta-çırak ders anlatımı
├── soru_cevap.md                  # 4 alt başlıklı 3 derin soru-cevap
├── rapor.md                       # 100/100 değerlendirme karnesi
├── sonuc.json                     # Otomasyon sonuç özeti
├── kanit_uretici.py               # Otomatik test ve kanıt üretici betik
├── uygulama/
│   ├── __init__.py
│   ├── secure_password_vault.py   # Çekirdek parola saklama motoru
│   └── vault_cli.py               # Komut satırı arayüzü
├── tests/
│   ├── __init__.py
│   └── test_secure_password_vault.py # 15 birim test paketi
├── ornek_veri/
│   ├── password_store_samples.json   # Örnek kullanıcı ve hash kayıtları
│   └── invalid_password_inputs.json  # 9 negatif kontrol test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt
    │   ├── negatif_kontrol_sonuclari.txt
    │   ├── parola_guvenlik_analiz_raporu.txt
    │   └── komut_ve_cikis.txt
    └── temsili/
        └── parola_saklama_mimarisi.txt # ASCII mimari şeması
```

---

## 🚀 KULLANIM TALİMATLARI

### 1. Parola Hashleme (Salt + Pepper + 100.000 İterasyon)
```bash
python uygulama/vault_cli.py --hash --password "GizliParola2026!" --pepper "HSM_KMS_BIBER" --iterations 100000
```

### 2. Parola Doğrulama (Sabit Zamanlı)
```bash
python uygulama/vault_cli.py --verify --password "GizliParola2026!" --record "$pbkdf2-sha256$i=100000$s=...$p=1$..." --pepper "HSM_KMS_BIBER"
```

### 3. Eski/Güvensiz Hash Analizi
```bash
python uygulama/vault_cli.py --detect-legacy --hash-str "5d41402abc4b2a76b9719d911017c592"
```

### 4. Veritabanı Sızıntısı Savunma Simülasyonu
```bash
python uygulama/vault_cli.py --leak-test
```

### 5. Birim Testlerin Çalıştırılması
```bash
python -m unittest tests/test_secure_password_vault.py -v
```

### 6. Kanıtların Yeniden Üretilmesi
```bash
python kanit_uretici.py
```
