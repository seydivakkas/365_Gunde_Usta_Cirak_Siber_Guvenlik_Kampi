# GÜN 103: FIPS 197 SİMETRİK ŞİFRELEME VE AES (ADVANCED ENCRYPTION STANDARD)
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
Bu modül; NIST FIPS 197 standardına tam uyumlu AES-128 ve AES-256 blok şifreleme motorunu, NIST SP 800-38A işletim modlarını (ECB, CBC, CTR), PKCS#7 dolgu yönetimini ve Encrypt-then-MAC (AEAD) kimlik doğrulamalı şifreleme mimarisini sunar. Saf Python standart kütüphanesi ile sıfır harici bağımlılık prensibiyle geliştirilmiştir.

### Temel Özellikler
1. **FIPS 197 Blok Motoru:** SubBytes, ShiftRows, MixColumns (Galois Alanı $GF(2^8)$ matris çarpımı) ve AddRoundKey adımları.
2. **NIST Test Vektörleri Uyumu:** NIST SP 800-38A resmi test vektörleriyle doğrulanmış blok şifreleme.
3. **Desen Sızıntısı Gösterimi (ECB Penguin):** ECB modunun zaaflarını gösteren karşılaştırma simülasyonu (`CWE-327`).
4. **Kriptografik IV Yönetimi:** CBC modunda tahmin edilebilir IV kullanımının engellenmesi (`CWE-329`).
5. **AEAD Bütünlük Koruması:** Encrypt-then-MAC ile kurcalanmış şifreli metinlerin anında tespiti (`CWE-353`).

---

## 📂 DİZİN YAPISI

```
gun_103/
├── README.md                   # Modül tanıtımı ve özel lisans
├── ders.md                     # Usta-çırak ders anlatımı
├── soru_cevap.md               # 4 alt başlıklı 3 derin soru-cevap
├── rapor.md                    # 100/100 değerlendirme karnesi
├── sonuc.json                  # Otomasyon sonuç özeti
├── kanit_uretici.py            # Otomatik test ve kanıt üretici betik
├── uygulama/
│   ├── __init__.py
│   ├── aes_cipher_engine.py    # Çekirdek FIPS 197 AES motoru
│   └── aes_cli.py              # Komut satırı arayüzü
├── tests/
│   ├── __init__.py
│   └── test_aes_cipher.py      # 15 birim test paketi
├── ornek_veri/
│   ├── aes_known_vectors.json  # NIST resmi test vektörleri
│   └── invalid_aes_inputs.json # 9 negatif kontrol senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt
    │   ├── negatif_kontrol_sonuclari.txt
    │   ├── aes_guvenlik_analiz_raporu.txt
    │   └── komut_ve_cikis.txt
    └── temsili/
        └── aes_mimarisi.txt    # ASCII mimari şeması
```

---

## 🚀 KULLANIM TALİMATLARI

### 1. NIST Resmi Test Vektörlerini Doğrulama
```bash
python uygulama/aes_cli.py --verify-nist
```

### 2. ECB vs CBC Desen Sızıntısı Deneyi
```bash
python uygulama/aes_cli.py --compare-modes
```

### 3. AES-CBC Şifreleme
```bash
python uygulama/aes_cli.py --encrypt --plaintext "GizliVeri2026" --key "2b7e151628aed2a6abf7158809cf4f3c" --mode cbc
```

### 4. AES-CBC Şifre Çözme
```bash
python uygulama/aes_cli.py --decrypt --ciphertext "<CIPHERTEXT_HEX>" --key "2b7e151628aed2a6abf7158809cf4f3c" --mode cbc --iv "<IV_HEX>"
```

### 5. Birim Testlerin Çalıştırılması
```bash
python -m unittest tests/test_aes_cipher.py -v
```

### 6. Kanıtların Yeniden Üretilmesi
```bash
python kanit_uretici.py
```
