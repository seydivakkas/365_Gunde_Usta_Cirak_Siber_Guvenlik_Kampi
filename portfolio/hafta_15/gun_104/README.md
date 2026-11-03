# GÜN 104: AEAD (AUTHENTICATED ENCRYPTION) VE NONCE YÖNETİMİ
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
Bu modül; AEAD (Authenticated Encryption with Associated Data) mimarisini, Nonce tekrarı kaynaklı Two-Time Pad felaketini ($C_1 \oplus C_2 = P_1 \oplus P_2$), durum bilgili Nonce takip önbelleğini (`StatefulNonceTracker`) ve Nonce kötüye kullanımına dirençli Synthetic IV (SIV) standardını sunar. Saf Python standart kütüphanesi ile bağımsız geliştirilmiştir.

### Temel Özellikler
1. **AEAD Bütünlük Kalkanı:** CTR akış şifrelemesi ve HMAC-SHA256 ile ilişkili verilerin (AAD) mühürlenmesi (`CWE-353`, `CWE-345`).
2. **Nonce Tekrarı Engelleme:** `StatefulNonceTracker` ile aynı (Anahtar, Nonce) çiftinin ikinci kez kullanımı anında engellenir (`CWE-323`).
3. **Two-Time Pad Simülasyonu:** Nonce tekrarı durumunda anahtar akışının nasıl iptal olduğunu ve Crib-Dragging saldırısını gösteren laboratuvar aracı.
4. **SIV (Synthetic IV) Modu:** RFC 5297 uyumlu deterministik Nonce türetimi ile dağıtık sistemlerde Nonce çakışması riskinin sıfırlanması.

---

## 📂 DİZİN YAPISI

```
gun_104/
├── README.md                     # Modül tanıtımı ve özel lisans
├── ders.md                       # Usta-çırak ders anlatımı
├── soru_cevap.md                 # 4 alt başlıklı 3 derin soru-cevap
├── rapor.md                      # 100/100 değerlendirme karnesi
├── sonuc.json                    # Otomasyon sonuç özeti
├── kanit_uretici.py              # Otomatik test ve kanıt üretici betik
├── uygulama/
│   ├── __init__.py
│   ├── aead_nonce_engine.py      # Çekirdek AEAD ve Nonce motoru
│   └── aead_cli.py               # Komut satırı yönetim aracı
├── tests/
│   ├── __init__.py
│   └── test_aead_nonce.py        # 15 birim test paketi
├── ornek_veri/
│   ├── aead_test_vectors.json    # Test vektörleri ve veri seti
│   └── invalid_aead_inputs.json  # 9 negatif kontrol senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt
    │   ├── negatif_kontrol_sonuclari.txt
    │   ├── aead_nonce_analiz_raporu.txt
    │   └── komut_ve_cikis.txt
    └── temsili/
        └── aead_nonce_mimarisi.txt # ASCII mimari şeması
```

---

## 🚀 KULLANIM TALİMATLARI

### 1. Two-Time Pad Zafiyet Simülasyonu
```bash
python uygulama/aead_cli.py --simulate-nonce-reuse
```

### 2. Nonce Takip Önbelleği Testi (CWE-323 Engeli)
```bash
python uygulama/aead_cli.py --test-tracker
```

### 3. AEAD Şifreleme (İlişkili Veri / AAD ile)
```bash
python uygulama/aead_cli.py --encrypt --plaintext "GizliFinansalVeri" --key "2b7e151628aed2a6abf7158809cf4f3c" --aad "user_id=104;role=auditor"
```

### 4. SIV (Synthetic IV) Deterministik Şifreleme
```bash
python uygulama/aead_cli.py --encrypt --plaintext "DeterministikVeri" --key "2b7e151628aed2a6abf7158809cf4f3c" --siv
```

### 5. Birim Testlerin Çalıştırılması
```bash
python -m unittest tests/test_aead_nonce.py -v
```

### 6. Kanıtların Yeniden Üretilmesi
```bash
python kanit_uretici.py
```
