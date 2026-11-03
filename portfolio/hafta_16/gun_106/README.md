# Gün 106: Asimetrik Kriptografi Temelleri ve RSA Mimarisi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](https://www.python.org/)
[![Test Status](https://img.shields.io/badge/tests-15%2F15%20PASS-brightgreen?style=flat-square)](tests/)
[![Security Standards](https://img.shields.io/badge/standards-NIST%20SP%20800--56B%20%7C%20RFC%208017-orange?style=flat-square)](rapor.md)

---

## 📌 Genel Bakış ve Amaç

Bu proje (Hafta 16 Başlangıcı); modern asimetrik şifrelemenin matematiksel temellerini (Miller-Rabin olasılıksal asallık testi, Genişletilmiş Öklid algoritması, modüler ters ve Euler Totient hesabı) saf Python (Pure Python) ile sıfırdan inşa eden, FIPS 186-4 ve PKCS#1 v2.2 (RFC 8017) uyumlu bir **RSA ve RSA-OAEP Güvenli Asimetrik Kriptografi Motoru**dur.

Proje, düz (textbook) RSA'nın neden asla kullanılmaması gerektiğini (çarpımsal homomorfizm, şekillendirilebilirlik / malleability ve küçük $e=3$ küp kök zafiyetleri) uygulamalı olarak kanıtlar ve RSA-OAEP dolgulaması ile IND-CCA2 semantik güvenliğin nasıl sağlandığını gösterir.

---

## 🛡️ Temel Güvenlik Özellikleri ve Savunulan Zafiyetler

1. **Miller-Rabin Kriptografik Asallık Testi (k=40 Tur):** Hata payı $4^{-40} \approx 10^{-24}$ olan yüksek kesinlikte asal sayı ($p, q$) üretimi.
2. **Güvenli Genel Üs Standartı ($e=65537$):** Küçük üs ($e=3$) küp kök ve Håstad yayın saldırılarını (CWE-327) engeller.
3. **PKCS#1 v2.2 Uyumlu RSA-OAEP Dolgusu (CWE-780 Savunması):** MGF1 (SHA-256) ve rastgele tohum (`seed`) ile her şifrelemede benzersiz şifreli metin üretir; determinizmi ve homomorfik manipülasyonu (CWE-327) yok eder.
4. **Sabit Zamanlı Dolgu Doğrulama (CWE-208):** `hmac.compare_digest` ile Bleichenbacher dolgu kahini (padding oracle) ve zamanlama yan kanal sızıntılarını önler.
5. **Zayıf Anahtar Boyutu Kalkanı (CWE-326):** 512 bit ve altındaki zayıf anahtarları derhal reddeder; üretim için 2048+ bit önerir.

---

## 📁 Proje Dizin Yapısı

```
portfolio/hafta_16/gun_106/
├── uygulama/
│   ├── __init__.py
│   ├── asymmetric_crypto_engine.py      # Miller-Rabin, RSA, RSA-OAEP çekirdek motoru
│   └── asymmetric_cli.py                # Anahtar üretimi, şifreleme ve zafiyet CLI aracı
├── tests/
│   ├── __init__.py
│   └── test_asymmetric_crypto.py        # 15 Birim testi (%100 Başarı)
├── ornek_veri/
│   ├── rsa_vectors.json                 # Standart parametreler ve test vektörleri
│   └── invalid_asymmetric_inputs.json   # 9 Negatif kontrol test senaryosu
├── kanit/
│   ├── gercek/                          # Gerçek test ve analiz çıktıları
│   │   ├── test_sonuclari.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── rsa_guvenlik_analiz_raporu.txt
│   │   └── komut_ve_cikis.txt
│   └── temsili/                         # Mimari ASCII diyagramı (Zorunlu bantlı)
│       └── asimetrik_kripto_mimarisi.txt
├── kanit_uretici.py                     # Otomatik kanıt üretim ve doğrulama betiği
├── ders.md                              # Usta-Çırak RSA ve OAEP ders notları
├── soru_cevap.md                        # 3 Kritik teknik mülakat sorusu ve derin analiz
├── rapor.md                             # 100/100 Puanlık değerlendirme ve CWE matrisi
├── sonuc.json                           # Makine tarafından okunabilir sonuç özeti
├── manifest.json                        # Günlük paket içerik dökümü ve hash listesi
└── README.md                            # Dokümantasyon ve lisans bildirimi
```

---

## 🚀 Kurulum ve Kullanım

Herhangi bir harici kütüphane gerektirmez (Pure Python Standard Library).

```bash
# 1. 1024-bit (veya 2048-bit) RSA Anahtar Çifti Üretme
python uygulama/asymmetric_cli.py --keygen --bits 1024 \
    --pub-out rsa_pub.json --priv-out rsa_priv.json

# 2. Metni RSA-OAEP ile Güvenli Şifreleme
python uygulama/asymmetric_cli.py --encrypt --pubkey rsa_pub.json \
    --message "Kriptografik Asimetrik Guvenlik Mesaji 2026" \
    --label "auth_v1"

# 3. Hex Formatındaki Şifreli Metni Çözme
python uygulama/asymmetric_cli.py --decrypt --privkey rsa_priv.json \
    --ciphertext <HEX_STRING> \
    --label "auth_v1"

# 4. Textbook RSA Zafiyetlerini (Homomorfizm ve e=3) Gösterme
python uygulama/asymmetric_cli.py --demo-flaws

# 5. Tüm Birim Testlerini Koşturma
python -m unittest tests/test_asymmetric_crypto.py -v
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
