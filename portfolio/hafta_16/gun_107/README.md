# Gün 107: Dijital İmza ve Doğrulama Mimarisi

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](https://www.python.org/)
[![Test Status](https://img.shields.io/badge/tests-15%2F15%20PASS-brightgreen?style=flat-square)](tests/)
[![Security Standards](https://img.shields.io/badge/standards-RFC%208017%20%7C%20FIPS%20186--4-orange?style=flat-square)](rapor.md)

---

## 📌 Genel Bakış ve Amaç

Bu proje (Hafta 16 / Gün 107); modern asimetrik dijital imza ve doğrulama süreçlerini (RSASSA-PSS, RSASSA-PKCS1-v1_5) saf Python (Pure Python) ile sıfırdan hayata geçiren, inkar edilemezlik (non-repudiation) ve veri bütünlüğünü matematiksel kesinlikle temin eden bir **Dijital İmza Motoru**dur.

Proje ayrıca, düz (textbook) RSA imzasındaki varoluşsal sahtecilik (existential forgery) ve çarpımsal manipülasyon zafiyetlerini (CWE-327), Bleichenbacher $e=3$ gevşek ayrıştırma imza sahteciliğini (CVE-2006-4339 / CWE-347) ve Sony PlayStation 3'ün kırılmasına yol açan ECDSA nonce yeniden kullanımını (CWE-323) pratik ve matematiksel olarak simüle eder.

---

## 🛡️ Temel Güvenlik Özellikleri ve Savunulan Zafiyetler

1. **RSASSA-PSS (RFC 8017 Section 8.1):** Olasılıksal (probabilistic) ve kanıtlanabilir güvenlik (provable security) sağlayan, her imzada 32 bayt rastgele tuz (`salt`) kullanan modern imza şeması.
2. **Katı (Strict) PKCS#1 v1.5 Doğrulaması:** Bleichenbacher $e=3$ imza sahteciliği atağını (CVE-2006-4339 / CWE-347) önleyen tam EM bloğu ve sabit zamanlı eşleştirme.
3. **Zamanlama Analizi Direnci (CWE-208):** Doğrulama kontrollerinde `hmac.compare_digest` kullanılarak yan kanal sızıntıları engellenmiştir.
4. **ECDSA Nonce Yeniden Kullanımı Savunması (CWE-323):** Aynı $k$ nonce değerinin iki farklı mesajda kullanılmasının kök özel anahtarı nasıl ifşa ettiği gösterilmiş ve RFC 6979 deterministik nonce kuralı vurgulanmıştır.
5. **Zayıf Anahtar Boyutu Kalkanı (CWE-326):** 512 bit altındaki anahtarlar derhal reddedilir.

---

## 📁 Proje Dizin Yapısı

```
portfolio/hafta_16/gun_107/
├── uygulama/
│   ├── __init__.py
│   ├── digital_signature_engine.py      # RSASSA-PSS, PKCS#1 v1.5 ve zafiyet çekirdek motoru
│   └── signature_cli.py                 # Anahtar üretimi, imzalama ve zafiyet CLI aracı
├── tests/
│   ├── __init__.py
│   └── test_digital_signature.py        # 15 Birim testi (%100 Başarı)
├── ornek_veri/
│   ├── signature_vectors.json           # Standart ASN.1 önekleri ve referans belgeler
│   └── invalid_signature_inputs.json    # 9 Negatif kontrol test senaryosu
├── kanit/
│   ├── gercek/                          # Gerçek test ve analiz çıktıları
│   │   ├── test_sonuclari.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── dijital_imza_analiz_raporu.txt
│   │   └── komut_ve_cikis.txt
│   └── temsili/                         # Mimari ASCII diyagramı (Zorunlu bantlı)
│       └── dijital_imza_mimarisi.txt
├── kanit_uretici.py                     # Otomatik kanıt üretim ve doğrulama betiği
├── ders.md                              # Usta-Çırak dijital imza ders notları
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
# 1. 1024-bit (veya 2048-bit) İmza Anahtar Çifti Üretme
python uygulama/signature_cli.py --keygen --bits 1024 \
    --pub-out sig_pub.json --priv-out sig_priv.json

# 2. Belgeyi RSASSA-PSS ile Dijital Olarak İmzalama
python uygulama/signature_cli.py --sign --privkey sig_priv.json \
    --message "Resmi Odeme Onay Belgesi #2026-11" \
    --scheme pss

# 3. Hex Formatındaki İmzayı Doğrulama
python uygulama/signature_cli.py --verify --pubkey sig_pub.json \
    --message "Resmi Odeme Onay Belgesi #2026-11" \
    --signature <HEX_STRING> \
    --scheme pss

# 4. Kriptografik İmza Zafiyetlerini Simüle Etme
python uygulama/signature_cli.py --demo-flaws

# 5. Tüm Birim Testlerini Koşturma
python -m unittest tests/test_digital_signature.py -v
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
