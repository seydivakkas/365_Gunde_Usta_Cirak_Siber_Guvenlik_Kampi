# Gün 108: X.509 ve Sertifika Zinciri Mimarisi (PKI Trust Chain)

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](https://www.python.org/)
[![Test Status](https://img.shields.io/badge/tests-15%2F15%20PASS-brightgreen?style=flat-square)](tests/)
[![Security Standards](https://img.shields.io/badge/standards-RFC%205280%20%7C%20RFC%206125-orange?style=flat-square)](rapor.md)

---

## 📌 Genel Bakış ve Amaç

Bu proje (Hafta 16 / Gün 108); X.509 v3 sertifika anatomisini, 3 kademeli PKI mimarisini (Root CA -> Intermediate CA -> Leaf Certificate) ve RFC 5280 yol doğrulama (path validation) kurallarını saf Python (Pure Python) ile sıfırdan inşa eden bir **Sertifika Güven Zinciri ve Doğrulama Motoru**dur.

Proje, internet PKI altyapısında en sık karşılaşılan kritik güvenlik açıklarını (BasicConstraints `is_ca=False` yetkisiz CA ihlali - CWE-295, Hostname Mismatch alan adı uyuşmazlığı - CWE-297, süresi dolmuş veya tarihi manipüle edilmiş sertifikalar - CWE-298 ve iptal edilmiş sertifikalar) simüle eder ve eksiksiz savunma kalkanı sunar.

---

## 🛡️ Temel Güvenlik Özellikleri ve Savunulan Zafiyetler

1. **RFC 5280 Yol Doğrulama (Path Validation):** Uç sertifikadan başlayarak ara sertifikalar üzerinden işletim sistemi/tarayıcı güven deposundaki (Trust Store) Kök CA'ya kadar güven zincirini hiyerarşik olarak doğrular (CWE-295).
2. **Temel Kısıtlamalar Denetimi (BasicConstraints - CWE-295):** Uç sertifikaların (`is_ca=False`) yetkisiz olarak alt sertifika üretmesini engeller.
3. **Alan Adı Doğrulama (RFC 6125 - CWE-297):** Talep edilen alan adı ile sertifikadaki Subject Alternative Name (SAN) ve Common Name (CN) alanlarını joker (wildcard) kurallarıyla eşleştirerek MITM saldırılarını önler.
4. **Zaman ve Süre Doğrulaması (CWE-298):** `NotBefore` ve `NotAfter` aralıkları sistem zamanı ile kontrol edilir; süresi dolmuş sertifikalar bloke edilir.
5. **Sertifika İptal Denetimi (CRL / OCSP Mantığı):** İptal listesinde yer alan seri numaralı sertifikalar derhal reddedilir.

---

## 📁 Proje Dizin Yapısı

```
portfolio/hafta_16/gun_108/
├── uygulama/
│   ├── __init__.py
│   ├── x509_chain_engine.py             # X.509 v3, PKI builder ve RFC 5280 zincir doğrulama motoru
│   └── x509_cli.py                      # PKI inşası, zincir doğrulama ve zafiyet CLI aracı
├── tests/
│   ├── __init__.py
│   └── test_x509_chain.py               # 15 Birim testi (%100 Başarı)
├── ornek_veri/
│   ├── pki_chain_sample.json            # 3 Kademeli PKI şeması ve referans parametreler
│   └── invalid_certificate_inputs.json  # 9 Negatif kontrol test senaryosu
├── kanit/
│   ├── gercek/                          # Gerçek test ve analiz çıktıları
│   │   ├── test_sonuclari.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   ├── x509_guvenlik_analiz_raporu.txt
│   │   └── komut_ve_cikis.txt
│   └── temsili/                         # Mimari ASCII diyagramı (Zorunlu bantlı)
│       └── sertifika_zinciri_mimarisi.txt
├── kanit_uretici.py                     # Otomatik kanıt üretim ve doğrulama betiği
├── ders.md                              # Usta-Çırak X.509 ve PKI ders notları
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
# 1. 3 Kademeli PKI Altyapısı Oluşturma (Root CA, Intermediate CA, Leaf, Trust Store)
python uygulama/x509_cli.py --build-pki --out-dir pki_output --domain secure.bank.com.tr

# 2. Sertifika Zincirini Doğrulama (Path Validation)
python uygulama/x509_cli.py --verify-chain \
    --leaf pki_output/leaf_cert.json \
    --intermediate pki_output/intermediate_ca.json \
    --trust-store pki_output/trust_store.json \
    --domain secure.bank.com.tr

# 3. PKI ve X.509 Zafiyet Savunma Simülasyonunu Çalıştırma
python uygulama/x509_cli.py --demo-flaws

# 4. Tüm Birim Testlerini Koşturma
python -m unittest tests/test_x509_chain.py -v
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
