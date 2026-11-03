# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 109: PKI ve Sertifika Yaşam Döngüsü (Certificate Lifecycle Management)

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Durum](https://img.shields.io/badge/durum-TAMAMLANDI%20(PASS)-brightgreen?style=flat-square)
![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)
![Standartlar](https://img.shields.io/badge/standartlar-RFC%202986%20%7C%20RFC%205280%20%7C%20RFC%206960%20%7C%20RFC%206962%20%7C%20RFC%208555-orange?style=flat-square)

---

## Genel Bakış

Bu çalışma; açık anahtar altyapısında (PKI) dijital sertifikaların **Doğumundan (KeyGen/CSR) Ölümüne (Revocation/Crypto-Shredding)** kadar tüm yaşam evrelerini inceleyen, simüle eden ve denetleyen bağımsız bir güvenlik mühendisliği paketidir.

Harici hiçbir üçüncü parti kütüphaneye (pip paketine) ihtiyaç duymadan, yalnızca Python standart kütüphanesi ile geliştirilmiş; kriptografik matematik, RFC standartları ve CWE zafiyet savunmaları uçtan uca modellenmiştir.

---

## Yaşam Döngüsü Evreleri

```
  [1. Doğum]       Anahtar Üretimi (CSPRNG) & PKCS#10 CSR (Proof-of-Possession / CWE-347)
       |
       v
  [2. Tescil]      CA İmzası & Certificate Transparency (CT Log / RFC 6962 / SCT)
       |
       v
  [3. İşletim]     İptal Denetimi (CRL RFC 5280 / OCSP RFC 6960 / OCSP Stapling RFC 6066)
       |           (CWE-294 Nonce Replay Savunması & Fail-Closed Tutumu)
       v
  [4. Yenileme]    ACME Protokolü (RFC 8555 / HTTP-01) ile Otomatik Rotasyon
       |
       v
  [5. İmha]        Kriptografik İmha (Crypto-Shredding): Eski anahtarların ezilerek yok edilmesi
```

---

## Proje Dizin Yapısı

```
portfolio/hafta_16/gun_109/
├── README.md                           # Proje genel tanıtım ve kullanım kılavuzu
├── ders.md                             # Usta-Çırak derinlemesine teknik ders anlatımı
├── soru_cevap.md                       # 4 alt başlıklı 3 kapsamlı mülakat ve teknik soru
├── rapor.md                            # 100/100 tam puanlı teknik değerlendirme karnesi
├── sonuc.json                          # Makine tarafından okunabilir sonuç özeti
├── kanit_uretici.py                    # Birim testleri, negatif senaryoları ve kanıtları üreten betik
├── uygulama/
│   ├── __init__.py                     # Paket tanımlayıcısı
│   ├── pki_lifecycle_engine.py         # PKI, CSR, CA, CT, CRL, OCSP ve ACME motoru
│   └── pki_cli.py                      # Yaşam döngüsü ve zafiyet analiz CLI aracı
├── tests/
│   ├── __init__.py                     # Test paketi tanımlayıcısı
│   └── test_pki_lifecycle.py           # 15 kapsamlı birim testi (15/15 PASS)
├── ornek_veri/
│   ├── pki_config_sample.json          # Örnek PKI yapılandırması
│   └── invalid_lifecycle_inputs.json   # 9 adet negatif güvenlik kontrol senaryosu
└── kanit/
    ├── gercek/                         # Gerçek yerel yürütme kanıtları
    │   ├── test_sonuclari.txt          # 15 birim test çalıştırma günlüğü
    │   ├── negatif_kontrol_sonuclari.txt # 9 negatif kontrol engelleme günlüğü
    │   ├── komut_ve_cikis.txt          # CLI yürütme çıktısı
    │   └── pki_yasam_dongusu_analiz_raporu.txt # Güvenlik analiz raporu
    └── temsili/
        └── pki_yasam_dongusu_mimarisi.txt # Etiketli ASCII mimari diyagramı
```

---

## Kurulum ve Çalıştırma

Harici hiçbir bağımlılık gerekmez (Pure Python):

```bash
# 1. Yaşam döngüsü simülasyonunu ve güvenlik zafiyet analizini çalıştırma:
python uygulama/pki_cli.py

# 2. JSON formatında çıktı alma:
python uygulama/pki_cli.py --json

# 3. Birim testleri yürütme (15 Test):
python -m unittest tests/test_pki_lifecycle.py

# 4. Tüm kanıtları otomatik üretme ve doğrulama:
python kanit_uretici.py
```

---

## Kapsanan Güvenlik Zafiyetleri (CWE Savunmaları)

- **CWE-347:** CSR üzerinde sahte mülkiyet ispatı (Proof-of-Possession) imza tahrifatı engellendi.
- **CWE-20:** Boş Subject Common Name (CN) veya SAN içeren talepler doğrulama katmanında reddedildi.
- **CWE-299:** İptal edilen sertifikaların CRL ve OCSP ile anında engellenmesi sağlandı.
- **CWE-298:** Süresi dolmuş (`NotAfter`) veya henüz geçerli olmayan (`NotBefore`) sertifikalar reddedildi.
- **CWE-294:** OCSP yanıtlarında tek kullanımlık `Nonce` doğrulamasıyla Replay saldırıları bertaraf edildi.
- **CWE-295:** İptal durumu doğrulanamayan sertifikalarda `FAIL_CLOSED` politikası uygulandı.
- **CWE-311:** Emekliye ayrılan özel anahtarların rastgele bitlerle ezilerek imha edilmesi (`Crypto-Shredding`) sağlandı.
