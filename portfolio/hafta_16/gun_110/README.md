# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 110: TLS Güvenlik Sınırları (Transport Layer Security Boundaries)

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Durum](https://img.shields.io/badge/durum-TAMAMLANDI%20(PASS)-brightgreen?style=flat-square)
![Puan](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)
![Standartlar](https://img.shields.io/badge/standartlar-RFC%205246%20%7C%20RFC%208446%20%7C%20RFC%207507%20%7C%20RFC%205869-orange?style=flat-square)

---

## Genel Bakış

Bu çalışma; Taşıma Katmanı Güvenliği (TLS) protokolünün el sıkışma (Handshake) ve kayıt (Record) katmanlarındaki güvenlik sınırlarını, TLS 1.2 vs 1.3 mimari devrimini, Downgrade Dance saldırılarına karşı savunmaları ve transkript bütünlüğünü inceleyen bağımsız bir güvenlik mühendisliği paketidir.

Tamamen harici bağımlılıksız (Pure Python standart kütüphanesi) olarak geliştirilmiş olup, HKDF anahtar türetimi, AEAD kimlik doğrulamalı şifreleme, Fallback-SCSV ve Sentinel kontrolleri uçtan uca simüle edilmiştir.

---

## TLS Protokol ve Güvenlik Mimarisi

```
  [İstemci (Client)]                                   [Sunucu (Server)]
         |                                                     |
         |---------------- 1. ClientHello -------------------->|
         |  - Sürümler, Şifre Paketleri, Fallback-SCSV         |
         |                                                     |
         |<--------------- 2. ServerHello ---------------------|
         |  - Sürüm, AEAD Şifre, Sentinel Baytları             |
         |                                                     |
         |    [Transcript-Hash: SHA-256(Handshake Messages)]   |
         |                                                     |
         |<--------------- 3. Finished (VerifyData) -----------|
         |---------------- 4. Finished (VerifyData) ---------->|
         |                                                     |
         |============ GÜVENLİ RECORD KATMANI (AEAD) ==========|
         |  - Sequence Number Kontrolü (Replay Engelleme)      |
         |  - 16 KB Azami Fragment Sınırı (Taşma Savunması)    |
```

---

## Proje Dizin Yapısı

```
portfolio/hafta_16/gun_110/
├── README.md                           # Proje genel tanıtım ve kullanım kılavuzu
├── ders.md                             # Usta-Çırak derinlemesine teknik ders anlatımı
├── soru_cevap.md                       # 4 alt başlıklı 3 kapsamlı mülakat ve teknik soru
├── rapor.md                            # 100/100 tam puanlı teknik değerlendirme karnesi
├── sonuc.json                          # Makine tarafından okunabilir sonuç özeti
├── kanit_uretici.py                    # Birim testleri, negatif senaryoları ve kanıtları üreten betik
├── uygulama/
│   ├── __init__.py                     # Paket tanımlayıcısı
│   ├── tls_security_boundary_engine.py # TLS el sıkışma, record ve güvenlik motoru
│   └── tls_cli.py                      # TLS protokol analiz ve zafiyet CLI aracı
├── tests/
│   ├── __init__.py                     # Test paketi tanımlayıcısı
│   └── test_tls_boundary.py            # 15 kapsamlı birim testi (15/15 PASS)
├── ornek_veri/
│   ├── tls_config_sample.json          # Sertleştirilmiş TLS yapılandırma örneği
│   └── invalid_tls_inputs.json         # 9 adet negatif güvenlik kontrol senaryosu
└── kanit/
    ├── gercek/                         # Gerçek yerel yürütme kanıtları
    │   ├── test_sonuclari.txt          # 15 birim test çalıştırma günlüğü
    │   ├── negatif_kontrol_sonuclari.txt # 9 negatif kontrol engelleme günlüğü
    │   ├── komut_ve_cikis.txt          # CLI yürütme çıktısı
    │   └── tls_guvenlik_analiz_raporu.txt # Güvenlik analiz raporu
    └── temsili/
        └── tls_guvenlik_sinirlari_mimarisi.txt # Etiketli ASCII mimari diyagramı
```

---

## Kurulum ve Çalıştırma

Harici hiçbir bağımlılık gerekmez (Pure Python):

```bash
# 1. TLS el sıkışma simülasyonunu ve güvenlik analizini çalıştırma:
python uygulama/tls_cli.py

# 2. JSON formatında çıktı alma:
python uygulama/tls_cli.py --json

# 3. Birim testleri yürütme (15 Test):
python -m unittest tests/test_tls_boundary.py

# 4. Tüm kanıtları otomatik üretme ve doğrulama:
python kanit_uretici.py
```

---

## Kapsanan Güvenlik Zafiyetleri (CWE Savunmaları)

- **CWE-757:** RFC 7507 `TLS_FALLBACK_SCSV` ve RFC 8446 Downgrade Sentinel baytları ile Downgrade Dance saldırıları önlendi.
- **CWE-327:** Statik RSA anahtar değişimi ve kırılmış ciphers (RC4, 3DES, CBC) yasaklandı; Ephemeral ECDHE ile PFS sağlandı.
- **CWE-353:** Finished `VerifyData` transkript özeti ve Record sıra numarası (Sequence Number) ile el sıkışma bütünlüğü temin edildi.
- **CWE-294:** TLS 1.3 0-RTT Erken Veri tekrar oynatma saldırılarına karşı anti-replay önbelleği işletildi.
- **CWE-20:** 16384 bayt azami fragment boyutu katı olarak kontrol edilerek bellek taşması ve DoS engellendi.
