# Gün 155: Web Uygulama Mimarisi ve Güven Sınırı (Trust Boundaries)

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Status: 100/100 PASS](https://img.shields.io/badge/status-100%2F100%20PASS-brightgreen?style=flat-square)
![Stage 7: Web Security](https://img.shields.io/badge/stage%207-WEB%20SECURITY-orange?style=flat-square)
![Tests: 15/15 Passed](https://img.shields.io/badge/tests-15%2F15%20Passed-success?style=flat-square)
![Negative Controls: 9/9 Passed](https://img.shields.io/badge/negative%20controls-9%2F9%20Passed-blue?style=flat-square)

---

## 📌 Genel Bakış

Bu modül, **Aşama 7: Web Güvenliği (Hafta 23 - 26)** döneminin açılış konusu olan **Web Uygulama Mimarisi ve Güven Sınırları (Trust Boundaries)** motorunu sunar.

Sistem, çok katmanlı web mimarilerinde (Sunum, Reverse Proxy, Uygulama ve Veritabanı) istemci-sunucu sınır geçişlerini modeller. HTTP/HTTPS istek ve yanıtlarını denetler, güvenlik başlıklarını (HSTS, CSP, X-Frame-Options, nosniff, Referrer, Permissions) doğrular, çerez bayraklarını (Secure, HttpOnly, SameSite) analiz eder, istemci tarafı güven varsayımlarını (fiyat ve rol manipülasyonu) saptar ve otomatik Nginx sertleştirme konfigürasyonları üretir.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_23/gun_155/
├── README.md                                # Proje genel tanıtımı ve kullanım kılavuzu
├── ders.md                                  # Usta-Çırak derin teknik web mimarisi ders notu
├── soru_cevap.md                            # 3 derin teknik soru ve 4 zorunlu alt başlıklı cevaplar
├── rapor.md                                 # 100/100 başarı ve değerlendirme raporu
├── sonuc.json                               # Yapılandırılmış sonuç özeti
├── manifest.json                            # 20 dosyanın SHA-256 bütünlük özetleri
├── kanit_uretici.py                         # Kanıtları üreten otomasyon betiği
├── uygulama/
│   ├── __init__.py                          # Python paket başlatıcısı
│   ├── web_architecture_engine.py          # Çekirdek güven sınırı ve başlık sertleştirme motoru
│   └── web_architecture_cli.py             # Komut satırı denetim ve yönetim arayüzü
├── tests/
│   ├── __init__.py                          # Test paketi başlatıcısı
│   └── test_web_architecture.py            # 15/15 birim test paketi
├── ornek_veri/
│   ├── clean_web_architecture_flow.json     # Kurumsal tam güvenli HTTP akış örneği
│   └── invalid_trust_boundary_scenarios.json # 9 adet negatif kontrol senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt               # 15/15 PASS birim test kanıtı
    │   ├── negatif_kontrol_sonuclari.txt    # 9/9 PASS negatif senaryo kanıtı
    │   ├── web_trust_boundary_audit.json    # JSON denetim raporu
    │   ├── hardened_web_response.json       # Otomatik sertleştirilmiş HTTP yanıtı
    │   ├── nginx_security_headers.conf      # Kurumsal Nginx güvenlik konfigürasyonu
    │   └── komut_ve_cikis.txt               # CLI konsol yürütme günlüğü
    └── temsili/
        └── web_mimarisi_guven_siniri.txt    # ASCII mimari diyagramı
```

---

## 🚀 Kullanım ve Çalıştırma

### 1. Birim Testleri Çalıştırma
```powershell
python -m unittest portfolio/hafta_23/gun_155/tests/test_web_architecture.py -v
```

### 2. HTTP Akışını (İstek + Yanıt) Güven Sınırları Açısından Denetleme
```powershell
python portfolio/hafta_23/gun_155/uygulama/web_architecture_cli.py audit-flow \
    --flow portfolio/hafta_23/gun_155/ornek_veri/clean_web_architecture_flow.json \
    --output portfolio/hafta_23/gun_155/kanit/gercek/web_trust_boundary_audit.json
```

### 3. Güvensiz HTTP Yanıtını Otomatik Sertleştirme
```powershell
python portfolio/hafta_23/gun_155/uygulama/web_architecture_cli.py harden-response \
    --flow portfolio/hafta_23/gun_155/ornek_veri/clean_web_architecture_flow.json \
    --output portfolio/hafta_23/gun_155/kanit/gercek/hardened_web_response.json
```

### 4. Kurumsal Nginx Güvenlik Başlıkları Konfigürasyonu Üretme
```powershell
python portfolio/hafta_23/gun_155/uygulama/web_architecture_cli.py export-nginx \
    --output portfolio/hafta_23/gun_155/kanit/gercek/nginx_security_headers.conf
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
