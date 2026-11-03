# 365 Günde Usta-Çırak Siber Güvenlik Kampı

[![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)](LICENSE)
[![Curriculum: 365 Days](https://img.shields.io/badge/curriculum-365%20Days-blue.svg)](Siber_Guvenlik_455_Gun_Mufredat_365_Gun_Guncellenmis.xlsx)
[![Pedagogy: Usta--Çırak Model](https://img.shields.io/badge/pedagogy-Usta--%C3%87%C4%B1rak-orange.svg)](#pedagojik-model)
[![Tests: 100% Pass](https://img.shields.io/badge/tests-100%25%20PASS-brightgreen.svg)](#kalite-ve-test-standartlar%C4%B1)

> **"Kökü sağlam olan ağaç fırtınadan korkmaz; temeli sağlam olan siber savunmacı hiçbir sıfırıncı gün saldırısından yılmaz."**  
> *— Usta*

---

## 🧭 Proje Hakkında

Bu depo, sıfırdan ileri düzeye kurumsal siber güvenlik uzmanlığı kazandırmak üzere tasarlanmış **365 Günlük Kapsamlı Siber Güvenlik Müfredatı ve Uygulama Paketi**'ni içermektedir.

Geleneksel teorik eğitimlerin aksine bu kamp, **Usta-Çırak (Mentorship & Mastery)** pedagojik modelini temel alır. Her gün bağımsız, eksiksiz, üretim kalitesinde Python motorları, komut satırı arayüzleri (CLI), 15 birim testi (%100 PASS), negatif sınır/zafiyet senaryoları ve doğrulanabilir somut kanıtlarla inşa edilir.

---

## 🏛️ Müfredat Aşamaları

Müfredat, 365 gün boyunca aşağıdaki 12 ana aşamada ilerlemektedir:

1. **Aşama 1: Temel Bilişim, Ağ Protokolleri ve Ağ Güvenliği** (Gün 1 – 35)
2. **Aşama 2: Linux Sistem Mimarisi, Servisler ve Sertleştirme** (Gün 36 – 70)
3. **Aşama 3: Kriptografi, Anahtar Yönetimi ve Güvenli İletişim** (Gün 71 – 98)
4. **Aşama 4: Web Güvenliği, OWASP Top 10 ve API Denetimi** (Gün 99 – 126)
5. **Aşama 5: Tehdit İstihbaratı, SOC ve Olay Müdahalesi** (Gün 127 – 140)
6. **Aşama 6: Uç Nokta Güvenliği, Active Directory ve Sertleştirme** (Gün 141 – 168)
7. **Aşama 7: Bulut Güvenliği (AWS, Azure, GCP) ve Konteyner İzolasyonu** (Gün 169 – 203)
8. **Aşama 8: Ağ Saldırıları, Paket Analizi ve IDS/IPS** (Gün 204 – 238)
9. **Aşama 9: Zararlı Yazılım Analizi, Tersine Mühendislik ve Sandbox** (Gün 239 – 273)
10. **Aşama 10: Sızma Testi Metodolojileri ve Kırmızı Takım Operasyonları** (Gün 274 – 308)
11. **Aşama 11: Mavi Takım Savunması, Tehdit Avcılığı (Hunting) ve SIEM** (Gün 309 – 343)
12. **Aşama 12: Güvenlik Mimarisi, Uyumluluk, Denetim ve Bitirme Projeleri** (Gün 344 – 365)

---

## 📦 Günlük Paket Mimarisi

Her bir gün (`portfolio/hafta_XX/gun_YYY/`), harici kütüphane bağımlılığı olmadan yalnızca saf Python 3 standart kütüphanesiyle bağımsız çalışabilen aşağıdaki standart bileşenlerden oluşur:

```text
gun_XXX/
├── README.md               # Konu özeti, mimari açıklamalar ve kullanım kılavuzu
├── ders.md                 # Usta-Çırak derinlemesine teknik ders anlatımı
├── soru_cevap.md           # 3 derin teknik soru ve 4 zorunlu alt başlık
├── rapor.md                # 100/100 PASS kalite ve denetim puan kartı
├── sonuc.json              # Standartlaştırılmış makine tarafından okunabilir sonuç
├── manifest.json           # SHA-256 bütünlük kontrolü ve dosya manifestosu
├── kanit_uretici.py        # Tüm test ve kanıt üretimini yöneten otomasyon
├── uygulama/
│   ├── __init__.py         # Paket arayüzü
│   ├── *_engine.py         # Endüstriyel sınıf güvenlik ve analiz motoru
│   └── *_cli.py            # Komut satırı yönetim arayüzü (CLI)
├── tests/
│   ├── __init__.py         # Test paketi başlangıcı
│   └── test_*.py           # 15 kapsamlı birim testi (%100 PASS)
├── ornek_veri/
│   ├── *_spec.json         # Standart konfigürasyon ve veri örnekleri
│   └── invalid_*_scenarios.json # 9 negatif/zafiyet test senaryosu
└── kanit/
    ├── gercek/             # Test çıktıları, JSON raporları, scriptler, loglar
    └── temsili/            # ASCII mimari ve akış şemaları (etiketli)
```

---

## 🛡️ Kalite ve Test Standartları

- **%100 Bağımsız Gün Prensibi:** Her gün kendi klasöründe tek başına çalışabilir. Önceki günlerden dosya veya kod aktarımı yapılmaz.
- **Didaktik Türkçe Yorumlar:** Tüm yürütülebilir Python, Bash ve PowerShell satırları detaylı Türkçe açıklamalarla zenginleştirilmiştir.
- **Sıfır Hata Politikası:** Tüm birim testleri (15/15) ve negatif senaryolar (9/9) istisnasız %100 başarıyla sonuçlanır.
- **Çift Doğrulama:** Sonuçlar hem yerel kanıt dosyalarında hem de ana Excel takip tablosunda (`Siber_Guvenlik_455_Gun_Mufredat_365_Gun_Guncellenmis.xlsx`) eşzamanlı tescil edilir.

---

## 🔒 Lisans — Tüm Hakları Saklıdır

```text
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
