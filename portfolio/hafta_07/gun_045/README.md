# Gün 045: IPv4 Adresleme, Alt Ağlar (Subnetting) ve CIDR Mimarisi

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

Bu çalışma, Siber Güvenlik 365 Günlük Müfredatı kapsamında Aşama 03 (Ağ Temelleri ve Ağ Güvenliği), Hafta 07, Gün 045 çalışmasıdır.

---

## 📋 Proje Özeti

IPv4 adres yapısını, CIDR gösterimini, bit düzeyinde ağ maskesi ve wildcard hesaplamalarını, RFC 1918 ve Bogon IP sınıflandırmasını, noktadan noktaya (/31 RFC 3021) ve tekil konak (/32) istisnalarını kapsamlı bir şekilde matematiksel ve güvenlik odaklı olarak modelleyen bağımsız laboratuvar paketidir.

### Temel Özellikler
- **32-Bit Matematik:** Dotted-decimal metin gösterimini 32-bit tamsayıya çevirme, bit kaydırma ve ikili format gösterimi.
- **Bitsel İşlemler:** Bitwise `AND` (Ağ adresi), Bitwise `OR` (Yayın adresi) ve Bitwise `NOT` (Wildcard maske) hesaplamaları.
- **Özel Standartlar:** RFC 3021 (/31 yayını olmayan noktadan noktaya yönlendirici linkleri) ve /32 (tekil konak rotası) desteği.
- **Sınıflandırma ve Güvenlik:** RFC 1918 (Özel IP'ler), RFC 6598 (CGNAT), RFC 1122 (Loopback), RFC 3927 (APIPA), RFC 5771 (Multicast) ve Bogon adres etiketleme.
- **VLSM Desteği:** Bir ana CIDR bloğunu daha küçük alt ağlara bölme (Subnet Splitting) ve alt ağ üyelik kontrolü.
- **Kod Açıklamaları:** Tüm uygulama ve test kodları satır satır didaktik yorumlarla açıklanmıştır.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_07/gun_045/
├── README.md                                    # Modül dokümantasyonu ve çalıştırma kılavuzu
├── ders.md                                      # Usta-Çırak pedagojisiyle hazırlanmış teorik ders
├── soru_cevap.md                                # Soru bankası (G045-SC1/2/3) 4 başlıklı cevapları
├── rapor.md                                     # 100/100 rubrik değerlendirme ve teknik rapor
├── sonuc.json                                   # Gün sonu standart makine çıktısı
├── manifest.json                                # SHA-256 doğruluk ve bütünlük tablosu
├── uygulama/
│   ├── __init__.py                              # Paket başlatıcı
│   └── ipv4_cidr_analyzer.py                    # Alt ağ hesaplama ve CIDR analiz motoru
├── tests/
│   ├── __init__.py                              # Test paketi başlatıcı
│   └── test_ipv4_cidr_analyzer.py               # 14 birim testi ve negatif kontroller
├── ornek_veri/
│   ├── sample_subnets.json                      # 8 doğrulanmış alt ağ test senaryosu
│   └── invalid_subnets.json                     # 8 geçersiz girdi ve hata senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                   # pytest 14/14 PASS kanıtı
    │   ├── komut_ve_cikis.txt                   # Konsol yürütme çıktısı
    │   ├── ipv4_subnet_hesaplama_raporu.txt     # Üretilen Markdown analiz raporu
    │   └── negatif_kontrol_sonuclari.txt        # 8 negatif vakanın yakalanma raporu
    └── temsili/
        └── ipv4_cidr_ve_subnetting_mimarisi.txt # Kavramsal mimari ve BCP 38 sınır diyagramı
```

---

## 🚀 Hızlı Başlangıç ve Çalıştırma

### 1. Alt Ağ Analiz Motorunu Çalıştırma
```powershell
python portfolio/hafta_07/gun_045/uygulama/ipv4_cidr_analyzer.py
```

### 2. Birim ve Güvenlik Testlerini Koşma
```powershell
pytest portfolio/hafta_07/gun_045/tests/test_ipv4_cidr_analyzer.py -v
```

---

## 🔒 Lisans Kuralı

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
