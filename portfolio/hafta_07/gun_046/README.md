# Gün 046: IPv6 Temel Kavramlar, Sıkıştırma ve Adres Güvenliği

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

Bu çalışma, Siber Güvenlik 365 Günlük Müfredatı kapsamında Aşama 03 (Ağ Temelleri ve Ağ Güvenliği), Hafta 07, Gün 046 çalışmasıdır.

---

## 📋 Proje Özeti

IPv6'nın 128-bitlik adres mimarisini, RFC 5952 kanonik sıkıştırma kurallarını, EUI-64 arayüz kimliği türetimini ve donanım izleme gizlilik risklerini (RFC 4941), komşu keşfi (NDP) için Solicited-Node Multicast adreslerini ve çift yığın (Dual-Stack Shadow Network) güvenlik tehditlerini inceleyen bağımsız laboratuvar paketidir.

### Temel Özellikler
- **128-Bit Açılım ve Dönüşüm:** Hextet doğrulaması, eksik sıfırların açılması (`expanded_address`) ve 128-bit tamsayı/ikili format hesabı.
- **RFC 5952 Kanonik Sıkıştırma:** Baş sıfırların ayıklanması, ardışık en uzun sıfır bloğunun tek bir `::` ile değiştirilmesi, tek sıfırın kısaltılmaması ve eşitlik durumunda ilk bloğun seçilmesi.
- **Adres Türleri ve Kapsamlar:** Global Unicast (GUA), Link-Local, Unique Local (ULA), Multicast, Loopback, Unspecified ve IPv4-Mapped adres sınıflandırması.
- **EUI-64 ve Gizlilik (RFC 4941):** 48-bit MAC adresinden U/L biti ters çevrilerek ve `FF:FE` baytları eklenerek 64-bitlik Link-Local IPv6 adresi türetimi.
- **Solicited-Node Multicast (RFC 4291):** Komşu Keşif Protokolü (NDP) için hedef çok noktaya yayın adresinin dinamik üretimi.
- **Kod Açıklamaları:** Tüm uygulama ve test kodları satır satır didaktik yorumlarla açıklanmıştır.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_07/gun_046/
├── README.md                                    # Modül dokümantasyonu ve çalıştırma kılavuzu
├── ders.md                                      # Usta-Çırak pedagojisiyle teorik IPv6 dersi
├── soru_cevap.md                                # Soru bankası (G046-SC1/2/3) 4 başlıklı cevapları
├── rapor.md                                     # 100/100 rubrik değerlendirme ve teknik rapor
├── sonuc.json                                   # Gün sonu standart makine çıktısı
├── manifest.json                                # SHA-256 doğruluk ve bütünlük tablosu
├── uygulama/
│   ├── __init__.py                              # Paket başlatıcı
│   └── ipv6_analyzer.py                         # IPv6 analiz ve RFC 5952 sıkıştırma motoru
├── tests/
│   ├── __init__.py                              # Test paketi başlatıcı
│   └── test_ipv6_analyzer.py                    # 14 birim testi ve negatif kontroller
├── ornek_veri/
│   ├── sample_ipv6_addresses.json               # 7 doğrulanmış IPv6 adres test senaryosu
│   └── invalid_ipv6_addresses.json              # 8 geçersiz girdi ve biçim hata senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                   # pytest 14/14 PASS kanıtı
    │   ├── komut_ve_cikis.txt                   # Konsol yürütme çıktısı
    │   ├── ipv6_analiz_raporu.txt               # Üretilen Markdown analiz raporu
    │   └── negatif_kontrol_sonuclari.txt        # 8 negatif vakanın yakalanma raporu
    └── temsili/
        └── ipv6_ve_slaac_mimarisi.txt           # Kavramsal mimari, SLAAC ve RA Guard şeması
```

---

## 🚀 Hızlı Başlangıç ve Çalıştırma

### 1. IPv6 Analiz Motorunu Çalıştırma
```powershell
python portfolio/hafta_07/gun_046/uygulama/ipv6_analyzer.py
```

### 2. Birim ve Güvenlik Testlerini Koşma
```powershell
pytest portfolio/hafta_07/gun_046/tests/test_ipv6_analyzer.py -v
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
