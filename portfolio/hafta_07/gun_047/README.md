# Gün 047: Adres Çözümleme Protokolü (ARP), Yerel Ağ Komşuluğu ve Güvenlik

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

Bu çalışma, Siber Güvenlik 365 Günlük Müfredatı kapsamında Aşama 03 (Ağ Temelleri ve Ağ Güvenliği), Hafta 07, Gün 047 çalışmasıdır.

---

## 📋 Proje Özeti

Katman 3 IPv4 mantıksal adresleri ile Katman 2 fiziksel Ethernet MAC adresleri arasındaki ARP (RFC 826) çözümleme mekanizmasını, dinamik ve statik önbellek yönetimini, Gratuitous ARP (GARP) işleyişini, ARP Zehirleme (Cache Poisoning / MitM) saldırılarını ve Katman-2 seviyesindeki Dynamic ARP Inspection (DAI) savunma mimarisini modelleyen bağımsız laboratuvar paketidir.

### Temel Özellikler
- **ARP Önbellek Yönetimi:** Dinamik öğrenme, statik koruma kilitleri ve adres normalizasyonu (Cisco, tire ve iki nokta biçimleri).
- **Protokol Yaşam Döngüsü:** ARP Request, ARP Reply ve Gratuitous ARP mesaj ayrıştırma ve simülasyonu.
- **ARP Spoofing ve Zehirleme Tespiti:**
  - Bir IP'ye bağlı MAC adresinin aniden değişmesi (`MAC_FLIP`).
  - Tek bir MAC adresinin birden fazla kurumsal IP'yi sahiplenmesi (`SINGLE_MAC_MULTIPLE_IP_ABUSE`).
  - DHCP Snooping veritabanı ile Dynamic ARP Inspection (DAI) doğrulaması.
- **Raporlama:** Önbellek durumunu ve tespit edilen güvenlik alarmlarını Markdown formatında üretme.
- **Kod Açıklamaları:** Tüm uygulama ve test kodları satır satır didaktik yorumlarla açıklanmıştır.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_07/gun_047/
├── README.md                                    # Modül dokümantasyonu ve çalıştırma kılavuzu
├── ders.md                                      # Usta-Çırak pedagojisiyle hazırlanmış ARP dersi
├── soru_cevap.md                                # Soru bankası (G047-SC1/2/3) 4 başlıklı cevapları
├── rapor.md                                     # 100/100 rubrik değerlendirme ve teknik rapor
├── sonuc.json                                   # Gün sonu standart makine çıktısı
├── manifest.json                                # SHA-256 doğruluk ve bütünlük tablosu
├── uygulama/
│   ├── __init__.py                              # Paket başlatıcı
│   └── arp_neighbor_analyzer.py                 # ARP önbellek ve zehirleme tespit motoru
├── tests/
│   ├── __init__.py                              # Test paketi başlatıcı
│   └── test_arp_neighbor_analyzer.py            # 14 birim testi ve negatif kontroller
├── ornek_veri/
│   ├── sample_arp_tables.json                   # 5 önbellek girişi ve 4 ARP trafik olayı
│   └── invalid_arp_entries.json                 # 8 geçersiz girdi ve biçim hata senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                   # pytest 14/14 PASS kanıtı
    │   ├── komut_ve_cikis.txt                   # Konsol yürütme çıktısı
    │   ├── arp_analiz_raporu.txt                # Üretilen Markdown analiz raporu
    │   └── negatif_kontrol_sonuclari.txt        # 8 negatif vakanın yakalanma raporu
    └── temsili/
        └── arp_ve_mitm_zehirleme_mimarisi.txt   # Kavramsal mimari, MitM ve DAI savunma şeması
```

---

## 🚀 Hızlı Başlangıç ve Çalıştırma

### 1. ARP Analiz ve Zehirleme Tespit Motorunu Çalıştırma
```powershell
python portfolio/hafta_07/gun_047/uygulama/arp_neighbor_analyzer.py
```

### 2. Birim ve Güvenlik Testlerini Koşma
```powershell
pytest portfolio/hafta_07/gun_047/tests/test_arp_neighbor_analyzer.py -v
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
