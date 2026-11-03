# Gün 048: ICMP Protokolü, Ağ Teşhisi ve Güvenlik Analizi

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

Bu çalışma, Siber Güvenlik 365 Günlük Müfredatı kapsamında Aşama 03 (Ağ Temelleri ve Ağ Güvenliği), Hafta 07, Gün 048 çalışmasıdır.

---

## 📋 Proje Özeti

Katman 3 ICMP (RFC 792) kontrol ve hata bildirim mekanizmalarını, RFC 1071 İnternet sağlama toplamı (checksum) algoritmasını, Ping (Echo Request/Reply) döngülerini, Traceroute (TTL Exceeded) sekme çözümleme mekanizmasını, Path MTU Discovery (PMTUD) dinamiklerini ve ICMP tünelleme (Covert Channel) güvenlik anomalilerini inceleyen ve modelleyen kapsamlı laboratuvar paketidir.

### Temel Özellikler
- **RFC 792 İkili Paket Modellemesi:** Tip (Type), Kod (Code), Sağlama Toplamı (Checksum) ve yük (Payload) ikili seviyede paketlenir ve ayrıştırılır.
- **RFC 1071 Sağlama Toplamı Motoru:** 16-bit 1'e tümleyen (1's complement) sağlama toplamı hesaplama ve sıfırlayarak doğrulama motoru sıfırdan geliştirilmiştir.
- **Ağ Teşhis ve Hata Raporlama:**
  - `Echo Request` (Tip 8) ve `Echo Reply` (Tip 0) döngüleri.
  - `Destination Unreachable` (Tip 3 Kod 1, 3, 4 - Host/Port Unreachable ve PMTUD Parçalanma Uyarısı).
  - `Time Exceeded` (Tip 11 Kod 0 - TTL Süresi Doldu).
  - `Redirect` (Tip 5 Kod 1 - Ağ Geçidi Yönlendirmesi).
- **Traceroute Simülasyonu:** TTL değerini 1'den artırarak ara düğümlerin kimliğini ve gecikmesini tespit eden simülasyon motoru.
- **Güvenlik Anomali Tespiti:**
  - Yük içine gizlenmiş Base64 veya yüksek entropili veri sızıntılarını (`ICMP_COVERT_CHANNEL_EXFILTRATION`) tespit etme.
  - Yanıltıcı ICMP Redirect saldırılarını ve PMTUD Black Hole risklerini analiz etme.
- **Satır Satır Açıklamalı Kod:** Uygulama ve test kodlarının tamamı didaktik açıklamalarla zenginleştirilmiştir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_07/gun_048/
├── README.md                                    # Modül dokümantasyonu ve çalıştırma kılavuzu
├── ders.md                                      # Usta-Çırak pedagojisiyle hazırlanmış ICMP dersi
├── soru_cevap.md                                # Soru bankası (G048-SC1/2/3) 4 başlıklı cevapları
├── rapor.md                                     # 100/100 rubrik değerlendirme ve teknik rapor
├── sonuc.json                                   # Gün sonu standart makine çıktısı
├── manifest.json                                # SHA-256 doğruluk ve bütünlük tablosu
├── uygulama/
│   ├── __init__.py                              # Paket başlatıcı
│   └── icmp_diagnostic_analyzer.py              # RFC 792 ICMP ayrıştırıcı ve anomali analiz motoru
├── tests/
│   ├── __init__.py                              # Test paketi başlatıcı
│   └── test_icmp_diagnostic_analyzer.py         # 14 birim testi ve negatif kontroller
├── ornek_veri/
│   ├── sample_icmp_packets.json                 # 8 farklı ICMP paket tipi ve yük örneği
│   └── invalid_icmp_packets.json                # 8 geçersiz girdi ve biçim hata senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                   # pytest 14/14 PASS kanıtı
    │   ├── komut_ve_cikis.txt                   # Konsol yürütme çıktısı
    │   ├── icmp_teshis_raporu.txt               # Üretilen Markdown analiz raporu
    │   └── negatif_kontrol_sonuclari.txt        # 8 negatif vakanın yakalanma raporu
    └── temsili/
        └── icmp_traceroute_ve_covert_channel_mimarisi.txt # Echo, Traceroute ve Tünelleme şeması
```

---

## 🚀 Hızlı Başlangıç ve Çalıştırma

### 1. ICMP Analiz ve Teşhis Motorunu Çalıştırma
```powershell
python portfolio/hafta_07/gun_048/uygulama/icmp_diagnostic_analyzer.py
```

### 2. Birim ve Güvenlik Testlerini Koşma
```powershell
pytest portfolio/hafta_07/gun_048/tests/test_icmp_diagnostic_analyzer.py -v
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
