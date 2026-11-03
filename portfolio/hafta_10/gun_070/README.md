# Gün 070: Aşama 3 Kalite Özeti ve Ağ Analizi Kabulü

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Stage: 03 Complete](https://img.shields.io/badge/Stage-03%20Complete-brightgreen?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/Score-100%2F100-success?style=flat-square)
![Tests: 14/14 PASS](https://img.shields.io/badge/Tests-14%2F14%20PASS-blue?style=flat-square)
![Negative Controls: 9/9 PASS](https://img.shields.io/badge/Negative%20Controls-9%2F9%20PASS-blue?style=flat-square)

## Lisans ve Telif Hakkı

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

---

## Genel Bakış

Bu paket, **Siber Güvenlik 365 Gün Müfredatı** kapsamında **Aşama 03 (Ağ Analizi ve Güvenliği - Gün 51-70)** safhasının tüm gereksinimlerini denetleyen, 6 temel kalite sütununu doğrulayan ve kriptografik kabul sertifikası üreten kurumsal kabul motorunu içerir.

### 6 Temel Kalite Sütunu:
1. **Paket Yakalama ve Ekran Filtreleri (Gün 51-57):** PCAP başlıkları, BPF ve ekran filtreleri, hiyerarşik istatistikler ve konuşma matrisleri.
2. **TCP Akış Rekonstrüksiyonu ve Filtreleme Otomasyonu (Gün 58-60):** Follow TCP Stream, Boole mantığıyla filtre birleştirme ve PCAP temizleme/arındırma.
3. **Temel L2-L4 Ağ Protokolleri Güvenliği (Gün 61-63):** ARP zehirlenmesi, ICMP keşfi, Rogue DHCP ve DNS çözümleme riskleri.
4. **L7 Protokolleri, TLS Kriptografi ve Zaman Çizelgesi (Gün 64-65):** Düz metin HTTP ile TLS 1.3 ayrımı, SNI analizi ve adli zaman çizelgesi.
5. **Ağ Anomalileri, Tünelleme ve QoS Performansı (Gün 66-67):** DGA entropisi, DNS tünelleme, HTTP Smuggling, paket kaybı, RTT ve RFC 3393/3550 jitter.
6. **KVKK/GDPR Gizlilik, PII Maskeleme ve Adli Ağ Raporlaması (Gün 68-70):** PII maskeleme (/24 IP, MAC, TCKN), Wireshark adli güvenlik skoru ve kabul tescili.

---

## Dizin Yapısı

```
portfolio/hafta_10/gun_070/
├── uygulama/
│   ├── __init__.py
│   └── asama_3_kalite_ozeti_analizor.py     # Aşama 3 kabul ve kalite denetim motoru
├── tests/
│   ├── __init__.py
│   └── test_asama_3_kalite_ozeti_analizor.py# 14 birim test ve 9 negatif kontrol
├── ornek_veri/
│   ├── asama_3_gunluk_metrikleri.json       # 20 günlük tam aşama metrikleri
│   └── invalid_asama_3_inputs.json          # 9 negatif sınır test senaryosu
├── kanit/
│   ├── gercek/
│   │   ├── asama_3_kalite_ozeti_raporu.txt  # Üretilen resmi kabul raporu
│   │   ├── komut_ve_cikis.txt               # Terminal komut ve çıktı kanıtı
│   │   ├── negatif_kontrol_sonuclari.txt    # 9 negatif kontrol doğrulama özeti
│   │   └── test_sonuclari.txt               # 14 birim test terminal çıktısı
│   └── temsili/
│       └── asama_3_kalite_mimarisi.txt      # 6 Sütun ve kabul mimarisi ASCII şeması
├── ders.md                                  # Usta-Çırak Aşama 3 kabul dersi
├── soru_cevap.md                            # 3 derinlemesine teknik soru ve cevap
├── rapor.md                                 # 100/100 tam puanlı kabul raporu
├── README.md                                # Proje dokümantasyonu ve lisans bildirimi
├── sonuc.json                               # 14 standartlaştırılmış aşama alanı
└── manifest.json                            # SHA-256 dosya bütünlük listesi
```

---

## Çalıştırma ve Test Talimatları

### Birim Testleri Çalıştırma:
```bash
python -m unittest portfolio.hafta_10.gun_070.tests.test_asama_3_kalite_ozeti_analizor -v
```

### Aşama 3 Denetim Motorunu Çalıştırma:
```bash
python -m portfolio.hafta_10.gun_070.uygulama.asama_3_kalite_ozeti_analizor \
    --input portfolio/hafta_10/gun_070/ornek_veri/asama_3_gunluk_metrikleri.json \
    --output-txt portfolio/hafta_10/gun_070/kanit/gercek/asama_3_kalite_ozeti_raporu.txt
```
