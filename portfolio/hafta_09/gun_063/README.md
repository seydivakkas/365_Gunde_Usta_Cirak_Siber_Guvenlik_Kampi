# G063: Hafta 09 Mini Proje 8 — Protokol Zaman Çizelgesi (Protocol Timeline Analyzer)

![Lisans: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama: 03](https://img.shields.io/badge/Asama-03-blue?style=flat-square)
![Hafta: 09](https://img.shields.io/badge/Hafta-09-indigo?style=flat-square)
![Test Durumu: 14/14 PASS](https://img.shields.io/badge/Tests-14%2F14%20PASS-brightgreen?style=flat-square)
![Puan: 100/100](https://img.shields.io/badge/Puan-100%2F100-success?style=flat-square)

---

## Lisans ve Kullanım Koşulları

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

## Proje Genel Bakış

Bu mini proje, Hafta 09 boyunca incelenen tüm ağ protokollerini (DNS, TCP, TLS 1.3, HTTP/2, Proxy/NAT ve VLAN) zaman serisi bazında analiz eden bir motor sunar. Ham paket izlerini mikrosaniye hassasiyetinde sıralar, çift yönlü 5-demet akış oturumlarını yeniden oluşturur, paketler arası gecikmeleri ($\Delta t$) ve RTT sürelerini hesaplar, merdiven (ladder) biçimli ASCII zaman çizelgesi çizer ve zamansal siber saldırı kalıplarını otonom olarak tespit eder.

### Temel Yetenekler
- **Kesin Monotonik Zaman Sıralaması:** ISO-8601 zaman damgalarını epoch saniyeye dönüştürerek saat gerilemesi ve saat sapması (clock skew) manipülasyonlarını yakalar.
- **TCP Sonlu Durum Makinesi:** SYN $\to$ SYN-ACK $\to$ ACK $\to$ FIN-ACK $\to$ ACK durum geçişlerini doğrular; el sıkışma RTT süresini hesaplar.
- **TLS 1.3 ve HTTP/2 Entegrasyonu:** TLS oturum kurulumunu izler, HTTP/2 eşzamanlı akımlarını (streams) paralel olarak ayrıştırır.
- **Kapsamlı Anomali Tespit Motoru:**
  - Hızlı Port Taraması (SYN Burst)
  - Slowloris Düşük ve Yavaş Başlık Damlatma Saldırısı
  - TCP Sıra Numarası Sıçraması (Session Hijacking)
  - El Sıkışma Öncesi Erken Veri Enjeksiyonu
  - Yüksek Entropili DNS Tünelleme Patlaması

---

## Dizin Yapısı

```
portfolio/hafta_09/gun_063/
├── README.md                                   # Proje genel bakış ve lisans belgesi
├── ders.md                                     # Usta-çırak teorik ders anlatımı
├── soru_cevap.md                               # 3 vaka analizi ve 4 zorunlu alt başlık
├── rapor.md                                    # 100/100 değerlendirme ve doğrulama raporu
├── sonuc.json                                  # 14 standart alanlı makine tarafından okunabilir çıktı
├── manifest.json                               # Dosya SHA-256 bütünlük özeti
├── uygulama/
│   ├── __init__.py
│   └── protocol_timeline_analyzer.py           # Protokol zaman serisi analiz motoru
├── tests/
│   ├── __init__.py
│   └── test_protocol_timeline_analyzer.py      # 14 birim test paketi
├── ornek_veri/
│   ├── sample_network_trace.json               # Standart çoklu protokol ağ izi
│   └── invalid_timeline_inputs.json            # 9 negatif sınır ve anomali senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                  # 14 birim testin koşu çıktısı
    │   ├── komut_ve_cikis.txt                  # Terminal yürütme logları
    │   ├── protokol_zaman_cizelgesi_raporu.txt # Motorun ürettiği analiz ve ASCII merdiven çıktısı
    │   └── negatif_kontrol_sonuclari.txt       # 9/9 negatif sınır test sonucu
    └── temsili/
        └── protokol_zaman_cizelgesi_mimarisi.txt # Kavramsal mimari şeması
```

---

## Testleri Çalıştırma

Tüm testleri kök dizinden çalıştırmak için:

```bash
python -m unittest portfolio.hafta_09.gun_063.tests.test_protocol_timeline_analyzer -v
```
