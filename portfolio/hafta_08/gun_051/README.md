# Gün 051: TCP Sıralama, Akış Kontrolü ve Yeniden İletim

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

Bu çalışma, Siber Güvenlik 365 Günlük Müfredatı kapsamında Aşama 03 (Ağ Temelleri ve Ağ Güvenliği), Hafta 08, Gün 051 çalışmasıdır.

---

## 📋 Proje Özeti

Katman-4 Taşıma Katmanı protokollerinden TCP'nin bayt akışı (byte-stream) sıralama mimarisini, kümülatif onay (Cumulative ACK) mekanizmasını, kayar pencere (Sliding Window) akış kontrolünü, paket kayıpları durumunda çalışan zaman aşımı (RTO) ve 3 Yinelenen Onay (Triple Duplicate ACK) ile Hızlı Yeniden İletim (Fast Retransmit) algoritmalarını inceleyen; "yinelenen paketler tek başına saldırı değildir" felsefesini doğrulayan ve Blind TCP Reset (RST) Injection ile Sıfır Pencere DoS tehditlerini analiz eden kapsamlı bir laboratuvar paketidir.

### Temel Özellikler
- **TCP Bayt Akışı ve Sıralama Modellemesi:** `next_seq = seq_no + payload_len` matematiksel takibi ve kümülatif onayların kurgulanması.
- **Kayar Pencere ve Akış Kontrolü:** Gönderici/alıcı tampon sınırları, pencere boyutu (Window Size) takibi ve alıcı tamponunun dolması durumunda ortaya çıkan Sıfır Pencere (`Window = 0`) analizi.
- **Paket Kaybı ve Yeniden İletim:**
  - Sıra dışı gelen paketlerin (Out-of-Order Segments) ve aradaki veri boşluklarının (Gaps) tespiti.
  - Alıcının son eksiksiz baytı tekrarlaması (Duplicate ACK).
  - Peş peşe 3 adet yinelenen onay ile devreye giren **Hızlı Yeniden İletim (Fast Retransmit)** tetiklenmesi ve kayıp parçanın tekrar iletilerek boşluğun kapatılması.
- **Güvenlik Tehditleri ve Anomali Analizi:**
  - `TCP_BLIND_RST_INJECTION_SALDIRISI`: Aktif kayar pencere içine sahte sıra numarasıyla enjekte edilen Blind TCP Reset (RST) saldırısının tespiti.
  - `TCP_ZERO_WINDOW_DOS_RISKI`: İstemcinin sunucuyu kilitlemek amacıyla `Window=0` anons etmesiyle oluşan kaynak kilitlenmesi analizi.
  - Ağ gecikmesi kaynaklı sahte yeniden iletimler (Spurious Retransmissions) ile gerçek siber saldırıların ayrıştırılması.
- **Satır Satır Açıklamalı Kod:** Uygulama ve test kodlarının tamamı didaktik açıklamalarla zenginleştirilmiştir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_08/gun_051/
├── README.md                                    # Modül dokümantasyonu ve çalıştırma kılavuzu
├── ders.md                                      # Usta-Çırak pedagojisiyle hazırlanmış TCP sıralama dersi
├── soru_cevap.md                                # Soru bankası (G051-SC1/2/3) 4 başlıklı cevapları
├── rapor.md                                     # 100/100 rubrik değerlendirme ve teknik rapor
├── sonuc.json                                   # Gün sonu standart makine çıktısı
├── manifest.json                                # SHA-256 doğruluk ve bütünlük tablosu
├── uygulama/
│   ├── __init__.py                              # Paket başlatıcı
│   └── tcp_sequence_retransmit_analyzer.py      # TCP sıralama ve yeniden iletim analiz motoru
├── tests/
│   ├── __init__.py                              # Test paketi başlatıcı
│   └── test_tcp_sequence_retransmit_analyzer.py # 14 birim testi ve güvenlik doğrulamaları
├── ornek_veri/
│   ├── sample_retransmit_packets.json           # 14 segmentlik TCP akış ve anomali veri seti
│   └── invalid_sequence_inputs.json             # 8 geçersiz girdi ve biçim hata senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                   # pytest 14/14 PASS kanıtı
    │   ├── komut_ve_cikis.txt                   # Konsol yürütme çıktısı
    │   ├── tcp_siralama_ve_retransmit_raporu.txt# Üretilen Markdown analiz raporu
    │   └── negatif_kontrol_sonuclari.txt        # 8 negatif vakanın yakalanma raporu
    └── temsili/
        └── tcp_sliding_window_ve_retransmission_mimarisi.txt # Kayar pencere ve Fast Retransmit şeması
```

---

## 🚀 Hızlı Başlangıç ve Çalıştırma

### 1. TCP Sıralama ve Yeniden İletim Motorunu Çalıştırma
```powershell
python portfolio/hafta_08/gun_051/uygulama/tcp_sequence_retransmit_analyzer.py
```

### 2. Birim ve Güvenlik Testlerini Koşma
```powershell
pytest portfolio/hafta_08/gun_051/tests/test_tcp_sequence_retransmit_analyzer.py -v
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
