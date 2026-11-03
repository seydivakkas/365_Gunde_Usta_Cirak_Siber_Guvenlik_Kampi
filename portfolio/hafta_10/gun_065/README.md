# G065: Hafta 10 Gün 65 — Follow TCP Stream ve Yeniden Birleştirme (TCP Stream Reassembly)

![Lisans: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama: 03](https://img.shields.io/badge/Asama-03-blue?style=flat-square)
![Hafta: 10](https://img.shields.io/badge/Hafta-10-indigo?style=flat-square)
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

Bu proje, IP katmanında bağımsız ve dağınık paketler halinde iletilen verileri, TCP sıra numaraları (Sequence Numbers) üzerinden milimetrik hassasiyetle sıralayan ve Wireshark **"Follow TCP Stream"** formatında çift yönlü diyalog haline getiren bir yeniden birleştirme motoru sunar.

Motor, sıra dışı (out-of-order) segmentleri arabelleğe alır, ardışık parçalar ulaştığında kuyruğu çözer, yinelenen (retransmission/duplicate) paketleri ayıklar ve kötü niyetli örtüşen (overlapping segment IDS evasion - Ptacek & Newsham 1998) saldırı girişimlerini tespit eder.

### Temel Yetenekler
- **TCP Bayt Akışı Modeli:** Başlangıç sıra numarası (ISN) tespiti ve göreceli (relative) sıra numarası hesaplama.
- **Sıra Dışı Segment Arabellekleme:** Sırası henüz gelmemiş paketleri kuyrukta saklar; eksik parça geldiğinde otomatik birleştirir.
- **Yeniden İletim ve Kopya Ayıklama:** Aynı sıra numarasına sahip yinelenen paketleri tespit eder ve akışı kirletmeden eler.
- **Örtüşme ve IDS Evasion Denetimi:** Çelişkili örtüşen segmentlerde veri tutarsızlığını yakalar (`OverlappingPayloadConflictError`).
- **Wireshark Follow Stream Çıktısı:** İstemci isteklerini kırmızı, sunucu yanıtlarını mavi etiketli kronolojik diyalog olarak biçimlendirir.

---

## Dizin Yapısı

```
portfolio/hafta_10/gun_065/
├── README.md                               # Proje genel bakış ve lisans belgesi
├── ders.md                                 # Usta-çırak teorik ders anlatımı
├── soru_cevap.md                           # 3 vaka analizi ve 4 zorunlu alt başlık
├── rapor.md                                # 100/100 değerlendirme ve doğrulama raporu
├── sonuc.json                              # 14 standart alanlı makine tarafından okunabilir çıktı
├── manifest.json                           # Dosya SHA-256 bütünlük özeti
├── uygulama/
│   ├── __init__.py
│   └── tcp_stream_reassembler.py           # TCP Stream yeniden birleştirme motoru
├── tests/
│   ├── __init__.py
│   └── test_tcp_stream_reassembler.py      # 14 birim test paketi
├── ornek_veri/
│   ├── sample_tcp_stream.json              # 11 segmentli örnek çift yönlü TCP HTTP akışı
│   └── invalid_stream_inputs.json          # 9 negatif sınır ve anomali senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt              # 14 birim testin koşu çıktısı
    │   ├── komut_ve_cikis.txt              # Terminal yürütme logları
    │   ├── tcp_stream_birlestirme_raporu.txt # Follow Stream diyaloğu ve metrik raporu
    │   └── negatif_kontrol_sonuclari.txt   # 9/9 negatif sınır test sonucu
    └── temsili/
        └── tcp_stream_birlestirme_mimarisi.txt # Reassembly durum makinesi ve Follow Stream şeması
```

---

## Testleri Çalıştırma

Tüm testleri kök dizinden çalıştırmak için:

```bash
python -m unittest portfolio.hafta_10.gun_065.tests.test_tcp_stream_reassembler -v
```
