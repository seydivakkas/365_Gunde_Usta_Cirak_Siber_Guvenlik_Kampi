# G069: Mini Proje 9 - Wireshark Analiz Raporu Üretici Motoru

![Lisans: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama: 03](https://img.shields.io/badge/A%C5%9Fama-03%20A%C4%9F%20G%C3%BCvenli%C4%9Fi-blue?style=flat-square)
![Hafta: 10](https://img.shields.io/badge/Hafta-10-green?style=flat-square)
![Test: 14/14 PASS](https://img.shields.io/badge/Test-14%2F14%20PASS-brightgreen?style=flat-square)
![Not: 100/100](https://img.shields.io/badge/Not-100%2F100-success?style=flat-square)

---

## 📌 Proje Genel Bakışı

Bu proje, Hafta 10 boyunca işlenen tüm ağ güvenliği ve Wireshark analizi kazanımlarını (Wireshark filtreleri, Follow TCP Stream, DNS/HTTP anomalileri, QoS/Jitter hesaplamaları ve PII arındırma) sentezleyen **Mini Proje 9** bitirme çalışmasıdır.

Sistem, ayrıştırılmış ağ yakalama (PCAP) telemetrisini otomatik olarak inceler; protokol hiyerarşisi dağılımını, en aktif konuşmacıları (Top Talkers), TCP bağlantı sağlığını (Zero Window, Retransmission), siber saldırı göstergelerini (SQL Injection, DNS Tünelleme, Açık Parola İfşası, CRLF Enjeksiyonu) ve adli tehdit göstergelerini (IoC) konsolide ederek hem C-Level yöneticiler hem de SOC analistleri için adli analiz raporları (TEXT ve JSON) üretir.

---

## 🛠️ Temel Yetenekler ve Teknik Mimarisi

- **Protokol Hiyerarşisi Analizi:** L2'den L7'ye kadar tüm paketlerin sayısal ve bayt hacmi dağılımının (% oranlarıyla) çıkarılması.
- **Konuşma Analizi (Conversations):** 5-demet (IP/Port/Protokol) eşleştirmesi ile en çok bant genişliği tüketen uç noktaların belirlenmesi.
- **TCP Sağlık ve Anomali İncelemesi:** TCP 3-Way Handshake, Zero Window tıkanıklıkları ve yeniden iletimlerin (Retransmissions) izlenmesi.
- **Siber Tehdit Avcılığı:**
  - SQL Injection & Otomatik Tarayıcı (sqlmap) Tespiti.
  - TXT Tipi DNS Tünelleme ve Veri Kaçırma (Data Exfiltration) Tespiti.
  - Telnet/FTP Açık Metin Parola İletim İhlali Tespiti.
  - HTTP CRLF Başlık Enjeksiyonu ve Response Splitting Tespiti.
- **Yönetici Güvenlik Skoru:** 100 tam puan üzerinden bulunan zafiyetlerin risk ağırlığına göre puan düşülerek kurumsal güvenlik seviyesinin hesaplanması.
- **Adli IoC Tablosu:** Saldırgan IP'leri, zararlı alan adları ve ele geçirilen kimliklerin çıkarılması.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_10/gun_069/
├── uygulama/
│   ├── __init__.py
│   └── wireshark_analysis_report_generator.py
├── tests/
│   ├── __init__.py
│   └── test_wireshark_analysis_report_generator.py
├── ornek_veri/
│   ├── sample_pcap_dissection.json
│   └── invalid_report_inputs.json
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt
│   │   ├── komut_ve_cikis.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   └── wireshark_analiz_raporu_ciktisi.txt
│   └── temsili/
│       └── wireshark_raporlama_mimarisi.txt
├── ders.md
├── soru_cevap.md
├── rapor.md
├── sonuc.json
├── manifest.json
└── README.md
```

---

## 🚀 Çalıştırma ve Test

Birim testlerini ve doğrulama paketini çalıştırmak için:

```bash
python -m unittest portfolio.hafta_10.gun_069.tests.test_wireshark_analysis_report_generator -v
```

---

## ⚖️ Lisans ve Kullanım Şartları

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
