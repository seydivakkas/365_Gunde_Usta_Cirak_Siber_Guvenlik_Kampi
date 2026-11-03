# G066: DNS ve HTTP Anomali İşaretleri Tespit Motoru

![Lisans: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama: 03](https://img.shields.io/badge/A%C5%9Fama-03%20A%C4%9F%20G%C3%BCvenli%C4%9Fi-blue?style=flat-square)
![Hafta: 10](https://img.shields.io/badge/Hafta-10-green?style=flat-square)
![Test: 14/14 PASS](https://img.shields.io/badge/Test-14%2F14%20PASS-brightgreen?style=flat-square)
![Not: 100/100](https://img.shields.io/badge/Not-100%2F100-success?style=flat-square)

---

## 📌 Proje Genel Bakışı

Bu proje, modern siber savunma merkezlerinde (SOC) ve tehdit avcılığı (threat hunting) operasyonlarında DNS ve HTTP protokolleri üzerinden gerçekleştirilen siber saldırıları ve anomalileri tespit eden yüksek performanslı bir analiz motorudur.

Sistem, DGA (Domain Generation Algorithm) alan adlarını Şannon bilgi entropisi ve harf frekanslarıyla yakalar; DNS tünelleme üzerinden veri sızdırmayı (data exfiltration), DNS yansıtma ve büyütme (amplification) DoS saldırılarını ve Fast Flux botnet C2 altyapılarını tespit eder. HTTP tarafında ise RFC 7230 ihlali olan Request Smuggling (CL.TE / TE.CL çatışması), CRLF başlık enjeksiyonu (Response Splitting), Dizin Geçişi (Path Traversal / LFI) ve otomatik saldırı tarayıcılarını (sqlmap, nikto, vb.) imza ve kural tabanlı yaklaşımlarla adli rapor haline getirir.

---

## 🛠️ Temel Yetenekler ve Teknik Mimarisi

- **DGA Tespiti:** Şannon Entropisi ($H \ge 3.4$), sessiz harf oranı ($\ge 0.65$) ve etiket uzunluğu ($\ge 12$).
- **DNS Tünelleme Tespiti:** TXT sorgu yükleri, FQDN uzunluğu $> 45$, Base64 şüpheli etiket analizi.
- **DNS Amplification Tespiti:** Yanıt/istek boyutu büyütme katsayısı ($\ge 25\times$) ve devasa `ANY` sorguları.
- **Fast Flux Botnet C2 Tespiti:** Mikro-TTL ($\le 30$ sn) ve dinamik IP havuzu ($\ge 5$ IP).
- **HTTP Request Smuggling Tespiti:** Tek bir istekte hem `Content-Length` hem de `Transfer-Encoding` varlığının yakalanması.
- **HTTP CRLF & Header Injection Tespiti:** URL kodlu `%0d%0a`, `\r\n` ve sahte `Set-Cookie` enjeksiyonları.
- **Path Traversal Tespiti:** `../`, `..\\`, `/etc/passwd` ve `win.ini` kaçış desenleri.
- **Otomatik Tarayıcı Avı:** Bilinen saldırı araçlarının User-Agent imzalarının filtrelenmesi.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_10/gun_066/
├── uygulama/
│   ├── __init__.py
│   └── dns_http_anomaly_detector.py
├── tests/
│   ├── __init__.py
│   └── test_dns_http_anomaly_detector.py
├── ornek_veri/
│   ├── sample_traffic_indicators.json
│   └── invalid_anomaly_inputs.json
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt
│   │   ├── komut_ve_cikis.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   └── dns_http_anomali_raporu.txt
│   └── temsili/
│       └── dns_http_anomali_mimarisi.txt
├── ders.md
├── soru_cevap.md
├── rapor.md
├── sonuc.json
├── manifest.json
└── README.md
```

---

## 🚀 Çalıştırma ve Test

Birim testleri ve doğrulama paketini çalıştırmak için:

```bash
python -m unittest portfolio.hafta_10.gun_066.tests.test_dns_http_anomaly_detector -v
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
