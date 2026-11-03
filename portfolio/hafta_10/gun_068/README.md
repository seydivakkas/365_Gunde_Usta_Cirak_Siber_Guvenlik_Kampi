# G068: Ağ Günlükleri ve Kişisel Veri (PII) Arındırma Motoru

![Lisans: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Aşama: 03](https://img.shields.io/badge/A%C5%9Fama-03%20A%C4%9F%20G%C3%BCvenli%C4%9Fi-blue?style=flat-square)
![Hafta: 10](https://img.shields.io/badge/Hafta-10-green?style=flat-square)
![Test: 14/14 PASS](https://img.shields.io/badge/Test-14%2F14%20PASS-brightgreen?style=flat-square)
![Not: 100/100](https://img.shields.io/badge/Not-100%2F100-success?style=flat-square)

---

## 📌 Proje Genel Bakışı

Bu proje, kurumsal ağ ve güvenlik operasyon merkezlerinde (SOC) toplanan telemetrilerde (PCAP, NetFlow, Zeek, Syslog, Web Günlükleri) yer alan kişisel verileri (PII - Personally Identifiable Information) tespit eden, arındıran ve KVKK / GDPR standartlarına tam uyumlu hale getiren endüstriyel bir güvenlik motorudur.

Sistem, IP adreslerini alt ağ maskeleme (`/24`) ve tuzlu HMAC-SHA256 sözde-anonimleştirme (Pseudonymization) ile korur; MAC adreslerinin donanım üretici kodunu (OUI) muhafaza ederek cihaz kimliğini gizler; HTTP başlıklarındaki oturum jetonlarını (`Authorization: Bearer`, `Cookie`) ve URI sorgu parametrelerindeki e-posta, TCKN ve telefon numaralarını adli bilişim kanıt değerini zedelemeden arındırır.

---

## 🛠️ Temel Yetenekler ve Teknik Mimarisi

- **IP Maskeleme & Sözde-Anonimleştirme:**
  - Alt Ağ Maskeleme (`192.168.1.145` $\longrightarrow$ `192.168.1.0/24`).
  - Tuzlu Kriptografik Özetleme (`IP_PSEUDO_...` ile korelasyon yeteneği korunur).
- **MAC Adresi Donanım Koruması:** Üretici OUI kısmı korunarak cihaz kimliği gizlenir (`00:1A:2B:XX:XX:XX`).
- **HTTP Yetki ve Oturum Başlık Arındırması:** `Authorization: Bearer [REDACTED_TOKEN]` ve `Cookie: [REDACTED_SESSION_COOKIE]`.
- **URI Query Sanitization:** `?email=...&tckn=...` parametrelerinin otomatik regex tespiti ve URL-encoded maskelemesi.
- **Finansal ve Kimlik Verisi Koruması:** PCI-DSS uyumlu kredi kartı maskeleme (`4543 **** **** 9012`), TCKN maskeleme (`12*******01`) ve telefon redaksiyonu.
- **Yasal Saklama Süresi Denetimi (Log Retention):** 730 günden (2 yıl) eski kayıtların otomatik tespiti ve imha uyarısı.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_10/gun_068/
├── uygulama/
│   ├── __init__.py
│   └── network_log_pii_sanitizer.py
├── tests/
│   ├── __init__.py
│   └── test_network_log_pii_sanitizer.py
├── ornek_veri/
│   ├── sample_raw_network_logs.json
│   └── invalid_sanitization_inputs.json
├── kanit/
│   ├── gercek/
│   │   ├── test_sonuclari.txt
│   │   ├── komut_ve_cikis.txt
│   │   ├── negatif_kontrol_sonuclari.txt
│   │   └── kisisel_veri_arindirma_raporu.txt
│   └── temsili/
│       └── pii_sanitization_mimarisi.txt
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
python -m unittest portfolio.hafta_10.gun_068.tests.test_network_log_pii_sanitizer -v
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
