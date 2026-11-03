# Gün 054: DNS Sorguları ve Kayıt Türleri

![Lisans: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Durum: Tamamlandı](https://img.shields.io/badge/durum-Tamamland%C4%B1-brightgreen?style=flat-square)
![Puan: 100/100](https://img.shields.io/badge/puan-100%2F100-blue?style=flat-square)
![Aşama: 03](https://img.shields.io/badge/a%C5%9Fama-03-orange?style=flat-square)
![Hafta: 08](https://img.shields.io/badge/hafta-08-yellow?style=flat-square)

---

## 🔒 Özel Lisans Bildirimi

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

## 📌 Proje Genel Bakış

Bu çalışma, **Siber Güvenlik 365 Gün Müfredatı** kapsamında 8. Haftanın 54. Günü için geliştirilmiş bağımsız, yerel çalışan bir **DNS (Domain Name System) Sorguları ve Kayıt Türleri Analizörüdür**.

RFC 1034 ve RFC 1035 standartlarına uygun olarak 12 baytlık ikili DNS başlığı paketleme, etiket (label) tabanlı alan adı kodlama/çözümleme, temel kaynak kayıtları (A, AAAA, CNAME, MX, TXT) modellemesi, ve "DNS Yanıtı Doğrulanmış Kimlik Değildir" ilkesi doğrultusunda SPF/DMARC e-posta güvenliği denetimi, Sahipsiz CNAME (Subdomain Takeover) tespiti ile Shannon Entropisi tabanlı DNS Tünelleme (Data Exfiltration) analizlerini yürütür.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_08/gun_054/
├── README.md                                           # Proje tanıtımı ve özel lisans
├── ders.md                                             # Usta-Çırak pedagojisi ile kapsamlı ders notu
├── soru_cevap.md                                       # Soru bankası (G054-SC1, SC2, SC3) detaylı yanıtları
├── rapor.md                                            # 100/100 rubrik puanlı teknik inceleme raporu
├── sonuc.json                                          # Standartlaştırılmış gün sonuç verisi
├── manifest.json                                       # SHA256 bütünlük özeti
├── uygulama/
│   ├── __init__.py                                     # Paket başlatıcı
│   └── dns_query_record_analyzer.py                    # DNS analizör ve güvenlik denetim motoru
├── tests/
│   ├── __init__.py                                     # Test başlatıcı
│   └── test_dns_query_record_analyzer.py               # 14 birim ve negatif test (%100 PASS)
├── ornek_veri/
│   ├── sample_dns_zone_and_queries.json                # Gerçekçi DNS bölge kayıtları ve şüpheli sorgular
│   └── invalid_dns_inputs.json                         # 8 adet sınır aşımı ve negatif test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                          # 14/14 PASS birim test konsol çıktısı
    │   ├── komut_ve_cikis.txt                          # Komut çalıştırma ve durum kayıtları
    │   ├── dns_sorgu_ve_kayit_raporu.txt               # DNS bölge ve tehdit güvenlik raporu
    │   └── negatif_kontrol_sonuclari.txt               # 8/8 engellenen geçersiz girdi kanıtları
    └── temsili/
        └── dns_hiyerarsi_ve_kayit_guvenlik_mimarisi.txt # Temsilî hiyerarşi ve ASCII diyagramı
```

---

## 🚀 Hızlı Başlangıç ve Çalıştırma

### 1. Birim Testleri Çalıştırma:
```bash
python -m unittest portfolio/hafta_08/gun_054/tests/test_dns_query_record_analyzer.py -v
```

### 2. DNS Güvenlik Denetimi Çalıştırma:
```python
from portfolio.hafta_08.gun_054.uygulama.dns_query_record_analyzer import DNSRecord, DNSSecurityAuditor

auditor = DNSSecurityAuditor()
record = DNSRecord("blog.example.com", "CNAME", 300, "abandoned.s3-website-us-east-1.amazonaws.com")
takeover_report = auditor.audit_subdomain_takeover([record])
print(takeover_report["bulgular"])
```

---

## 🛡️ Güvenlik ve Savunma Prensipleri

1. **"DNS Yanıtı Doğrulanmış Kimlik Değildir":** Standart DNS şifresiz ve imzasızdır; yanıtların doğrulanması için DNSSEC ve DoH/DoT şarttır.
2. **Subdomain Takeover Savunması:** Silinen bulut depolarına işaret eden sahipsiz (dangling) CNAME kayıtları düzenli taranmalı ve derhal silinmelidir.
3. **E-posta Güvenliği:** Katı SPF (`-all`) ve DMARC (`p=reject`) politikalarıyla alan adının sahte e-postalarda kullanımı engellenmelidir.
4. **DNS Tünelleme İzleme:** Shannon entropisi ve olağandışı alt alan adı etiket uzunlukları izlenerek veri kaçırma girişimleri yakalanmalıdır.
