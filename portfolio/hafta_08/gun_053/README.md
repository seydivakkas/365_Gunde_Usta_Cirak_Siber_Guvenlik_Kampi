# Gün 053: Port, Soket ve Bağlantı Durumu

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

Bu çalışma, **Siber Güvenlik 365 Gün Müfredatı** kapsamında 8. Haftanın 53. Günü için geliştirilmiş bağımsız, yerel çalışan bir **Port, Soket ve Bağlantı Durumu Analizörüdür**.

RFC 793 ve RFC 9293 standartlarına uygun olarak TCP bağlantı durum makinesi geçişlerini simüle eder, IANA port kategorilerini (Well-known, Registered, Ephemeral) sınıflandırır, "Açık Port != Zafiyet" ilkesi doğrultusunda `0.0.0.0` hassas servis ifşasını (Redis RCE riski), Metasploit Reverse Shell (Port 4444) oturumlarını, SYN Flood ve TIME_WAIT yığılması anomalilerini tespit eder.

---

## 📁 Dizin Yapısı

```
portfolio/hafta_08/gun_053/
├── README.md                                           # Proje tanıtımı ve özel lisans
├── ders.md                                             # Usta-Çırak pedagojisi ile kapsamlı ders notu
├── soru_cevap.md                                       # Soru bankası (G053-SC1, SC2, SC3) detaylı yanıtları
├── rapor.md                                            # 100/100 rubrik puanlı teknik inceleme raporu
├── sonuc.json                                          # Standartlaştırılmış gün sonuç verisi
├── manifest.json                                       # SHA256 bütünlük özeti
├── uygulama/
│   ├── __init__.py                                     # Paket başlatıcı
│   └── port_socket_state_analyzer.py                   # Soket ve durum analizörü motoru
├── tests/
│   ├── __init__.py                                     # Test başlatıcı
│   └── test_port_socket_state_analyzer.py              # 14 birim ve negatif test (%100 PASS)
├── ornek_veri/
│   ├── sample_socket_table.json                        # Gerçekçi soket tablosu ve tehdit senaryoları
│   └── invalid_socket_inputs.json                      # 8 adet sınır aşımı ve negatif test senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                          # 14/14 PASS birim test konsol çıktısı
    │   ├── komut_ve_cikis.txt                          # Komut çalıştırma ve durum kayıtları
    │   ├── port_socket_baglanti_raporu.txt             # Soket güvenlik denetim ve risk raporu
    │   └── negatif_kontrol_sonuclari.txt               # 8/8 engellenen geçersiz soket kanıtları
    └── temsili/
        └── port_socket_baglanti_ve_saldiri_mimarisi.txt # Temsilî mimari ve ASCII diyagramı
```

---

## 🚀 Hızlı Başlangıç ve Çalıştırma

### 1. Birim Testleri Çalıştırma:
```bash
python -m unittest portfolio/hafta_08/gun_053/tests/test_port_socket_state_analyzer.py -v
```

### 2. Soket Denetimini Çalıştırma:
```python
from portfolio.hafta_08.gun_053.uygulama.port_socket_state_analyzer import SocketEndpoint, SocketSecurityAuditor

auditor = SocketSecurityAuditor()
sock = SocketEndpoint("TCP", "0.0.0.0", 6379, "0.0.0.0", 0, "LISTEN", pid=3300, process_name="redis-server.exe")
report = auditor.audit_socket_table([sock])
print(report["bulgular"])
```

---

## 🛡️ Güvenlik ve Savunma Prensipleri

1. **"Açık Port != Zafiyet":** Port meşru bir kapıdır; zafiyet kapının arkasındaki servisin yetkisiz, yamasız veya dışa kontrolsüz açılmasıdır.
2. **Localhost Bağlama Zorunluluğu:** Veritabanları ve iç servisler mutlaka `127.0.0.1` adresine bağlanmalıdır (`bind 127.0.0.1`).
3. **Egress Filtrelemesi:** Güvenlik duvarlarında giden yetkisiz portlar (örn. 4444) engellenerek ters kabuk (Reverse Shell) bağlantıları önlenmelidir.
4. **Çekirdek Parametreleri:** SYN Flood'a karşı `tcp_syncookies = 1`, geçici port tükenmesine karşı `tcp_tw_reuse = 1` yapılandırılmalıdır.
