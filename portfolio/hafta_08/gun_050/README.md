# Gün 050: TCP Üçlü El Sıkışma, Bayraklar ve Bağlantı Güvenliği

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)

Bu çalışma, Siber Güvenlik 365 Günlük Müfredatı kapsamında Aşama 03 (Ağ Temelleri ve Ağ Güvenliği), Hafta 08, Gün 050 çalışmasıdır.

---

## 📋 Proje Özeti

Katman-4 Taşıma Katmanı (Transport Layer) protokollerinden TCP'nin (RFC 793 ve RFC 9293) başlık yapısını, IPv4 sahte başlığı (pseudo-header) üzerinden RFC 1071 sağlama toplamı (checksum) hesaplamasını, üç aşamalı el sıkışma (Three-Way Handshake) durum makinesini (State Machine), ISN/Ack sıra numarası matematiğini ve SYN Flood ile port tarama anomalilerini (Stealth SYN, XMAS, NULL, SYN+FIN) inceleyen ve modelleyen kapsamlı laboratuvar paketidir.

### Temel Özellikler
- **RFC 793 / RFC 9293 İkili Başlık Modellemesi:** Kaynak/hedef port, 32-bit sıra numarası (Seq), 32-bit onay numarası (Ack), veri ofseti, pencere boyutu ve 8 kontrol bayrağının (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR) ikili paketlenmesi ve ayrıştırılması.
- **RFC 793 Sahte Başlık ve Checksum:** Sahte başlık (kaynak/hedef IP, sıfır baytı, protokol 6, TCP boyutu) ile TCP segmenti üzerinden 16-bit 1'e tümleyen sağlama toplamı motoru.
- **Üçlü El Sıkışma Durum Makinesi (`TCPHandshakeSession`):**
  - İstemci `CLOSED -> SYN_SENT -> ESTABLISHED` durum geçişleri.
  - Sunucu `LISTEN -> SYN_RECEIVED -> ESTABLISHED` durum geçişleri.
  - İstemci ve sunucu ISN senkronizasyonu ve `Ack = ISN + 1` doğrulaması.
  - Handshake paketlerinde veri yükü (payload) taşınmama kuralı ve anomali tespiti.
- **Güvenlik Anomali ve Port Tarama Tespiti:**
  - `SYN_FLOOD_BELIRTISI`: Düşük pencere boyutlu ve yanıtsız izole SYN paketleri.
  - `GIZLI_SYN_TARAMASI_SUPHESI`: Nmap gizli SYN taraması benzeri erken RST sonlandırmaları.
  - `PORT_TARAMA_XMAS`: `FIN+PSH+URG` bayrak kombinasyonları.
  - `PORT_TARAMA_NULL`: Tüm bayrakların sıfır olduğu taramalar.
  - `KURAL_DISI_BAYRAK_SYN_FIN`: Protokol mantığına aykırı eşzamanlı SYN ve FIN bayrakları.
- **Satır Satır Açıklamalı Kod:** Uygulama ve test kodlarının tamamı didaktik açıklamalarla zenginleştirilmiştir.

---

## 📂 Dizin Yapısı

```
portfolio/hafta_08/gun_050/
├── README.md                                    # Modül dokümantasyonu ve çalıştırma kılavuzu
├── ders.md                                      # Usta-Çırak pedagojisiyle hazırlanmış TCP dersi
├── soru_cevap.md                                # Soru bankası (G050-SC1/2/3) 4 başlıklı cevapları
├── rapor.md                                     # 100/100 rubrik değerlendirme ve teknik rapor
├── sonuc.json                                   # Gün sonu standart makine çıktısı
├── manifest.json                                # SHA-256 doğruluk ve bütünlük tablosu
├── uygulama/
│   ├── __init__.py                              # Paket başlatıcı
│   └── tcp_handshake_analyzer.py                # TCP el sıkışma ve anomali analiz motoru
├── tests/
│   ├── __init__.py                              # Test paketi başlatıcı
│   └── test_tcp_handshake_analyzer.py           # 14 birim testi ve güvenlik doğrulamaları
├── ornek_veri/
│   ├── sample_tcp_handshake_packets.json        # 8 adet meşru ve anormal TCP paket örneği
│   └── invalid_tcp_packets.json                 # 8 geçersiz girdi ve biçim hata senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt                   # pytest 14/14 PASS kanıtı
    │   ├── komut_ve_cikis.txt                   # Konsol yürütme çıktısı
    │   ├── tcp_el_sikisma_raporu.txt            # Üretilen Markdown analiz raporu
    │   └── negatif_kontrol_sonuclari.txt        # 8 negatif vakanın yakalanma raporu
    └── temsili/
        └── tcp_uc_asamali_el_sikisma_ve_syn_flood_mimarisi.txt # Handshake ve SYN Flood şeması
```

---

## 🚀 Hızlı Başlangıç ve Çalıştırma

### 1. TCP El Sıkışma Analiz Motorunu Çalıştırma
```powershell
python portfolio/hafta_08/gun_050/uygulama/tcp_handshake_analyzer.py
```

### 2. Birim ve Güvenlik Testlerini Koşma
```powershell
pytest portfolio/hafta_08/gun_050/tests/test_tcp_handshake_analyzer.py -v
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
