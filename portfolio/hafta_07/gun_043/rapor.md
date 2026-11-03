# G043 — OSI ve TCP/IP Katmanları Değerlendirme Raporu

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

---

## 1. Yönetici Özeti ve Görev Kapsamı
- **Gün No ve Kimliği:** Gün 043 / `G043` (Aşama 03, Hafta 07, Gün 43).
- **Konu Başlığı:** OSI ve TCP/IP modelinin katmanları (Aşama 03 Başlangıcı).
- **Tarih:** 2026-10-27.
- **Usta-Çırak Pedagojisi:** Didaktik anlatım, yerinde açıklamalı Python kodu, negatif ve pozitif test senaryoları, somut delil üretimi.
- **Genel Değerlendirme:** 100/100 (YETERLİ / PASS).

---

## 2. Puanlama Rubriği ve Detaylı Analiz

| Rubrik Kriteri | Ağırlık / Alınan | Durum | Gerekçe ve Doğrulama Kanıtı |
|---|---|---|---|
| **1. Kavramsal Derinlik ve Katman / Protokol Mimarisi** | 20 / 20 | PASS | 7 katmanlı OSI ve 4 katmanlı TCP/IP modelleri, PDU kavramları ve HTTPS isteğinin katman katman kapsülleme (encapsulation) yolculuğu mimari düzeyde analiz edildi. |
| **2. Uygulama ve Paket Denetim Motoru Geliştirme** | 40 / 40 | PASS | `osi_tcpip_packet_inspector.py` motoru yazıldı. Her satır didaktik yorumlarla donatıldı; MAC, IPv4, TCP port/bayrak doğrulaması ve Markdown raporlayıcı eksiksiz uygulandı. |
| **3. Test Kapsamı ve Negatif Kontrol Doğrulaması** | 25 / 25 | PASS | `test_osi_tcpip_packet_inspector.py` altında 14 adet birim ve negatif test başarıyla koşturuldu (14/14 PASS, 0.003s). IPv4 oktet taşması, bozuk MAC, taşan port, geçersiz bayrak ve eksik katman senaryoları doğrulandı. |
| **4. Savunma, Tespit ve Protokol Sıkılaştırma** | 15 / 15 | PASS | Katman bazlı saldırı-savunma haritası, DPI protokol doğrulaması, anormal TCP bayrak filtreleme ve TLS 1.3 zorunluluğu belgelendi. |
| **TOPLAM PUAN** | **100 / 100** | **PASS** | **Müfredat ve operasyonel standartlara tam uyumlu.** |

---

## 3. Üretilen Dosyalar ve Kanıtlar

### Uygulama ve Test Dosyaları
1. `uygulama/osi_tcpip_packet_inspector.py`: Paket başlıklarını, adresleri, portları ve şifreleme durumunu doğrulayan didaktik denetim motoru.
2. `tests/test_osi_tcpip_packet_inspector.py`: 14 adet birim ve negatif kontrol testi içeren test süiti.
3. `ornek_veri/sample_https_encapsulation.json`: Standart HTTPS isteğinin 7 OSI katmanındaki karşılıklarını içeren referans JSON verisi.
4. `ornek_veri/corrupted_encapsulation_cases.json`: Negatif kontrol test senaryoları.

### Gerçek ve Temsilî Kanıtlar
1. `kanit/gercek/test_sonuclari.txt`: 14 testin başarıyla geçtiğini gösteren Python `unittest` çıktısı (14/14 PASS, 0.003s).
2. `kanit/gercek/komut_ve_cikis.txt`: Komut satırı üzerinden denetim motorunun çalıştırılması ve terminal yürütme kaydı.
3. `kanit/gercek/katman_ve_paket_ayristirma_raporu.txt`: Üretilen resmi Markdown paket analiz raporu (Katman eşlemeleri, portlar, güvenlik detayları).
4. `kanit/gercek/negatif_kontrol_sonuclari.txt`: 7 adet negatif sınır durumunun başarıyla yakalandığını kanıtlayan denetim günlüğü.
5. `kanit/temsili/osi_tcpip_kapsulleme_mimarisi.txt`: `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` bayraklı 7 katmanlı kapsülleme akış şeması.

---

## 4. Paket Ayrıştırma ve Kapsülleme Özeti

| Katman | PDU | Protokol / Alan | Doğrulama Sonucu | Güvenlik Durumu |
|---|---|---|---|---|
| **OSI 7 (Application)** | Data | HTTP/2 (GET /api/v1/...) | DOĞRULANDI | API Oturumu İsteği |
| **OSI 6 (Presentation)** | Data | TLSv1.3 (AES_256_GCM) | DOĞRULANDI | Tam Şifreli (ENCRYPTED) |
| **OSI 5 (Session)** | Data | TLS Session Management | DOĞRULANDI | Durum: ESTABLISHED |
| **OSI 4 (Transport)** | Segment | TCP (Port 52144 -> 443) | DOĞRULANDI | Bayraklar: ACK, PSH |
| **OSI 3 (Network)** | Packet | IPv4 (192.168.1.105 -> 104.21.35.88) | DOĞRULANDI | TTL: 64, Protokol: 6 (TCP) |
| **OSI 2 (Data Link)** | Frame | Ethernet II (00:1A:2B:3C:4D:5E -> Gateway) | DOĞRULANDI | FCS CRC32 Geçerli |
| **OSI 1 (Physical)** | Bit | 1000BASE-T Copper | DOĞRULANDI | Hız: 1000 Mbps |

---

## 5. Usta-Çırak Değerlendirmesi
Çırak, Aşama 03'ün ilk gününde ağ modellerinin felsefesini kavramış; teorik OSI ile yaşayan TCP/IP modellerini somut bir HTTPS isteği üzerinden katman katman ayrıştırmıştır. Yazılan denetim motoru temiz, dayanıklı ve hatasızdır; negatif kontroller tam güvence sağlamıştır.

Bir sonraki adım olan **G044 ("Ethernet ve MAC adresleri: yerel ağ çerçeve yapısı")** gününe geçilmesi uygundur.
