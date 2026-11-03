<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 52: UDP ve Kullanım Alanları — Değerlendirme ve Teknik İnceleme Raporu

---

## 1. Yürütme ve Değerlendirme Özeti

| Parametre | Değer |
|---|---|
| **Eğitim Günü / ID** | Gün 52 / G052 |
| **Aşama / Hafta** | Aşama 03 (Ağ Temelleri ve Protokol Güvenliği) / Hafta 08 |
| **Konu Başlığı** | UDP ve kullanım alanları |
| **Tarih** | 2026-10-29 |
| **Nihai Değerlendirme Puanı** | **100 / 100** |
| **Nihai Karar** | **YETERLİ / PASS** |
| **Yürütme Modu** | OTOMATIK_ZINCIR (Tamamen Yerel ve Bağımsız Çalıştırma) |
| **Toplam Test Sayısı / Başarı** | 14 Test / 14 Başarılı (%100 PASS, 0.002 saniye) |
| **Kod Açıklama Satırları** | Tamamlandı (Uygulama ve test kodlarının her satırı didaktik yorumlarla yazıldı) |

---

## 2. Ajan Kalite Rubriği Puanlama Detayı

```
+------------------------------------+-----------+--------------+------------------------------------------------------------+
| Rubrik Kriteri                     | Max Puan  | Alınan Puan  | Gerekçe ve Teknik Doğrulama                                |
+------------------------------------+-----------+--------------+------------------------------------------------------------+
| 1. Kavramsal Derinlik              | 20        | 20           | RFC 768, RFC 1071, RFC 5452, RFC 8200 ve BCP 38 standart-  |
|                                    |           |              | ları eksiksiz açıklandı. UDP vs TCP felsefesi incelendi.  |
| 2. Uygulama Geliştirme             | 40        | 40           | 8 baytlık başlık paketleme, sahte başlık checksum hesabı,  |
|                                    |           |              | DNS/NTP ayrıştırma, BAF ve port entropisi kodlandı.       |
| 3. Test Kapsamı ve Kanıtlar        | 25        | 25           | 14 birim testi PASS (%100); 8 negatif sınır kontrolü      |
|                                    |           |              | yapıldı; gerçek/temsili kanıt dosyaları üretildi.         |
| 4. Savunma ve Sıkılaştırma         | 15        | 15           | BCP 38/uRPF, RRL, monlist kapatma, SPRs ve DTLS            |
|                                    |           |              | savunma mimarisi detaylandırıldı.                          |
+------------------------------------+-----------+--------------+------------------------------------------------------------+
| TOPLAM PUAN                        | 100       | 100          | DURUM: YETERLİ / PASS                                      |
+------------------------------------+-----------+--------------+------------------------------------------------------------+
```

---

## 3. Gerçekleştirilen Teknik İncelemeler ve Bulgular

### A. RFC 768 Başlık ve Sahte Başlık Checksum Hesaplama
- **Başlık Yapısı:** `struct.pack("!HHHH", src_port, dst_port, length, checksum)` kullanılarak tam 8 baytlık ikili başlık elde edilmiş ve `unpack` ile doğrulanmıştır.
- **Sahte Başlık Matematiği:** 12 baytlık IPv4 sahte başlığı (Kaynak IP, Hedef IP, 0x00, Protokol 17, UDP Uzunluğu) ile başlık ve yük birleştirilmiş, tek baytlık yüklerde 1 bayt `0x00` dolgusu ile 16-bit birin tümleyeni toplamı kusursuz hesaplanmıştır.
- **IPv4 Checksum İstisnası:** RFC 768 gereği `checksum=0x0000` durumunun "sağlama toplamı devre dışı" manasına geldiği ve çekirdek tarafından kabul edilmesi gerektiği `test_udp_zero_checksum_ipv4_allowed` ile kanıtlanmıştır.

### B. Protokol Sınıflandırma ve Güvenlik Ayrıştırması
- **DNS (Port 53):** Transaction ID (`0x1a2b`), QR biti (Sorgu / Yanıt), Soru ve Cevap sayıları ayrıştırılmıştır.
- **NTP (Port 123):** İlk bayttan Leap Indicator, NTP Versiyonu (VN=4) ve Mod (Mode 3: Client, Mode 4: Server, Mode 7: Monlist) çözümlenmiştir.
- **Amplifikasyon / Yansıtma Riski (BAF Puanlaması):**
  - Standart DNS: İstek 45B -> Yanıt 120B (BAF: 2.67x) -> `SAFE`
  - DNS ANY + EDNS0: İstek 50B -> Yanıt 3200B (BAF: 64.00x) -> `CRITICAL`
  - NTP monlist: İstek 8B -> Yanıt 4000B (BAF: 500.00x) -> `CRITICAL`

### C. Anomali ve Zafiyet Tespiti
- **UDP Flood Tespiti:** Saniyede 500 paket hızına ulaşan (pps threshold = 100) trafik tespit edilmiş ve saldırgan IP (`10.0.0.99`) anında yakalanmıştır.
- **UDP Port Sweep Tespiti:** Tek bir kaynaktan (`10.0.0.50`) 8 farklı hedef porta yapılan tarama girişimi `UDP_PORT_SWEEP_SCAN` anomalisi olarak raporlanmıştır.
- **Kaminsky Zafiyet Denetimi (Port Entropisi):** Ardışık +1 şeklinde artan sıralı istemci portları `KAMINSKY_DNS_POISONING_VULNERABLE` olarak işaretlenmiş, yüksek entropili rastgele portlar güvenli bulunmuştur.

---

## 4. Negatif Kontroller ve Sınır Güvenliği Doğrulaması

`ornek_veri/invalid_udp_inputs.json` içerisinde tanımlanan 8 negatif girdi test edilmiş ve `kanit/gercek/negatif_kontrol_sonuclari.txt` dosyasına kaydedilmiştir:
1. `NEG-UDP-01 (ERR_SRC_PORT_NEGATIVE)`: Kaynak port `-1` -> `UDPValidationError` ile engellendi.
2. `NEG-UDP-02 (ERR_SRC_PORT_OVERFLOW)`: Kaynak port `70000` -> `UDPValidationError` ile engellendi.
3. `NEG-UDP-03 (ERR_DST_PORT_OVERFLOW)`: Hedef port `65536` -> `UDPValidationError` ile engellendi.
4. `NEG-UDP-04 (ERR_LENGTH_UNDERFLOW)`: Başlık uzunluğu `7` (min 8) -> `UDPValidationError` ile engellendi.
5. `NEG-UDP-05 (ERR_LENGTH_OVERFLOW)`: Başlık uzunluğu `65536` -> `UDPValidationError` ile engellendi.
6. `NEG-UDP-06 (ERR_LENGTH_PAYLOAD_MISMATCH)`: Başlık uzunluğu 20 fakat toplam 13 -> `UDPValidationError` ile engellendi.
7. `NEG-UDP-07 (ERR_MALFORMED_SRC_IP)`: Kaynak IP `999.1.2.3` -> `UDPValidationError` ile engellendi.
8. `NEG-UDP-08 (ERR_MALFORMED_DST_IP)`: Hedef IP `not_an_ip_address` -> `UDPValidationError` ile engellendi.

**Negatif Başarı Oranı:** 8 / 8 (%100).

---

## 5. Mühendislik ve Savunma Tavsiyeleri

1. **Ağ Çıkışlarında BCP 38 / uRPF:** Saldırganların sahte IP ile dış ağlara paket fırlatması ağ sınırında önlenmelidir.
2. **DNS Response Rate Limiting (RRL):** Yanıt sıklığı kısıtlanmalı, eşik aşımında `TC=1` ile meşru istemciler TCP'ye yönlendirilerek sahte amplifikasyon kırılmalıdır.
3. **NTP ve Memcached Servis Sıkılaştırma:** NTP yapılandırmasında `monlist` kapatılmalı (`noquery`), memcached UDP portu (`11211`) kesinlikle internete kapatılmalıdır.
4. **RFC 5452 Kaynak Port Rastgeleleştirmesi:** Çözümleyiciler ephemeral port havuzundan kriptografik rastgelelikle port seçmeli, Kaminsky zafiyetine geçit verilmemelidir.
