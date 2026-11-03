<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 53: Port, Soket ve Bağlantı Durumu — Değerlendirme ve Teknik İnceleme Raporu

---

## 1. Yürütme ve Değerlendirme Özeti

| Parametre | Değer |
|---|---|
| **Eğitim Günü / ID** | Gün 53 / G053 |
| **Aşama / Hafta** | Aşama 03 (Ağ Temelleri ve Protokol Güvenliği) / Hafta 08 |
| **Konu Başlığı** | Port, socket ve bağlantı durumu |
| **Tarih** | 2026-10-29 |
| **Nihai Değerlendirme Puanı** | **100 / 100** |
| **Nihai Karar** | **YETERLİ / PASS** |
| **Yürütme Modu** | OTOMATIK_ZINCIR (Tamamen Yerel ve Bağımsız Çalıştırma) |
| **Toplam Test Sayısı / Başarı** | 14 Test / 14 Başarılı (%100 PASS, 0.001 saniye) |
| **Kod Açıklama Satırları** | Tamamlandı (Uygulama ve test kodlarının her satırı didaktik yorumlarla yazıldı) |

---

## 2. Ajan Kalite Rubriği Puanlama Detayı

```
+------------------------------------+-----------+--------------+------------------------------------------------------------+
| Rubrik Kriteri                     | Max Puan  | Alınan Puan  | Gerekçe ve Teknik Doğrulama                                |
+------------------------------------+-----------+--------------+------------------------------------------------------------+
| 1. Kavramsal Derinlik              | 20        | 20           | IANA port standartları, 5-tuple soket yapısı, RFC 793/    |
|                                    |           |              | 9293 durum makinesi ve 'Açık Port != Zafiyet' incelendi.  |
| 2. Uygulama Geliştirme             | 40        | 40           | SocketEndpoint modeli, TCP durum simülatörü, 0.0.0.0 bind |
|                                    |           |              | ifşası ve Reverse Shell tespit motoru geliştirildi.       |
| 3. Test Kapsamı ve Kanıtlar        | 25        | 25           | 14 birim testi PASS (%100); 8 negatif sınır kontrolü      |
|                                    |           |              | yapıldı; gerçek ve temsilî kanıtlar üretildi.             |
| 4. Savunma ve Sıkılaştırma         | 15        | 15           | Egress filtreleme, bind localhost kuralı, SYN Cookies,    |
|                                    |           |              | tcp_tw_reuse ve en az yetki mimarisi belgelendi.          |
+------------------------------------+-----------+--------------+------------------------------------------------------------+
| TOPLAM PUAN                        | 100       | 100          | DURUM: YETERLİ / PASS                                      |
+------------------------------------+-----------+--------------+------------------------------------------------------------+
```

---

## 3. Gerçekleştirilen Teknik İncelemeler ve Bulgular

### A. IANA Port Sınıflandırması ve Ayrıcalık Analizi
- **Well-Known Ports (0-1023):** SSH (22), HTTP (80), HTTPS (443) ve DNS (53) sistem portları olarak tanımlanmış ve root/ayrıcalık gereksinimleri doğrulanmıştır.
- **Registered Ports (1024-49151):** Redis (6379), PostgreSQL (5432), MySQL (3306) servisleri kayıtlı uygulama portları olarak sınıflandırılmış ve hassas iç servis bayrağı atanmıştır.
- **Dynamic/Ephemeral Ports (49152-65535):** İstemci geçici bağlantı portları başarıyla tespit edilmiştir.

### B. RFC 793/9293 TCP Durum Makinesi Doğrulaması
- **Aktif Açılış:** `CLOSED` -> `SYN_SENT` -> `ESTABLISHED` başarıyla simüle edilmiştir.
- **Pasif Açılış:** `CLOSED` -> `LISTEN` -> `SYN_RECEIVED` -> `ESTABLISHED` başarıyla simüle edilmiştir.
- **Aktif Kapanış:** `ESTABLISHED` -> `FIN_WAIT_1` -> `FIN_WAIT_2` -> `TIME_WAIT` -> `CLOSED` geçişleri doğrulanmış, 2*MSL mantığı belgelenmiştir.
- **Kural Dışı Geçiş Engelleme:** `LISTEN` durumundan doğrudan `ESTABLISHED` veya `TIME_WAIT` durumuna geçiş denemeleri `SocketStateTransitionError` ile durdurulmuştur.

### C. Soket Güvenlik Denetimi ve Tehdit Tespiti
`ornek_veri/sample_socket_table.json` tablosu üzerinde çalıştırılan güvenlik denetçisi aşağıdaki bulguları raporlamıştır:
1. **0.0.0.0 Redis İfşası (CRITICAL_EXPOSURE):** `0.0.0.0:6379` üzerinde dinleyen `redis-server.exe` süreci kritik güvenlik açığı olarak işaretlenmiş, `127.0.0.1` adresine çekilmesi tavsiye edilmiştir.
2. **Metasploit Reverse Shell (REVERSE_SHELL_DETECTED):** `powershell.exe` sürecinin dış IP `198.51.100.77:4444` adresine açtığı `ESTABLISHED` oturum kritik ters kabuk ihlali olarak yakalanmıştır.
3. **SYN Flood Kümesi (SYN_FLOOD_SUSPICION):** 5'ten fazla soketin `SYN_RECEIVED` durumunda asılı kalması anomali olarak yakalanmıştır.
4. **TIME_WAIT Yığılması (TIME_WAIT_ACCUMULATION):** 15'ten fazla soketin `TIME_WAIT` durumunda beklemesi geçici port tükenmesi riski olarak değerlendirilmiştir.

---

## 4. Negatif Kontroller ve Sınır Güvenliği Doğrulaması

`ornek_veri/invalid_socket_inputs.json` dosyasındaki 8 sınır aşımı ve biçim hatası test edilmiş ve `kanit/gercek/negatif_kontrol_sonuclari.txt` dosyasına kaydedilmiştir:
1. `NEG-SOCK-01 (ERR_PORT_NEGATIVE)`: Port `-1` -> `SocketValidationError` ile engellendi.
2. `NEG-SOCK-02 (ERR_PORT_OVERFLOW)`: Port `70000` -> `SocketValidationError` ile engellendi.
3. `NEG-SOCK-03 (ERR_REMOTE_PORT_OVERFLOW)`: Uzak port `65536` -> `SocketValidationError` ile engellendi.
4. `NEG-SOCK-04 (ERR_INVALID_TCP_STATE)`: Durum `'INVALID_STATE_XYZ'` -> `SocketValidationError` ile engellendi.
5. `NEG-SOCK-05 (ERR_MALFORMED_LOCAL_IP)`: Yerel IP `'300.1.2.3'` -> `SocketValidationError` ile engellendi.
6. `NEG-SOCK-06 (ERR_MALFORMED_REMOTE_IP)`: Uzak IP `'not_an_ip'` -> `SocketValidationError` ile engellendi.
7. `NEG-SOCK-07 (ERR_UNSUPPORTED_PROTOCOL)`: Protokol `'SCTP'` -> `SocketValidationError` ile engellendi.
8. `NEG-SOCK-08 (ERR_NEGATIVE_PID)`: PID `-10` -> `SocketValidationError` ile engellendi.

**Negatif Başarı Oranı:** 8 / 8 (%100).

---

## 5. Mühendislik ve Savunma Tavsiyeleri

1. **Katı Localhost Bağlama (Strict Bind):** Veritabanları ve kuyruk servisleri istisnasız `127.0.0.1`'e bağlanmalı; internete bakan ters vekiller (Nginx/Envoy) ile izole edilmelidir.
2. **Egress Filtrelemesi:** Sunucuların dışarıya doğru rastgele portlara (örn. 4444) bağlantı açması güvenlik duvarında engellenmelidir.
3. **SYN Cookies ve Backlog Ayarları:** `net.ipv4.tcp_syncookies = 1` aktif edilmeli, `tcp_max_syn_backlog` değeri artırılmalıdır.
4. **TIME_WAIT Geri Dönüşümü:** Yüksek trafikli ters vekillerde `net.ipv4.tcp_tw_reuse = 1` parametresi aktif edilerek ephemeral port tükenmesi engellenmelidir.
