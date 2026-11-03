# Gün 050: Soru-Cevap ve Kavramsal Pekiştirme (TCP Üçlü El Sıkışma)

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## Soru 1 (G050-SC1): TCP Üçlü El Sıkışma Mekanizması ve Güvenlik Önemi

### Temel Mekanizma ve Güvenlik Önemi
TCP (RFC 793 ve RFC 9293), durum bilgisi tutan (stateful), bağlantı yönelimli (connection-oriented) ve güvenilir bir Taşıma Katmanı (Katman-4) protokolüdür. İki uç noktanın veri aktarımına başlayabilmesi için üç aşamalı el sıkışma (Three-Way Handshake) sürecini tamamlaması gerekir:
1. **Senkronizasyon (SYN - 1. Adım):** İstemci, rastgele bir başlangıç sıra numarası (ISN_c) seçer ve `SYN=1, ACK=0` bayraklarıyla sunucuya gönderir. Bu paket istemcinin `SYN_SENT`, sunucunun ise `SYN_RECEIVED` durumuna geçmesini sağlar.
2. **Kabul ve Karşılıklı Senkronizasyon (SYN-ACK - 2. Adım):** Sunucu, istemcinin ISN değerini 1 artırarak onaylar (`Ack = ISN_c + 1`) ve kendi bağımsız başlangıç sıra numarasını belirler (`Seq = ISN_s`). `SYN=1, ACK=1` bayraklarıyla istemciye döner. İstemci bu paketi aldığında `ESTABLISHED` durumuna geçer.
3. **Nihai Onay (ACK - 3. Adım):** İstemci, sunucunun ISN değerini 1 artırarak onaylar (`Ack = ISN_s + 1`, `Seq = ISN_c + 1`) ve `SYN=0, ACK=1` bayraklı paketi gönderir. Sunucu bu paketi aldığında oturumu `ESTABLISHED` durumuna taşır.

**Kritik Güvenlik İlkesi:** Handshake paketleri (SYN, SYN-ACK ve ilk ACK) uygulama verisi (payload) **taşımaz**; yük boyutu 0 bayttır. Bu paketlerin amacı yalnızca uçlar arasında sıra numaralarını eşitlemek, tampon (pencere) boyutunu bildirmek ve maksimum segment boyutunu (MSS) müzakere etmektir. Bir handshake paketinde veri taşınması, TCP Fast Open (TFO) gibi özel uzantılar hariç tutulursa, genellikle bir güvenlik duvarı atlatma veya protokol istismar girişimidir.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:** `portfolio/hafta_08/gun_050/ornek_veri/sample_tcp_handshake_packets.json` dosyası içinde tanımlı 8 TCP paketi (Meşru SYN, SYN-ACK, ACK, HTTP GET veri paketi, izole SYN Flood paketi, gizli RST tarama paketi, XMAS paketi ve SYN+FIN paketi).
- **İşlem:**
  1. `TCPPacket` sınıfı ile 20 baytlık ikili başlık ayrıştırılır; kaynak/hedef port, seq, ack, data offset ve bayrak maskesi doğrulanır.
  2. `calculate_tcp_checksum` ile 12 baytlık IPv4 Sahte Başlığı (Pseudo Header) üzerinden RFC 1071 sağlama toplamı doğrulanır.
  3. `TCPHandshakeSession` durum makinesinde `CLOSED -> SYN_SENT -> ESTABLISHED` geçişi yürütülür.
  4. Ack ve Seq numarası eşleşmeleri denetlenir.
- **Beklenen Çıktı:** 14 birim testin 0.05 saniyenin altında `PASSED` olması; meşru el sıkışmanın `ESTABLISHED` durumuna ulaşması, diğer 4 test oturumunun anomaliler sebebiyle "YARIM AÇIK / HATA" olarak etiketlenmesi.
- **Negatif Kontrol:** Port 0, Port 70000, 20 bayttan kısa başlık, negatif sıra numarası ve 5'ten küçük veri ofsetinin `TCPValidationError` ile engellenmesi.

### Risk Analizi ve Tehdit Senaryoları
- **Öngörülebilir ISN Zafiyeti (TCP Spoofing / Hijacking):** Eğer işletim sistemi ISN değerlerini rastgele üretmezse, saldırgan sunucuya sahte IP ile bağlanıp sunucunun üreteceği `ISN_s` değerini tahmin ederek oturumu çalabilir (Mitnick Saldırısı).
- **SYN Flood (DDoS):** Saldırganın çok sayıda sahte IP üzerinden `SYN` gönderip 3. adımdaki `ACK` paketini bilerek iletmemesi; sunucunun `SYN Backlog` kuyruğunu doldurarak meşru kullanıcıların web sitesine veya servise erişmesini engellemesi.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:**
  1. Güvenlik duvarı ve IDS üzerinde tek bir kaynaktan kısa sürede gelen yüksek hacimli ve yanıtlanmamış `SYN` akışlarının izlenmesi.
  2. Handshake paketlerinde payload boyutunun sıfırdan büyük olması durumunda IDS alarmı üretilmesi.
- **Önleme:**
  1. **SYN Cookies (RFC 4987):** Sunucunun durum tablosunda yer ayırmadan ISN içine kriptografik özet gömerek SYN Flood saldırılarını donanım hızında bertaraf etmesi.
  2. **RFC 6528 Kriptografik ISN:** Başlangıç sıra numaralarının PRF (Pseudo-Random Function) ve gizli anahtar ile üretilmesinin sağlanması.
  3. **Stateful Inspection (Durum Denetimli Güvenlik Duvarı):** Tamamlanmamış oturumlara ait paketlerin iç ağa geçirilmemesi.

---

## Soru 2 (G050-SC2): Bağımsız Laboratuvarın Girdisi, İşlemi, Beklenen Sonucu ve Negatif Kontrolü

### Temel Mekanizma ve Güvenlik Önemi
Katman-4 TCP analiz motorları, canlı işletim sistemi soketlerine veya harici kütüphanelere bağımlı olmaksızın, ikili düzeyde (binary) TCP başlıklarını inşa edebilmeli, sahte başlık (pseudo header) sağlama toplamlarını hesaplayabilmeli ve paketlerdeki durum makinesi geçişlerini matematiksel kesinlikle doğrulayabilmelidir.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:**
  1. `sample_tcp_handshake_packets.json`: 3 adımlı tam el sıkışma, 1 veri paketi ve 4 farklı anomali paketi (SYN Flood, Stealth SYN, XMAS, SYN+FIN).
  2. `invalid_tcp_packets.json`: 8 adet biçimsel negatif test senaryosu.
- **İşlem:**
  1. `TCPPacket.to_bytes()` ile 20 baytlık ikili başlık paketlenir ve pseudo-header checksum hesaplanır.
  2. `TCPPacket.from_bytes()` ile bayt dizisi çözülerek alan sınırları ve veri ofseti denetlenir.
  3. `TCPHandshakeSession.process_packet()` ile oturumun el sıkışma adımları sırayla işletilir.
  4. Anomali kuralları (`check_packet_anomalies`) ile kural dışı bayraklar taranır.
  5. Bulgular `kanit/gercek/tcp_el_sikisma_raporu.txt` dosyasına Markdown formatında kaydedilir.
- **Beklenen Çıktı:** 
  - 14 birim testin 0.03 saniyede `14 passed` olarak tamamlanması.
  - Meşru oturumun `ESTABLISHED` durumunu alması, 5 adet güvenlik anomalisinin konsola ve rapora eksiksiz yansıması.
- **Negatif Kontrol:**
  - 8 farklı geçersiz girdinin (Port 70000, Port 0, Ofset 4, 14 baytlık eksik başlık, negatif seq, geçersiz bayrak tipi, boş ikili veri, float port) tamamının `TCPValidationError` fırlatması ve `kanit/gercek/negatif_kontrol_sonuclari.txt` dosyasına "%100 DOĞRULAMA BAŞARILI" şeklinde kaydedilmesi.

### Risk Analizi ve Tehdit Senaryoları
Yetersiz başlık ve bayrak doğrulaması:
- Güvenlik duvarının geçersiz bayrak kombinasyonlarına (`SYN+FIN`, `NULL`) sahip paketleri doğrudan iç ağdaki sunuculara iletmesine ve sunucu TCP yığınlarının kilitlenmesine ya da bypass edilmesine neden olur.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:** Wireshark veya `tcpdump` ile paket yakalamada `tcp.flags.syn == 1 && tcp.flags.ack == 0` filtreleriyle bağlantı taleplerinin izlenmesi; `tcp.flags.reset == 1` oranındaki ani artışların takip edilmesi.
- **Önleme:** Güvenlik duvarı kurallarında bağlantı durumunun `NEW`, `ESTABLISHED`, `RELATED` şeklinde katı takibi (`iptables -m state --state ESTABLISHED,RELATED -j ACCEPT`).

---

## Soru 3 (G050-SC3): Risk Oluşumu, Tespiti ve Savunma Kontrolleri

### Temel Mekanizma ve Güvenlik Önemi
TCP bağlantı mekanizmasındaki durumsuzluk ve güven varsayımları; kaynak IP sahteciliği (IP Spoofing), durum tablosu şişirme (State Exhaustion) ve aktif port keşfi (Reconnaissance) saldırılarına zemin hazırlar.

### Bağımsız Laboratuvar ve Doğrulama Adımları
Laboratuvarımızda bu tehditlerin her biri simüle edilmiş ve tespit edilmiştir:
1. **Risk 1: Gizli SYN Taraması (Stealth SYN Scan):** Nmap `-sS` taramasında olduğu gibi, saldırgan portun açık olduğunu `SYN-ACK` ile teyit eder etmez `RST` göndererek oturumu kapatır. Motorumuz bu durumu `GIZLI_SYN_TARAMASI_SUPHESI` alarmı ile yakalamıştır.
2. **Risk 2: XMAS ve NULL Taramaları:** `FIN+PSH+URG` veya hiçbir bayrağın bulunmadığı paketlerle işletim sistemi tespiti (OS fingerprinting) yapılması. Motorumuz `PORT_TARAMA_XMAS` ve `PORT_TARAMA_NULL` alarmları üretmiştir.
3. **Risk 3: Protokol Mantık Hatası (SYN+FIN):** Aynı anda hem bağlantı başlatma hem sonlandırma emri içeren paketler `KURAL_DISI_BAYRAK_SYN_FIN` ile KRİTİK seviyede engellenmiştir.

### Risk Analizi ve Tehdit Senaryoları
- **Güvenlik Duvarı Durum Tablosunun Tükenmesi:** Güvenlik duvarlarının eşzamanlı oturum takip kapasitesi sınırlıdır. Binlerce yarım açık SYN paketi ile güvenlik duvarının bellek tablosu şişirilerek yeni meşru bağlantıların düşmesi sağlanabilir.
- **Saldırganın Ağ Taramasını Gizlemesi:** Normal bir TCP bağlantısı uygulama loglarına (Apache/Nginx access log) düşerken, el sıkışması tamamlanmadan RST ile sonlandırılan Stealth SYN taraması uygulama loglarına düşmez; yalnızca ağ seviyesinde yakalanabilir.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:**
  1. SIEM üzerinde `SYN/ACK` oranının anormal biçimde sapması (örneğin gelen SYN sayısı giden ACK sayısının 100 katı ise).
  2. Snort / Suricata IDS üzerinde `flags:SF;` (SYN+FIN) veya `flags:FPU;` (XMAS) kural imzalarının tetiklenmesi.
- **Önleme:**
  1. **SYN Proxy / SYN Protection:** Ağ sınırındaki yeni nesil güvenlik duvarının (NGFW) el sıkışmayı kendi üzerinde karşılayıp, ancak 3. adım (ACK) tamamlandıktan sonra iç ağdaki sunucuya bağlantıyı iletmesi.
  2. **Rate Limiting:** IP başına birim zamanda açılabilecek maksimum SYN istek sayısının sınırlandırılması (`hashlimit` modülü).
  3. **Strict TCP Flags Validation:** Kural dışı bayrak kombinasyonlarına sahip paketlerin yönlendirici seviyesinde doğrudan çöpe atılması (Drop).
