<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 52: UDP ve Kullanım Alanları — Soru Bankası ve Usta-Çırak Mülakatı

---

## Soru 1 (G052-SC1): Temel Mekanizma ve Güvenlik Önemi

### Soru
UDP ve kullanım alanları bağlamında: Temel mekanizmayı ve protokolün siber güvenlik açısından taşıdığı kritik önemi açıklayınız.

### Usta Cevabı
UDP (User Datagram Protocol - RFC 768), Taşıma Katmanında (Transport Layer) çalışan, bağlantısız (connectionless), durumsuz (stateless) ve son derece hafif (lightweight) bir protokoldür. TCP'nin aksine 3 aşamalı el sıkışma (three-way handshake), sıralama (sequence numbering), akış kontrolü (flow control) veya otomatik yeniden iletim (retransmission) mekanizmalarına sahip değildir. Yalnızca 8 baytlık sabit bir başlık taşır (Kaynak Port, Hedef Port, Uzunluk, Sağlama Toplamı).

Güvenlik açısından önemi iki temel kutupta toplanır:
1. **IP Sahteciliği ve Yansıtma Saldırıları (Spoofing & Amplification):** El sıkışma olmadığı için gönderici kaynak IP adresini kurbanın IP'si olarak taklit edebilir. Sunucu durumu doğrulamadan kurbana yanıt döner. Eğer yanıt istekten katlarca büyükse (DNS ANY, NTP monlist, Memcached) BAF (Bandwidth Amplification Factor) yüzlerce katına çıkar ve devasa DDoS saldırıları üretilir.
2. **Durumsuzluk ve Kaynak Tüketimi:** UDP sunucuları bağlantı oturumu tutmadığı için yüksek hacimli UDP flood saldırılarında soket havuzunu tüketmez; ancak hedef portlar kapalı olduğunda işletim sistemi çekirdeği her paket için ICMP Port Unreachable (Type 3 Code 3) üretmeye çalışırken işlemciyi kilitler.

### Kritik Güvenlik / Mühendislik Noktası
RFC 768'de tanımlanan IPv4 UDP Checksum alanının `0x0000` olabilmesi (yani sağlama toplamının devre dışı bırakılabilmesi), saldırganların veri paketinin içeriğini ağ üzerindeki aracı cihazlarda (MITM) veya uç noktalarda sağlama toplamı hatası vermeden değiştirebilmesine kapı aralar. Bu nedenle modern IPv6 standardında (RFC 8200) UDP Checksum kullanımı zorunlu kılınmış, `0x0000` taşıyan paketlerin doğrudan düşürülmesi emredilmiştir.

### Çırak İçin Pratik Çıkarım
Uygulama geliştirirken "hızlı olsun" diye körü körüne UDP seçme. Eğer UDP seçeceksen, uygulama katmanında sıra denetimi, zaman damgası veya kriptografik doğrulama (DTLS / SRTP) inşa etmek zorunda olduğunu unutma. Korunmasız UDP açık bir davetiyedir.

---

## Soru 2 (G052-SC2): Bağımsız Laboratuvar Tasarımı ve Kontroller

### Soru
UDP ve kullanım alanları laboratuvarının girdisi, işleme adımları, beklenen gözlenebilir sonucu ve negatif kontrolleri nelerdir?

### Usta Cevabı
G052 laboratuvarı harici hiçbir kütüphaneye veya önceki günün kodlarına bağımlı olmaksızın kendi başına çalışan yerel bir test ve doğrulama ortamıdır:
- **Girdi:** 
  1. Standart DNS A kaydı sorgu/yanıt ikili yükleri (`ornek_veri/sample_udp_datagrams.json`).
  2. Standart NTPv4 Client/Server ve Mode 7 `monlist` ikili yükleri.
  3. RFC 768 gereği IPv4 Sahte Başlık (Pseudo-Header) parametreleri (Kaynak IP, Hedef IP, Protokol 17, UDP Uzunluğu).
  4. 8 adet sınır aşımı ve biçim bozukluğu içeren negatif kontrol senaryosu (`ornek_veri/invalid_udp_inputs.json`).
- **İşlem:**
  1. `UDPHeader`: 8 baytlık ikili başlığı `!HHHH` formatında paketleme ve geri açma (unpack).
  2. `UDPHeader.calculate_checksum`: Sahte başlık ve veri yükü üzerinden 16-bit birin tümleyeni sağlama toplamını hesaplama.
  3. `UDPDatagram.verify_checksum`: Paketin bozulup bozulmadığını kontrol etme (ayrıca `checksum=0` IPv4 toleransını denetleme).
  4. `UDPProtocolAnalyzer.classify_datagram`: Port ve yük özniteliklerine göre protokolü (DNS, NTP, DHCP vb.) ve işlem modunu sınıflandırma.
  5. `UDPProtocolAnalyzer.evaluate_amplification_factor`: BAF katsayısını hesaplayarak DDoS risk derecelendirmesi üretme.
  6. `UDPProtocolAnalyzer.detect_traffic_anomalies`: UDP Flood (yüksek PPS) ve UDP Port Sweep (çoklu hedef port) anomalilerini yakalama.
  7. `UDPProtocolAnalyzer.audit_source_port_randomization`: Kaynak portların entropisini ölçerek Kaminsky DNS zehirleme zafiyetini denetleme.
- **Beklenen Sonuç:** 14 birim testin tamamının 0.01 saniyenin altında `PASS` alması; meşru DNS ve NTP paketlerinin başarıyla ayrıştırılması; BAF > 500x durumunda `CRITICAL` risk alarmı verilmesi; rastgele portların güvenli, sıralı portların zafiyetli olarak raporlanması.
- **Negatif Kontrol:** Port aralığı dışı (-1 veya 70000), 8 bayttan küçük başlık uzunluğu, başlık uzunluğu ile yük boyutu uyuşmazlığı ve geçersiz IP formatları verildiğinde sistemin sessizce başarısız olmak yerine `UDPValidationError` fırlatarak paketi reddetmesi (8/8 başarı).

### Kritik Güvenlik / Mühendislik Noktası
Sahte başlık (pseudo-header) hesaplamasında veri uzunluğu tek sayı olduğunda RFC 768 standardı gereğince 1 baytlık `0x00` dolgusu (padding) eklenmelidir; ancak bu dolgu baytı asla gerçek paketin uzunluğuna (UDP Length) dahil edilmemelidir. Bu ayrımı yapamayan kodlar hem yanlış checksum üretir hem de güvenlik duvarlarında ve IDS/IPS sistemlerinde paketlerin düşmesine yol açar.

### Çırak İçin Pratik Çıkarım
Test yazarken sadece "çalışıyor mu" diye bakma. Paketin yükünden 1 baytı değiştirip sağlama toplamının bozulduğunu kendi gözünle doğrula (`test_udp_checksum_verification_valid_and_corrupt`). Gerçek kanıt, hatayı yakalayabildiğini ispatladığın andır.

---

## Soru 3 (G052-SC3): Tehdit Modeli, Tespit ve Savunma Kontrolleri

### Soru
"UDP ve kullanım alanları" bağlamında risk nasıl oluşur, ağ trafiğinde hangi sinyallerle tespit edilir ve hangi mühendislik kontrolleriyle önlenir?

### Usta Cevabı
- **Risk Oluşumu:** UDP'nin el sıkışmasız ve durumsuz mimarisi, IP sahteciliğine (spoofing) açıktır. İnternette açık bırakılan çözücüler (Open DNS Resolvers) veya yönetim arayüzleri (NTP monlist, Memcached), küçük istek paketlerine devasa yanıtlar üreterek kurbana yönlendirilen amplifikasyon silahlarına dönüşür. Ayrıca DNS istemcileri kaynak portlarını sıralı veya tahmin edilebilir seçtiğinde Kaminsky Önbellek Zehirleme saldırısı ile sahte sitelere yönlendirme riski doğar.
- **Tespit Sinyalleri:**
  1. **Trafik Asimetrisi ve BAF:** Gelen sorgu trafiği ile giden yanıt trafiği arasındaki oranın 10x, 50x veya 1000x seviyesine fırlaması.
  2. **Yüksek PPS ve Port Çeşitliliği:** Tek bir kaynaktan hedef sistemin rastgele veya sıralı kapalı UDP portlarına saniyede yüzlerce paket gelmesi (UDP Flood / Port Sweep).
  3. **Monlist ve ANY İmzaları:** NTP paketlerinde Mode=7 (`0x17`) baytının görülmesi; DNS sorgularında QTYPE=255 (`ANY`) ve EDNS0 büyük tampon boyutu (DO biti) istenmesi.
  4. **Düşük Port Entropisi:** DNS sorgusu yapan bir çözümleyicinin ardışık ephemeral portlar (1050, 1051, 1052...) kullandığının ağ izleme araçlarıyla (Wireshark / Zeek) yakalanması.
- **Savunma Kontrolleri:**
  1. **BCP 38 / RFC 2827 (Ingress Filtering):** Kenar yönlendiricilerde (Edge Routers) uRPF uygulanarak, kendi IP bloğuna ait olmayan sahte kaynak IP'li paketlerin internete çıkışı engellenmelidir.
  2. **Response Rate Limiting (RRL):** DNS sunucularında aynı istemci subnet'ine gönderilen yanıt sıklığı kısıtlanmalı, eşik aşımında `TC=1` bayrağı ile istemci TCP'ye zorlanmalıdır.
  3. **Savunmasız Fonksiyonları Kapatma:** NTP sunucularında `ntp.conf` içerisine `noquery` direktifi eklenmeli; memcached için UDP desteği (`-U 0`) tamamen devre dışı bırakılmalıdır.
  4. **Kaynak Port Rastgeleleştirmesi (RFC 5452):** DNS ve UDP istemcilerinde portlar kriptografik rastgelelikle (CSPRNG) 49152-65535 aralığından seçilmelidir.
  5. **Protokol Şifreleme ve Doğrulama:** DNS trafiği DoH/DoT ile, kritik UDP akışları DTLS veya IPsec ile korunmalıdır.

### Kritik Güvenlik / Mühendislik Noktası
RRL (Response Rate Limiting) uygulandığında istemciye tamamen sessiz kalmak yerine `TC=1 (Truncated)` dönmek saldırganı felç eder. Çünkü meşru istemci hemen TCP SYN atarak sorgusunu TCP üzerinden güvenle tamamlar; oysa sahte IP kullanan saldırgan TCP 3'lü el sıkışmasını asla tamamlayamayacağı için amplifikasyon anında son bulur.

### Çırak İçin Pratik Çıkarım
Sistem yöneticisi olduğunda dışarıya açık DNS veya NTP sunucularını düzenli olarak shodan ve nmap taramalarıyla denetle. Senin kontrolünden çıkan bir sunucu, başka bir kurumun internetini kesmek için kullanılan bir kiralık katile dönüşebilir.
