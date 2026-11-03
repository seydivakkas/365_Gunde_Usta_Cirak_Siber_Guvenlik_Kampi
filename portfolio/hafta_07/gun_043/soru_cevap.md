# G043 — OSI ve TCP/IP Katmanları: Soru ve Çözüm Analizleri

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

---

## [G043-SC1] Katmanlı Ağ Mimarisi: Kavramsal OSI ve Yaşayan TCP/IP Modelleri

### Temel Kavram ve Güvenlik Mekanizması
Modern bilgisayar ağları, karmaşık donanım ve yazılım bileşenlerinin birbiriyle uyum içinde çalışabilmesi için katmanlı (layered) mimariler üzerine kurulmuştur. Bu kapsamda iki temel referans modeli bulunur:

1. **OSI Modeli (Open Systems Interconnection):** ISO tarafından tanımlanan 7 katmanlı kavramsal modeldir. Her katmanın sorumluluk sınırını ve diğer katmanlarla arayüzünü teorik olarak kesin çizgilerle tanımlar. Güvenlik mimarisinde "Katman 2 Güvenliği" (MAC/Port Security), "Katman 3/4 Güvenlik Duvarı" (Stateful Packet Filter) veya "Katman 7 Güvenlik Duvarı" (WAF/DPI) gibi terminolojilerin ortak referansıdır.
2. **TCP/IP Modeli:** Pratik internet protokol kümesidir. OSI'nin üst üç katmanını (Uygulama, Sunum, Oturum) tek bir Uygulama katmanında; alt iki katmanını (Veri Bağlantısı ve Fiziksel) ise Ağ Erişimi katmanında konsolide eder. Pratikte çalışan tüm internet protokolleri (HTTP, TLS, TCP, UDP, IP, Ethernet) TCP/IP yığını üzerinde icra edilir.

---

### Soru ve Didaktik Çözüm
**Soru:**  
"OSI ve TCP/IP modelinin katmanları" konusunda temel mekanizmayı ve siber güvenlik açısından önemini açıkla. Neden "OSI kavramsal yedi katmanlı modeldir, İnternet protokolleri pratikte TCP/IP modeline göre geliştirilir" ilkesini bilmek bir güvenlik mühendisi için zorunludur?

**Didaktik Çözüm:**  
- **Modellerin Ayrışımı:** Eğer bir güvenlik uzmanı OSI modelini gerçekte donanım ve yazılımlarda birebir ayrık çalışan yedi ayrı modül zannederse, uygulamada yanılgıya düşer. Örneğin işletim sistemi çekirdeğinde TCP/IP yığını tek bir çekirdek sürücüsü olarak çalışırken; TLS şifrelemesi genellikle kullanıcı alanındaki (user-space) OpenSSL gibi kütüphanelerle yürütülür.
- **Güvenlik Önemi:** Katmanlama prensibi, **"Derinlemesine Savunma" (Defense-in-Depth)** stratejisinin temelidir. Bir saldırgan ağ katmanını (IP) taklit etse (IP Spoofing) bile, taşıma katmanındaki TCP üçlü el sıkışmasını (SYN/ACK) tamamlayamazsa oturum kuramaz. Taşıma katmanını aşsa bile, sunum katmanındaki TLS şifrelemesini kıramazsa uygulama verisini okuyamaz. Her katman, bir alttakinin sağladığı hizmete güvenir ancak kendi güvenlik kontrollerini bağımsız uygular.

---

### Savunma ve Tespit Kılavuzu
- **Katman Tabanlı Savunma Stratejisi:**
  - *Katman 2:* Ağ anahtarlarında (Switch) DHCP Snooping ve Dynamic ARP Inspection (DAI) aktif edilerek MAC ve ARP zehirlenmeleri önlenir.
  - *Katman 3/4:* Güvenlik duvarlarında Stateful Inspection ile yalnızca geçerli TCP durum makinesine (`NEW`, `ESTABLISHED`, `RELATED`) uyan paketlere izin verilir.
  - *Katman 7:* WAF kullanılarak HTTP payload içerisindeki SQLi, XSS veya komut enjeksiyonu denemeleri engellenir.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, sahada bir güvenlik olayı olduğunda herkes birbiriyle konuşurken OSI numaralarıyla konuşur. Biri sana 'Sorun Layer 3'te' dediğinde, kabloya ya da web sayfasına bakmayacaksın; IP adresine, alt ağ maskesine ve yönlendirme tablosuna bakacaksın. 'Layer 4 engeli var' dediklerinde port numaralarına ve güvenlik duvarı kurallarına odaklanacaksın. Katmanları bilmek, güvenlikçinin telsiz dilini bilmektir."*

---

## [G043-SC2] HTTPS İstek Kapsüllemesi ve Bağımsız Paket Denetim Döngüsü

### Temel Kavram ve Güvenlik Mekanizması
Veri ağ üzerinden taşınırken yukarıdan aşağıya doğru **Kapsülleme (Encapsulation)** sürecine uğrar:
- Uygulama Katmanı veriyi üretir (HTTP `GET /api/v1/auth/session`).
- Sunum Katmanı veriyi şifreler (TLS 1.3 `ApplicationData`).
- Oturum Katmanı oturum durumunu yönetir.
- Taşıma Katmanı TCP başlığı ekleyerek veriyi bir **Segment** haline getirir (Kaynak Port: 52144, Hedef Port: 443).
- Ağ Katmanı IP başlığı ekleyerek bir **Paket** oluşturur (Kaynak IP -> Hedef IP).
- Veri Bağlantısı Katmanı Ethernet başlığı ve FCS kuyruğu ekleyerek bir **Çerçeve (Frame)** oluşturur (Kaynak MAC -> Ağ Geçidi MAC).
- Fiziksel Katman çerçeveyi kablodan akacak bit sinyallerine dönüştürür.

---

### Soru ve Didaktik Çözüm
**Soru:**  
Bir HTTPS isteğinin her katmandaki karşılığını şemalaştıran bağımsız bir paket denetim motoru için laboratuvarın girdisi, işlemi, beklenen çıktısı ve negatif kontrolleri nelerdir? Önceki günlerin dosyalarına neden ihtiyaç duyulmaz?

**Didaktik Çözüm:**  
- **Laboratuvar Girdisi:** `sample_https_encapsulation.json` dosyası. İçerisinde Katman 7'den Katman 1'e kadar tüm başlık alanlarını barındıran yapılandırılmış paket verisi yer alır.
- **Laboratuvar İşlemi:** `osi_tcpip_packet_inspector.py` motoru; MAC biçimini (`validate_mac_address`), IPv4 oktet sınırlarını (`validate_ipv4_address`), port sınırlarını (`validate_port_number`), TCP bayraklarını ve TLS şifreleme durumunu doğrular; 7 OSI ve 4 TCP/IP modeline haritalandırır.
- **Beklenen Çıktı:** `kanit/gercek/katman_ve_paket_ayristirma_raporu.txt` ve `kanit/gercek/komut_ve_cikis.txt` dosyaları.
- **Negatif Kontroller:** 14 adet unittest (`test_osi_tcpip_packet_inspector.py`) ile sınanır:
  - 255'i aşan IPv4 adresi (`999.300.1.1`) reddedilir.
  - Geçersiz MAC adresi (`00:1A:2B:3C:GG:ZZ`) reddedilir.
  - Taşan port (70000) veya negatif port (-443) hata fırlatır.
  - Geçersiz TCP bayrağı (`INVALID_FLAG_XYZ`) yakalanır.
  - Eksik katman tespit edildiğinde `PacketEncapsulationError` fırlatılır.
- **Bağımsızlık Şartı:** G043 tamamen kendi kendine yeten (self-contained) bir modüldür. Ağ temelleri yeni bir aşama olduğu için önceki işletim sistemi günlerinin kodlarına ihtiyaç duyulmaz.

---

### Savunma ve Tespit Kılavuzu
- **Paket Analiz Araçları:**
  - Wireshark ve `tshark`: `tshark -r capture.pcap -Y "tcp.port == 443" -T fields -e ip.src -e ip.dst -e tcp.flags`
  - `tcpdump`: `tcpdump -nn -vvv -i eth0 port 443`
- Bu araçlarla canlı yakalanan paketler, geliştirdiğimiz denetim motorunun kurallarıyla kıyaslanarak anormal paket başlıkları (malformed headers) anında tespit edilir.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, bir paketi incelerken en alttan yukarıya doğru bakmayı öğren. Eğer MAC adresi yanlışsa paket router'a bile ulaşamaz. Eğer IP adresi yanlışsa paket internette kaybolur. Eğer port yanlışsa sunucu RST paketi fırlatır. Eğer TLS el sıkışması başarısızsa uygulama veriye asla ulaşamaz. Sorun gidermede 'Aşağıdan Yukarıya' (Bottom-Up) yaklaşımı işletilirse, arıza 5 dakikada çözülür."*

---

## [G043-SC3] Ağ Katmanlarında Risk Analizi: Hatalı Varsayımlar, Güvensiz Bağlantılar ve Segmentasyon

### Temel Kavram ve Güvenlik Mekanizması
Ağ altyapılarında meydana gelen güvenlik zafiyetlerinin çoğu, protokollerin varsayılan çalışma şekline dair **"Hatalı Güven Varsayımlarından" (Implicit Trust Assumptions)** kaynaklanır:
1. "Yerel ağdaki herkes güvenilirdir" varsayımı -> Katman 2'de ARP zehirlenmesine ve dinlemeye yol açar.
2. "Paketin kaynak IP'si ne yazıyorsa gelen odur" varsayımı -> Katman 3'te IP Spoofing zafiyetine yol açar.
3. "Port 443 açıksa trafik güvenlidir" varsayımı -> Katman 7'de C2 (Command & Control) tünellemesine ve veri sızıntısına zemin hazırlar.

---

### Soru ve Didaktik Çözüm
**Soru:**  
"OSI ve TCP/IP modelinin katmanları" bağlamında risk nasıl oluşur? İzinli trafik alanları, protokol sırası ve negatif paket örnekleriyle bu risk nasıl tespit edilir? Protokol doğrulaması, TLS ve ağ segmentasyonu ile nasıl savunulur?

**Didaktik Çözüm:**  
- **Risk Oluşumu:** Saldırganlar protokol başlıklarını manipüle ederek güvenlik duvarlarını aşmaya çalışır. Örneğin, TCP SYN bayrağı olmadan doğrudan ACK paketi göndererek durum bilgisi tutmayan (stateless) filtreleri atlatabilirler. Veya şifresiz HTTP trafiğini 443 portundan geçirerek denetimden kaçırmaya çalışırlar.
- **Tespit Mekanizması:**
  - *İzinli Trafik Alanları:* Ağda yalnızca onaylı protokol dizilimlerine izin verilir (Ethernet -> IPv4 -> TCP -> TLS -> HTTP).
  - *Negatif Paket Taraması:* TCP bayrak anomalileri (örneğin aynı anda SYN ve FIN set edilmiş "Xmas Scan" paketleri) veya RFC standartlarına uymayan bozuk paketler IDS/IPS (Suricata/Snort) tarafından tespit edilir.
- **Savunma Stratejisi:**
  - *Protokol Doğrulaması (Strict Protocol Enforcement):* Güvenlik duvarı 443 portundan geçen verinin sentaksını denetler; TLS başlığı içermiyorsa bağlantıyı düşürür (`DROP`).
  - *TLS 1.3 ve HSTS:* İstemcinin asla şifresiz HTTP'ye düşürülmemesi (Downgrade/SSL Strip) için HSTS zorunlu kılınır.
  - *Ağ Segmentasyonu:* Katman 3 seviyesinde DMZ, Yönetim VLAN'ı ve Kullanıcı VLAN'ı birbirinden yalıtılır.

---

### Savunma ve Tespit Kılavuzu
- **Sıkılaştırma Kuralları:**
  - `iptables` ile anormal TCP bayraklarını engelleyin:
    ```bash
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP # Null Scan
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP  # Xmas Scan
    iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    ```
  - Web sunucularında HTTP'den HTTPS'e kalıcı 301 yönlendirmesi ve `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` başlığı ekleyin.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, güvenlikte en tehlikeli cümle 'Nasılsa 443 portu şifrelidir' cümlesidir. Saldırgan da senin 443 portuna izin verdiğini bilir; bu yüzden zararlı yazılımının komut kontrol sunucusuyla iletişimini HTTPS gibi gösterir. Sen sadece porta değil, katmanların protokol uyumuna ve davranışına bakacaksın. Sıfır Güven (Zero Trust) tam olarak budur: Katman 1'den Katman 7'ye kadar hiçbir pakete körü körüne güvenme, her başlığı doğrula!"*
