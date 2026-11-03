# G065: Follow TCP Stream ve Yeniden Birleştirme Soru-Cevap ve Vaka Analizi
**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*

---

## G065-SC1: Örtüşen TCP Segmentleri (Overlapping TCP Segments) ile IDS/IPS Atlatma Girişimi

### Senaryo Açıklaması
Finansal bir kurumun web uygulama güvenlik duvarı (WAF) ve Snort/Suricata tabanlı ağ IDS sistemi, web sunucularına yönelik herhangi bir SQL Injection veya zararlı komut alarmı üretmemiştir. Ancak veritabanı loglarında `admin` kullanıcısının şüpheli bir oturum açtığı ve yetkisiz veri çektiği saptanmıştır. Olay müdahale ekibi, saldırı anına ait pcap dosyasını incelemeye aldığında, aynı TCP akışı içinde kasıtlı olarak örtüşen sıra numaralarına sahip paketler tespit etmiştir.

### Karşılaşılan Tehdit / Güvenlik Riski
Karşılaşılan tehdit, **TCP Akış Parçalama ve Örtüşme Yoluyla IDS Atlatma (Ptacek-Newsham TCP Evasion Attack)** yöntemidir. Saldırgan, ilk pakette zararsız görünen `SELECT name FROM products WHERE id=1` komutunun parçalarını göndermiş, hemen ardından gelen örtüşen segmentte ise aynı bayt ofsetlerine zararlı SQL Injection yükünü (`UNION SELECT password FROM users`) enjekte etmiştir. IDS sistemi "First-Write-Wins" politikası uygulayarak ilk gelen zararsız segmenti birleştirirken, hedef Linux web sunucusu "Last-Write-Wins" politikası ile son gelen zararlı segmenti işlemiş ve saldırı IDS'e yakalanmadan hedefe ulaşmıştır.

### Teknik Çözüm ve Uygulama Adımları
1. **Adli Akış İncelemesi:** Ağ izi `FollowTCPStreamEngine` motoruna yüklenmiş ve `add_segment()` fonksiyonuyla TCP segmentleri sırayla incelenmiştir.
2. **Çelişkili Örtüşme Tespiti:** Motor, birleştirilmiş akış ile sonradan gelen örtüşen segment arasında veri uyumsuzluğu saptamış ve derhal `OverlappingPayloadConflictError` fırlatarak saldırıyı tespit etmiştir.
3. **IPS Normalizasyon Modülü (TCP Normalization):** Güvenlik duvarı ve IDS katmanına TCP Normalizer (Trafik Temizleyici) modülü eklenmiştir. Bu modül, iç ağdaki işletim sistemlerinin TCP yığın politikalarını eşleştirmiş ve çelişkili örtüşen segmentleri doğrudan ağ kartı seviyesinde `TCP RST` ile düşürecek şekilde yapılandırılmıştır.
4. **WAF Seviyesinde Yük Denetimi:** Taşıma katmanı hilelerinden etkilenmemek adına uygulama katmanı WAF'ı ters proxy modunda çalıştırılarak TCP akışının doğrudan WAF üzerinde sonlandırılması (TCP termination) sağlanmıştır.

### Alınan Ders ve Kalıcı Güvenlik Tedbiri
Ağ tabanlı saldırı tespit sistemleri, korudukları hedef sunucuların işletim sistemi seviyesindeki TCP birleştirme davranışlarını (BSD, Linux, Windows farklılıkları) bilmeli veya trafiği sonlandırarak (full proxy) normalize etmelidir. Çelişkili örtüşen segmentler olağan bir ağ davranışı değildir; her zaman aktif bir saldırı göstergesi olarak değerlendirilmelidir.

---

## G065-SC2: Asimetrik Yönlendirme (Asymmetric Routing) Nedeniyle TCP Akışının Birleşememesi

### Senaryo Açıklaması
Kurumsal bir şube ile merkez veri merkezi arasında iki ayrı internet hattı (BGP multi-homing) üzerinden iletişim kurulmaktadır. Güvenlik operasyon merkezi analistleri, Wireshark ile şube çıkışında aldıkları pcap dosyalarında "Follow TCP Stream" komutunu çalıştırdıklarında, yalnızca istemcinin gönderdiği HTTP GET isteklerini (kırmızı metin) görebildiklerini, sunucunun yanıtlarının ise hiçbir şekilde görünmediğini fark etmiştir.

### Karşılaşılan Tehdit / Güvenlik Riski
Karşılaşılan durum bir siber saldırı değil, **Asimetrik Yönlendirme (Asymmetric Routing)** kaynaklı bir görünürlük (observability) ve güvenlik açığıdır. İstemciden çıkan istek paketleri Hat-A üzerinden giderken, sunucudan dönen yanıt paketleri BGP yönlendirmesi nedeniyle Hat-B üzerinden şubeye ulaşmaktadır. Tek bir hat üzerinden dinleme yapan analist veya durum denetimli güvenlik duvarı (Stateful Firewall), bağlantının yalnızca tek yönünü gördüğü için TCP durumunu `SYN_SENT` veya yarım açık (half-open) olarak algılamakta, akışı birleştirememekte ve yanıt trafiğindeki zararlı yazılımları denetleyememektedir.

### Teknik Çözüm ve Uygulama Adımları
1. **Olay Analizi ve Yön Tespiti:** `FollowTCPStreamEngine` motoru çalıştırıldığında `client_to_server` akışının 69 bayt ile eksiksiz birleştiği, ancak `server_to_client` akışının hiç segment içermediği raporlanmıştır.
2. **Yönlendirme Simetrisi Yapılandırması:** Şube ve veri merkezi kenar yönlendiricilerinde (Border Routers) BGP yönlendirme metrikleri düzenlenerek gidiş ve dönüş trafiğinin aynı omurga üzerinden akması zorunlu kılınmıştır.
3. **Merkezi Ağ Görünürlüğü (Packet Broker):** Şubelerdeki fiziksel TAP veya SPAN portları, merkezi bir Ağ Paket Aracısına (Network Packet Broker - NPB) bağlanmış; her iki hattan gelen paketler tek bir pcap havuzunda birleştirilerek adli bilişim analizine sunulmuştur.

### Alınan Ders ve Kalıcı Güvenlik Tedbiri
Ağ adli bilişiminde çift yönlü akışın birleştirilebilmesi için trafiğin her iki yönünün de aynı sensör tarafından yakalanması şarttır. Asimetrik yönlendirme durumlarında ağ paket aracıları (NPB) kullanılarak trafik birleştirilmeli, stateful güvenlik duvarlarında asimetrik akışları engelleyecek simetri politikaları uygulanmalıdır.

---

## G065-SC3: Bellek Tüketimi (DoS) Amaçlı Yapay Sıra Dışı Segment (Out-of-Order Queue Flooding)

### Senaryo Açıklaması
Kritik bir dosya aktarım sunucusuna bağlanan harici bir istemci, TCP bağlantısını kurduktan sonra sıra numarası 1.000.000 olan ilk paketin ardından beklenen 1.000.050 yerine 1.500.000, 2.000.000, 2.500.000 gibi aralarında devasa boşluklar bulunan binlerce dağınık segment göndermiştir. Sunucu üzerindeki bellek kullanımı hızla fırlamış ve sunucu diğer kullanıcılara hizmet veremez hale gelmiştir.

### Karşılaşılan Tehdit / Güvenlik Riski
Tehdit, **TCP Yeniden Birleştirme Arabelleği Tüketimi (TCP Out-of-Order Queue Flooding / Memory Exhaustion DoS)** saldırısıdır. TCP yığını, kural gereği sırası henüz gelmemiş paketleri ileride ardışık hale gelebilir umuduyla çekirdek belleğinde (kernel out-of-order queue) saklar. Saldırgan aradaki boşluğu hiçbir zaman doldurmayarak sunucunun belleğini rehin alır ve işletim sistemini OOM (Out of Memory) çöküşüne sürükler.

### Teknik Çözüm ve Uygulama Adımları
1. **Arabellek Kapasite Eşiği:** `DirectionalStreamReassembler` modülüne `max_buffer_size = 5` sınırı konulmuştur. Arabelleğe alınabilecek sıra dışı parça sayısı 5'i aştığında motor derhal `ReassemblyBufferOverflowError` fırlatarak akışı durdurmuştur.
2. **İşletim Sistemi TCP İnce Ayarı:** Linux sunucuda `net.ipv4.tcp_max_orphans` ve `net.ipv4.tcp_reordering` parametreleri sınırlandırılmış; sıra dışı arabelleğin tüketebileceği azami bellek `tcp_rmem` üzerinden kısıtlanmıştır.
3. **SYN Proxy ve Saldırganın Engellenmesi:** Güvenlik duvarında SYN Proxy devreye alınarak aralık doldurmayan ve sıra dışı paket fırtınası başlatan kaynak IP'ler geçici olarak engellenmiştir.

### Alınan Ders ve Kalıcı Güvenlik Tedbiri
Sıra dışı paket arabellekleme mekanizması sınırsız olamaz. Hem yazılımsal analiz motorlarında hem de çekirdek ağ yığınında katı arabellek kuyruk sınırları (queue limits) ve sıra boşluğu zaman aşımları tanımlanmalıdır.
