# G064: Wireshark Filtre Sözdizimi Soru-Cevap ve Vaka Analizi
**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*

---

## G064-SC1: Wireshark Görüntüleme Filtreleri ile Ağ İçi Açık Metin Parola Sızıntısı Avı

### Senaryo Açıklaması
Bir kamu kurumunun iç ağında çalışan eski bir ERP uygulamasının web arayüzüne personelin şifresiz HTTP üzerinden giriş yaptığı yönünde bir ihbar alınmıştır. SOC analistleri, kurum ana omurgasından span portu aracılığıyla 15 dakikalık pcap kaydı (yaklaşık 850 MB, 1.2 milyon paket) almıştır. Bu devasa veri yığını içinde kullanıcıların gönderdiği giriş bilgilerinin ve parolaların gerçekten açık metin olarak gidip gitmediğinin ivedilikle tespit edilmesi istenmiştir.

### Karşılaşılan Tehdit / Güvenlik Riski
Karşılaşılan risk, **Hassas Bilgilerin Şifresiz İletimi (CWE-319: Cleartext Transmission of Sensitive Information)** ve aradaki herhangi bir kötü niyetli aktör veya zararlı yazılım tarafından koklanarak (sniffing) ele geçirilmesidir (Credential Theft). Kullanıcı kimlik bilgileri düz metin aktarıldığında, saldırganlar bu verileri ele geçirerek oturum açabilir, yetki yükseltebilir ve iç ağda yanal hareket (lateral movement) gerçekleştirebilir.

### Teknik Çözüm ve Uygulama Adımları
1. **Hedefe Yönelik Filtre Oluşturma:** Wireshark filtresi olarak `http.request.method == "POST" && (http contains "password" || http contains "auth")` kuralı derlenmiştir.
2. **Paket Ayrıştırma ve İnceleme:** Motorumuz bu filtreyi çalıştırarak 1.2 milyon paket arasından ilgili giriş paketini saniyeler içinde süzmüştür (Paket No: 2).
3. **Yük (Payload) Analizi:** Süzülen paketin HTTP gövdesi incelendiğinde `username=admin&password=SuperSecretPassword123!` parametresinin açık metin olarak iletildiği belgelenmiştir.
4. **HTTPS ve Yönlendirme Politikası:** ERP web sunucusunda HTTP (Port 80) tamamen kapatılmış, HTTP Strict Transport Security (HSTS) başlığı zorunlu kılınmış ve tüm giriş trafiği TLS 1.3 (Port 443) üzerine taşınmıştır.

### Alınan Ders ve Kalıcı Güvenlik Tedbiri
Geniş hacimli ağ izlerinde içerik bazlı `contains` operatörü ile protokol bazlı alan eşleştirmelerini birleştirmek, hassas veri sızıntılarını tespit etmenin en hızlı yoludur. İç ağlar dahil olmak üzere hiçbir web uygulaması şifresiz HTTP ile çalıştırılmamalı, mTLS veya HTTPS kullanımı zorunlu hale getirilmelidir.

---

## G064-SC2: Şüpheli DNS Trafiğinde Tünelleme ve Veri Kaçırma (Data Exfiltration) Tespiti

### Senaryo Açıklaması
Kurumsal bir bankanın siber olay müdahale ekibi, sınır güvenlik duvarlarının tüm doğrudan giden bağlantıları engellediği yüksek güvenlikli bir veritabanı sunucusundan şüpheli DNS trafiği çıktığını fark etmiştir. Veritabanı sunucusu, iç DNS sunucusuna saniyede onlarca kez sıra dışı uzunlukta alan adı çözümleme istekleri göndermektedir.

### Karşılaşılan Tehdit / Güvenlik Riski
Tehdit, **DNS Tünelleme (DNS Tunneling / Data Exfiltration - MITRE ATT&CK T1071.004)** saldırısıdır. Saldırgan, doğrudan internet çıkışı olmayan sunucudaki hassas müşteri verilerini (kredi kartı veya kimlik no) Base32/Hex ile kodlamış ve bunları alt alan adı (subdomain) parçaları olarak DNS A veya TXT sorguları içine gömmüştür. İç DNS sunucusu bu sorguları yetkili dış sunucuya ilettiğinde veri ağ dışına kaçırılmaktadır.

### Teknik Çözüm ve Uygulama Adımları
1. **Uzunluk ve Bayrak Tabanlı Filtreleme:** Wireshark filtre motorunda `dns.qry.name.len > 40 && dns.flags.response == 0` kuralı koşturulmuştur.
2. **Süzülen Paketlerin Analizi:** Paket havuzundan `a9f82bc7102de841029481abcefa738.exfil.darknet.org` gibi 51 karakter uzunluğunda ve rastgele karakter dizisi içeren şüpheli sorgu yakalanmıştır (Paket No: 5).
3. **Entropi ve Frekans Doğrulaması:** Sorgu adının Şannon entropisi ölçülmüş ve 3.8 bit/karakter ile şifrelenmiş/kodlanmış veri olduğu doğrulanmıştır.
4. **Alan Adı Engelleme ve İzolasyon:** `exfil.darknet.org` etki alanı iç DNS çözümleyicilerinde (Recursive DNS) kara listeye (Sinkhole) alınmış; sunucu ağdan izole edilerek zararlı yazılım temizlenmiştir.

### Alınan Ders ve Kalıcı Güvenlik Tedbiri
DNS protokolü yalnızca isim çözümleme için değil, saldırganlar tarafından covert-channel (gizli kanal) olarak da kullanılır. SOC izleme sistemlerinde DNS sorgu uzunluğu (`dns.qry.name.len`) ve sorgu sıklığı düzenli olarak taranmalı, DNS Firewall ve RPZ (Response Policy Zone) mekanizmaları devreye alınmalıdır.

---

## G064-SC3: TCP Sıfır Pencere Kilitlenmesi (Zero Window DoS) ile Sunucu Askıya Alma Teşebbüsü

### Senaryo Açıklaması
Kurumsal bir API ağ geçidinin arka uç servislerine bağlanan bazı istemcilerin, veri aktarımı başladıktan hemen sonra `TCP Zero Window` bayrağı gönderdiği ve bağlantıyı sonlandırmadan uzun süre açık tuttuğu gözlemlenmiştir. API sunucusundaki bağlantı arabellekleri tükenmiş ve sunucu yeni bağlantılara yanıt veremez hale gelmiştir.

### Karşılaşılan Tehdit / Güvenlik Riski
Bu tehdit, **TCP Sıfır Pencere Kaynak Tüketim Saldırısıdır (TCP Window Exhaustion / Sockstress DoS)**. İstemci, sunucudan büyük bir veri talep eder ancak kendi TCP pencere boyutunu (`tcp.window_size == 0`) sıfır olarak bildirir. TCP standartlarına göre sunucu, istemcinin penceresi açılana kadar veriyi belleğinde tutmak ve periyodik olarak `TCP Window Probe` paketleri göndermek zorundadır. Bu durum sunucunun RAM ve soket kaynaklarını tüketerek hizmet kesintisine yol açar.

### Teknik Çözüm ve Uygulama Adımları
1. **Pencere Boyutu Filtresi:** Wireshark filtresi `tcp.window_size == 0 && tcp.flags.reset == 0` olarak derlenmiş ve trafiğe uygulanmıştır.
2. **Anormal Bağlantıların Tespiti:** Paket No: 7 üzerinde pencere boyutunun sıfır olduğu ve bağlantının askıda tutulduğu kesin olarak tespit edilmiştir.
3. **Zaman Aşımı Kuralları:** Çekirdek (Kernel TCP Stack) parametrelerinde `tcp_probe_interval` ve sıfır pencere durumunda kalma maksimum süresi 15 saniye ile sınırlandırılmıştır.
4. **DDoS Koruması:** Yük dengeleyici üzerinde istemci pencere boyutu sıfırda kalan ve veri çekmeyen oturumlar `TCP RST` ile zorla düşürülmüştür.

### Alınan Ders ve Kalıcı Güvenlik Tedbiri
Taşıma katmanı parametreleri (pencere boyutu, MSS, SACK) saldırganlar tarafından protokol seviyesi kaynak tüketimi için manipüle edilebilir. Wireshark filtreleriyle L4 anormallikleri düzenli olarak taranmalı ve işletim sistemi TCP yığını agresif arabellek zaman aşımları ile korunmalıdır.
