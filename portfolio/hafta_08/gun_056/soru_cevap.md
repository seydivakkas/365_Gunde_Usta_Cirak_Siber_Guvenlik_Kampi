# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

# Gün 056: Mini Proje 7 — Soru, Cevap ve Senaryo Analizleri

Bu dokümanda, çok katmanlı paket analizi, protokol hiyerarşisi haritalandırması, TCP yeniden iletim tespiti, DNS tabanlı veri sızıntısı avcılığı ve L2/L3 tehdit analizi senaryoları ele alınmaktadır.

---

## Senaryo G056-SC1: PCAP Analizinde TCP Yeniden İletim ve Gecikmiş ACK Anomalilerinin Kök Neden Tespiti

### Soru / Senaryo
Kritik bir e-ticaret platformunda kullanıcılar ödeme sayfasında (HTTPS) aşırı yavaşlık ve zaman aşımı (timeout) şikayetleri iletmektedir. Ağ mühendisi, web sunucusu ile yük dengeleyici (load balancer) arasındaki trafikten 10 dakikalık bir `.pcap` yakalamıştır. Bu paket akışında çok sayıda mükerrer `TCP Retransmission`, `Fast Retransmission` ve `TCP Dup ACK` paketleri göze çarpmaktadır. Bir SOC ve Ağ Performans Analisti olarak, bu yakalanan akıştan paket kaybının istemci tarafında mı, sunucu tarafında mı yoksa ara ağ donanımlarında mı olduğunu nasıl tespit edersiniz? Bu durum bir DoS saldırısının işareti olabilir mi?

### Ustanın Cevabı / Çözüm Yaklaşımı
Evladım, TCP paket akışındaki yeniden iletimleri (retransmission) çözmek için adli tıp uzmanı gibi adım adım ilerlemelisin:
1. **Zaman Damgası ve Sıra Numarası (Seq/Ack) Analizi:**
   - Eğer gelen paket aynı `Seq` numarasına, aynı bayt uzunluğuna ve aynı veriye sahipse bu kesin bir yeniden iletimdir.
   - Paketin ilk gönderilme zamanı ile tekrar gönderilme zamanı arasındaki fark ölçülür. Eğer fark `RTO (Retransmission Timeout)` süresine (ör. 200ms - 1s) eşitse, bu zaman aşımı kaynaklı standart yeniden iletimdir.
   - Eğer 3 adet arka arkaya gelen `TCP Dup ACK` hemen ardından tetiklenmişse, bu `Hızlı Yeniden İletim (Fast Retransmission)`'dir ve alıcının belirli bir segmenti hiç alamadığını gösterir.
2. **Kayıp Konumunun Tespiti:**
   - Yakalama noktamız web sunucusu önündeyse; sunucunun gönderdiği paketler yeniden iletiliyorsa, paketler yük dengeleyiciye veya istemciye giderken yolda düşmektedir.
   - Eğer istemcinin gönderdiği `PSH+ACK` veri paketleri mükerrer geliyorsa, sunucunun gönderdiği `ACK` onayları istemciye ulaşmamaktadır.
3. **Güvenlik Boyutu (SYN/RST Flood ve Buffer Exhaustion):**
   - Ağdaki bir ara anahtarın (switch) veya güvenlik duvarının tampon belleği (buffer) bir `SYN Flood` veya bant genişliği tüketme saldırısı nedeniyle dolmuşsa, meşru ödeme paketleri kuyruk taşması (tail drop) nedeniyle rastgele düşürülür. Bu da kitlesel yeniden iletime ve gecikmeye yol açar.

### Kritik Güvenlik Çıkarımı
TCP yeniden iletimi sadece kablo veya donanım arızası değildir. Dağıtık Hizmet Engelleme (DDoS) saldırılarında ağ donanımlarının CPU veya ASIC paket kuyrukları doyuma ulaştığında ortaya çıkan ilk belirti, meşru oturumlardaki `Retransmission` ve `Dup ACK` patlamalarıdır.

### Savunma / Uygulama Kontrol Listesi
- [ ] Wireshark veya tshark üzerinde `tcp.analysis.retransmission` ve `tcp.analysis.duplicate_ack` filtreleriyle yeniden iletim oranını ölçün (Normal ağlarda %1-2'nin altı hedeflenir).
- [ ] Yük dengeleyiciler ve anahtarlarda arabirim düşüş (interface drop / CRC error) sayaçlarını denetleyin.
- [ ] Ara güvenlik duvarlarında `TCP SYN Cookie` özelliğini devreye alarak yarım açık (half-open) bağlantıların bellek tüketmesini önleyin.
- [ ] TCP pencere boyutlarını (Window Size) izleyerek `TCP ZeroWindow` gönderen uç noktaların uygulama seviyesinde tıkanıp tıkanmadığını doğrulayın.

---

## Senaryo G056-SC2: Şüpheli DNS Trafiğinde Shannon Entropisi ve C2 Tünelleme Tespiti

### Soru / Senaryo
Bir kurumun iç ağındaki bir muhasebe bilgisayarından dış dünyadaki bilinmeyen bir DNS sunucusuna (UDP 53) saatte yaklaşık 5.000 adet DNS sorgusu gönderildiği tespit edilmiştir. Güvenlik duvarı dışarıya HTTP/HTTPS trafiğini tamamen engellemiş durumdadır ancak DNS sorgularına izin verilmektedir. Gönderilen sorgu alan adları `a7f9c10e8b2.tunnel.c2server.org`, `1b8d4e99f01.tunnel.c2server.org` gibi rastgele görünen alt alan adlarından oluşmaktadır. Bu trafiğin bir **DNS Tünelleme (Data Exfiltration / C2)** olduğunu matematiksel ve mantıksal olarak nasıl ispatlarsınız?

### Ustanın Cevabı / Çözüm Yaklaşımı
Evladım, güvenlik duvarlarının DNS'i (Port 53) sorgusuz sualsiz dışarıya açması, saldırganların en sevdiği arka kapıdır. Bu saldırıyı ispatlamak için **Shannon Entropisi** ve **Protokol Haritası Davranış Analizi** kullanılır:

1. **Shannon Entropi Analizi:**
   Normal insan yapımı alan adları (örneğin `google.com`, `turkiye.gov.tr`, `banka.com.tr`) belirli sesli-sessiz harf dizilimlerine sahip olup düşük entropiye (düzensizliğe) sahiptir ($H \approx 1.5 - 2.5$ bit/karakter). Ancak şifrelenmiş, sıkıştırılmış veya heksadesimal/Base64 kodlanmış gizli veriler rastgele dağılım gösterir ve entropisi fırlar ($H \ge 2.8 - 4.0$ bit/karakter).
2. **Sorgu Uzunluğu ve Kayıt Türü (QTYPE):**
   - Normal kullanıcılar `A` veya `AAAA` kaydı sorgular. Tünelleme araçları (ör. dnscat2, iodine) ise tek bir yanıtta maksimum bayt taşıyabilmek için `TXT` veya `NULL` kayıtlarını kullanır.
   - Alt alan adı uzunluğu 25 karakterin üzerine çıkıyorsa ve her sorguda alt alan adı değişiyorsa (DGA benzeri), bu kesin bir veri sızdırma kanıtıdır.
3. **Protokol Haritasındaki Aykırılık:**
   Protokol hiyerarşisi haritasında normalde UDP trafiğinin %1-3'ünü oluşturan DNS, toplam hacmin %20'sini aşmışsa ve tek bir IP'den çıkıyorsa bu istatistiksel bir sapmadır (Outlier).

### Kritik Güvenlik Çıkarımı
DNS yalnızca isim çözücü değil, iki yönlü bir taşıma protokolü gibi istismar edilebilir. Uç noktaların doğrudan dış DNS sunucularına sorgu göndermesine izin vermek, ağdaki tüm veri koruma ve DLP politikalarını baypas eder.

### Savunma / Uygulama Kontrol Listesi
- [ ] İç ağdaki istemcilerin dış DNS IP'lerine (8.8.8.8, 1.1.1.1 vb.) doğrudan erişimini güvenlik duvarında kesin olarak engelleyin.
- [ ] Tüm DNS trafiğini kurumsal iç DNS sunucusuna (Recursive Resolver) zorunlu kılın.
- [ ] Kurumsal DNS sunucusunda `Response Rate Limiting (RRL)` ve yüksek entropili TXT sorgularını denetleyen DNS Firewall / RPZ (Response Policy Zone) yapılandırın.
- [ ] SIEM / EDR sistemine `Query Name Length > 30` ve `Entropy > 2.8` kurallı korelasyon alarmları ekleyin.

---

## Senaryo G056-SC3: Çok Katmanlı Protokol Haritası (Protocol Hierarchy) ile SOC Tehdit Avcılığı (Threat Hunting)

### Soru / Senaryo
Bir SOC seviye-2 analisti olarak sabah vardiyasına başladığınızda, ağ izleme platformunda bir önceki geceye ait 5 GB boyutunda ham bir ağ dökümü (.pcap) ile karşılaştınız. Herhangi bir hazır IDS imzası (Snort/Suricata) tetiklenmemiştir. Sıfır bilgiyle (Zero-Knowledge) bu döküm içerisinde gelişmiş bir tehdit aktörünün (APT) varlığını tespit etmek için **Protokol Dağılım Hiyerarşisi (Protocol Hierarchy)** ve **5'li Demet Akış Matrisini (Flow Matrix)** nasıl bir tehdit avcılığı metodolojisiyle kullanırsınız?

### Ustanın Cevabı / Çözüm Yaklaşımı
Evladım, imzasız tehditleri yakalamanın tek yolu **davranışsal anomali avcılığıdır**. Protokol haritasını şu metodolojiyle tararız:

1. **Katman-2 ve Katman-3 Oran Sapmaları:**
   - Normal bir kurumsal ağda `IPv4/IPv6` oranı %95+, `ARP` oranı %1-3 civarındadır. Eğer ARP oranı %15-20'lere tırmanmışsa, içeride bir `ARP Poisoning (MitM)` veya kontrolsüz bir ağ taraması (Netdiscover/Nmap ARP scan) vardır.
2. **Katman-4 Taşıma Analizi:**
   - TCP ve UDP oranlarına bakılır. `TCP SYN` paket sayısı, tamamlanan `TCP ESTABLISHED` oturum sayısından 10 kat fazlaysa, ağda agresif bir `Port Tarama (SYN Port Scan)` veya `SYN Flood` yürütülmektedir.
   - Tek bir kaynak IP'nin yüzlerce farklı portla kısa süreli ve verisiz (0 bayt payload) oturum açıp kapattığı 5-tuple akış matrisinde hemen sırıtır.
3. **Katman-7 Protokol / Port Uyuşmazlığı (Protocol-on-Non-Standard-Port):**
   - Saldırganlar güvenlik duvarı kurallarını aşmak için genellikle HTTP/HTTPS trafiğini 443 yerine 8080, 8443 veya DNS portu olan 53 üzerinden geçirir. Akış matrisinde port numarası ile içerideki yükün (L7 Payload) uyuşup uyuşmadığı denetlenir (Deep Packet Inspection).
4. **Bilinmeyen Protokoller (Unknown Layer-7):**
   - Hiyerarşi haritasında `UNKNOWN` bayt hacmi yüksek olan akışlar filtrelenir. Özel şifreli C2 protokolleri genellikle bu kategoride yakalanır.

### Kritik Güvenlik Çıkarımı
Gelişmiş tehdit aktörleri (APT) bilinen antivirüs ve IDS imzalarından kaçabilir; ancak fizik ve ağ protokol kurallarından kaçamazlar. Bir sisteme sızan saldırgan keşif yapmak, komuta kontrolle konuşmak ve veri çalmak zorundadır. Bu eylemlerin tümü Protokol Haritası ve Akış Matrisinde kaçınılmaz istatistiksel izler bırakır.

### Savunma / Uygulama Kontrol Listesi
- [ ] Günlük veya haftalık bazda kurumsal ağın temel trafik profilini (Baseline) çıkarın; normal TCP, UDP, DNS, ARP oranlarını kaydedin.
- [ ] Zeek (Bro) veya Suricata ile trafikten otomatik 5-tuple bağlantı kayıtları (`conn.log`) üretip SIEM'e aktarın.
- [ ] Standart dışı portlarda çalışan bilinen protokolleri (ör. Port 53 üzerinde TCP/HTTP) tespit eden uygulama tanımlama (App-ID) kuralları yazın.
- [ ] Akış matrisindeki `SYN-SENT` durumunda kalan ve asla `ESTABLISHED` olmayan yarım kalmış oturumları tarama göstergesi olarak filtreleyin.
