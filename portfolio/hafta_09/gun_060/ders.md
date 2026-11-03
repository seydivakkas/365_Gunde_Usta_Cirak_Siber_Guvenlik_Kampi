# G060: HTTP/2 ve HTTP/3 Mimari Farkları ve QUIC Güvenliği — Usta Dersi

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya ticari olarak kullanılamaz.
```

---

## 1. Giriş: Web Protokollerinin Tarihsel Evrimi ve Çıkmazlar

Evlat, dünkü dersimizde HTTPS ve TLS el sıkışmasını, 1-RTT gecikmesini ve kriptografik korumaları inceledik. Ancak HTTPS, altında çalışan taşıma katmanının ve uygulama protokolünün fiziksel kısıtlamalarından bağımsız değildir. Web dünyası 1999 yılından 2015 yılına kadar **HTTP/1.1 (RFC 2616)** protokolü üzerine inşa edilmişti.

HTTP/1.1'in temel mimari kusuru, **tek bir TCP bağlantısı üzerinde aynı anda yalnızca tek bir istek ve yanıt döngüsünün işletilebilmesiydi**. Bir web sayfası onlarca CSS, JavaScript ve resim dosyası içerdiğinde, tarayıcı ilk istek tamamlanmadan ikincisini gönderemiyordu. Buna **Uygulama Katmanı Hat Başı Tıkanması (Application-layer Head-of-Line / HoL Blocking)** denir. Tarayıcılar bu tıkanıklığı aşabilmek için aynı alan adına 6 adede kadar paralel TCP bağlantısı açma hilesine başvurdular. Ancak bu durum, sunucularda on binlerce boşta bekleyen TCP soketi, aşırı bellek tüketimi ve ağ darboğazı yarattı.

2015 yılında **RFC 7540 (HTTP/2)**, 2022 yılında ise **RFC 9114 (HTTP/3)** yayımlanarak internetin omurgasını baştan aşağı değiştirdi. Bugün bir siber güvenlik uzmanı ve ağ mimarı olarak bu iki devasa protokolün iç mekanizmalarını, avantajlarını ve ölümcül güvenlik tehditlerini inceleyeceğiz.

---

## 2. HTTP/2 Mimarisi: İkili Çerçeveleme (Binary Framing) ve Çoklama

HTTP/2, HTTP semantiğini (GET, POST, başlıklar, durum kodları) değiştirmedi; ancak bu verilerin kablo üzerinden nasıl aktarıldığını devrimsel olarak yeniden tasarladı.

### 2.1. İkili Çerçeveleme Katmanı (Binary Framing Layer)
HTTP/1.1 metin tabanlı (`ASCII text`) bir protokoldü. Boşluklar, satır sonları (`\r\n`) ve belirsiz ayrıştırıcılar yüzünden HTTP Request Smuggling saldırılarına açıktı. HTTP/2, metin tabanlı iletişimi çöpe atarak **İkili Çerçeveleme Katmanı**'nı getirdi. Tüm mesajlar küçük, ayrık ve ikili formatta paketlenmiş **çerçevelere (frames)** bölünür.

```
+-------------------------------------------------------------------------+
| HTTP/2 İkili Çerçeve Başlığı (Sabit 9 Bayt - RFC 7540 Bölüm 4.1)       |
+-------------------------------------------------------------------------+
| Uzunluk (Length): 24-bit (Maksimum 16384 bayt = 16 KB)                  |
+-------------------------------------------------------------------------+
| Çerçeve Tipi (Type): 8-bit (DATA, HEADERS, RST_STREAM, SETTINGS vb.)    |
+-------------------------------------------------------------------------+
| Bayraklar (Flags): 8-bit (END_STREAM = 0x1, END_HEADERS = 0x4 vb.)      |
+-------------------------------------------------------------------------+
| R (1-bit Rezerve) | Akış Kimliği (Stream Identifier): 31-bit            |
+-------------------------------------------------------------------------+
```

### 2.2. Çoklama (Multiplexing) Mekanizması
HTTP/2'de istemci ile sunucu arasında **yalnızca TEK BİR TCP bağlantısı** kurulur. Bu tek bağlantı üzerinde, birbirinden bağımsız çalışan mantıksal kanallara **Akış (Stream)** adı verilir.
- İstemci tarafından başlatılan akışlar **tek sayılarla** (1, 3, 5, 7...),
- Sunucu tarafından başlatılan akışlar (Server Push) **çift sayılarla** (2, 4, 6...) numaralandırılır.
- Akış ID 0 ise bağlantının geneline ait kontrol mesajlarına (`SETTINGS`, `PING`) ayrılmıştır.

Tarayıcı aynı anda 50 farklı resim veya komut dosyasını istemek istediğinde, 50 ayrı TCP bağlantısı açmaz; tek bağlantı üzerinden Akış 1, Akış 3, Akış 5 şeklinde çerçeveleri birbirinin arasına örerek (interleaving) gönderir. Sunucu da yanıt çerçevelerini aynı şekilde çoklayarak geri döndürür.

### 2.3. HPACK Başlık Sıkıştırması (RFC 7541)
HTTP isteklerindeki `User-Agent`, `Cookie`, `Accept` gibi başlıklar her istekte tekrar tekrar gönderilerek devasa veri israfına yol açar. HTTP/2, **HPACK** algoritmasını kullanarak iki tablo tutar:
1. **Statik Tablo:** En yaygın 61 başlığı (ör. `:method: GET`, `:status: 200`) sabit 1 baytlık indekslerle temsil eder.
2. **Dinamik Tablo:** Bağlantı süresince tarafların gönderdiği yeni başlıkları hafızada tutar ve sonraki isteklerde yalnızca indeks numarasını iletir.

---

## 3. HTTP/2'nin Büyük Kusuru: TCP Hat Başı Tıkanması (TCP HoL Blocking)

Usta gözüyle baktığında şu gerçeği görmelisin: **HTTP/2, uygulama katmanındaki tıkanıklığı çözdü ancak sorunu TCP katmanına havale etti!**

HTTP/2'deki tüm o akışlar (Akış 1, 3, 5, 7...) tek bir TCP bağlantısı üzerinde taşınır. TCP protokolü ise bayt akışının kesinlikle **sıralı ve eksiksiz** iletilmesini garanti etmek zorundadır.
Eğer internet yönlendiricisinde meydana gelen bir gürültü sebebiyle Akış 3'e ait tek bir TCP paketi düşerse (packet drop):
- TCP alıcı çekirdeği (OS Kernel), eksik olan Akış 3 paketi yeniden iletilip (retransmit) gelene kadar beklemek zorundadır.
- Bu bekleme esnasında işletim sistemi, eline sağlam ulaşmış olan Akış 1 ve Akış 5 paketlerini dahi web sunucusuna/tarayıcıya **teslim edemez!**
- **Sonuç:** Tek bir paketin kaybı, o tek bağlantıdaki yüzlerce HTTP/2 akışının TAMAMINI kilitler! Zayıf veya dalgalı mobil ağlarda (4G/3G) HTTP/2, HTTP/1.1'den bile DAHA YAVAŞ çalışabilmektedir!

---

## 4. HTTP/3 ve QUIC Devrimi: UDP Üzerinde Yeniden Doğuş

İşte bu TCP çıkmazını aşmak için Google tarafından temelleri atılan ve IETF tarafından **RFC 9000 (QUIC Taşıma Protokolü)** ve **RFC 9114 (HTTP/3)** olarak standartlaştırılan teknoloji sahneye çıkmıştır.

### 4.1. Neden TCP Bırakıldı ve UDP Seçildi?
İnternet omurgasındaki milyonlarca yönlendirici ve güvenlik duvarı (middlebox) yalnızca TCP ve UDP paketlerini tanır. Yeni bir L4 protokolü (örneğin SCTP) tanımlamak, küresel donanım değişimi gerektireceğinden imkansızdı. Bu yüzden QUIC mühendisleri, işletim sistemi çekirdeğine gömülü katı TCP yığınını terk edip, **kullanıcı alanında (userspace) çalışan ve UDP üzerinde koşan akıllı bir taşıma protokolü** tasarladılar.

```
+-------------------------------------------------------------------------+
|                  HTTP/3 (Uygulama Katmanı - QPACK)                      |
+-------------------------------------------------------------------------+
|                  QUIC (Akış Kontrolü + Yerleşik TLS 1.3)               |
+-------------------------------------------------------------------------+
|                  UDP (Port 443 - Hızlı Datagram Aktarımı)               |
+-------------------------------------------------------------------------+
|                  IP (Ağ Katmanı - IPv4 / IPv6)                          |
+-------------------------------------------------------------------------+
```

### 4.2. QUIC Protokolünün Temel Güvenlik ve Mimari Üstünlükleri
1. **Gerçek Sıfır HoL Blokajı (Zero Head-of-Line Blocking):**
   QUIC içinde her akışın (stream) kendi sıra numarası ve akış kontrolü vardır. Akış 2'nin bir UDP paketi kaybolursa, işletim sistemi Akış 1 ve Akış 3'ü sıfır gecikmeyle derhal HTTP/3 motoruna teslim eder! Yalnızca Akış 2 bekler.
2. **Yerleşik Kriptografi (Built-in TLS 1.3):**
   QUIC'te açık metin (cleartext) bir mod yoktur! TLS 1.3 doğrudan QUIC taşıma katmanına entegre edilmiştir. Paket numaraları ve kontrol başlıkları dahi şifrelenir. Araya giren saldırganlar paketlerin akış ID'lerini veya bayraklarını göremez.
3. **1-RTT / 0-RTT Birleşik Bağlantı Kurulumu:**
   TCP el sıkışması (1 RTT) + TLS el sıkışması (1 RTT) beklemek yerine, QUIC ilk pakette hem taşıma parametrelerini hem de TLS 1.3 anahtarlarını takas ederek **tek bir gidiş-dönüşte (1-RTT)** veya devam oturumlarında **0-RTT** ile bağlantıyı açar.
4. **Bağlantı Göçü (Connection Migration):**
   Geleneksel TCP bağlantısı `(Kaynak IP, Kaynak Port, Hedef IP, Hedef Port)` 4'lüsüne sıkı sıkıya bağlıdır. Kullanıcı evdeki Wi-Fi ağından çıkıp hücresel ağa (4G/5G) geçtiğinde IP adresi değişir ve tüm TCP/HTTPS oturumları kopar. QUIC ise paketlerinde rastgele bir **Connection ID (CID)** taşır. IP veya port değişse bile CID değişmediği için kullanıcı video izlerken veya dosya indirirken hiçbir kesinti hissetmez!
5. **QPACK Başlık Sıkıştırması (RFC 9204):**
   HPACK'in akışlar arası bağımlılık yaratan dinamik tablosu yerine, QPACK sıra dışı (out-of-order) başlık açmaya izin vererek başlık düzeyindeki HoL blokajını da ortadan kaldırmıştır.

---

## 5. Siber Güvenlik Tehdit Modelleri ve Saldırı Vektörleri

Bir güvenlik mühendisi olarak HTTP/2 ve HTTP/3 protokollerini incelerken şu üç kritik tehdidi ezbere bilmelisin:

### 5.1. HTTP/2 Rapid Reset DDoS Saldırısı (CVE-2023-44487)
Ekim 2023'te tarihin en büyük DDoS saldırısı (saniyede 398 milyon istek - Cloudflare/Google/AWS verisi) olarak kayıtlara geçen bu açık, HTTP/2'nin mantıksal bir istismarıdır:
- **Saldırı Mekanizması:** Saldırgan tek bir TCP bağlantısı üzerinde `HEADERS` çerçevesiyle pahalı bir istek başlatır (`GET /arama?q=...`), ancak sunucu arka uçta veritabanı sorgusu yapıp iş parçacığı ayırır ayırmaz, saldırgan aynı milisaniyede `RST_STREAM` (İptal) çerçevesi gönderir.
- **Sunucu Tuzağı:** Sunucu akışın iptal edildiğini görür ve yanıtı çöpe atar; ancak sunucunun CPU ve RAM'i bu isteği karşılamak için harcanmıştır. Saldırgan saniyede yüz binlerce HEADERS + RST_STREAM döngüsü üreterek sunucu kaynaklarını sıfıra indirir.
- **Savunma Stratejisi:** Web sunucularında (Nginx, Envoy) RST_STREAM hız sınırlandırması (`rate limiting`) devreye alınmalıdır. Belirli bir zaman penceresinde eşik değerden (örneğin 100 iptal/sn) fazla sıfırlama yapan istemciler `GOAWAY` çerçevesiyle derhal bağlantıdan atılmalıdır.

### 5.2. QUIC UDP Yükseltme (Amplification) Saldırısı ve RFC 9000 3x Kuralı
UDP protokolü kaynak IP sahteciliğine (IP spoofing) açık olduğundan, saldırganlar kurbanın IP'sini sahte kaynak olarak yazıp QUIC sunucularına küçük `Initial` paketleri yollayabilir. Sunucu kurbana devasa TLS sertifika zincirleri dönerse, internette yeni bir yansıtmalı DDoS felaketi doğardı.
- **RFC 9000 Bölüm 8.1 Savunması:** QUIC sunucusu, istemcinin kaynak IP adresini doğrulayana (Path Validation / Handshake Complete) kadar, istemciden aldığı toplam baytın **en fazla 3 katı (3x)** kadar yanıt gönderebilir! Eğer istemci 1200 bayt Initial gönderdiyse, sunucu en fazla 3600 bayt gönderebilir; kalan sertifika bloklarını istemciden ACK alana kadar bekletir.

### 5.3. Alt-Svc Hijacking ve HTTP/3 Sürüm Düşürme (Downgrade)
HTTP/3 UDP üzerinde çalıştığı için tarayıcılar ilk istekte sunucunun HTTP/3 destekleyip desteklemediğini bilemez. Sunucu HTTP/2 yanıtında `Alt-Svc: h3=":443"; ma=86400` başlığı dönerse tarayıcı sonraki istekleri HTTP/3'e taşır. Ağdaki bir saldırgan UDP port 443'ü filtreler veya `Alt-Svc` başlığını silerse, istemciyi sessizce HTTP/2 veya HTTP/1.1'e düşürerek eski zaafiyetleri istismar edebilir.

---

## 6. Usta-Çırak Öğütleri ve Sektörel Pratik

1. **Sunucu Mimarinde:** HTTP/2 aktif edilen her web sunucusunda CVE-2023-44487 yamalarının uygulandığından emin olacaksın (`keepalive_requests` ve reset limitleri).
2. **Güvenlik Duvarında:** Kurumsal ağlarda UDP 443 portunun (QUIC) denetimsizce dışarı açılması, geleneksel DPI (Deep Packet Inspection) araçlarını körleştirebilir; çünkü QUIC başlıkları dahi şifrelidir. QUIC trafiğini ya sonlandırıp inceleyecek ya da kontrollü politikalarla yöneteceksin.
3. **Wireshark Analizinde:** HTTP/2 trafiğini çözmek için `SSLKEYLOGFILE` ortam değişkeniyle TLS oturum anahtarlarını Wireshark'a yükleyecek ve `http2.type == 0x01` filtresiyle başlık akışlarını denetleyeceksin.

---
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
ÖZEL LİSANS — Bu ders notu yalnızca görüntüleme ve eğitim amacıyla hazırlanmıştır.
