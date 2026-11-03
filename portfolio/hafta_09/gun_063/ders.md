# G063: Hafta 09 Mini Proje 8 — Protokol Zaman Çizelgesi (Protocol Timeline Analyzer)
**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*

---

## 1. Usta-Çırak Girişi: Neden "Zaman" Ağ Adli Bilişiminin Kalbidir?

Evlat, ağ trafiğini incelerken çoğu acemi mühendis yalnızca paketlerin "içeriğine" (payload) odaklanır. HTTP başlıklarına bakar, DNS sorgu metinlerini okur, TLS sertifikasını inceler. Ancak siber güvenlikte en ölümcül saldırıların ve en karmaşık sistem açıklarının izleri **içerikte değil, zamanda (zaman serisinde)** gizlidir.

Bir ağ olayında zaman bize üç temel gerçeği fısıldar:
1. **Nedensellik (Causality):** Bir istemci, DNS yanıtını almadan TCP SYN gönderemez. TCP 3'lü el sıkışması tamamlanmadan TLS ClientHello iletemez. TLS oturum anahtarları türetilmeden HTTP/2 veri çerçevesi enjekte edemez. Zaman sırasındaki en ufak bir sapma, ya bir sahtecilik (spoofing), ya bir enjeksiyon ya da zaman damgası manipülasyonu (timestamp tampering) işaretidir.
2. **Gecikme ve Performans Metrikleri (Latency & RTT):** SYN ile ACK arasındaki süre ($RTT$), istemci ile sunucu arasındaki coğrafi ve fiziksel ağ mesafesini ortaya koyar. Beklenmeyen dalgalanmalar (jitter) veya sunucu yanıt sürelerindeki gecikmeler, arka uçtaki veritabanı tıkanıklıklarını ya da ara belleğe alma (buffering) saldırılarını ele verir.
3. **Davranışsal Güvenlik Kalıpları (Behavioral Patterns):** Bir insan kullanıcı bir web sayfasına tıkladığında paketler insan refleks süreleriyle ($100\text{ ms} - 2\text{ s}$) akar. Ancak bir port tarama aracı (Nmap SYN scan) 20 milisaniyede yüzlerce porta vurur; bir Slowloris saldırısı ise soketi tüketmek için HTTP başlıklarını 20 saniyede bir damlatır.

Bu mini projede, 9. Hafta boyunca öğrendiğimiz tüm protokolleri (DNS, TCP, TLS 1.3, HTTP/2, Proxy/NAT ve VLAN) bir araya getirerek, ham zaman serisi paket olaylarından kronolojik bir adli zaman çizelgesi inşa eden ve zaman tabanlı saldırıları otonom tespit eden bir analiz motoru geliştirdik.

---

## 2. Ağ Gecikmesinin Fiziksel ve Matematiksel Bileşenleri

Bir ağ paketinin $A$ noktasından $B$ noktasına ulaşmasında geçen toplam tek yönlü gecikme ($T_{\text{gecikme}}$), dört temel bileşenin toplamıdır:

$$T_{\text{gecikme}} = T_{\text{yayilim}} + T_{\text{iletim}} + T_{\text{kuyruk}} + T_{\text{isleme}}$$

1. **Yayılım Gecikmesi ($T_{\text{yayilim}} = \frac{d}{v}$):** Sinyalin fiziksel ortamda (bakır kablo veya fiber optik) kat ettiği mesafedir. $d$ mesafe, $v$ ise ortamdaki ışık hızıdır (fiberde yaklaşık $2 \times 10^8\text{ m/s}$). Bu fiziksel sınır aşılamaz.
2. **İletim Gecikmesi ($T_{\text{iletim}} = \frac{L}{R}$):** Paketin tüm bitlerinin fiziksel hatta basılması için geçen süredir. $L$ paket boyutu (bit), $R$ ise bağlantı bant genişliğidir (bps).
3. **Kuyruk Gecikmesi ($T_{\text{kuyruk}}$):** Yönlendirici (router) ve anahtarların (switch) arabelleklerinde paketin iletilmeyi bekleme süresidir. Ağ yoğunluğuna bağlı olarak dinamik değişir ve dalgalanmaya (jitter) yol açar.
4. **İşleme Gecikmesi ($T_{\text{isleme}}$):** Yönlendiricinin paket başlığını incelemesi, sağlama toplamını (checksum) doğrulaması ve yönlendirme tablosuna bakması için geçen mikrosaniyelik süredir.

TCP el sıkışması ($SYN \to SYN\text{-}ACK \to ACK$), gidiş-dönüş süresini ($RTT = 2 \times T_{\text{gecikme}}$) ampirik olarak ölçmemizi sağlar. Motorumuz, $SYN$ paketi ile $ACK$ paketi arasındaki zaman damgası farkını milisaniye hassasiyetinde ölçerek akışın temel baz RTT değerini çıkarır.

---

## 3. Protokol Durum Zinciri ve Akış Rekonstrüksiyonu

Gerçek bir web erişim oturumu aşağıdaki sıralı durum geçişlerine kesinlikle uymak zorundadır:

```
[ DNS Çözümleme ] -> [ TCP 3-Way Handshake ] -> [ TLS 1.3 Handshake ] -> [ HTTP/2 Çoklama ] -> [ TCP Teardown ]
```

### 3.1. TCP Durum Makinesi
- **CLOSED $\to$ SYN_SENT:** İstemci rastgele bir başlangıç sıra numarası ($ISN_{c} = 1000$) ile SYN gönderir.
- **SYN_SENT $\to$ SYN_RCVD:** Sunucu kendi sıra numarasını ($ISN_{s} = 5000$) ve istemciye onayını ($ACK = 1001$) döner.
- **SYN_RCVD $\to$ ESTABLISHED:** İstemci $ACK = 5001$ ile yanıt vererek çift yönlü güvenilir kanalı tamamlar.
- **FIN_WAIT $\to$ CLOSED:** Çift taraflı FIN/ACK paketleri ile bağlantı zarafetle (graceful) sonlandırılır.

### 3.2. TLS 1.3 ve HTTP/2 Entegrasyonu
TLS 1.3 protokolünde el sıkışma tek bir RTT içinde ($1\text{-}RTT$) tamamlanır:
- İstemci `ClientHello` içinde desteklenen şifre paketlerini (Cipher Suites) ve Diffie-Hellman anahtar paylaşım parametrelerini (Key Share) iletir.
- Sunucu `ServerHello` ile yanıt verir ve hemen ardından `EncryptedExtensions` ve `Finished` paketlerini gönderir.
- Güvenli kanal kurulur kurulmaz HTTP/2 `SETTINGS` çerçevesi ile akım (stream) parametreleri müzakere edilir ve `Stream 1` ile `Stream 3` bağımsız istek/yanıt çiftleri halinde aynı TCP bağlantısı üzerinden paralel olarak çoklanır (multiplexing).

---

## 4. Zaman Serisi Güvenlik Anomalileri ve Tespit Mekanizmaları

Geliştirdiğimiz analiz motoru, zaman çizelgesi üzerinde 5 kritik saldırı kalıbını matematiksel ve durumsal olarak tarar:

1. **Zaman Gerilemesi / Saat Sapması (Clock Skew Tampering - NEG_01):**
   Bir saldırgan veya bozuk telemetri aracı paketleri manipüle ettiğinde $t_{i} < t_{i-1}$ durumu ortaya çıkar. Motor, kesin monotonik zaman kuralını işleterek zaman gerilemesini yakalar (`TimelineOrderError`).
2. **Erken Veri Enjeksiyonu (Premature Data Injection - NEG_03):**
   TCP bağlantısı henüz `ESTABLISHED` durumuna gelmeden HTTP/2 veya TLS veri çerçevesi gönderilmesi tipik bir TCP oturum manipülasyonu veya sahte paket enjeksiyonudur (`HandshakeViolationError`).
3. **TCP Sıra Numarası Sıçraması (Session Hijacking - NEG_04):**
   Aynı akışta ardışık paketler arasında açıklanamayan devasa bir sıra numarası farkı ($\Delta SEQ > 1.000.000$) oluşması, araya giren saldırganın (Man-in-the-Middle) körleme paket enjeksiyonu denemesidir (`SequenceAnomalyError`).
4. **Slowloris Yavaş Başlık Damlatma (Slowloris Drip Attack - NEG_05):**
   Saldırgan sunucu iş parçacıklarını (worker threads) rehin almak için HTTP başlıklarını tamamlamaz; her 15-20 saniyede bir tek bir başlık satırı gönderir. Motor, HTTP başlık paketleri arasındaki zaman aralığını inceleyerek 15 saniyeyi aşan damlatmaları yakalar (`SlowlorisAnomalyError`).
5. **Hızlı Port Taraması (SYN Burst - NEG_06):**
   Bir kaynak IP'nin 100 milisaniyeden kısa bir zaman penceresinde 4 veya daha fazla farklı hedef porta SYN göndermesi, keşif amaçlı otomatik port taramasıdır (`PortScanAnomalyError`).
6. **DNS Tünelleme Patlaması (DNS Tunneling Burst - NEG_07):**
   Kısa bir zaman aralığında ($\Delta t < 500\text{ ms}$) uzun ve yüksek Şannon bilgi entropisine ($H \ge 3.2\text{ bit}$) sahip rastgele alt alan adlarının sorgulanması, verinin DNS üzerinden dışarı sızdırıldığını (data exfiltration) gösterir (`DnsTunnelingAnomalyError`).

---

## 5. Mühendislik Çıkarımları

Bir siber güvenlik operasyon merkezinde (SOC) ya da olay müdahale (IR) sürecinde, pcap dosyalarını körlemesine incelemek yerine önce **zaman çizelgesi izdüşümünü (timeline projection)** çıkarmak gerekir. Zaman çizelgesi, saldırının sıfır anını ($t_0$), saldırganın içeride kalma süresini (dwell time), komuta kontrol (C2) işaretçilerini (beaconing) ve veri sızdırma anını saniyeler içinde gözler önüne serer.
