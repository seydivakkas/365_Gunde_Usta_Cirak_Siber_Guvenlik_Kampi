# Gün 051: TCP Sıralama, Akış Kontrolü ve Yeniden İletim Mekanizmaları

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## 1. Ustanın Girişi: Bağlantıyı Kurduk, Peki Veri Nasıl Sağlam Taşınır?

Evlat, dünkü dersimizde iki ucun birbirine nasıl selam verdiğini, yani üçlü el sıkışmayı (SYN, SYN-ACK, ACK) öğrendik. Kapıyı araladık, oturumu `ESTABLISHED` durumuna getirdik. Peki ya sonra?

İşte asıl mühendislik ve siber güvenlik savaşı şimdi başlıyor. Katman-3 IP dünyası paketleri kafasına göre yönlendirir; kimi paket sağdaki fiberden ışık hızında gider, kimi paket soldaki uydu hattına takılır, kimi ise aradaki aşırı yüklü bir yönlendiricinin (router) kuyruğunda ezilip çöpe atılır. 

Buna rağmen sen tarayıcında bir web sayfasını açtığında veya gigabaytlarca boyutunda bir dosyayı indirdiğinde, bir tek baytın dahi yeri karışmaz, tek bir piksel bozulmaz. 

İşte bu mucizenin adı: **TCP Sıralama (Sequencing), Akış Kontrolü (Flow Control) ve Yeniden İletimdir (Retransmission)**.

Bugün seninle TCP'nin paketleri nasıl numaralandırdığını, kaybolan segmentlerin nasıl fark edilip yeniden istendiğini ve bir saldırganın bu mekanizmayı istismar ederek oturumları nasıl koparmaya çalıştığını (Blind RST Injection) en ince ayrıntısına kadar inceleyeceğiz.

---

## 2. Bayt Akışı (Byte-Stream) ve Sıra Numarası Matematiği

Çırakların en büyük yanılgısı şudur: TCP'nin paketleri "1. Paket, 2. Paket, 3. Paket" diye numaralandırdığını sanırlar. Hayır evlat! 

TCP paket tabanlı değil, **bayt akışı (byte-stream)** yönelimli bir protokoldür. TCP için her şey, baştan sona uzanan kesintisiz bir bayt nehridir. Sıra numarası (Sequence Number), o segmentin ilk baytının bu nehir içindeki kaçıncı bayt olduğunu söyler:

$$\text{Next\_Seq} = \text{Seq\_Current} + \text{Payload\_Length}$$

Örnekle görelim:
- İstemci `Seq = 1000` ile 500 baytlık veri gönderdiğinde, bu segment `1000` ile `1499` arasındaki baytları taşır.
- Göndericinin bir sonraki segmentte kullanacağı sıra numarası: $1000 + 500 = 1500$'dür!

### Kümülatif Onay (Cumulative ACK) Mantığı
Alıcı taraf (Sunucu), aldığı her bayt için tek tek teşekkür etmez. Sunucu onay (ACK) paketinde şunu söyler:
> *"Bana şu ana kadar gönderdiğin tüm baytları eksiksiz aldım; şimdi senden falanca numaralı bayttan itibaren devam etmeni bekliyorum!"*

Yani alıcı `Ack = 1500` döndüğünde, bu şu anlama gelir:
*"0'dan 1499'a kadar olan her şeyi sağ salim teslim aldım. Benim kapım şu an 1500 numaralı bayt için açıktır!"*

---

## 3. Kayar Pencere (Sliding Window) ve Akış Kontrolü

Alıcının belleği sonsuz değildir; akıllı telefonun, sunucunun veya IoT cihazının bir tampon belleği (buffer) vardır. Eğer hızlı bir sunucu, yavaş bir cep telefonuna saniyede 100 MB veri basarsa ne olur? Alıcının tamponu taşar, paketler yerlere dökülür.

Bunu önleyen mekanizma **Kayar Pencere (Sliding Window)** akış kontrolüdür:
1. Alıcı, her ACK paketinde başlığın `Window Size` (Pencere Boyutu) alanına tamponunda ne kadar boş yer kaldığını yazar (Örn: `Window = 64240`).
2. Gönderici, onay almadan ağa en fazla bu pencere boyutu kadar veri salabilir. Onay geldikçe pencere sağa doğru kayar.
3. **Sıfır Pencere (Zero Window):** Eğer alıcının uygulaması veriyi işlemekte gecikirse, alıcı `Window = 0` anons eder. Bu, *"Dur! Nefes alamıyorum, bana tek bir bayt dahi gönderme!"* demektir. Gönderici derhal frene basar ve periyodik olarak küçük problar (Zero Window Probe) yollayarak pencerenin açılmasını bekler.

---

## 4. Paket Kaybı ve İki Büyük Yeniden İletim Mekanizması

Ağda bir paket kaybolduğunda TCP bunu nasıl anlar ve nasıl telafi eder? İki temel yol vardır:

### 1. Zaman Aşımı Tabanlı Yeniden İletim (RTO - Retransmission Timeout)
Gönderici bir segment yolladığında bir kronometre başlatır. Eğer beklenen süre içinde ACK gelmezse kronometre çalar (RTO biter) ve gönderici paketi tekrar yollar. 
- **Dezavantajı:** RTO süresi dinamik olarak hesaplansa da genellikle 200 ms ile 1 saniye arasındadır. Bu bekleme süresi yüksek hızlı bağlantılarda iletimi felç eder.

### 2. Hızlı Yeniden İletim (Fast Retransmit & 3 Duplicate ACKs)
İşte mühendislik dehası buradadır! RTO'nun dolmasını beklemek yerine alıcının yardımına başvurulur:
- Gönderici sırasıyla 1, 2, 3, 4 numaralı paketleri göndersin.
- 2 numaralı paket (Seq 2000) yolda kaybolsun.
- 3 numaralı paket (Seq 2500) alıcıya ulaştığında, alıcı bakar ki arada bir boşluk var! Kural gereği sıra dışı paketi onaylayamaz. Son eksiksiz aldığı yere ait onayı yineler: `Ack = 2000 (Dup ACK #1)`.
- 4 numaralı paket (Seq 3000) geldiğinde alıcı yine `Ack = 2000 (Dup ACK #2)` gönderir.
- 5 numaralı paket geldiğinde alıcı bir kez daha `Ack = 2000 (Dup ACK #3)` gönderir.
- **Eşik Kuralı:** Gönderici aynı onay numarasını **peş peşe 3 kez mükerrer (Triple Duplicate ACK)** aldığında anlar ki: *"Ağ çalışıyor ama 2000 numaralı segment kayboldu!"*
- Gönderici RTO zaman aşımını hiç beklemeden derhal 2000 numaralı segmenti tekrar yollar (**Fast Retransmit**)!
- Kayıp paket ulaştığında alıcı aradaki tüm boşlukları kapatır ve toplu bir kümülatif onay fırlatır: `Ack = 4000`!

---

## 5. Güvenlik ve Tehdit Analizi: Ustanın İkazları

### Altın Kural: "Yinelenen Paketler Tek Başına Saldırı Değildir!"
Genç analistler Wireshark'ta kırmızı ve siyah renkle işaretlenmiş `[TCP Retransmission]` veya `[TCP Dup ACK]` satırlarını görünce hemen panikler: *"Saldırı altındayız, DoS yapılıyor!"* 

Sakin ol evlat. Yeniden iletimler IP ağlarının doğasında vardır. Wi-Fi sinyalinin zayıflaması, yönlendiricideki anlık kuyruk doluluğu veya rota sapması sebebiyle meşru paketler kaybolabilir veya gecikmeli olarak mükerrer gelebilir (**Spurious Retransmission**). Bir duruma saldırı diyebilmek için trafik hacminin, eşik değerlerin ve anomalinin bağlamının doğrulanması şarttır.

### Gerçek Güvenlik Tehditleri:
1. **Blind TCP Reset (RST) Injection:**
   İki taraf güvenli bir şekilde konuşurken, araya girmeyen ama ağdaki oturumu dinleyen bir saldırgan, alıcının aktif kayar penceresi (Window) içine düşecek bir sıra numarası tahmin ederek sahte bir `RST` paketi enjekte eder. 
   - **Geleneksel TCP Açığı:** Gelen RST'nin Seq numarası alıcının penceresi içindeyse alıcı oturumu derhal öldürürdü!
   - **Modern Savunma (RFC 5961):** Modern çekirdekler, tam eşleşmeyen pencere içi RST paketlerini doğrudan kabul etmez; karşı tarafa bir **Challenge ACK** göndererek oturumun gerçekten kopup kopmadığını teyit eder!
2. **Zero Window Kaynak Tükenmesi (Window Squeeze DoS):**
   Kötü niyetli bir istemci, sunucuya büyük bir dosya indirme talebi gönderip hemen ardından `Window = 0` ilan eder. Sunucu dosya verisini tampon belleğinde tutmak ve bağlantıyı açık bekletmek zorunda kalır. Binlerce sahte istemci aynı anda bunu yaptığında sunucunun RAM ve soket kapasitesi tükenir.

---

## 6. Savunma İlkeleri ve Sıkılaştırma

1. **RFC 5961 Protokol İyileştirmesi:** Tüm kurumsal sunucularda ve güvenlik duvarlarında RFC 5961 TCP sıkılaştırma standartları devrede tutulmalıdır.
2. **TCP Window Probing Zaman Aşımları:** Sıfır pencerede bekleyen istemcilerin oturumları sonsuza kadar açık tutulmamalı, agresif zaman aşımı süreleriyle (`tcp_retries2`) kaynaklar serbest bırakılmalıdır.
3. **Akıllı IDS/IPS Eşikleri:** IDS motorlarında tekil yeniden iletimler değil, belirli bir zaman diliminde eşik değeri aşan ani Dup ACK veya Out-of-Order patlamaları alarm olarak tanımlanmalıdır.

---

## 7. Ustanın Öğüdü

Evlat, sıralama numaraları verinin bekçisi, kayar pencere ise ağın vicdanıdır. Vicdansızca veri basarsan ağ boğulur; bekçiyi uyutursan saldırgan araya girer. 

Bugün yazdığın motor hem sıralı bayt akışını hem de 3 Dup ACK ile devreye giren hızlı yeniden iletimi gözlerinin önüne serdi. Ağın iç sesini dinlemeyi öğrendin; şimdi bu temeli bir sonraki adım olan TCP oturum sonlandırma ve bayrak manipülasyonlarıyla birleştireceğiz!
