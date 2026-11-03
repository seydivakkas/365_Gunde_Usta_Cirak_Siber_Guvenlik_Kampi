# Hafta 10 Gün 67: Paket Kaybı, Gecikme ve Jitter Soru-Cevap

---

### G067-SC1: RTT, Tek Yönlü Gecikme ve Jitter Arasındaki Farklar Nelerdir ve VoIP Kalitesini Nasıl Etkiler?

#### 1. Soru Başlığı ve Tanımı
Ağ telemetrisinde Tek Yönlü Gecikme (One-Way Delay), Gidiş-Dönüş Süresi (RTT) ve Gecikme Değişimi (Jitter) kavramları arasındaki teknik farklar nelerdir? Bu üç metrik gerçek zamanlı ses iletiminde (VoIP / RTP) ve QoS SLA anlaşmalarında kullanıcı deneyimini nasıl şekillendirir?

#### 2. Derinlemesine Teknik Analiz
Gerçek zamanlı ağ uygulamaları (VoIP, video konferans, uzaktan ameliyat, finansal borsa sistemleri) paketlerin hedefe varış düzenine son derece duyarlıdır:

1. **Tek Yönlü Gecikme (One-Way Delay - OWD):**
   - Paketin verici ağ kartından alıcı ağ kartına ulaşma süresidir ($T_{\text{varış}} - T_{\text{gönderim}}$).
   - ITU-T G.114 standardına göre VoIP'te konuşmacıların birbirlerinin sözünü kesmeden doğal konuşabilmesi için tek yönlü gecikme en fazla $150\text{ ms}$ olmalıdır.
   - Ölçülebilmesi için her iki uçta mikrosaniye hassasiyetli zaman senkronizasyonu (PTP IEEE 1588 veya GPS destekli NTP) şarttır.
2. **Gidiş-Dönüş Süresi (RTT):**
   - İstemciden paketin çıkışı ile karşı uçtan yanıtın (TCP ACK veya ICMP Echo Reply) dönüşü arasındaki toplam süredir.
   - Uçtan uca iki yönlü gecikmeyi ve karşı sunucunun işleme gecikmesini (Processing Delay) içerir. Saat senkronizasyonu gerektirmez.
3. **Jitter (Gecikme Değişimi / IPDV):**
   - Ardışık paketlerin iletim süreleri arasındaki farktır. Örneğin 1. paket 20ms'de, 2. paket 80ms'de gelirse aradaki 60ms'lik fark jitter oluşturur.
   - Alıcı cihazdaki "Jitter Buffer" (oynatma tampon belleği) bu dalgalanmayı dengelemeye çalışır. Ancak jitter buffer boyutundan daha geç gelen paketler "zaman aşımına uğramış" sayılarak doğrudan çöpe atılır (Discarded / Artificial Packet Loss). Bu durum sesin robotikleşmesine, hecelerin yutulmasına veya konuşmanın tamamen kopmasına neden olur.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir çağrı merkezinde IP telefonlardan yapılan müşteri görüşmelerinde sesin kesildiği ve müşterilerin şikayetçi olduğu bildiriliyor. Ağ analisti Wireshark üzerinden RTP akışını (`Telephony -> RTP -> RTP Stream Analysis`) inceler.

**Bulgular:**
- Paket kaybı: %1.2 (kabul edilebilir sınırda, < %3).
- Ortalama gecikme: 45 ms (mükemmel, < 150 ms).
- Ortalama Jitter: 92 ms (kabul edilemez! SLA sınırı 30 ms).

**Kök Neden ve Çözüm:**
Ağ anahtarında (Switch) QoS / CoS önceliklendirmesi yapılmamıştır. Veri yedekleme sunucusu ile ses paketleri aynı kuyruğa girmekte; büyük dosya transferleri ses paketlerinin önünde anlık tıkanıklıklar yaratarak jitter'ı patlatmaktadır.
1. Ses VLAN'ı ayrılarak DSCP EF (Expedited Forwarding - Değer 46) işaretlemesi uygulanır.
2. Ağ anahtarlarında ses trafiği için Strict Priority (PQ) kuyruğu tanımlanarak ses paketleri veri paketlerinin önüne geçirilir. Jitter 8 ms'ye düşürülerek sorun çözülür.

#### 4. Ustanın Çırağa Tavsiyesi
Çırak! Sabit bir 100 ms gecikmeyle mükemmel bir telefon görüşmesi yapabilirsin; çünkü insan beyni düzenli gecikmeye hızla adapte olur. Ama gecikme 20 ms ile 200 ms arasında bir salıncak gibi sallanıyorsa (yüksek jitter), dünyanın en pahalı ses kodlayıcısı (codec) bile o sesi kurtaramaz. Gerçek zamanlı trafikte gecikmenin büyüklüğünden değil, dengesizliğinden korkacaksın!

---

### G067-SC2: TCP Yeniden İletimlerinin (Retransmission) Arkasındaki Fiziksel ve Siber Nedenler Nasıl Ayrıştırılır?

#### 1. Soru Başlığı ve Tanımı
Wireshark veya ağ akış analizinde yoğun TCP Yeniden İletimleri (Retransmissions) gözlemlendiğinde, bunun fiziksel bir donanım arızasından (kablo, arayüz hatası, duplex uyuşmazlığı) mı yoksa bir siber saldırıdan (SYN Flood, TCP Reset enjeksiyonu, MitM manipülasyonu) mu kaynaklandığı nasıl ayırt edilir?

#### 2. Derinlemesine Teknik Analiz
TCP yeniden iletimi, bir segmentin gönderildikten sonra alıcıdan beklenen sürede geçerli bir onay (ACK) alamaması durumunda gerçekleşir. İki ana grupta incelenir:

1. **Fiziksel ve Altyapı Kaynaklı Nedenler:**
   - **Kablo / SFP / Port Hataları:** CRC hataları, FCS hataları ve runts/giants paket düşüşleri arayüz seviyesinde (Interface Drops) artar. Ağ anahtarında `show interfaces` komutunda CRC artışı görülür.
   - **Bufferbloat / Aşırı Yük:** Ağ yönlendiricisinin çıkış tamponu aşırı dolar. RTT süresi kademeli olarak yükselir (örneğin 20ms'den 800ms'ye çıkar) ve ardından paketler kuyruk sonundan (Tail Drop) düşmeye başlar.
   - **Duplex Uyuşmazlığı:** Bir uç Full-Duplex, diğer uç Half-Duplex çalıştığında hat yükü arttıkça çarpışmalar (Collisions) ve geç çarpışmalar (Late Collisions) yaşanır.

2. **Siber Tehdit Kaynaklı Nedenler:**
   - **SYN Flood / Yarı Açık Bağlantı Saldırısı:** Sunucunun SYN kuyruğu dolar. Sunucu meşru istemcilerin SYN-ACK paketlerini düşürür ve istemciler sürekli SYN retransmission yapar.
   - **TCP RST / Bağlantı Kesme Enjeksiyonu:** Saldırgan araya girerek sahte RST paketleri basar. İstemci onay alamadığı segmentleri tekrar iletmeye çalışırken oturum zorla sonlandırılır.
   - **BGP Hijacking / Rerouting:** Trafik aniden farklı bir güzergaha yönlendirildiğinde MTU boyut farkları nedeniyle parçalama (Fragmentation Needed) sorunları ve devasa paket kayıpları patlar.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir veri merkezinde web sunucularına yapılan bağlantılarda aniden %35 oranında TCP Retransmission ve paket kaybı raporlanıyor.

**Analiz Protokolü:**
```bash
# 1. Adım: Arayüz fiziksel hata sayaçları kontrol edilir
$ netstat -s | grep -i retrans
    12480 segments retransmitted
    4280 fast retransmits

# 2. Adım: Wireshark filtreleriyle paket paternleri incelenir
# Sadece SYN yeniden iletimlerini izle:
tcp.flags.syn == 1 && tcp.analysis.retransmission

# 3. Adım: TCP Pencere boyutu ve RTT grafiği çıkarılır:
# tcp.analysis.flags && !tcp.analysis.window_update
```

**Karar Mantığı:**
- Eğer yeniden iletimler yalnızca `SYN` bayraklı paketlerde yoğunlaşıyorsa ve hedef sunucunun CPU'su tavan yapmışsa bu bir **SYN Flood DoS** saldırısıdır.
- Eğer yeniden iletimler tüm veri akışlarında homojen dağılıyorsa, RTT uçuşa geçmişse ve switch portlarında `Input Errors / Discards` artıyorsa bu bir **Ağ Tıkanıklığı / Donanım Sınırı** problemidir.

**Müdahale:**
SYN Flood için Linux çekirdeğinde `net.ipv4.tcp_syncookies = 1` ve `tcp_max_syn_backlog = 8192` aktif edilir, güvenlik duvarında SYN rate-limit kuralı işletilir.

#### 4. Ustanın Çırağa Tavsiyesi
Çırak! Bir hekime gittiğinde sana hemen ameliyat demez; önce nabzına, tansiyonuna bakar. Sen de bir sunucu yavaşladığında hemen kabloyu suçlama ya da hemen saldırı var diye yangın çıkarma. Önce TCP analiz bayraklarına bak: Hızlı yeniden iletim mi var (Fast Retransmit), yoksa RTO zaman aşımı mı? RTO varsa paket kara deliğe düşmüştür; Fast Retransmit varsa sadece yolun bir şeridi tıkanmıştır!

---

### G067-SC3: Siber Saldırganların Kullandığı Gizli Zamanlama Kanalları (Covert Timing Channels) Ağ Gecikmesi ve Jitter ile Nasıl Tespit Edilir?

#### 1. Soru Başlığı ve Tanımı
Ağ Gizli Zamanlama Kanalı (Network Covert Timing Channel) nedir? Gelişmiş saldırganlar (APT grupları) paket içeriklerine hiç dokunmadan paketler arasındaki gecikmeyi (Inter-Packet Delay) modüle ederek nasıl gizli veri sızdırır (exfiltration) ve bu durum istatistiksel jitter analiziyle nasıl yakalanır?

#### 2. Derinlemesine Teknik Analiz
Geleneksel DLP (Veri Sızıntısı Önleme) ve IDS sistemleri paketlerin yükünü (payload) denetler. Eğer içerikte gizli belge, kredi kartı veya imza yoksa paketi geçirir.

Gelişmiş saldırganlar bu denetimi aşmak için **Zamanlama Kanallarını (Timing Channels)** kullanır:
- **İkili Modülasyon (Binary Inter-Packet Timing):** Saldırgan ardışık paketler arasındaki gecikmeyi bit transferi için kullanır.
  - Örnek: İki paket arası gecikme $10\text{ ms}$ ise bu `0` bitidir.
  - İki paket arası gecikme $50\text{ ms}$ ise bu `1` bitidir.
- Bu teknikle dışarıya gönderilen sıradan ICMP Echo, NTP veya DNS sorguları üzerinden saniyede birkaç yüz bitlik şifre, özel anahtar (private key) veya token sızdırılabilir.
- **İstatistiki İz:** Doğal ağ trafiğinde paketler arası gecikme (Inter-Arrival Time - IAT) Poisson veya üstel (exponential) dağılım sergiler; sürekli bir varyasyon vardır. Ancak zamanlama gizli kanalında belirli gecikme süreleri (örneğin tam 10ms ve tam 50ms) etrafında kümelenen yapay bimodal (çift tepeli) veya ayrık bir olasılık dağılımı ortaya çıkar. Jitter standart sapması yapay olarak belirli periyotlara kilitlenir.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Yüksek güvenlikli bir savunma sanayii laboratuvarında dışarıya sadece NTP (Port 123) zaman sorguları yapılmasına izin verilmektedir. SOC analisti iç ağdaki bir sunucunun dışarıya yaptığı NTP isteklerinin paketler arası gecikmelerini (IAT) histograma döker.

```python
# Zamanlama Kanalı Tespiti için İstatistiki Varyasyon Katsayısı (Coefficient of Variation)
import numpy as np

# iat_list: Ardışık paket varış aralıkları listesi
iat = np.array([0.010, 0.050, 0.010, 0.010, 0.050, 0.050, 0.010])
mean_iat = np.mean(iat)
std_iat = np.std(iat)
cov = std_iat / mean_iat  # Varyasyon katsayısı

# Eğer gecikmeler doğal rastgelelik yerine 2 sabit süre arasında gidip geliyorsa
# ve entropisi yapay bir bilgi taşıyorsa alarm üretilir:
if abs(cov - 0.8) < 0.05:  # Yapay bimodal gecikme paterni
    print("[ALARM] Gizli zamanlama kanalı şüphesi! Modüle edilmiş paket aralıkları!")
```

**Çözüm:**
1. Ağ geçidinde "Traffic Normalizer / Shaper" kullanılarak paket çıkış aralıklarına yapay mikrosaniyelik rastgele gecikmeler (jitter injection / packet pacing) eklenir. Böylece saldırganın kurduğu zamanlama kodu bozulur ve sızdırılan veri alıcı tarafta anlamsız gürültüye dönüşür.
2. Dış NTP sunucularına doğrudan çıkış yasaklanarak kurum içine yerel bir Stratum-1 atomik/GPS zaman sunucusu kurulur.

#### 4. Ustanın Çırağa Tavsiyesi
Çırak! Saldırgan bazen sana bir mektup yollamaz; mektup taşıyıcısının adımlarının ritmiyle haberleşir! Paketlerin içine baktın temiz çıktı diye rahatlama. Paketlerin ne sıklıkla, hangi ritimle ve ne kadarlık aralıklarla kapından geçtiğine bak. Ritimde insan doğasına veya protokol mantığına aykırı bir düzen varsa, bil ki arkasında bir casusun parmak izi vardır!
