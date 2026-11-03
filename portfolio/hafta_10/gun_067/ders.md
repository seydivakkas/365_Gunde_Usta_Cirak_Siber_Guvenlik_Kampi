# Hafta 10 Gün 67: Paket Kaybı, Gecikme ve Jitter (Usta-Çırak Dersi)

> **Usta Notu:**  
> *"Evlat, acemi bir ağ analisti yalnızca 'bağlantı var mı yok mu' diye bakar. Usta bir siber güvenlik mühendisi ise hattaki mikrosaniyelik gecikme oynamalarından, paket kaybı oranının tırmanışından ve jitter eğrisinden ağın kalbini dinler! Bir ağda aniden RTT (Round Trip Time) 15 katına çıkıyor ve paket kaybı %30'u aşıyorsa, bu sadece bir kablo temassızlığı değildir; arka planda çalışan bir SYN Flood, DNS Amplification DoS saldırısı veya ara belleği şişiren (Bufferbloat) devasa bir siber saldırının işaret fişeğidir. Gecikme ve jitter'ı matematiksel olarak modelleyemeyen bir analist, ağın feryatlarını asla duyamaz!"*

---

## 1. Gecikme (Latency) ve RTT (Round Trip Time) Temelleri

Ağ performansının ve hizmet kalitesinin (QoS) en temel ölçütü gecikmedir. Gecikme iki temel perspektiften incelenir:

### 1.1 Tek Yönlü Gecikme (One-Way Delay - OWD)
Bir paketin kaynak düğümden çıktığı an ile hedef düğümün ağ kartına ulaştığı an arasında geçen süredir:
$$\text{OWD} = T_{\text{varış}} - T_{\text{gönderim}}$$

- **Önkoşul:** Kaynak ve hedef düğümlerin saatlerinin son derece hassas (NTP / PTP IEEE 1588) senkronize olması gerekir. Aksi halde saat kayması (Clock Skew) nedeniyle yapay negatif gecikmeler veya devasa süreler hesaplanır.
- **ITU-T G.114 Standardı:** İnsan kulağının iki yönlü bir konuşmada gecikmeyi fark etmeden akıcı iletişim kurabilmesi için tek yönlü gecikmenin $150\text{ ms}$'nin altında olması şarttır. $400\text{ ms}$ üzeri gecikmeler kabul edilemez seviyedir.

### 1.2 Gidiş-Dönüş Süresi (Round Trip Time - RTT)
Kaynak düğümün bir istek paketi (veya TCP veri segmenti) göndermesi ile hedeften dönen yanıtın (veya TCP ACK paketinin) gelmesi arasında geçen toplam süredir:
$$\text{RTT} = T_{\text{ACK\_varış}} - T_{\text{gönderim}}$$

- **Avantajı:** İki ucu da aynı yerel saat üzerinden ölçtüğü için mutlak saat senkronizasyonu gerektirmez.
- **Bileşenleri:** Yayılma gecikmesi (Propagation delay), İletim gecikmesi (Serialization delay), İşleme gecikmesi (Processing delay) ve Kuyruk gecikmesi (Queuing delay).

---

## 2. Jitter (Gecikme Değişimi / IPDV) Matematiği

Jitter, ardışık olarak iletilen paketlerin gecikmelerindeki dalgalanmadır. Ağ anahtarlarındaki kuyruk doluluklarının anlık değişmesi paketlerin farklı sürelerde hedefe varmasına yol açar.

### 2.1 RFC 3393: Paketler Arası Gecikme Farkı (IPDV)
$i$ ve $j$ paketleri arasındaki gecikme farkı:
$$D(i, j) = (R_j - S_j) - (R_i - S_i) = (R_j - R_i) - (S_j - S_i)$$
Burada $S$ gönderim zamanı, $R$ ise varış zamanıdır.  
**Ortalama Mutlak Jitter (Mean Absolute Jitter):**
$$J_{\text{ort}} = \frac{1}{N-1} \sum_{k=1}^{N-1} |D(k, k+1)|$$

### 2.2 RFC 3550: Düşük Geçirgen Jitter Filtresi (Smoothed Jitter)
Gerçek zamanlı aktarım protokolü (RTP / VoIP) oturumlarında her yeni gelen paketle jitter şu şekilde güncellenir:
$$J(i) = J(i-1) + \frac{|D(i-1, i)| - J(i-1)}{16}$$
Bu formül, anlık istatistiksel sapmaları sönümleyerek ağın kararlı jitter eğilimini gösterir. VoIP SLA standartlarında filtrelenmiş jitter değerinin $30\text{ ms}$ altında kalması beklenir.

---

## 3. Paket Kaybı (Packet Loss) ve TCP Yeniden İletimleri

### 3.1 Kayıp Oranı Hesabı
Ağ tampon belleğinin taşması, gürültü veya yönlendirici kuyruk düşürmeleri (Tail Drop / RED) sonucu kaybolan paketlerin oranı:
$$\text{Kayıp Oranı (\%)} = \frac{P_{\text{gönderilen}} - P_{\text{alınan}}}{P_{\text{gönderilen}}} \times 100$$

### 3.2 TCP Retransmission Dinamikleri
TCP güvenilir bir protokoldür; paket kaybını otomatik olarak tespit eder ve yeniden iletir:
1. **Hızlı Yeniden İletim (Fast Retransmit):** Alıcı eksik bir segment gördüğünde göndericiye peş peşe 3 Tekrarlanan Onay (Triple Duplicate ACK) yollar. Gönderici RTO zaman aşımını beklemeden o segmenti derhal tekrar yollar.
2. **Yeniden İletim Zaman Aşımı (RTO - Retransmission Timeout):** Hiç ACK gelmezse RTO süresi dolar ve TCP penceresi (CWND) 1 MSS'e düşürülerek paket yeniden gönderilir.
3. **Retransmission Oranı:** Bir TCP oturumunda yeniden iletilen segment sayısı toplam segmentlerin %5'ini aşıyorsa ağda ciddi bir fiziksel hasar, yetersiz bant genişliği veya araya girme (MitM) girişimi vardır.

---

## 4. Siber Güvenlik ve Tehdit Avcılığı Korelasyonu

| Ağ Belirtisi | Olası Siber Tehdit | Tehdit Avcılığı Mekanizması |
|---|---|---|
| **Ani RTT Patlaması + Yüksek Kayıp** | DDoS / Volumetrik Saldırı (SYN Flood, UDP Flood) | Ağ anahtarlarındaki kuyruk taşması ve tampon bellek kilitlenmesi (Bufferbloat) analizi |
| **Tekrarlı Düzenli Mikro Gecikmeler** | Zamanlama Gizli Kanalı (Covert Timing Channel) | İki paket arasındaki gecikmenin modüle edilerek veri sızdırılması (Steganography) |
| **Gecikmenin Aniden 3-4 Katına Çıkması** | BGP Hijacking / Trafik Yönlendirme | Paketlerin normal rotasından çıkarılıp yabancı bir ülkedeki gözetleme sunucusundan geçirilmesi |
| **Spurious Retransmission / Out-of-Order** | TCP RST Enjeksiyonu / MitM Saldırısı | Saldırganın sahte paketlerle bağlantıyı düşürme veya oturum çalma denemeleri |

---

## 5. Ustanın Çırağa Öğüdü
Çırak! Ağ izleme panellerinde kırmızı alarm çaldığında herkes "sunucu çöktü" diye bağırır. Ama sen sakin olacaksın. Önce RTT grafiğine bakacaksın: Eğer RTT yükselmeden kayıp başladıysa donanım veya arayüz seviyesinde bir problem vardır. Yok eğer önce RTT tavan yapmış, ardından kuyruklar dolup paket kaybı patlamışsa bil ki birisi o hattı boğuyordur! Sorunun kökünü görmek için metriklerin dansını iyi oku!
