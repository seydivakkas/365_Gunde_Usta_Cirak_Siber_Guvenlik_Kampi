# G063: Mini Proje 8 — Protokol Zaman Çizelgesi Soru-Cevap ve Vaka Analizi
**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*

---

## G063-SC1: Zaman Serisi Analizi ile Dağıtık Slowloris Hizmet Dışı Bırakma (DoS) Tespiti

### Senaryo Açıklaması
Kurumsal bir e-ticaret platformunun web sunucuları (Nginx & Apache), CPU veya bellek tüketimi %15'in altındayken bile yeni gelen yasal müşteri isteklerine yanıt veremez hale gelmiş ve 504 Gateway Timeout hataları vermeye başlamıştır. Güvenlik duvarı (Firewall) ve IDS sistemleri, geleneksel volumetrik DDoS eşiklerini tetikleyecek yüksek bant genişliği veya paket hacmi görmediği için herhangi bir alarm üretmemiştir. Ağ mühendisleri, şüpheli IP adreslerinden gelen bağlantıların TCP seviyesinde açıldığını fakat HTTP başlıklarının tamamlanmadığını fark etmiştir.

### Karşılaşılan Tehdit / Güvenlik Riski
Karşılaşılan tehdit, tipik bir **Slowloris (Düşük ve Yavaş - Low & Slow) Uygulama Katmanı DoS** saldırısıdır. Saldırgan, sunucuya meşru bir HTTP GET isteği başlatır ancak istek başlıklarını sonlandıran çift satır sonunu (`\r\n\r\n`) kasıtlı olarak göndermez. Sunucunun bağlantı zaman aşımına (keep-alive timeout) uğramasını engellemek için her 15 ila 25 saniyede bir yapay ve anlamsız bir başlık satırı (`X-Slow-Header: val\r\n`) damlatır. Sunucu üzerindeki eşzamanlı maksimum bağlantı havuzu (worker_connections / MaxRequestWorkers) hızla tükenir ve yeni istemciler kuyrukta kalarak erişim engeli yaşar.

### Teknik Çözüm ve Uygulama Adımları
1. **Zaman Serisi Paket İncelemesi:** Ağ izi `ProtocolTimelineAnalyzer` motoruna yüklenerek her bir TCP akışındaki paketler arası varış süresi ($\Delta t$) kronolojik olarak incelenmiştir.
2. **Damlatma Gecikmesi Tespiti:** Motorun `detect_anomalies()` algoritması, HTTP başlık parçaları arasındaki sürenin 15 saniyenin üzerine çıktığını tespit etmiş ve `SlowlorisAnomalyError` fırlatarak şüpheli akışları anında karantinaya almıştır.
3. **Web Sunucu Zaman Aşımı Konfigürasyonu:** Sunucu seviyesinde `client_header_timeout` süresi 60 saniyeden 10 saniyeye indirilmiş ve `client_body_timeout 10s;` kuralı getirilmiştir.
4. **WAF ve Ters Proxy Kuralı:** Ters proxy üzerinde minimum veri iletim hızı (minimum data rate) eşiği tanımlanmış; istemci saniyede en az 500 bayt veri göndermiyorsa soketin derhal sonlandırılması (`HTTP 408 Request Timeout`) sağlanmıştır.

### Alınan Ders ve Kalıcı Güvenlik Tedbiri
Hacimsel (volumetric) analizler, düşük hızlı ve durum tüketen (state-exhaustion) saldırıları tespit etmekte yetersiz kalır. Ağ adli bilişiminde paket hacmi değil, paketler arasındaki **zaman aralıkları ($\Delta t$) ve protokol durum süreleri** izlenmelidir. Kalıcı çözüm olarak tüm ters proxy katmanlarında agresif başlık okuma zaman aşımları ve bağlantı başı asgari veri hızı zorunlulukları uygulanmalıdır.

---

## G063-SC2: Adli Ağ İncelemesinde Zaman Damgası Sahteciliği (Clock Skew / Timestamp Tampering)

### Senaryo Açıklaması
Finansal bir kuruluşa yönelik gelişmiş kalıcı tehdit (APT) sızma girişimi sonrasında, adli bilişim uzmanları saldırının kaynaklandığı sunucudan ve ara yönlendiricilerden pcap kayıtları toplamıştır. Ancak farklı sensörlerden gelen loglar birleştirildiğinde, bir TCP akışında SYN-ACK paketinin göndericiden çıktığı zaman damgasının, istemcinin gönderdiği SYN paketinin zaman damgasından 50 milisaniye daha eski olduğu ($t_{\text{syn-ack}} < t_{\text{syn}}$) görülmüştür. Olay inceleme yazılımları bu çelişki nedeniyle çökmüş veya olayları yanlış sıralamıştır.

### Karşılaşılan Tehdit / Güvenlik Riski
Karşılaşılan risk, **Zaman Damgası Manipülasyonu (Timestamp Tampering / Clock Skew)** veya saldırganın adli izleri karartmak amacıyla paket başlıklarındaki zaman damgalarını geriye doğru değiştirmesidir. Ağ paketlerinde nedensellik ilkesinin çiğnenmesi (etkinin nedenden önce gerçekleşmesi), korelasyon motorlarının olay zincirini yanlış kurmasına, adli bilişim raporlarının mahkemede delil niteliğini kaybetmesine ve saldırganın eylemlerinin tespit edilememesine yol açar.

### Teknik Çözüm ve Uygulama Adımları
1. **Monotonik Zaman Doğrulama:** `ProtocolTimelineAnalyzer` motorunun `validate_and_sort_timeline(enforce_strict_monotonic=True)` fonksiyonu devreye alınmıştır.
2. **Negatif Delta Tespiti:** Ardışık iki paket arasında negatif delta ($t_i - t_{i-1} < 0$) tespit edildiğinde sistem sessizce sıralamak yerine `TimelineOrderError` istisnası fırlatmış ve anomaliyi adli raporda `NEGATIF_DELTA_ZAMAN_GERILEMESI` olarak etiketlemiştir.
3. **NTP ve PTP Senkronizasyon Denetimi:** Ağ altyapısındaki tüm sensörlerin, yönlendiricilerin ve log toplayıcıların ortak bir Stratum-1 NTP (Network Time Protocol) veya PTP (Precision Time Protocol / IEEE 1588) sunucusuna kriptografik kimlik doğrulamalı (NTP symmetric key / NTS) bağlı olduğu doğrulanmıştır.
4. **Zaman Damgası Donanım Katmanı:** Yüksek hızlı paket yakalama kartlarında (NIC hardware timestamping) zaman damgasının yazılımsal değil, doğrudan donanım PHY katmanında basılması kuralı yürürlüğe konmuştur.

### Alınan Ders ve Kalıcı Güvenlik Tedbiri
Farklı kaynaklardan toplanan ağ kayıtları korelasyona tabi tutulmadan önce mutlaka kesin kronolojik ve monotonik zaman doğrulamasından geçirilmelidir. Zaman damgaları donanımsal olarak basılmalı ve zaman senkronizasyonu saldırılara karşı kriptografik olarak güvence altına alınmalıdır.

---

## G063-SC3: TCP Sıra Numarası Sıçraması ile Oturum Çalma (Session Hijacking) Girişimi

### Senaryo Açıklaması
Kritik bir SCADA yönetim ağı ile sunucuları arasındaki şifresiz TCP veri akışında, istemci 1001 sıra numarasıyla veri aktarırken, araya giren harici bir kaynak aniden aynı 5-demet üzerinde sıra numarasını 9.999.999 olarak belirten ve sistem kapatma komutu içeren sahte bir TCP DATA paketi göndermiştir. Sunucu uygulamasının bu paketi işleyip işlemediği ve oturumun ele geçirilip geçirilmediği adli bilişim incelemesine konu olmuştur.

### Karşılaşılan Tehdit / Güvenlik Riski
Tehdit, **Kör TCP Oturum Çalma (Blind TCP Session Hijacking / Sequence Number Injection)** saldırısıdır. Saldırgan, istemcinin IP adresini taklit ederek ve tahmin ettiği ya da rastgele ürettiği bir TCP sıra numarası ile sunucuya komut enjekte etmeye çalışmaktadır. Eğer sıra numarası TCP alıcı penceresi (receive window) dışında kalırsa TCP yığını paketi reddeder; ancak sıra numarası beklenmedik biçimde devasa bir sıçrama gösteriyorsa bu durum aktif bir sızma ve oturum çalma teşebbüsüdür.

### Teknik Çözüm ve Uygulama Adımları
1. **Durumsal Sıra Numarası Doğrulama:** Zaman çizelgesi motorunun `detect_anomalies()` modülü, ardışık TCP paketlerinin sıra numaralarını ve önceki paket boyutlarını ($SEQ_{yeni} = SEQ_{eski} + Len$) takip etmiştir.
2. **Sıra Numarası Sıçraması İkazı:** Ardışık iki paket arasındaki $\Delta SEQ$ farkının $1.000.000$'ı aştığı tespit edilmiş ve `SequenceAnomalyError` fırlatılarak saldırı anında tespit edilmiştir.
3. **Oturumun Sonlandırılması ve İzolasyon:** Anomali tespit edilen akışa derhal her iki yönde geçerli `TCP RST` paketleri gönderilerek şüpheli oturum düşürülmüş, saldırganın enjekte ettiği komutun işletilmesi engellenmiştir.
4. **Taşıma Katmanı Güvenliği (TLS Zorunluluğu):** SCADA ve yönetim ağındaki tüm düz metin TCP akışları mTLS (karşılıklı TLS doğrulaması) protokolüne geçirilerek sıra numarası taklidi yapılsa dahi kriptografik MAC/AEAD doğrulaması ile paketin reddedilmesi sağlanmıştır.

### Alınan Ders ve Kalıcı Güvenlik Tedbiri
TCP sıra numaraları tek başına bir güvenlik mekanizması değildir; yalnızca iletim güvenilirliğini sağlar. Kritik ağlarda oturum bütünlüğü, mutlaka TLS 1.3 veya IPsec gibi kriptografik kimlik doğrulama ve bütünlük denetimi sağlayan güvenlik protokolleri ile korunmalıdır.
