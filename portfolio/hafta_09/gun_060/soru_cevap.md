# G060: HTTP/2 ve HTTP/3 Farkları — Soru-Cevap Dokümanı

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya ticari olarak kullanılamaz.
```

---

## G060-SC1: Çoklama ve Hat Başı Tıkanması (HoL Blocking) Çıkmazı

### Soru
HTTP/2 protokolü tek bir TCP bağlantısı üzerinde ikili çerçevelerle çoklama (multiplexing) yapmasına rağmen Hat Başı Tıkanması (Head-of-Line / HoL Blocking) sorununu neden tamamen ortadan kaldıramamıştır? HTTP/3 protokolünün QUIC taşıma katmanı (UDP) bu sorunu bağımsız akış mimarisiyle nasıl kökten çözmektedir?

### Derin Teknik Cevap
HTTP/1.1'deki Hat Başı Tıkanması, **uygulama katmanı (Application Layer)** düzeyindeydi; tek bir TCP soketinde bir HTTP yanıtı tamamlanmadan sonraki istek işlenemiyordu. HTTP/2 (RFC 7540), her isteği mantıksal olarak bağımsız **Akışlara (Streams)** ve küçük 9 baytlık başlıklı **İkili Çerçevelere (Binary Frames)** bölerek uygulama katmanındaki tıkanıklığı çözdü. Artık tek bir TCP bağlantısı üzerinde yüzlerce akışın çerçeveleri (örneğin Akış 1 DATA, Akış 3 HEADERS, Akış 5 DATA) birbirinin arasına örülerek eşzamanlı taşınabilmektedir.

Ancak HTTP/2, **taşıma katmanında (Transport Layer) TCP protokolüne bağımlıdır**. TCP protokolü, doğası gereği tüm bayt akışının alıcıya kesinlikle sıralı, eksiksiz ve hatasız teslim edilmesini zorunlu kılar (In-order Byte Stream Abstraction). Eğer internet ağında yönlendirici seviyesinde tek bir IP paketi düşerse (packet drop):
1. TCP alıcı tamponu (TCP receive buffer), kaybolan o tek paketin sıra numarasını tespit eder ve yeniden iletim (retransmission / SACK) talep eder.
2. Kaybolan paket örneğin Akış 3'e ait olsa dahi, TCP protokolü ardışık gelen Akış 1, Akış 5 veya Akış 7 paketlerini **uygulama katmanına (web sunucusuna veya tarayıcıya) teslim edemez ve çekirdek tamponunda bekletir**.
3. Çünkü TCP, paketlerin içindeki HTTP/2 akış kimliklerinden (Stream ID) habersizdir; o yalnızca tek bir kesintisiz bayt dizisi görür.
4. Kayıp paket yeniden iletilip onaylanana kadar, o TCP bağlantısı üzerindeki TÜM HTTP/2 akışları kilitlenir. Özellikle paket kaybı oranının %1-2 olduğu dalgalı mobil (4G/LTE) veya Wi-Fi ağlarında, HTTP/2'nin performansı HTTP/1.1'in 6 ayrı TCP bağlantılı modelinden bile daha kötü hale gelmektedir.

HTTP/3 (RFC 9114) ise bu çıkmazı TCP'yi tamamen terk edip **UDP üzerinde koşan QUIC (RFC 9000)** taşıma protokolünü kullanarak aşmıştır. QUIC protokolünde:
1. Akış yönetimi ve güvenilirlik (reliability) mekanizması doğrudan taşıma katmanına entegre edilmiştir.
2. Her QUIC akışı bağımsız bir mantıksal kanaldır ve kendi sıra numaralandırmasına sahiptir.
3. Eğer Akış 3'e ait bir UDP datagramı ağda kaybolursa, işletim sistemi ve QUIC motoru yalnızca Akış 3 için yeniden iletim süreci başlatır.
4. Bu esnada Akış 1 ve Akış 5'e ait gelen UDP paketleri **hiçbir gecikmeye uğramadan derhal HTTP/3 ayrıştırıcısına teslim edilir ve işlenir**.
5. Böylece ağ seviyesindeki paket kayıpları diğer akışları kesinlikle etkilemez ve gerçek anlamda Sıfır HoL Blokajı (Zero Head-of-Line Blocking) elde edilir.

### Siber Güvenlik ve Tehdit Modeli Açısından Kritik Önemi
Ağ kalitesinin düşük veya paket enjeksiyonu/saldırısı altında olduğu senaryolarda, TCP tabanlı HTTP/2 sistemleri yapay gecikme (latency) ve DoS durumlarına sürüklenir. Kötü amaçlı bir aktör, TCP bağlantısına yönelik mikro düzeyde paket düşürme veya ACK manipülasyonu yaparak tüm web oturumlarını felç edebilir. QUIC'in bağımsız akış mimarisi, ağ gürültüsüne ve kısmi paket engellemelere karşı protokol seviyesinde dayanıklılık sağlar.

### Pratik / Sektörel Yansıma ve Analiz
- Küresel CDN ve teknoloji devleri (Google, Cloudflare, Meta), mobil kullanıcıların video akışlarında ve arama sorgularında HTTP/3'e geçtikten sonra sayfa yükleme sürelerinde (Time to First Byte - TTFB) %15 ila %30 arasında somut iyileşme raporlamıştır.
- Özellikle metro tünelleri, asansörler ve zayıf baz istasyonu geçişlerinde HTTP/3, paket kayıplarından etkilenmeyerek kullanıcı deneyiminin kesilmesini önler.

---

## G060-SC2: CVE-2023-44487 HTTP/2 Rapid Reset DDoS İstismarı

### Soru
Tarihin en büyük DDoS saldırı hacimlerine (saniyede 398 milyon istek) ulaşan CVE-2023-44487 "HTTP/2 Rapid Reset" güvenlik açığının temel çalışma prensibi nedir? Protokolün hangi tasarım özelliği kötüye kullanılmıştır ve web sunucusu mimarisinde bu zafiyet nasıl hafifletilir?

### Derin Teknik Cevap
HTTP/2 spesifikasyonu (RFC 7540), istemcilere kaynak tasarrufu sağlamak amacıyla bir akışı tamamlanmadan önce tek taraflı olarak iptal etme hakkı tanımıştır. İstemci, bir istek başlattıktan sonra (`HEADERS` çerçevesi ile), kullanıcının sayfadan ayrılması veya isteğin gereksiz kalması durumunda sunucuya `RST_STREAM` (kod: `CANCEL = 0x8`) çerçevesi göndererek sunucudan yanıt üretimini durdurmasını talep edebilir.

Normal şartlarda HTTP/2'de sunucu, `SETTINGS_MAX_CONCURRENT_STREAMS` parametresi ile eşzamanlı açık kalabilecek akış sayısını (örneğin 100) sınırlar. Ancak saldırganlar şu mimari boşluğu keşfetmiştir:
1. Saldırgan tek bir TCP/TLS bağlantısı üzerinden bir `HEADERS` çerçevesi yollar (örneğin `GET /api/heavy-query`).
2. Sunucu bu isteği alır almaz arka planda iş parçacığı (worker thread) ayırır, oturum belleği açar, veritabanı sorgusu başlatır veya dosya sistemine erişir.
3. Saldırgan, sunucunun yanıt vermesini beklemeden hemen arkasından aynı milisaniyede bir `RST_STREAM` çerçevesi fırlatır.
4. `RST_STREAM` çerçevesi akışı derhal "CLOSED" durumuna soktuğu için, sunucunun `MAX_CONCURRENT_STREAMS` sayacı anında 1 eksilir!
5. Sonuç olarak saldırgan, **eşzamanlı akış sınırına (concurrent limit) asla takılmadan**, tek bir bağlantı üzerinden saniyede yüz binlerce istek açıp anında kapatabilir.
6. Sunucu tarafında istek iptal edilse bile, arka uç sistemlerde tetiklenen CPU döngüleri, veritabanı bağlantı havuzları ve bellek tahsisleri çöpe atılır ve sunucu dakikalar içinde kaynak tükenmesiyle (CPU %100, OOM) çöker.

**Hafifletme ve Savunma Stratejisi:**
1. **RST_STREAM Hız Sınırlaması (Rate Limiting):** Web sunucuları ve ters vekil sunucuları (Nginx, Envoy, Cloudflare), bir bağlantıda belirli bir zaman penceresinde gelen `RST_STREAM` oranını izlemelidir. Eğer bir istemci saniyede izin verilen eşikten (örneğin 100 iptal/sn) fazla sıfırlama yapıyorsa, sunucu istemciyi uyarmadan doğrudan bir `GOAWAY` çerçevesi ile bağlantıyı sonlandırmalı ve istemci IP'sini geçici olarak kara listeye almalıdır.
2. **Kuyruk ve Maliyet Takibi:** Arka uç uygulamaya istek yönlendirilmeden önce, iptal edilen akışların arka uç kuyruklarından da derhal temizlenmesini sağlayan asenkron iptal zincirleri (Context Cancellation - Go'da `context.Done()`) kurulmalıdır.

### Siber Güvenlik ve Tehdit Modeli Açısından Kritik Önemi
Rapid Reset saldırısı, klasik hacimsel (volumetric) DDoS saldırılarından farklı olarak **asimetrik bir protokoler istismardır**. Saldırgan birkaç megabitlik çok düşük bir bant genişliği harcayarak, gigabitlik omurgaya sahip devasa veri merkezlerini çökertebilmiştir. Bu durum, bir protokolün teorik olarak verimli tasarlanmasının, kötü niyetli kullanımda nasıl ölümcül bir hizmet dışı bırakma silahına dönüşebileceğinin en somut kanıtıdır.

### Pratik / Sektörel Yansıma ve Analiz
- Bu açık keşfedildiğinde Google, Cloudflare, Amazon ve Microsoft koordineli bir güvenlik bülteni yayınlamıştır.
- Nginx `keepalive_requests` ve HTTP/2 reset limit yamalarını (1.25.3+ sürümlerinde) devreye almıştır. Modern WAF kurallarında HTTP/2 reset oranları kritik bir anomali metriği olarak izlenmektedir.

---

## G060-SC3: QUIC Bağlantı Göçü ve RFC 9000 3x Anti-Amplification Sınırı

### Soru
QUIC protokolünün Bağlantı Göçü (Connection Migration) yeteneği mobil istemcilerde kesintisiz oturumu nasıl sağlamaktadır? UDP tabanlı bir protokol olması sebebiyle doğabilecek Dağıtık Hizmet Dışı Bırakma (DDoS Amplification) risklerine karşı RFC 9000 standardı sunuculara hangi 3x Anti-Amplification sınırını zorunlu kılmıştır?

### Derin Teknik Cevap
**Bağlantı Göçü (Connection Migration) Mekanizması:**
Klasik TCP bağlantılarında soket kimliği `(Kaynak IP, Kaynak Port, Hedef IP, Hedef Port)` 4'lü demetiyle (4-tuple) tanımlanır. Bir mobil telefon kullanıcısı evindeki Wi-Fi ağından (örneğin `192.168.1.100:54321`) ayrılıp hücresel veriye (örneğin `100.64.10.5:61234`) geçtiğinde, kaynak IP adresi ve portu fiziksel olarak değişir. TCP bu yeni paketi tanıyamaz ve RST döner; tarayıcıdaki tüm TLS el sıkışmaları ve HTTP bağlantıları sıfırdan kurulmak zorunda kalır.

QUIC (RFC 9000), bağlantıyı IP ve port adreslerine bağlamaz. Bunun yerine paket başlıklarında bağımsız bir **Bağlantı Kimliği (Connection ID - CID)** taşır:
1. İstemci ağ değiştirdiğinde, yeni IP adresinden aynı Connection ID bilgisini içeren bir QUIC paketi gönderir.
2. Sunucu bu paketi aldığında, paketin içindeki kriptografik doğrulamayı teyit eder ve istemcinin yeni IP'sine bir `PATH_CHALLENGE` çerçevesi yollar.
3. İstemci `PATH_RESPONSE` ile karşılık verdiğinde yol doğrulaması (Path Validation) tamamlanır.
4. Kullanıcının indirmekte olduğu dosya, izlediği video veya yaptığı API çağrısı milisaniyelik bir kesinti dahi yaşamadan akmaya devam eder.

**RFC 9000 Bölüm 8.1 - 3x Anti-Amplification Sınırı:**
UDP protokolü bağlantısızdır ve kaynak IP adresi saldırganlar tarafından kolaylıkla sahtelenebilir (IP spoofing). Bir saldırgan, hedef kurbanın IP adresini kaynak göstererek bir QUIC sunucusuna 1200 baytlık bir `Initial` el sıkışma paketi gönderirse, sunucu karşılık olarak kurbana onlarca kilobaytlık TLS sertifikası dönerek kurbanı yansıtmalı DDoS ile boğabilir (Amplification Attack).

Bu riski matematiksel olarak engellemek amacıyla RFC 9000 Bölüm 8.1 şu kuralı zorunlu kılmıştır:
$$\text{Sunucunun Gönderebileceği Maksimum Veri} \le 3 \times \text{Alınan Doğrulanmamış Veri Boyutu}$$
1. Sunucu, istemcinin kaynak IP adresini doğrulamadan (yani istemciden sunucu paketlerine karşılık gelen bir yanıt/ACK almadan) önce, istemciden aldığı toplam bayt miktarının **en fazla 3 katı (3x)** kadar veri gönderebilir.
2. Örneğin istemci 1200 bayt Initial gönderdiyse, sunucu en fazla $1200 \times 3 = 3600$ bayt veri gönderebilir.
3. Eğer sunucunun sertifika zinciri 6000 bayt tutuyorsa, sunucu ilk 3600 baytı gönderdikten sonra durmak ZORUNDADIR!
4. Kalan 2400 baytı ancak ve ancak istemci ilk paketi aldığını doğrulayan bir paket yolladıktan (böylece IP sahteciliği ihtimali ortadan kalktıktan) sonra gönderebilir.

### Siber Güvenlik ve Tehdit Modeli Açısından Kritik Önemi
3x sınırı, QUIC sunucularının internet üzerindeki DNS veya NTP sunucuları gibi 50x-100x katsayılı devasa UDP Amplification saldırı araçlarına dönüştürülmesini önleyen temel emniyet sibobudur. Bu kural sayesinde QUIC, UDP'nin hızını alırken UDP'nin en büyük güvenlik açığını matematiksel bir bariyerle kapatmıştır.

### Pratik / Sektörel Yansıma ve Analiz
- Tüm standart QUIC kütüphaneleri (quiche, msquic, aioquic, ngtcp2), dahili sayaçlarla bu 3x kotasını takip eder ve kota dolduğunda soket yazma işlemlerini bloke eder.
- Web geliştiricileri ve sistem yöneticileri, QUIC el sıkışmasının 1-RTT içinde tamamlanabilmesi için sunucu TLS sertifika zincirlerini mümkün olduğunca optimize etmeli (örneğin gereksiz ara sertifikaları budamalı veya ECDSA sertifikaları tercih etmeli), böylece sertifika boyutunun 3x sınırını aşarak fazladan RTT gecikmesine yol açmasını önlemelidir.

---
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
ÖZEL LİSANS — Soru-cevap dokümanı yalnızca görüntüleme ve eğitim amacıyla paylaşılmıştır.
