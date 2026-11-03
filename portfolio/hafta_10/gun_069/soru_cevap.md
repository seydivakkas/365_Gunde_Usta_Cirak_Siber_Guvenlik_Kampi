# Hafta 10 Gün 69: Mini Proje 9 - Wireshark Analiz Raporu Soru-Cevap

---

### G069-SC1: Wireshark'ta Protokol Hiyerarşisi (Protocol Hierarchy) ve Konuşma Listeleri (Conversations) Bir Tehdit Avcılığı Operasyonunda İlk Adım Olarak Nasıl Kullanılır?

#### 1. Soru Başlığı ve Tanımı
Bir siber güvenlik analisti gigabaytlarca büyüklükteki bir PCAP dosyasını incelerken neden tek tek paketleri okumak yerine öncelikle Protokol Hiyerarşisi (`Statistics -> Protocol Hierarchy`) ve Ağ Konuşmaları (`Statistics -> Conversations`) istatistiklerine bakar? Bu iki araç tehdit avcılığı sürecini nasıl hızlandırır?

#### 2. Derinlemesine Teknik Analiz
Milyonlarca paketin aktığı devasa bir ağ yakalamasında iğneyle kuyu kazmak imkansızdır. Usta analistler "Yukarıdan Aşağıya (Top-Down)" tümdengelim yöntemini kullanır:

1. **Protokol Hiyerarşisi (Protocol Hierarchy):**
   - Tüm trafiğin OSI katmanları boyunca yüzde ve bayt dağılımını gösterir.
   - **Anomali İşaretleri:**
     - Şifreli web dünyasında `Hypertext Transfer Protocol (HTTP)` oranının `Transport Layer Security (TLS)` oranından yüksek olması, kurumda şifresiz veri transferi yapıldığını gösterir.
     - `User Datagram Protocol (UDP)` altında `DNS` paket hacminin normalden 10-20 kat yüksek olması DNS Tünelleme veya Amplification DoS saldırısını anında ele verir.
     - Ağda hiç olmaması gereken protokollerin (IRC, BitTorrent, Telnet, SMBv1) hiyerarşide belirmesi içeride bir truva atı veya eski savunmasız bir cihaz olduğunu belgeler.

2. **Ağ Konuşmaları (Conversations / Top Talkers):**
   - Trafiği IP çiftleri ve portlar bazında gruplar.
   - En çok bayt tüketen ilk 5 konuşma incelendiğinde, kurumun dışına gigabaytlarca veri akıtan istemci IP'si saniyeler içinde tespit edilir (Data Exfiltration).
   - Paket sayısı çok yüksek fakat bayt hacmi çok düşük olan konuşmalar ise SYN Flood veya TCP port taramalarını (Port Scanning) net bir şekilde ortaya koyar.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir üretim tesisinde SCADA kontrol sisteminin yavaşladığı ve dışarıya şüpheli bağlantılar yaptığı ihbarı gelir. Analist 2 GB'lık PCAP dosyasını Wireshark'a yükler.

```text
Protokol Hiyerarşisi Özeti:
- IPv4 (100%)
  -- TCP (45%)
  -- UDP (55%) -> Normalde %5 olması gereken UDP tavan yapmış!
     --- DNS (52%) -> DNS trafiği tüm ağ hacminin yarısını kaplıyor!
```

**Adli İnceleme ve Müdahale:**
1. Analist hemen `dns` filtresi uygular.
2. `Statistics -> Conversations -> IPv4` sekmesine geçer ve en çok konuşan IP'nin `192.168.1.105` olduğunu ve `8.8.8.8` ile sürekli TXT kaydı konuştuğunu görür.
3. 2 GB'lık dosya içinde kaybolmadan, ilk 60 saniyede DNS Tünelleme yapan cihazın IP adresi tespit edilir ve EDR üzerinden ağ bağlantısı kesilir.

#### 4. Ustanın Çırağa Tavsiyesi
Çırak! Bir ormana girdiğinde hemen yerdeki karıncaları saymaya kalkarsan ağaçları göremezsin, kaybolursun. Önce bir tepeye çıkıp ormanın genel sınırlarına ve nereden duman tüttüğüne bakacaksın. Protokol Hiyerarşisi senin gözetleme kulendir; dumanın çıktığı yönü belirledikten sonra büyüteci eline alıp paketlere ineceksin!

---

### G069-SC2: Ağ Paket Analizi Sırasında Tespit Edilen TCP Zero Window ve Retransmission Paternleri Bir Siber Saldırının Göstergesi Olabilir mi?

#### 1. Soru Başlığı ve Tanımı
Wireshark raporunda `TCP Zero Window` ve yüksek oranda `TCP Retransmission` görülmesi yalnızca bir ağ tıkanıklığı veya zayıf sunucu donanımı sorunu mudur, yoksa hedefli bir siber saldırının (DoS/DDoS, Slowloris, Buffer Exhaustion) doğrudan göstergesi olabilir mi?

#### 2. Derinlemesine Teknik Analiz
TCP akış kontrol mekanizmasında (Flow Control), alıcı taraf göndericiye TCP başlığındaki "Pencere Boyutu (Window Size)" alanı ile ne kadar boş tampon belleği kaldığını bildirir:

1. **TCP Zero Window Mekanizması:**
   - Sunucunun çekirdek ağ tamponu (socket receive buffer) dolduğunda, istemciye `Window Size = 0` içeren bir ACK paketi gönderir. Bu "dur, artık veri kabul edemiyorum, nefes alamıyorum" demektir.
2. **Siber Saldırı Boyutu:**
   - **Slowloris ve Slow-Read DoS Saldırıları:** Saldırgan sunucuya çok sayıda TCP bağlantısı açar ve sunucunun yanıtlarını bilinçli olarak `Window Size = 0` veya çok küçük pencere boyutlarıyla okuyarak sunucunun iş parçacıklarını (thread) ve bellek kuyruklarını sonsuza kadar kilitler.
   - **SYN/ACK Flood veya Yüksek Hacimli İstekler:** Arka uç web sunucusu (Tomcat, Node.js) veritabanı kilitlenmesi yaşadığında gelen istekleri işleyemez; işletim sistemi soketleri tıkanır ve Zero Window fırtınası başlar.
3. **Retransmission ile Korelasyon:**
   - Zero Window durumunun ardından istemci veriyi yeniden iletmeye çalışır (`TCP Keep-Alive` veya `TCP Retransmission`). Ağda hem Zero Window hem de yüksek retransmission bir aradaysa, bu durum sunucunun aktif bir DoS saldırısı altında boğulduğunun kesin kanıtıdır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir e-ticaret sitesi kampanya günü aniden çöker. Altyapı ekibi "internet hattımız yetersiz kaldı" derken SOC analisti Wireshark raporunu inceler:

**Rapordaki Veriler:**
- Web sunucusu `10.0.0.80`, 50 farklı istemciye peş peşe `TCP Zero Window` bayrağı üretmektedir.
- İstemcilerin gönderdiği HTTP istekleri tek bir IP bloğundan (`192.168.1.100 - 192.168.1.110`) gelmektedir ve her biri `GET /search?q=...` ağır veritabanı sorgusu çalıştırmaktadır.

**Çözüm:**
1. Saldırının bant genişliği tüketme saldırısı değil, arka uç veritabanı kilitlenmesiyle bellek tüketme (Application-layer DoS) olduğu raporlanır.
2. WAF üzerinde aynı IP bloğundan gelen arama isteklerine dakikada maksimum 10 istek (Rate Limiting) kuralı konur.
3. Sunucu tamponları boşalır, Zero Window paketleri kesilir ve web sitesi normale döner.

#### 4. Ustanın Çırağa Tavsiyesi
Çırak! Bir sunucu "Zero Window" diyorsa nefes borusu sıkılıyordur. Kimi zaman bu doğal bir kalabalığın ağırlığıdır, kimi zaman da boğazına çökmüş bir saldırganın parmaklarıdır. Paketleri yollayan istemcilerin IP çeşitliliğine ve isteklerin niteliğine bakacaksın. Herkes aynı kapıya vuruyor ve içeri girmiyorsa, orada bir kaza değil organize bir sabotaj vardır!

---

### G069-SC3: Bir Olay Müdahale (Incident Response) Sürecinde Yönetim Kurulu (C-Level) ile SOC Teknik Ekipleri İçin Raporlama Dili Nasıl Ayrıştırılmalıdır?

#### 1. Soru Başlığı ve Tanımı
Aynı PCAP analizi sonucunda hazırlanan bir adli bilişim raporu, Yönetim Kurulu / Genel Müdür (C-Level) ile SOC/CERT teknik analistlerine sunulurken dil, kapsam ve metrikler açısından nasıl yapılandırılmalıdır?

#### 2. Derinlemesine Teknik Analiz
Tek bir rapor her iki kitleyi birden tatmin edemez; çünkü öncelikleri ve karar alma mekanizmaları tamamen farklıdır:

1. **Yönetici Özeti (C-Level / CISO / CEO):**
   - **Odak:** İş riski, finansal etki, yasal yükümlülük (KVKK/GDPR cezaları), itibar kaybı ve eylem kararı.
   - **Dil:** Sade, teknik jargondan arındırılmış, risk odaklı.
   - **İçerik:**
     - Güvenlik Skoru (örn. 35/100 - KRİTİK TEHLİKE).
     - Olayın tanımı: *"14:00 sularında dış kaynaklı bir saldırgan web sitemize sızmış ve müşteri şifrelerini çalmaya teşebbüs etmiştir."*
     - Ne yapıldı: *"Saldırgan izole edildi, sızıntı durduruldu."*
     - Bütçe/Aksiyon kararı: *"WAF lisansının yenilenmesi ve EDR ajanlarının güncellenmesi gerekmektedir."*

2. **Teknik Adli İnceleme (SOC / DFIR / Sistem Mühendisleri):**
   - **Odak:** Kök neden (Root Cause), saldırı vektörü (Attack Vector), teknik kanıtlar ve IoC (Indicators of Compromise).
   - **Dil:** Protokol seviyesinde, kesin, RFC referanslı ve matematiksel.
   - **İçerik:**
     - Paket numaraları (`Paket #4, #6`), TCP Sequence/ACK numaraları.
     - Ham yük (Payload) hex/ASCII dökümleri.
     - Saldırganın IP/Port bilgileri, User-Agent dizgileri, zararlı SQL kalıpları.
     - Firewall, Suricata/Snort ve WAF için uygulanacak kesin kural sözdizimleri.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir şirkette SQL Injection ile veri tabanına sızılmıştır. Analist iki ayrı bölüm içeren çift katmanlı rapor üretir:

```text
BÖLÜM 1: YÖNETİCİ ÖZETİ
- Durum: Kritik Güvenlik İhlali (Skor: 35/100)
- Etki: Şirket web sunucusuna yetkisiz erişim sağlanmış, yönetici şifreleri ifşa olmuştur.
- Hukuki Risk: KVKK 12. Madde uyarınca 72 saat içinde Kişisel Verileri Koruma Kurumu'na bildirim zorunludur.

BÖLÜM 2: TEKNİK ADLİ BİLİŞİM KANITLARI
- Saldırgan IP: 192.168.1.105:54321
- İstek: GET /admin/login.php?user=admin%27%20OR%201=1-- HTTP/1.1 (Paket #4)
- Araç İmzası: sqlmap/1.7.11#stable
- Yanıt: HTTP/1.1 200 OK (Paket #5) -> Body: {"gizli_anahtar": "AKIA_TEST_KEY_EXPOSED"}
```

**Sonuç:**
Genel Müdür hukuki bildirim sürecini başlatıp bütçeyi onaylarken; sistem mühendisleri Paket #4'teki URI açığını yazılımcıya iletip kodu aynı saat içinde yamalar.

#### 4. Ustanın Çırağa Tavsiyesi
Çırak! Bir komutana cephedeki kurşunun kimyasal alaşımını anlatırsan savaşı kaybedersin; komutana düşmanın nereden geldiğini ve hangi tepeyi tutman gerektiğini söyleyeceksin. Ama cephanelikteki topçu çavuşuna da 'düşman kötü' demeyeceksin, ona koordinatı ve merminin çapını vereceksin! Kime konuştuğunu bilmeyen analistin raporu çöp kutusunu boylar!
