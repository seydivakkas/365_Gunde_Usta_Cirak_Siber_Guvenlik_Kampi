# Hafta 10 Gün 66: DNS ve HTTP Anomali İşaretleri Soru-Cevap

---

### G066-SC1: DNS Tünelleme ve DGA Alan Adları Nasıl Ayrıştırılır ve Kurumsal Ağda Nasıl Engellenir?

#### 1. Soru Başlığı ve Tanımı
DNS tünelleme (data exfiltration/C2) ile DGA (Domain Generation Algorithm) alan adları arasındaki farklar nelerdir? Kurumsal ağ ortamında bir SIEM/NDR analisti bu iki tehdidi hangi istatistiksel ve davranışsal metriklerle birbirinden ayırır ve nasıl engeller?

#### 2. Derinlemesine Teknik Analiz
Her iki tehdit de DNS protokolünü kötüye kullansa da operasyonel amaçları ve telemetri imzaları tamamen farklıdır:

1. **DGA (Domain Generation Algorithm):**
   - **Amaç:** Zararlı yazılımın (botnet/ransomware) sabit bir IP veya alan adına bağımlı kalmadan dinamik C2 sunucusuyla buluşması (rendezvous).
   - **Trafik Özelliği:** Genellikle `A` veya `AAAA` sorgularıdır. Çoğu sorgu başarısız olur ve yüksek oranda `NXDOMAIN` (Böyle bir alan adı yok) hata kodu döner.
   - **İstatistiki Profil:** Şannon bilgi entropisi çok yüksektir ($H \ge 3.4$ bit), sessiz harf oranı ($\ge 0.65$) doğallıktan uzaktır ve n-gram dağılımı insan diline uymaz.

2. **DNS Tünelleme (Tunneling & Exfiltration):**
   - **Amaç:** Kurumsal ağdan gizli verileri (şifreler, dosyalar) güvenlik duvarlarını atlatarak dışarı kaçırmak veya çift yönlü komut çalıştırmak (Cobalt Strike, iodine, dnscat2).
   - **Trafik Özelliği:** Genellikle `TXT`, `NULL` veya `CNAME` kayıtları kullanılır. İstemci sürekli yeni alt alan adları (`<base64-veri>.attacker-zone.com`) sorgular ve bu sorgular başarılı (`NOERROR`) yanıt alır.
   - **İstatistiki Profil:** Toplam FQDN uzunluğu $45-255$ karakter arasındadır. Tek bir alan adı altında binlerce benzersiz alt alan adı (subdomain cardinality) oluşur ve DNS istek sıklığı çok yüksektir.

Engelleme için uç nokta makinelerinin doğrudan dış DNS sunucularına (8.8.8.8, 1.1.1.1) UDP 53 erişimi güvenlik duvarında kapatılmalı; yalnızca yetkili iç DNS sunucularına (Active Directory / BIND) izin verilmeli ve bu sunucular üzerinde RPZ (Response Policy Zones) ve DNS Firewall kuralları işletilmelidir.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir finans kuruluşunun SOC merkezinde nöbetçisiniz. SIEM ekranında bir muhasebe bilgisayarından her saniyede 15 adet `*.fin-exfil-cdn.biz` sorgusu yapıldığı ve sorgu tipinin `TXT` olduğu görülüyor.

```python
# Tünelleme Tespiti ve Bloklama için Zeek / Snort Kuralı Mantığı
# DNS FQDN uzunluğu > 50 ve sorgu tipi TXT ise alarm üret
alert dns $HOME_NET any -> any 53 (msg:"ET HUNTING DNS Tunneling High Subdomain Length"; dns.query; content:"."; pcre:"/^[a-zA-Z0-9+\/]{30,}\./"; classtype:bad-unknown; sid:20261066; rev:1;)
```

**Müdahale Adımları:**
1. Cihazın ağ bağlantısı EDR üzerinden derhal karantinaya alınır.
2. İç DNS sunucusunda `fin-exfil-cdn.biz` alan adı Sinkhole IP'sine (`0.0.0.0` veya `127.0.0.1`) yönlendirilir.
3. Çalınan verinin boyutu, DNS sorgu kayıtlarının toplam yük boyutu toplanarak adli bilişim raporuna işlenir.

#### 4. Ustanın Çırağa Tavsiyesi
Çırak! Ağında çok sayıda `NXDOMAIN` görüyorsan bir DGA botnet'i avlıyorsun demektir; çünkü saldırganın kaydetmediği yüzlerce aday alan adı hata döndürüyordur. Ancak hiç `NXDOMAIN` görmüyor, buna karşın her sorguda harf harf `NOERROR` alıyorsan ve etiketler Base64 gibi görünüyorsa şirketin verileri kapıdan dışarı akıyordur. Bir an bile tereddüt etmeden o kabloyu çekeceksin!

---

### G066-SC2: HTTP Request Smuggling (CL.TE / TE.CL) Saldırısının Mekanizması Nedir ve WAF Seviyesinde Nasıl Tespit Edilir?

#### 1. Soru Başlığı ve Tanımı
HTTP Request Smuggling nedir? Ön uç (Reverse Proxy) ile arka uç (Backend) sunucuları arasındaki `Content-Length` ve `Transfer-Encoding` başlık yorumlama farklılıkları nasıl bir güvenlik açığı oluşturur ve modern WAF sistemlerinde nasıl engellenir?

#### 2. Derinlemesine Teknik Analiz
HTTP/1.1 protokolünde istemci ile sunucu arasında TCP bağlantılarının sürekli yeniden açılmasını önlemek için HTTP Pipelining ve Keep-Alive mekanizmaları kullanılır. Bu mekanizmada ardışık istekler tek bir TCP soketi üzerinden akar.

Bir isteğin nerede bittiğini ve bir sonraki isteğin nerede başladığını anlamanın iki yolu vardır:
1. `Content-Length`: Gövdenin tam bayt boyutunu belirtir.
2. `Transfer-Encoding: chunked`: Gövdenin parçalar (chunk) halinde iletildiğini ve son parçanın `0\r\n\r\n` olduğunu belirtir.

**RFC 7230 Bölüm 3.3.3 Standardı der ki:**
> *"Eğer bir HTTP isteğinde hem Content-Length hem de Transfer-Encoding başlığı bulunuyorsa, Transfer-Encoding başlığı önceliklidir ve Content-Length başlığı yoksayılmalıdır. Hatta vekil sunucular bu tür çatışan istekleri doğrudan 400 Bad Request ile reddetmelidir."*

Ancak bazı eski veya farklı konfigüre edilmiş arka uç sunucuları RFC standardını ihlal eder:
- **CL.TE Saldırısı:** Ön uç `Content-Length` başlığına bakar, arka uç `Transfer-Encoding` başlığına bakar. Saldırgan gövde içine ikinci bir gizli HTTP isteği yerleştirir. Ön uç tüm gövdeyi tek bir istek sanıp arka uca iletir. Arka uç ise chunked gövdeyi `0` gördüğü yerde bitirir; artakalan zararlı istek arka ucun soket kuyruğunda bekler ve bir sonraki masum kullanıcının isteğinin başına eklenir!
- **TE.CL Saldırısı:** Ön uç `Transfer-Encoding` başlığına, arka uç `Content-Length` başlığına bakar.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir e-ticaret sitesinde Cloudflare (Ön Uç) arkasında çalışan özel bir Tomcat/Java uygulaması (Arka Uç) bulunmaktadır. Saldırgan admin paneline erişim yetkisi olmamasına rağmen şu isteği yollar:

```http
POST /search HTTP/1.1
Host: magaza.local
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin/delete-database HTTP/1.1
Host: magaza.local
Dummy:
```

Ön uç 13 baytı okur (`0\r\n\r\n` kısmını kapsar) ve arka uca iletir. Arka uç ise `0` chunk'ını görünce isteği bitti kabul eder. Kuyrukta kalan `GET /admin/delete-database` isteği, hemen arkasından gelen oturum açmış yöneticinin isteğiyle birleşir ve yönetici yetkileriyle işletilir!

**Çözüm:**
1. WAF ve Reverse Proxy seviyesinde: Hem `Content-Length` hem de `Transfer-Encoding` içeren tüm istekler istisnasız `400 Bad Request` ile düşürülmelidir.
2. Ön uç ile arka uç arasında HTTP/2 veya HTTP/3 protokolüne geçilmelidir; çünkü HTTP/2'de ikili çerçeveleme (binary framing) kullanıldığından metin tabanlı sınır çatışması imkansızdır.

#### 4. Ustanın Çırağa Tavsiyesi
Çırak! İki farklı sistem aynı veriyi farklı okuyorsa orada mutlaka bir güvenlik açığı doğar. Request Smuggling bunun siber dünyadaki en kusursuz örneğidir. Ağında WAF yapılandırırken "toleranslı ol, istekleri düzeltmeye çalış" felsefesini asla benimseme. Protokol kuralına uymayan tek bir harf veya çatışan tek bir başlık gördüğün an o bağlantıyı acımasızca kes!

---

### G066-SC3: Fast Flux Botnet Mimarisi Geleneksel DNS Güvenlik Duvarlarını Nasıl Aşar ve Hangi Telemetrilerle Yakalanır?

#### 1. Soru Başlığı ve Tanımı
Fast Flux Service Networks (FFSN) nedir? Tek Akılı (Single Flux) ve Çift Akılı (Double Flux) C2 mimarileri geleneksel DNS itibar (reputation) sistemlerini nasıl yanıltır ve SOC analistleri bu yapıları tespit etmek için hangi telemetri korelasyonlarını kullanır?

#### 2. Derinlemesine Teknik Analiz
Geleneksel siber güvenlik savunması IP kara listelerine (IP Blacklists) dayanır. Bir C2 IP adresi tespit edildiğinde güvenlik duvarında engellenir. Saldırganlar bu engeli aşmak için Fast Flux tekniğini geliştirmiştir:

1. **Tek Akılı (Single Flux):**
   - Alan adının `A` kayıtları sürekli değişir.
   - DNS TTL (Time-To-Live) süresi 10 ila 60 saniye gibi son derece kısa bir süreye ayarlanır.
   - Her DNS çözümlemesinde dünyanın dört bir yanındaki ele geçirilmiş ev kullanıcılarının (ADSL/Fiber modem arkasındaki zombilerin) IP'leri döner. Bu zombiler gelen istekleri arka plandaki gerçek gizli C2 sunucusuna (mothership) TCP/HTTP proxy olarak iletir.
2. **Çift Akılı (Double Flux):**
   - Yalnızca `A` kayıtları değil, alan adının Yetkili Ad Sunucuları (`NS` kayıtları) da sürekli değişir. Böylece saldırgan alan adının kayıt operatörü (registrar) seviyesinde kapatılmasını bile saatlerce geciktirir.

**Telemetri ve Tespit Kriterleri:**
- **Mikro-TTL:** TTL süresi $\le 30$ saniyedir. Meşru CDN'ler (Akamai, Cloudflare) de düşük TTL kullanabilir; ancak Fast Flux'ta dönen IP adresleri heterojendir (farklı ASN'ler, farklı ISP'ler ve genellikle ev/bireysel IP blokları).
- **Yüksek IP Çeşitliliği:** Tek bir sorguda dönen IP sayısı $\ge 5$'tir ve birkaç dakika içindeki sorgularda onlarca farklı BGP Otonom Sistem Numarası (ASN) görülür.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir bankanın SOC analisti, kurum içindeki bir sunucudan `update-sync.online-core.cc` adresine yapılan periyodik DNS sorgularını inceler.

```bash
# Çırak sorgu yaptığında dönen DNS yanıtı:
$ dig +noall +answer update-sync.online-core.cc
update-sync.online-core.cc. 15 IN A 185.190.22.1
update-sync.online-core.cc. 15 IN A 91.200.12.3
update-sync.online-core.cc. 15 IN A 103.45.67.8
update-sync.online-core.cc. 15 IN A 45.12.34.1
update-sync.online-core.cc. 15 IN A 194.26.29.5

# 20 saniye sonra aynı sorgu tekrarlandığında:
$ dig +noall +answer update-sync.online-core.cc
update-sync.online-core.cc. 15 IN A 77.88.99.10
update-sync.online-core.cc. 15 IN A 212.45.12.99
... (tamamen farklı IP'ler)
```

**Analist Çözümü:**
Tekil IP'leri engellemek faydasızdır; çünkü saldırganın havuzunda on binlerce zombi IP vardır. Doğru müdahale:
1. Alan adının kök seviyesinde DNS Sinkhole yapılması (kurumsal DNS'te `online-core.cc` bölgesinin tamamını izole IP'ye yönlendirme).
2. TTL değeri $\le 60$ sn olan ve çözülen IP'lerin AS numaraları 3'ten fazla farklı coğrafyayı kapsayan alan adlarını otomatik tespit eden SIEM kuralının devreye alınması.

#### 4. Ustanın Çırağa Tavsiyesi
Çırak! Bir nehir gibi durmadan akan, her baktığında başka bir şekil alan IP adreslerine aldanma. Yapraklarla değil kökle uğraşacaksın. Fast Flux ağlarında IP'lerin peşinden koşarsan nefesin tükenir; kök alan adını (FQDN) ve kayıt operatörü bağlantısını kestiğin an bütün zombi ordusu kör kalır!
