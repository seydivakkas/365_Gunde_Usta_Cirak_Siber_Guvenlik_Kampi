# G061: Proxy, NAT ve Güvenlik Duvarı — Usta Dersi

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya ticari olarak kullanılamaz.
```

---

## 1. Giriş: Ağın Sınır Muhafızları ve Güvenlik Katmanları

Evlat, düne kadar tekil protokollerin (HTTP/1.1, HTTP/2, HTTP/3, TLS) nasıl çalıştığını, paketlerin ikili çerçevelere nasıl bölündüğünü ve şifrelendiğini inceledik. Ancak gerçek dünyada hiçbir istemci veya sunucu internetin açık dalgalarına doğrudan çıplak bir IP adresiyle bırakılmaz. 

Modern kurumsal ve telekomünikasyon ağları üç temel sınır muhafızı tarafından korunur ve yönetilir:
1. **Vekil Sunucular (Proxies):** Uygulama katmanında (L7) trafiği sonlandırıp, denetleyip taraflar adına yeniden başlatan sistemler.
2. **Ağ Adresi Dönüştürücüleri (NAT / PAT):** Ağ ve aktarım katmanında (L3/L4) özel iç adresleri genel internet adreslerine dönüştüren yönlendiriciler.
3. **Güvenlik Duvarları (Firewalls):** Ağ paketlerini durum takibi (Stateful Inspection) ve kural kümeleriyle denetleyip meşru olmayan paketleri düşüren kalkanlar.

Bugün bir siber güvenlik analisti, sızma testi uzmanı ve mimar olarak bu üç teknolojinin iç mimarisini, nasıl suistimal edildiklerini ve nasıl sertleştirileceklerini adım adım öğreneceksin.

---

## 2. Vekil Sunucu (Proxy) Mimarisi ve Tipleri

Vekil sunucu, istemci ile sunucu arasında duran ve iki bağımsız TCP/HTTP oturumu yöneten bir ara yazılımdır.

```
+-------------------------------------------------------------------------+
|                  FORWARD PROXY (İstemci Vekili)                         |
|  İç İstemciler (192.168.1.x) ----> [Forward Proxy] ----> İnternet       |
|  * İstemcinin kimliğini gizler, internet çıkışını filtreler/denetler.   |
+-------------------------------------------------------------------------+
|                  REVERSE PROXY (Sunucu Vekili)                          |
|  İnternet İstemcileri ----------> [Reverse Proxy] ----> Arka Uç Sunucu  |
|  * Sunucuların kimliğini gizler, yükü dağıtır, SSL'i sonlandırır.       |
+-------------------------------------------------------------------------+
```

### 2.1. İleri Yönlü Vekil Sunucu (Forward Proxy)
Forward Proxy, iç ağdaki kullanıcıların internete çıkış kapısıdır.
- **Kullanım Amacı:** Kurumsal ağlarda çalışanların zararlı yazılım C2 (Command & Control) adreslerine, kumar, oltalama (phishing) veya veri sızıntısı (DLP) sitelerine erişmesini engellemek.
- **HTTPS Tünellemesi (HTTP CONNECT Metodu):** İstemci şifreli bir HTTPS sitesine (`https://banka.com`) gitmek istediğinde, vekile şu komutu yollar:
  $$\text{CONNECT banka.com:443 HTTP/1.1}$$
  Vekil sunucu hedef sunucuyla TCP bağlantısını açar ve istemciye `HTTP/200 Connection Established` döner. Bundan sonra vekil sunucu yalnızca baytları körü körüne ileri taşır (eğer SSL Interception/MIMT sertifikası yüklü değilse).
- **Güvenlik Kuralı:** Güvenli bir Forward Proxy, `CONNECT` metoduna **yalnızca port 443** (HTTPS) için izin vermelidir! Saldırganlar iç ağdaki SSH (port 22) veya SMTP (port 25) servislerine tünel açarak güvenlik duvarını atlatmak için bu metodu kötüye kullanabilirler.

### 2.2. Ters Yönlü Vekil Sunucu (Reverse Proxy)
Reverse Proxy, kurumun web ve uygulama sunucularının (ör. Nginx, HAProxy, Envoy) önüne konumlandırılır.
- **Yük Dengeleme (Load Balancing):** Gelen milyonlarca isteği arka uçtaki sunucu havuzuna (Round Robin, En Az Bağlantı / Least Connections, Kaynak IP Özeti / IP Hash) dağıtır.
- **SSL/TLS Sonlandırma (SSL Offloading):** Ağır kriptografik el sıkışma ve şifre çözme yükünü reverse proxy üstlenir; arka uç sunucularına saf HTTP ileterek sunucuların CPU gücünü korur.
- **WAF ve DDoS Koruması:** Kötü niyetli SQL Injection veya XSS içeren istekleri arka uçtaki veritabanına ulaşmadan kapıda imha eder.

### 2.3. Saydam Vekil Sunucu (Transparent Proxy)
İstemcinin işletim sisteminde veya tarayıcısında hiçbir proxy ayarı yapılmamıştır. Ağ geçidi (Router/Firewall), port 80/443 trafiğini iptables kurallarıyla (`REDIRECT` veya `TPROXY`) gizlice vekil sunucuya yönlendirir.

---

## 3. Ağ Adresi Dönüştürme: NAT ve PAT (NAPT) Mimarisi

1980'lerde tasarlanan IPv4 protokolü yalnızca yaklaşık 4.3 milyar ($2^{32}$) benzersiz adres barındırır. İnternetin patlama yapmasıyla birlikte adresler tükenme noktasına gelince, **RFC 1918 Özel Adres Blokları** ve **RFC 3022 NAT** icat edilmiştir.

### 3.1. RFC 1918 Özel (Private) IP Blokları:
- `10.0.0.0/8` (10.0.0.0 - 10.255.255.255): Büyük ölçekli kurumsal ağlar
- `172.16.0.0/12` (172.16.0.0 - 172.31.255.255): Orta ölçekli ağlar
- `192.168.0.0/16` (192.168.0.0 - 192.168.255.255): Ev ve KOBİ ağları

Bu özel adresler internet omurgasında (Public Internet) **yönlendirilemez (non-routable)**. İnternete çıkabilmek için mutlaka genel (Public) bir IP adresine dönüştürülmeleri gerekir.

### 3.2. PAT (Port Address Translation / NAT Overload) Nasıl Çalışır?
En yaygın model olan PAT, binlerce iç cihazın **tek bir genel IP adresi** üzerinden internete çıkmasını sağlar:
1. İç istemci (`192.168.1.50:45678`), Google'a (`142.250.185.206:443`) istek atar.
2. Yönlendirici (Router) paketin kaynak IP'sini kendi genel IP'siyle (`203.0.113.10`) ve kaynak portunu dinamik port havuzundan seçtiği boş bir portla (`10001`) değiştirir (**Kaynak NAT / SNAT**).
3. Bu eşlemeyi belleğindeki **NAT Çevirim Tablosu'na** yazar:
   $$\text{(192.168.1.50:45678)} \iff \text{(203.0.113.10:10001)} \iff \text{(142.250.185.206:443)}$$
4. Google sunucusu yanıtı `203.0.113.10:10001` adresine gönderir.
5. Yönlendirici tablosuna bakar, 10001 numaralı portun iç ağdaki `192.168.1.50:45678` istemcisine ait olduğunu anlar ve paketin hedef IP/portunu değiştirerek iç ağa iletir (**Hedef NAT / DNAT**).

> **Siber Güvenlik Uyarısı (PAT Port Tükenmesi):** Bir genel IP adresinde kullanılabilecek maksimum dinamik port sayısı teorik olarak $65535 - 1024 \approx 64500$'dür. Eğer iç ağdaki bir virüs (botnet) dışarıya saniyede yüz binlerce bağlantı açmaya çalışırsa, PAT port havuzu tükenir (`NAT Exhaustion`) ve kurumun internet çıkışı tamamen felç olur!

### 3.3. CGNAT (Carrier-Grade NAT - RFC 6598)
İnternet servis sağlayıcıları (ISS), IPv4 yetersizliği nedeniyle ev kullanıcılarına genel IP vermek yerine `100.64.0.0/10` bloğundan IP dağıtır ve ikinci bir NAT katmanı uygular. Adli bilişimde (Forensics), suç işleyen bir kullanıcının tespiti için yalnızca IP adresi yetmez; **kesin zaman damgası (timestamp) ve kaynak port numarası** da loglanmış olmalıdır!

---

## 4. Güvenlik Duvarı: Durumsuz vs Durum Takipli (Stateful Inspection)

### 4.1. Durumsuz Paket Filtreleme (Stateless Firewall)
İlk nesil güvenlik duvarlarıdır. Her paketi diğer paketlerden bağımsız olarak inceler.
- **Kusuru:** İstemcinin dışarıdaki web sunucusuna (port 80) gitmesine izin verirseniz, sunucunun istemciye döneceği yanıt paketleri için de güvenlik duvarında `1024-65535` arasındaki tüm yüksek portları dışarıdan içeriye **açık bırakmak zorundasınızdır!** Bu durum saldırganların içeriye kontrolsüzce sızmasına zemin hazırlar.

### 4.2. Durum Takipli Güvenlik Duvarı (Stateful Inspection / Conntrack)
Günümüzdeki tüm modern güvenlik duvarları (iptables, pfSense, Palo Alto, Fortinet) **durum takipli (Stateful)** çalışır. Güvenlik duvarı çekirdeğinde bir **Bağlantı Takip Tablosu (Conntrack Table)** tutar.

Her paket 4 mantıksal durumdan birine atanır:
1. **NEW:** Yeni bir bağlantı başlatmak isteyen ilk paket (TCP için yalnızca `SYN` bayrağı taşıyan paket).
2. **ESTABLISHED:** El sıkışması başarıyla tamamlanmış ve iki yönlü iletişimi teyit edilmiş aktif oturum paketleri.
3. **RELATED:** Mevcut bir oturum tarafından tetiklenen ilişkili bağlantılar (ör. FTP pasif veri portu veya ICMP hata mesajları).
4. **INVALID:** Durum tablosunda hiçbir kaydı olmayan, sıra numarası bozuk veya kurallara aykırı paketler (Ör. durup dururken gelen sahte `ACK` veya `FIN` paketleri).

**Altın Kural:**
Durum takipli güvenlik duvarının ilk kuralı her zaman şudur:
$$\text{iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT}$$
Dışarıdan gelen `NEW` istekler ise varsayılan olarak reddedilir (`DROP by default`), yalnızca belirli servis portlarına (ör. DMZ 443) kontrollü izin verilir.

---

## 5. Siber Güvenlik Tehdit Modelleri ve Savunma Vektörleri

### 5.1. X-Forwarded-For (XFF) IP Sahteciliği ve Yetki Atlatma
Ters vekil sunucu arkasındaki arka uç uygulamaları, istemcinin gerçek IP'sini soket seviyesinde göremez (çünkü gelen paket reverse proxy'den gelmektedir). Bu yüzden vekil sunucu HTTP isteğine `X-Forwarded-For: <gercek_ip>` başlığı ekler.
- **Saldırı Vektörü:** Dışarıdaki bir saldırgan, isteğine kendi eliyle şu başlığı ekler:
  $$\text{X-Forwarded-For: 127.0.0.1}$$
  Eğer ters vekil sunucu bu başlığı filtrelemeden arka uca geçirirse ve arka uç uygulama da "127.0.0.1'den gelen istekler yerel admin isteğidir" kontrolü yapıyorsa, saldırgan tüm kimlik doğrulamasını atlatır!
- **Savunma:** Ters vekil sunucuda `proxy_set_header X-Forwarded-For $remote_addr;` direktifiyle dışarıdan gelen sahte XFF başlıkları **ezilmeli (overwrite)**, yalnızca güvenilir iç vekillerin başlık zincirine ekleme yapmasına izin verilmelidir.

### 5.2. Conntrack Tablo Taşması (SYN Flood DDoS)
Durum takipli güvenlik duvarının conntrack tablosu sınırlı belleğe sahiptir (örneğin 65.536 veya 262.144 girdi). Saldırganlar sahte IP adresleriyle milyonlarca TCP SYN paketi göndererek conntrack tablosunu doldurur. Tablo dolduğunda güvenlik duvarı yeni meşru bağlantıları kabul edemez (`Conntrack Overflow`).
- **Savunma:** Çekirdek seviyesinde **SYN Cookies (RFC 4987)** aktif edilmeli, boşta bekleme zaman aşımları (`tcp_syn_sent` timeout) düşürülmelidir.

### 5.3. Gizli TCP Bayrak Taramaları (Stealth Scans)
Nmap gibi araçlar, durumsuz veya zayıf güvenlik duvarlarını atlatmak için RFC 793 standart dışı paketler üretir:
- **SYN+FIN Scan:** Hem bağlantı aç hem kapat bayrağı. Standart dışıdır; güvenlik duvarının kafasını karıştırmayı amaçlar.
- **Null Scan:** Hiçbir bayrak set edilmemiştir (`Flags = 0`).
- **Xmas Scan:** `FIN`, `PSH` ve `URG` bayrakları aynı anda yanıktır (Noel ağacı gibi).
- **Savunma:** Güvenlik duvarı bu anomali bayraklarını L4 denetiminde yakalayıp derhal düşürmelidir (`DROP`).

---

## 6. Usta-Çırak Öğütleri ve Sektörel Pratik

1. **Güvenlik Duvarı Politikasında:** Her zaman **"Açıkça izin verilmeyen her şey yasaktır" (Default Deny / Drop)** prensibini uygulayacaksın.
2. **Reverse Proxy Yapılandırmasında:** Arka uç uygulamalara asla istemciden gelen XFF başlıklarına doğrudan güvenmemesini, vekil sunucunun IP'sini doğrulamadan yetkilendirme kararı vermemesini öğreteceksin.
3. **Wireshark İncelemesinde:** NAT arkasındaki trafiği incelerken `ip.addr` filtresinin tek başına yetmediğini, PAT port dönüşümlerini izlemek için `tcp.port` ve conntrack loglarını çaprazlaman gerektiğini bileceksin.

---
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
ÖZEL LİSANS — Bu ders notu yalnızca görüntüleme ve eğitim amacıyla hazırlanmıştır.
