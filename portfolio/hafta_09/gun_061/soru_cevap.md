# G061: Proxy, NAT ve Güvenlik Duvarı — Soru-Cevap Dokümanı

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya ticari olarak kullanılamaz.
```

---

## G061-SC1: Durumsuz vs Durum Takipli Güvenlik Duvarı Mimarisi

### Soru
Durumsuz (stateless) paket filtreleme ile durum takipli (stateful inspection / conntrack) güvenlik duvarları arasındaki mimari farklar nelerdir? Bağlantı takip tablosunun (Conntrack Table) `NEW`, `ESTABLISHED`, `RELATED` ve `INVALID` durumları nasıl çalışır ve durumsuz filtreleme neden modern ağ savunmasında tek başına yetersizdir?

### Derin Teknik Cevap
Durumsuz (Stateless) paket filtreleme güvenlik duvarları, her ağ paketini birbirinden tamamen bağımsız bir birim olarak değerlendirir. Yalnızca L3/L4 başlıklarındaki statik kuralları (Kaynak IP, Hedef IP, Kaynak Port, Hedef Port, Protokol) inceler. Bir iç ağ istemcisinin dışarıdaki bir web sunucusuna erişebilmesi için:
1. İçeriden dışarıya doğru `Port 80/443 TCP SYN` paketine izin verilmelidir.
2. Ancak dışarıdaki sunucunun döneceği yanıt paketleri, istemcinin rastgele açtığı efemeral portlara (`1024-65535`) gelecektir.
3. Durumsuz güvenlik duvarı, gelen bir paketin içeriden giden bir isteğe yanıt mı olduğunu yoksa dışarıdan bir saldırganın içeriye sızma girişimi mi olduğunu **ayırt edemez**.
4. Bu yüzden durumsuz güvenlik duvarı yöneticisi, dışarıdan içeriye doğru tüm efemeral portları (`1024-65535`) açık bırakmak zorunda kalır. Bu da devasa bir güvenlik açığıdır.

Durum Takipli (Stateful Inspection / Conntrack) güvenlik duvarları ise belleğinde dinamik bir **Bağlantı Takip Tablosu (Connection Tracking Table / conntrack)** tutar. Her paket akışı 5'li demet `(Kaynak IP, Kaynak Port, Hedef IP, Hedef Port, L4 Protokolü)` üzerinden takip edilir:
- **`NEW`:** Bağlantıyı başlatan ilk meşru paket. TCP için yalnızca `SYN` bayrağı taşıyan ve güvenlik duvarı erişim kurallarıyla (ACL) eşleşen paketlerdir. Eşleşirse conntrack tablosuna yeni bir oturum kaydı açılır.
- **`ESTABLISHED`:** İki yönlü el sıkışmanın tamamlandığı durum. İstemcinin `SYN` paketine karşılık sunucunun döndüğü `SYN-ACK` ve istemcinin attığı `ACK` paketleri görüldüğünde conntrack durumu `ESTABLISHED` olur. Artık bu oturuma ait tüm veri paketleri hiçbir statik kural kontrolüne gerek kalmadan otomatik olarak geçirilir.
- **`RELATED`:** Mevcut bir oturumun tetiklediği ikincil bağlantılar. Örneğin FTP kontrol kanalının (port 21) başlattığı pasif veri kanalı veya mevcut bir TCP bağlantısında yönlendiricinin ürettiği `ICMP Destination Unreachable` mesajları.
- **`INVALID`:** Conntrack tablosunda kaydı bulunmayan, sıra numarası bozuk veya kural dışı bayrak taşıyan paketler (örneğin durup dururken dışarıdan gelen sahte bir `ACK` paketi veya `SYN+FIN` taraması). Bu paketler doğrudan **`DROP`** edilir.

Böylece durum takipli güvenlik duvarı, dışarıdan içeriye hiçbir yüksek portu açık bırakmadan, yalnızca içeriden başlatılan oturumların yanıtlarını güvenle içeri alır.

### Siber Güvenlik ve Tehdit Modeli Açısından Kritik Önemi
Durumsuz güvenlik duvarları, TCP bayrak manipülasyonlarına (ACK Taraması, FIN Taraması) ve yetkisiz arka kapı (backdoor) iletişimlerine karşı savunmasızdır. Saldırgan, dışarıdan içeriye doğru rastgele bir porta `ACK` bayraklı paket gönderdiğinde durumsuz filtre "bu bir yanıt paketidir" yanılgısıyla paketi içeri alabilir. Durum takipli mimari, önceden başlatılmış bir oturum olmadığını anında fark ederek sızmayı engeller.

### Pratik / Sektörel Yansıma ve Analiz
Linux çekirdeğindeki `netfilter/iptables` veya `nftables` altyapısı bu mantıkla çalışır:
```bash
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
iptables -P INPUT DROP
```
Bu üç kural, modern kurumsal sunucuların %95'inde kullanılan temel savunma omurgasıdır.

---

## G061-SC2: PAT Mekanizması, Port Tükenmesi ve CGNAT Adli Bilişimi

### Soru
Port Adres Dönüşümü (PAT / NAPT / NAT Overload) mekanizması tek bir genel IP adresi üzerinden yüzlerce iç istemciyi nasıl internete çıkarır? PAT port tükenmesi (NAT Exhaustion) saldırıları nasıl gerçekleşir ve CGNAT (Carrier-Grade NAT) ortamlarında adli bilişim (forensics) incelemelerinde karşılaşılan teknik engeller nelerdir?

### Derin Teknik Cevap
Port Adres Dönüşümü (PAT / NAPT - RFC 3022), internete çıkış noktasındaki yönlendiricinin iç istemcilerin özel (RFC 1918) IP adreslerini tek bir genel (Public) IP adresine dönüştürürken, her oturum için benzersiz bir **Kaynak Portu (Source Port)** tahsis etmesi prensibine dayanır.
1. İç ağdaki `192.168.1.10:50123` istemcisi, internetteki `93.184.216.34:80` web sunucusuna istek gönderir.
2. PAT yönlendiricisi genel IP'si olan `203.0.113.10` üzerindeki dinamik port havuzundan (örneğin `10000 - 65535`) boşta duran bir port seçer (ör. `10005`).
3. Paketin kaynak adresini `203.0.113.10:10005` olarak değiştirir (**SNAT**) ve bunu belleğindeki NAT tablosuna yazar:
   $$\text{İç Adres: 192.168.1.10:50123} \iff \text{Genel Adres: 203.0.113.10:10005} \iff \text{Hedef: 93.184.216.34:80}$$
4. Web sunucusu yanıtı `203.0.113.10:10005` adresine döner.
5. Yönlendirici gelen paketin hedef portuna (`10005`) bakar, tablodan orijinal istemcinin `192.168.1.10:50123` olduğunu anlar ve hedefi değiştirerek iç istemciye teslim eder (**DNAT**).

**PAT Port Tükenmesi (NAT Exhaustion):**
Tek bir IP adresi üzerinde kullanılabilecek maksimum port sayısı $65535$'tir. Sistem ve servis portları (0-1023) düşüldüğünde kullanılabilir dinamik havuz yaklaşık 64.000 porttur. Bir iç ağda zararlı yazılım bulaşmış cihazlar (botnet / crypto miner / scanner) aynı anda binlerce dış hedefe bağlantı açtığında veya saldırgan içeriden dışarıya taşkın yaptığında:
- PAT tablosundaki tüm boş portlar tükenir (`NATExhaustionError`).
- Tabloda yer kalmadığı için meşru kullanıcıların hiçbir yeni internet bağlantısı (DNS, web, e-posta) açılamaz; tüm kurumun internet çıkışı felç olur (DoS).

**CGNAT (RFC 6598) ve Adli Bilişim Zorlukları:**
İnternet Servis Sağlayıcıları (ISS), binlerce aboneyi `100.64.0.0/10` bloğundan IP ile numaralandırıp tek bir kamuya açık genel IP üzerinden internete çıkarır. Bir siber suç işlendiğinde (örneğin bir bankaya saldırı yapıldığında veya yasadışı içerik paylaşıldığında), hedef sunucu loglarında yalnızca servis sağlayıcının CGNAT genel IP'si (`203.0.113.50`) görünür.
- Eğer savcılık veya olay müdahale ekibi ISS'ten yalnızca "Şu tarihte bu IP kime aitti?" sorgusu yaparsa, ISS "O IP'yi aynı anda 50.000 abone paylaşıyordu, şüpheliyi bulamayız" yanıtını verir!
- Suçlunun kesin tespiti için hedef sistemin **mutlaka istemcinin kaynak portunu (Source Port / Ephemeral Port) ve milisaniyelik zaman damgasını** kaydetmiş olması, ISS'in de CGNAT oturum loglarını (hangi aboneye hangi portun tahsis edildiğini) saklamış olması şarttır.

### Siber Güvenlik ve Tehdit Modeli Açısından Kritik Önemi
NAT, geçmişte bir "güvenlik kalkanı" olarak pazarlanmışsa da, gerçekte yalnızca adres dönüştürme aracıdır. Doğrudan dışarıdan içeriye erişimi engellemesi güvenlik hissi yaratsa da, içeriden dışarıya doğru açılan tersine kabuk (Reverse Shell) veya C2 oturumlarına karşı hiçbir koruma sağlamaz. Ayrıca loglarda kaynak port kaydedilmediğinde adli iz sürülebilirliği yok eder.

### Pratik / Sektörel Yansıma ve Analiz
- SIEM ve SOC analistleri, web sunucu loglarında (Nginx/Apache) ve güvenlik duvarı loglarında `$remote_port` (istemci kaynak portu) alanının mutlaka log formatına (`Combined Log Format`) eklenmesini zorunlu kılmalıdır.
- Kurumsal güvenlik duvarlarında istemci başına maksimum eşzamanlı NAT oturum limiti (ör. kullanıcı başına max 500 oturum) uygulanarak tek bir cihazın tüm kurum port havuzunu kurutması engellenir.

---

## G061-SC3: Ters Vekil Sunucuda X-Forwarded-For (XFF) IP Sahteciliği ve Savunma

### Soru
Ters vekil sunucu (Reverse Proxy) mimarilerinde `X-Forwarded-For` (XFF) başlığının kötüye kullanılmasıyla IP sahteciliği (IP spoofing) ve yetkilendirme kontrollerinin atlatılması nasıl gerçekleştirilir? Bu zafiyet kurumsal WAF ve ters vekil sunucularda nasıl hafifletilir?

### Derin Teknik Cevap
Ters vekil sunucu (örneğin Cloudflare, Nginx, AWS ALB), istemciden gelen TCP/HTTP bağlantısını kendi üzerinde sonlandırır ve arka uçtaki uygulama sunucusuna (örneğin Tomcat, Node.js, Django) yeni bir bağlantı açarak isteği iletir. Bu mimaride arka uç uygulama sunucusu, soket düzeyinde TCP kaynak IP'si olarak istemcinin gerçek IP'sini değil, **ters vekil sunucunun yerel IP adresini (`10.0.0.1` veya `127.0.0.1`)** görür.

İstemcinin gerçek IP'sini arka uç sunucusuna bildirmek amacıyla standart olarak `X-Forwarded-For` (XFF) başlığı kullanılır (RFC 7239'da `Forwarded` olarak standardize edilmiştir):
$$\text{X-Forwarded-For: <istemci_gercek_ip>, <vekil_1_ip>, <vekil_2_ip>}$$

**Saldırı Vektörü (XFF Spoofing & Yetki Atlatma):**
Birçok arka uç uygulama veya mikroservis, yönetim panellerine (`/admin`, `/metrics`, `/debug`) erişim iznini kontrol ederken ya da API hız sınırlandırması (Rate Limiting) uygularken doğrudan gelen `X-Forwarded-For` başlığındaki değere bakar:
```python
# KÖTÜ VE ZAAFİYETLİ KOD:
client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
if client_ip == "127.0.0.1":
    grant_full_admin_access()
```
Dışarıdaki bir saldırgan, doğrudan genel internetten istek yaparken HTTP isteğine şu başlığı enjekte eder:
```http
GET /admin/kullanici-sil HTTP/1.1
Host: sirket.com
X-Forwarded-For: 127.0.0.1
```
Eğer ters vekil sunucu düzgün yapılandırılmamışsa, istemciden gelen bu sahte başlığı arka uç sunucusuna aynen iletir. Arka uç uygulama isteğin yerel makineden (localhost) geldiğini zanneder ve saldırgana tam yönetici yetkisi verir!

**Hafifletme ve Güvenlik Mimarisi:**
1. **Güvenilmeyen XFF Başlıklarını Ezme (Overwrite Untrusted):**
   Ters vekil sunucu, doğrudan internetten gelen (yani güvenilir bir iç proxy zincirinden gelmeyen) isteklerdeki `X-Forwarded-For` başlığını **kesinlikle silmeli veya soketteki gerçek IP ile ezmelidir**.
   Nginx Konfigürasyonu:
   ```nginx
   # Saldırganın gönderdiği sahte XFF başlığını çöpe at, gerçek istemci soket IP'sini yaz:
   proxy_set_header X-Forwarded-For $remote_addr;
   ```
2. **Güvenilir Vekil Beyaz Listesi (Trusted Proxies):**
   Eğer ön tarafta bir CDN veya başka bir vekil sunucu varsa, arka uç veya ana vekil sunucu yalnızca belirli IP bloklarından (`set_real_ip_from 173.245.48.0/20;`) gelen XFF zincirini kabul etmeli; zincirin sağdan sola doğru güvenilir olmayan ilk halkasını gerçek istemci IP'si olarak seçmelidir (`real_ip_recursive on;`).

### Siber Güvenlik ve Tehdit Modeli Açısından Kritik Önemi
X-Forwarded-For sahteciliği; kimlik doğrulama atlatma, IP tabanlı coğrafi kısıtlamaları (Geo-blocking) baypas etme, WAF IP kara listelerini delme ve API kaba kuvvet (Brute-Force) hız sınırlandırmalarını sıfırlama gibi son derece geniş bir etki alanına sahiptir. Bir güvenlik testi uzmanı, ters vekil arkasındaki tüm sistemlerde ilk olarak XFF enjeksiyonunu denemelidir.

### Pratik / Sektörel Yansıma ve Analiz
- Spring Security, Django ve Laravel gibi popüler web çatıları, `server.forward-headers-strategy=framework` veya `TrustedProxies` ara yazılımları sunar. Bu ayarlarda güvenilir vekiller tanımlanmadığı sürece çatı XFF başlığını varsayılan olarak yok sayar.
- Yanlış XFF yapılandırması yüzünden Shopify, Gitlab ve birçok büyük platformda geçmişte kritik seviyede IP Yetki Atlatma (CVE) açıkları keşfedilmiştir.

---
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
ÖZEL LİSANS — Soru-cevap dokümanı yalnızca görüntüleme ve eğitim amacıyla paylaşılmıştır.
