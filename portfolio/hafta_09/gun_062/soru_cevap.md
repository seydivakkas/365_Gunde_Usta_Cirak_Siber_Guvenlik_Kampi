# G062: VLAN, Segmentasyon ve DMZ — Soru-Cevap Dokümanı

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya ticari olarak kullanılamaz.
```

---

## G062-SC1: IEEE 802.1Q Etiketleme Mimarisi ve Access vs Trunk Port Mantığı

### Soru
IEEE 802.1Q standardının 4 baytlık etiket yapısı (TPID ve TCI) Ethernet çerçevesi içine nasıl yerleştirilir ve anahtar portlarındaki Access vs Trunk modlarının çalışma mantığı L2 çerçeve iletimini nasıl belirler?

### Derin Teknik Cevap
Standart bir Ethernet II çerçevesi; 6 bayt Hedef MAC, 6 bayt Kaynak MAC, 2 bayt EtherType (ör. `0x0800` IPv4), 46-1500 bayt veri yükü ve 4 bayt FCS (Frame Check Sequence) içerir. IEEE 802.1Q standardı, çerçeve boyutunu 4 bayt genişleterek Kaynak MAC ile EtherType alanlarının arasına **4 baytlık bir VLAN Etiketi (VLAN Tag)** enjekte eder:
1. **TPID (Tag Protocol Identifier - 16-bit):** Sabit `0x8100` değeridir. Ağ kartına veya anahtara bu çerçevenin standart bir Ethernet çerçevesi değil, 802.1Q etiketli bir çerçeve olduğunu bildirir.
2. **TCI (Tag Control Information - 16-bit):**
   - **PCP (Priority Code Point - 3-bit):** IEEE 802.1p standardı uyarınca 0 ile 7 arasında Hizmet Kalitesi (QoS / CoS) önceliği atar (ör. ses ve video trafiğine yüksek öncelik vermek için).
   - **DEI (Drop Eligible Indicator - 1-bit):** Ağda aşırı yüklenme olduğunda paketin kuyruktan öncelikle düşürülüp düşürülemeyeceğini belirtir.
   - **VID (VLAN Identifier - 12-bit):** 1 ile 4094 arasında sanal yerel ağ kimliğini taşır ($2^{12} = 4096$; 0 öncelikli etiket, 4095 ise rezerve kabul edilir).

**Access vs Trunk Port Çalışma Mantığı:**
- **Access Port:** Son kullanıcı uç cihazlarının (iş istasyonu, yazıcı, sunucu) bağlandığı tek bir VLAN'a özgü porttur (`switchport mode access`). İstemci cihazlar 802.1Q etiketlerinden habersizdir ve standart etiketsiz paket üretir. Paket anahtara girdiği anda anahtar pakete o access portun VLAN kimliğini dahili olarak atar. Paketi anahtardan kullanıcı cihazına iletirken ise 802.1Q etiketini **kesinlikle soyar (strip)**.
- **Trunk Port:** İki anahtar veya bir anahtar ile yönlendirici/güvenlik duvarı arasındaki omurga bağlantısıdır (`switchport mode trunk`). Tek bir fiziksel kablo üzerinden birden çok VLAN'ın trafiğini taşır. Paketler trunk hattan geçerken 802.1Q etiketleri korunur. Trunk port üzerinde tanımlanan **Native VLAN**, geriye dönük uyumluluk amacıyla etiketsiz olarak taşınan varsayılan VLAN'dır.

### Siber Güvenlik ve Tehdit Modeli Açısından Kritik Önemi
VLAN etiketleme, mantıksal izolasyonun temel yapı taşıdır. L2 katmanında doğru yapılandırılmamış bir port (örneğin son kullanıcıya trunk modda bırakılmış bir port), saldırganın tüm departmanların ağ trafiğini izlemesine ve paket enjekte etmesine olanak tanır. Etiketin ikili (binary) düzeyde doğru işlenmesi, donanım düzeyinde trafik ayrımını garanti eder.

### Pratik / Sektörel Yansıma ve Analiz
- Kurumsal anahtar konfigürasyonlarında en yaygın zafiyetlerden biri, trunk portlarda varsayılan `switchport trunk allowed vlan all` komutunun bırakılmasıdır.
- Güvenlik standardı (CIS Benchmarks), trunk portlarda yalnızca taşınması zorunlu olan VLAN'ların beyaz listeye alınmasını (`switchport trunk allowed vlan 10,20,30`) şart koşar.

---

## G062-SC2: VLAN Hopping Saldırıları (Double Tagging & Switch Spoofing) ve Savunma

### Soru
Saldırganlar L2 katmanında VLAN sınırlarını aşarak diğer segmentlere sızmak için Çift Etiketleme (Double Tagging / QinQ) ve Anahtar Sahteciliği (Switch Spoofing / DTP) tekniklerini nasıl kullanır? Bu saldırıların gerçekleşme koşulları ve kurumsal anahtarlama altyapısındaki kesin hafifletme yöntemleri nelerdir?

### Derin Teknik Cevap
VLAN Hopping, bir saldırganın kendi bulunduğu VLAN'dan yönlendirici veya L3 güvenlik duvarı denetimini tamamen atlayarak başka bir hedef VLAN'a yetkisiz paket göndermesi işlemidir. İki ana saldırı vektörü bulunur:

**1. Çift Etiketleme (Double Tagging / QinQ İstismarı):**
Bu saldırı, anahtarların Native VLAN paketlerini trunk hat üzerinde etiketsiz iletme davranışındaki mimari boşluğu sömürür:
- **Ön Koşul:** Saldırganın bağlı olduğu Access portun VLAN kimliği, trunk hattın **Native VLAN kimliği (genellikle varsayılan VLAN 1)** ile aynı olmalıdır.
- **Saldırı Mekanizması:** Saldırgan özel olarak manipüle edilmiş çift 802.1Q etiketli bir Ethernet paketi üretir. Dış etikete anahtarın Native VLAN'ını (`VID 1`), iç etikete ise hedeflemek istediği kurbanın VLAN'ını (`VID 30` - örneğin Veritabanı Ağı) yazar.
- **İletim:** İlk anahtar paketi alır; dış etiketteki `VID 1` değerinin kendi Native VLAN'ı ile aynı olduğunu görür. Trunk porta paketi aktarırken standart kural gereği dış etiketi **soyar** ve paketi etiketsiz sanarak hatta basar.
- **Hedefe Ulaşma:** Karşıdaki ikinci anahtar paketi aldığında, paketin başında artık iç etiket olan `VID 30` durmaktadır. İkinci anahtar paketin doğrudan VLAN 30'a ait olduğunu varsayar ve paketi hedef veritabanı portlarına teslim eder! Saldırgan L3 güvenlik duvarını hiç görmeden L2 seviyesinde hedef ağa sızmıştır.
*(Not: Bu saldırı tek yönlüdür; saldırgan yanıt paketlerini göremez ancak tek yönlü UDP veya kör TCP exploitleri fırlatabilir).*

**2. Anahtar Sahteciliği (Switch Spoofing / DTP İstismarı):**
Birçok kurumsal anahtarda portlar varsayılan olarak `Dynamic Auto` veya `Dynamic Desirable` modundadır ve Cisco DTP (Dynamic Trunking Protocol) protokolü aktiftir:
- **Saldırı Mekanizması:** Saldırgan, Kali Linux veya Yersinia aracını kullanarak bilgisayarından anahtara sahte DTP müzakere paketleri gönderir.
- **Sonuç:** Anahtar, karşısındaki cihazın meşru bir anahtar olduğunu düşünerek portu otomatik olarak **Trunk moduna** geçirir. Saldırgan artık ağdaki istisnasız TÜM VLAN'ların paketlerini dinleyebilir (sniff) ve çift yönlü olarak her VLAN ile konuşabilir.

**Kesin Savunma ve Sertleştirme Yöntemleri:**
1. **DTP'yi Kapatmak:** Tüm kullanıcı portlarında DTP müzakeresi kapatılmalı ve port statik access yapılmalıdır:
   ```text
   switchport mode access
   switchport nonegotiate
   ```
2. **Native VLAN İzolasyonu:** Native VLAN olarak asla varsayılan VLAN 1 kullanılmamalıdır! Ağda hiçbir kullanıcının bulunmadığı, veri taşımayan sahte/kukla bir VLAN (ör. VLAN 99) Native VLAN olarak atanmalıdır.
3. **Native VLAN Etiketleme Zorunluluğu:** Trunk portlarda Native VLAN paketlerinin de etiketlenmesi şart koşulmalıdır:
   ```text
   vlan dot1q tag native
   ```

### Siber Güvenlik ve Tehdit Modeli Açısından Kritik Önemi
VLAN Hopping, ağ segmentasyonu savunmasının kalbine vurulan bir darbedir. Kurum milyonlarca liralık Yeni Nesil Güvenlik Duvarı (NGFW) satın almış olsa bile, anahtar konfigürasyonundaki tek bir `nonegotiate` eksikliği veya Native VLAN dikkatsizliği yüzünden güvenlik duvarı tamamen baypas edilebilir.

### Pratik / Sektörel Yansıma ve Analiz
- Sızma testlerinde (Penetration Testing) ilk adım, bağlanan portun DTP gönderip göndermediğini kontrol etmektir.
- CIS Cisco Benchmark kuralları, tüm access portlarda DTP'nin kapatılmasını ve Native VLAN'ın ayrılmasını Seviye 1 zorunlu güvenlik maddesi olarak listeler.

---

## G062-SC3: DMZ Çevre Ağı İzolasyonu ve Zero Trust Yanal Yayılım Blokajı

### Soru
DMZ (Arındırılmış Bölge) çevre ağı mimarisinde dış güvenlik duvarı ile iç güvenlik duvarı (Dual-Homed / Three-Legged Firewall) ayrımı neden gereklidir ve ele geçirilen bir DMZ sunucusunun iç ağa doğru yanal yayılımı (Lateral Movement) Zero Trust prensipleriyle nasıl engellenir?

### Derin Teknik Cevap
DMZ (Demilitarized Zone), internet gibi güvenilmeyen bir dış ağ ile kurumun en değerli varlıklarının bulunduğu iç ağ arasında konumlandırılan **tampon güvenlik bölgesidir**. Web sunucuları, e-posta ağ geçitleri, genel DNS ve ters vekil sunucuları doğası gereği internete açık olmak zorundadır ve bu durum onları saldırganların ilk hedefi haline getirir.

**Dual-Homed / Three-Legged Güvenlik Duvarı Mimarisi:**
Geleneksel ağlarda tek bir güvenlik duvarının üç bacağı (WAN, DMZ, LAN) ayrılır veya en güvenli mimaride **farklı iki üreticiden (örneğin dışta Fortinet, içte Palo Alto) çift güvenlik duvarı** kullanılır:
1. **Dış Güvenlik Duvarı (Edge Firewall):** Yalnızca internetten DMZ'ye doğru gelen belirli servis portlarına (ör. port 443 HTTPS, port 53 DNS) izin verir. İnternetten doğrudan iç ağa giden TÜM trafiği koşulsuz reddeder.
2. **İç Güvenlik Duvarı (Internal Firewall):** DMZ ile iç ağ (Kullanıcı LAN ve Veritabanı LAN) arasına yerleştirilir.

**Zero Trust Yanal Yayılım (Lateral Movement) Blokajı:**
Varsayalım ki DMZ'deki web sunucusunda kritik bir Uzaktan Kod Çalıştırma (RCE) açığı çıktı ve saldırgan sunucuya bir web kabuğu (Web Shell / Cobalt Strike Beacon) yerleştirdi.
- **Kötü / Güvensiz Mimari (Flat DMZ):** Eğer DMZ ile iç ağ arasında gevşek kurallar varsa, saldırgan DMZ sunucusu üzerinden iç ağdaki çalışanların bilgisayarlarına (VLAN 10) SMB (Port 445) veya RDP (Port 3389) ile saldırarak fidye yazılımı (Ransomware) yayabilir.
- **Zero Trust Mikrosegmentasyon Kuralı:**
  1. **DMZ'den İç Kullanıcı Ağına Sıfır Erişim (Default Deny):** DMZ sunucusundan kullanıcı VLAN'ına (VLAN 10) doğru hiçbir bağlantı açılamaz! Yönlendirme tablosunda ve güvenlik duvarında `SRC: VLAN 20 -> DST: VLAN 10 = DROP` kuralı mutlak olmalıdır.
  2. **DMZ'den Veritabanına Yalnızca İhtiyaç Duyulan Port (Least Privilege):** Web sunucusunun veritabanına erişmesi gerekiyorsa, yalnızca tek bir iç IP'ye ve tek bir veritabanı portuna (`192.168.30.15:5432`) durum takipli izin verilir. Veritabanından DMZ'ye doğru ise hiçbir yeni bağlantı başlatılamaz.
  3. **Yönetim Ayrımı (Out-of-Band Management):** DMZ sunucularının bakımı doğrudan kullanıcı ağından SSH ile yapılmamalıdır; araya bir Atlama Sunucusu (Jumpbox / Bastion Host) ve Çok Faktörlü Kimlik Doğrulama (MFA) konulmalıdır.

### Siber Güvenlik ve Tehdit Modeli Açısından Kritik Önemi
Siber saldırıların %90'ında ilk sızılan nokta nihai hedef değildir; nihai hedef içerideki Active Directory veya müşteri veritabanıdır. DMZ izolasyonu ve inter-VLAN mikrosegmentasyon, "İçeri sızılsa dahi saldırganı DMZ hücresinde hapset" (Assume Breach) doktrininin en temel mekanik kalkanıdır.

### Pratik / Sektörel Yansıma ve Analiz
- PCI-DSS (Kredi Kartı Güvenlik Standardı) Madde 1.3 uyarınca, kredi kartı verilerinin saklandığı ortam (CDE) ile internete açık sunucular arasında DMZ ve durum takipli güvenlik duvarı izolasyonu bulunması zorunludur.
- Bir denetimde DMZ'deki bir sunucudan iç ağdaki herhangi bir makineye ICMP Ping veya port erişimi tespit edilirse, sistem anında denetimden kalır.

---
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
ÖZEL LİSANS — Soru-cevap dokümanı yalnızca görüntüleme ve eğitim amacıyla hazırlanmıştır.
