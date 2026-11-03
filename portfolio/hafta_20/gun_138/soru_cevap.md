# Gün 138: Linux Güvenlik Duvarı: nftables ve UFW Kavramı — Soru & Cevap

---

## SORU 1

### 1. Soru Başlığı ve Tanımı
**"Default Deny" (Varsayılan Reddetme) İlkesi vs "Default Accept" ve Netfilter Paket Filtreleme Dinamikleri (CWE-284 / MITRE ATT&CK T1046)**  
Bir Linux sunucusunda Netfilter gelen (INPUT) ve yönlendirilen (FORWARD) zincirleri için varsayılan politikanın `ACCEPT` bırakılması durumunda oluşabilecek güvenlik riskleri nelerdir? "Default Deny" (Whitelist) yaklaşımı saldırganların port tarama (Nmap / T1046), servis keşfi ve yetkisiz arka kapı istismarı kabiliyetlerini nasıl engeller?

### 2. Derinlemesine Teknik Analiz
Linux çekirdeğinin paket filtreleme altyapısında (Netfilter), gelen bir paket tanımlı kurallardan hiçbirine uymadığında zincirin **varsayılan politikası (Default Policy)** devreye girer:

1. **Default Accept (Kara Liste / Blacklist) Yaklaşımı:**
   - Yöneticinin yalnızca aklına gelen birkaç portu engellediği, geri kalan tüm trafiği varsayılan olarak kabul ettiği durumdur.
   - **Risk Analizi:** Sistem yöneticisinin sunucuda çalışan her servisi (geliştiricilerin açtığı test portları, veritabanı portları, Docker konteynerlerinin `0.0.0.0`'a bind ettiği portlar, RPC ve yönetim servisleri) tek tek tahmin edip engellemesi imkansızdır.
   - Bir saldırgan Nmap ile SYN taraması (`nmap -sS -p- <target>`) yaptığında, açık unutulmuş tüm portları (örneğin Redis 6379, Elasticsearch 9200, Telnet 23) anında keşfeder. Kimlik doğrulamasız bir servis üzerinden sunucuyu ele geçirebilir (CWE-284).

2. **Default Deny (Beyaz Liste / Whitelist) Yaklaşımı:**
   - CIS Linux Benchmark Section 3.4.3 ve 3.5.2 standartları gereğince gelen tüm paketler varsayılan olarak `DROP` veya `DENY` edilir.
   - Yalnızca hizmet vermesi zorunlu olan portlar (örneğin Web için TCP 80/443 ve yönetim için kısıtlı TCP 22) açıkça `ACCEPT` kuralı ile tanımlanır.
   - Saldırgan sunucuyu taradığında, izin verilen portlar dışındaki 65.533 portun tamamı "Filtered" (Filtrelenmiş) olarak görünür. Sunucu hiçbir TCP RST veya ICMP Port Unreachable yanıtı dönmediği için saldırgan hedef sistemin ayakta olup olmadığını dahi anlamakta zorlanır.
   - Ayrıca sunucu bir router olmadığı sürece `FORWARD` zinciri de kesinlikle `DROP` olmalıdır; aksi halde sunucu bir ara köprü olarak kullanılarak iç ağlar arasında yetkisiz paket aktarımına (pivot/tunneling) alet edilebilir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir yazılım şirketinde üretim Kubernetes worker sunucusunda güvenlik duvarı varsayılan olarak `INPUT ACCEPT` modunda bırakılmıştır. Bir geliştirici geçici olarak konteyner içerisinde parolasız bir MongoDB (`port 27017`) ayağa kaldırmıştır. İnternet üzerindeki otomatik fidye tarayıcı botları bu açık portu saniyeler içinde keşfetmiş, veritabanını şifreleyerek fidye notu bırakmıştır.

**Pratik Çözüm:**
1. nftables üzerinde varsayılan politika `DROP` olarak ayarlanır:
   ```ini
   table inet filter {
       chain input {
           type filter hook input priority 0; policy drop;
           # Yalnızca meşru servislere izin verilir:
           tcp dport { 80, 443 } accept
       }
       chain forward {
           type filter hook forward priority 0; policy drop;
       }
   }
   ```
2. Ya da UFW kullanılıyorsa:
   ```bash
   sudo ufw default deny incoming
   sudo ufw default deny routed
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw enable
   ```
Artık geliştirici yerel bir port açsa dahi güvenlik duvarı bu porta dış dünyadan gelen tüm paketleri sessizce düşürür.

### 4. Ustanın Çırağa Tavsiyesi
Çırak! Güvenlik dünyasında "Yasaklamadığım her şeye izin veriyorum" demek intihardır. "İzin vermediğim hiçbir şey içeri giremez" diyeceksin. Default Deny senin temel refleksin olacak. Önce kapıyı tamamen kilitleyeceksin; sonra kimin içeri gireceğine sen karar vereceksin.

---

## SORU 2

### 1. Soru Başlığı ve Tanımı
**Durum Denetimli (Stateful Inspection) Filtreleme ve Linux `conntrack` Mekanizması (CWE-693 / T1059)**  
Stateless (durumsuz) ve Stateful (durum denetimli) paket filtreleme arasındaki mimari ve güvenlik farkı nedir? Linux çekirdeğinin `conntrack` modülü bağlantı durumlarını (NEW, ESTABLISHED, RELATED, INVALID) nasıl takip eder? `ct state established,related accept` ve `ct state invalid drop` kuralları sunucuyu hangi ağ seviyesi saldırılara karşı korur?

### 2. Derinlemesine Teknik Analiz
Geleneksel ve ilkel paket filtreleyiciler (stateless), her IP paketini diğerlerinden bağımsız bir veri bloğu olarak inceler. Ancak modern ağ iletişimi durum temellidir (Stateful):

1. **Stateless Filtrelemenin Çıkmazı:**
   - Sunucumuz dışarıdaki bir API'ye istek attığında (örneğin sunucu istemci olup `api.github.com:443`'e bağlandığında), sunucumuz yüksek numaralı rastgele bir porttan (örneğin port 49152) çıkış yapar.
   - Dışarıdan gelen HTTP yanıt paketinin içeri girebilmesi için stateless bir güvenlik duvarında `INPUT` zincirinde tüm yüksek portların (1024-65535) içeriye açık tutulması gerekir. Bu da sunucuyu devasa bir saldırı yüzeyiyle baş başa bırakır.

2. **Linux conntrack ve Stateful İnceleme (CWE-693):**
   - Linux çekirdeğindeki `nf_conntrack` modülü, bellekte bir bağlantı takip tablosu (`/proc/net/nf_conntrack`) tutar.
   - İki host arasındaki 5'li demeti (Kaynak IP, Hedef IP, Kaynak Port, Hedef Port, Protokol) izler ve her pakete bir durum atar:
     - **NEW:** Yeni bir bağlantı başlatma talebi (TCP SYN paketi gibi).
     - **ESTABLISHED:** Üçlü el sıkışması (Three-Way Handshake: SYN -> SYN/ACK -> ACK) tamamlanmış, çift yönlü meşru trafiğe ait paketler.
     - **RELATED:** Mevcut bir bağlantıyla ilişkili olan ancak farklı port/protokol kullanan paketler (Örn: Bağlantının kopması sonucu dönen ICMP Destination Unreachable veya FTP veri kanalı).
     - **INVALID:** Mevcut hiçbir oturumla eşleşmeyen, TCP durum makinesine (Finite State Machine) aykırı bayrak kombinasyonlarına sahip paketler (Örn: Ortada bağlantı yokken gelen FIN/ACK, RST paketleri veya sıra dışı bayraklar).

3. **Güvenlik Savunması:**
   - `ct state established,related accept`: Sunucunun kendisinin başlattığı tüm dış bağlantıların dönüş paketleri otomatik olarak içeri alınır; hiçbir rastgele port açmaya gerek kalmaz!
   - `ct state invalid drop`: Saldırganların güvenlik duvarını aşmak veya işletim sistemi parmak izini çıkarmak (OS Fingerprinting) için kullandığı **XMAS Scan** (FIN, PSH, URG bayrakları aynı anda set edilmiş), **NULL Scan** (hiçbir bayrak yok) ve **FIN Scan** gibi bozuk paketler çekirdek tarafından anında tespit edilerek çöpe atılır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir siber saldırgan, hedef Linux sunucusunun güvenlik duvarını atlatmak ve arkada çalışan servisleri haritalandırmak için Nmap ile `nmap -sN -p 1-1000` (NULL scan) ve `nmap -sX -p 1-1000` (XMAS scan) paketleri göndermektedir. Durumsuz bir filtreleme kullanılan sistemde bu paketler işletim sisteminin TCP yığınına kadar ulaşmakta ve yanıt dönülerek OS sürümü ifşa edilmektedir.

**Pratik Çözüm:**
nftables kural kümesinin en başına durum denetimli kurallar eklenir:
```ini
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Önceden kurulmuş meşru bağlantıları kabul et
        ct state established,related accept

        # Bozuk ve sahte paketleri kapıda düşür
        ct state invalid drop
    }
}
```
Bu kural eklendiği anda geçersiz TCP bayraklı tüm tarama paketleri sessizce yok edilir; saldırganın eline hiçbir bilgi geçmez.

### 4. Ustanın Çırağa Tavsiyesi
Evlat! Durum denetimi olmayan güvenlik duvarı, pasaport kontrolü yaparken gelen her adama "Sen daha önce çıkmış mıydın?" diye sormayan sınır polisine benzer. `conntrack` çekirdeğin hafızasıdır. Kurduğun her güvenlik duvarında ilk yazacağın iki satır: "Established, related accept" ve "Invalid drop" olacaktır.

---

## SORU 3

### 1. Soru Başlığı ve Tanımı
**nftables Bytecode VM, Setler (Sets) ve Atomik Kurallar ile iptables'a Karşı Üstünlükleri; UFW ve Rate-Limiting**  
Yüksek trafikli kurumsal sunucularda ve DDoS saldırıları altında `iptables` neden darboğaza girer? Modern `nftables` sanal makine (Bytecode VM) mimarisi ve Set/Dictionary veri yapıları ile bu sorunu nasıl çözer? Ubuntu/Debian sistemlerde UFW kaba kuvvet saldırılarına karşı `ufw limit` mekanizmasını nasıl işletir?

### 2. Derinlemesine Teknik Analiz
Linux ağ güvenliğinde `iptables`'tan `nftables`'a geçiş sıradan bir sözdizimi güncellemesi değil, çekirdek düzeyinde radikal bir mimari devrimdir:

1. **iptables'ın Yapısal Sorunları:**
   - **Doğrusal Arama Maliyeti (O(N)):** iptables'ta her kural zincirde sırayla değerlendirilir. Eğer kara listede 10.000 IP varsa, gelen her paket bu 10.000 satırı tek tek dolaşır. Yüksek paket hızlarında (Gbps) CPU %100'e vurur ve sistem paket düşürmeye başlar.
   - **Kural Değiştirme Kesintisi:** iptables'a tek bir kural eklemek veya silmek için tüm çekirdek tablosu kullanıcı alanına kopyalanır, değiştirilir ve tekrar çekirdeğe yazılır. Büyük kural kümelerinde bu işlem milisaniyelerce sürer ve paket kaybına (race condition) yol açar.
   - **Kod Çokluğu:** IPv4 için iptables, IPv6 için ip6tables, ARP için arptables çekirdekte ayrı ayrı kod modülleri çalıştırır.

2. **nftables Sanal Makine (VM) ve Set Mimarisi:**
   - **Bytecode Execution:** nftables, çekirdeğin içine küçük, izole ve optimize bir Sanal Makine (VM) yerleştirir. `nft` komutu kuralları derleyerek bytecode'a çevirir ve çekirdeğe iletir.
   - **Setler ve Sözlükler (Sets & Dictionaries):** nftables doğal olarak hash tabloları ve kırmızı-siyah ağaçlar (rbtree) destekler. Binlerce IP veya port tek bir sette toplanabilir:
     ```text
     set blacklisted_ips {
         type ipv4_addr
         flags interval
         elements = { 198.51.100.0/24, 203.0.113.5, 192.0.2.1 }
     }
     ip saddr @blacklisted_ips drop
     ```
     Bu kuralda arama süresi O(1) veya O(log N)'dir. 100.000 IP olsa bile paket nanosaniyeler içinde sorgulanır.
   - **Atomik Taahhüt (Atomic Commit):** `flush ruleset` ve yeni kurallar tek bir işlem (transaction) içinde çekirdeğe yüklenir; paket akışı hiçbir zaman kesintiye uğramaz.

3. **UFW ve Hız Sınırlandırması (`ufw limit`):**
   - UFW, karmaşık iptables/nftables sözdizimini kullanıcı dostu bir kabuk haline getirir.
   - İnternete açık SSH portuna yöneltilen kaba kuvvet saldırılarına karşı UFW yerleşik bir koruma sunar:
     ```bash
     ufw limit 22/tcp
     ```
   - Bu kural arka planda `recent` modülünü çalıştırır: Aynı kaynak IP'den 30 saniye içinde 6'dan fazla yeni TCP bağlantı denemesi gelirse, o IP'den gelen yeni bağlantılar otomatik olarak reddedilir (Rate-Limiting).

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Yoğun bir e-ticaret sitesine kampanya döneminde dağıtık botnetler tarafından SYN Flood ve SSH kaba kuvvet saldırısı başlatılmıştır. Eski iptables kullanan sunucu, binlerce IP engelleme kuralı eklendikten sonra CPU darboğazına girmiş ve meşru müşterilerin sipariş paketleri düşmeye başlamıştır.

**Pratik Çözüm:**
1. Güvenlik duvarı modern nftables'a taşınır.
2. IP engellemeleri ve rate-limit kuralları setler üzerinden atomik olarak tanımlanır:
   ```ini
   table inet filter {
       set bad_actors {
           type ipv4_addr
           flags timeout
       }
       chain input {
           type filter hook input priority 0; policy drop;
           ip saddr @bad_actors drop

           # SYN Flood koruması
           tcp flags syn / fin,syn,rst,ack limit rate 200/second burst 50 packets accept

           # SSH bağlantı sınırlaması (Dakikada en fazla 10 yeni istek)
           tcp dport 22 ct state new limit rate 10/minute accept
       }
   }
   ```
Sonuç olarak binlerce saldırgan IP sıfır CPU maliyetiyle elenir ve sunucu tam kapasiteyle meşru müşterilere hizmet vermeye devam eder.

### 4. Ustanın Çırağa Tavsiyesi
Çırak! Teknoloji yerinde saymaz. 20 yıl önce iptables kraldı; bugün ise modern Linux çekirdeğinin tek efendisi nftables'tır. Setleri kullanmayı, kuralları atomik derlemeyi ve rate-limit koymayı iyi öğren. Bir fırtına koptuğunda sunucunun ayakta kalmasını sağlayan şey, çekirdeğin içinde dönen bu mikroskobik sanal makinedir.
