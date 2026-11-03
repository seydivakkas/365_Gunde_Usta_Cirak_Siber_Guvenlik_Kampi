# Gün 138: Linux Güvenlik Duvarı: nftables ve UFW Kavramı (Hoca Dersi / Usta-Çırak Rehberi)

**Eğitmen / Usta:** Seydi Eryılmaz (@seydivakkas)  
**Kapsam:** Linux Çekirdeği Netfilter Kancaları (Hooks), iptables'tan nftables'a Geçiş, nftables Sanal Makine (VM) Mimarisi, UFW (Uncomplicated Firewall) Yönetimi, Varsayılan Reddetme (Default Deny), Durum Denetimli (Stateful/conntrack) Paket Filtreleme, Loopback İzolasyonu ve CIS Benchmark Section 3.4 & 3.5 Standartları  
**Seviye:** İleri Düzey Güvenlik Mühendisliği / Sistem Savunması  

---

## 1. Giriş: Ağın Kapısındaki Nöbetçi — Güvenlik Duvarı

Evlat, sunucunun işletim sistemini ne kadar sertleştirirsen sertleştir; SSH anahtarlarını, PAM politikalarını, systemd sandboxing kurallarını ne kadar kusursuz kurgularsan kurgula; eğer ağ arayüzünden gelen her IP paketini sorgusuz sualsiz içeri alıyorsan, kale kapısı ardına kadar açıktır.

Bir Linux sunucusunda çalışan uygulamaları dış dünyanın zehirli paketlerinden koruyan ilk ve en kritik savunma hattı **Host-Based Firewall (Sunucu Tabanlı Güvenlik Duvarı)** mekanizmasıdır.

Yıllarca Linux dünyasında `iptables`, `ip6tables`, `arptables` ve `ebtables` gibi parçalı ve karmaşık araçlar kullanıldı. Ancak modern Linux çekirdeği (Kernel 3.13+) ile birlikte tüm bu hantal yapı yerini devrimsel bir teknolojiye bıraktı: **nftables**.

Bugün seninle:
1. Linux çekirdeğindeki Netfilter kancalarının (hooks) nasıl çalıştığını,
2. Neden `iptables` yerine `nftables` ve kullanıcı dostu `UFW` tercih ettiğimizi,
3. Durum denetimli (stateful / conntrack) paket filtrelemenin matematiğini,
4. Kurumsal bir sunucuyu CIS Linux Benchmark standartlarında nasıl kilit altına alacağımızı derinlemesine öğreneceğiz.

---

## 2. Linux Çekirdeği Netfilter ve Paket Yolculuğu

Linux çekirdeğinde ağ paketlerinin geçtiği 5 temel kanca (hook) noktası bulunur:

```text
                                  +-------------------+
                                  | Gelen Ağ Paketi   |
                                  +-------------------+
                                            |
                                            v
                                     [ PREROUTING ]
                           (Hedef NAT, mangle, raw kontrolleri)
                                            |
                                            v
                                  /-------------------\
                                 /  Yönlendirme Kararı \
                                <   (Routing Decision)  >
                                 \  Bu host'a mı ait?  /
                                  \-------------------/
                                   /                 \
                          EVET    /                   \   HAYIR (Başka host'a)
                                 v                     v
                            [ INPUT ]             [ FORWARD ]
                      (Yerel Servis Koruması)   (Paket Aktarımı / Router)
                                 |                     |
                                 v                     |
                         +---------------+             |
                         | Yerel Süreç   |             |
                         | (Nginx, SSH)  |             |
                         +---------------+             |
                                 |                     |
                                 v                     |
                            [ OUTPUT ]                 |
                      (Sunucudan Çıkan Paket)          |
                                 \                     /
                                  \                   /
                                   v                 v
                                    [ POSTROUTING ]
                             (Kaynak NAT / Masquerade)
                                            |
                                            v
                                  +-------------------+
                                  | Giden Ağ Paketi   |
                                  +-------------------+
```

Host güvenliği (uç nokta sertleştirmesi) açısından bizim odaklanacağımız iki hayati zincir şunlardır:
- **INPUT:** Dış dünyadan sunucumuzdaki süreçlere gelen paketlerin filtrelendiği yer.
- **FORWARD:** Sunucumuz bir router/gateway değilse **asla izin verilmemesi gereken**, doğrudan `DROP` edilmesi gereken zincir.

---

## 3. iptables vs nftables: Neden nftables?

Evlat, "Hocam iptables yetmiyor muydu, niye nftables çıktı?" diye sorabilirsin. Farkı iyi anla:

```text
+------------------------------------+------------------------------------+
| Özellik                            | Eski İptables                      | Modern Nftables (nft)              |
+------------------------------------+------------------------------------+
| Mimari                             | Her kural çekirdeğe C kodu         | Çekirdekte küçük, hızlı bir sanal  |
|                                    | modülü olarak yüklenir.            | makine (Bytecode VM) çalışır.      |
+------------------------------------+------------------------------------+
| IPv4 & IPv6 Desteği                | Ayrı ayrı iptables ve ip6tables    | 'inet' ailesi altında tek kural    |
|                                    | ile iki kat kural yönetimi.        | kümesiyle her ikisini de yönetir.  |
+------------------------------------+------------------------------------+
| Arama Hızı ve Performans           | Kurallar satır satır taranır (O(N))| Setler ve sözlükler ile O(1) veya  |
|                                    | Binlerce IP varsa sistem tıkanır.  | O(log N) anlık eşleştirme.         |
+------------------------------------+------------------------------------+
| Kural Güncelleme                   | Kural eklenirken tüm zincir        | Atomik kural taahhüdü (Transaction)|
|                                    | kopyalanır, geçici kesinti olur.   | Sıfır kesinti, anlık güncelleme.   |
+------------------------------------+------------------------------------+
| Sözdizimi                          | Kriptik parametreler (-m state...) | İnsan tarafından okunabilir temiz  |
|                                    |                                    | hiyerarşik yapı (table, chain, rule|
+------------------------------------+------------------------------------+
```

### UFW (Uncomplicated Firewall) Nedir?
Ubuntu ve Debian tabanlı sistemlerde varsayılan olarak gelen UFW, arka planda `iptables` veya `nftables` motorunu kullanan, sistem yöneticilerine karmaşık zincirler yerine `ufw default deny incoming`, `ufw allow 22/tcp` gibi anlaşılır ve hata yapmayı zorlaştıran yüksek seviyeli bir yönetim arayüzü sunan koruma katmanıdır.

---

## 4. Altın Kural: "Default Deny" (Varsayılan Reddetme)

Güvenlik mühendisliğinin birinci kuralı şudur:  
**"Açıkça izin verilmeyen her şey yasaktır!" (Whitelist Yaklaşımı)**

Bir sunucuda INPUT politikası `ACCEPT` bırakılmışsa, o sunucuda güvenlik duvarı var denemez. Saldırgan port taraması yaptığında sunucuda unutulmuş tüm test portlarını, veri tabanlarını, debug servislerini görebilir.

CIS Linux Benchmark gereğince:
```text
INPUT   --> DROP (veya DENY)
FORWARD --> DROP
OUTPUT  --> ACCEPT (veya kontrollü çıkış)
```

---

## 5. Durum Denetimli (Stateful Inspection / conntrack) Paket Filtreleme

Eski paket filtreleme sistemleri (stateless), her paketi birbirinden bağımsız değerlendirirdi. Ancak TCP ve UDP oturum tabanlıdır.

Örneğin, sunucumuz bir DNS sorgusu (`UDP 53`) veya `apt update` (`TCP 80/443`) için dışarıya paket gönderdiğinde, dışarıdaki sunucunun verdiği yanıtın geri dönebilmesi gerekir.

Bunu çözmek için Linux çekirdeğinin **conntrack (Connection Tracking)** modülü kullanılır. conntrack her paketi 4 durumdan birine atar:
1. **NEW:** Yeni başlatılmak istenen bir bağlantının ilk paketi (örn. TCP SYN).
2. **ESTABLISHED:** Daha önce meşru bir şekilde başlatılmış ve iki yönlü onaylanmış oturuma ait paketler.
3. **RELATED:** Mevcut bir bağlantıyla ilişkili yeni bağlantılar (örn. FTP data kanalı veya ICMP hata mesajları).
4. **INVALID:** Hiçbir bilinen oturuma uymayan, TCP bayrakları bozuk, sırası kaymış veya spoof edilmiş şüpheli paketler!

### nftables Kuralı:
```text
ct state established,related accept
ct state invalid drop
```
Bu iki kural sayesinde:
- Dışarıya giden bağlantılarımızın yanıtları sorunsuz içeri girer.
- Ancak dışarıdan gelen ve önceden onaylanmamış yabancı paketler anında engellenir.
- Bozuk (invalid) paketler çekirdeğin derinliklerine inmeden kapıda düşürülür.

---

## 6. Loopback İzolasyonu ve Anti-Spoofing (CWE-290)

Sunucu üzerindeki servisler (örneğin bir web uygulaması ile yerel veritabanı `localhost:5432`) `lo` (loopback - `127.0.0.1`, `::1`) arayüzü üzerinden konuşur.
- Eğer loopback arayüzüne izin vermezseniz sistemin kendi iç süreçleri kilitlenir.
- Ancak dış arayüzden (`eth0`) bir saldırgan, kaynak IP'sini sahte olarak `127.0.0.1` göstererek paket gönderirse (IP Spoofing), güvenlik duvarını aldatmaya çalışabilir.

Bunu engellemek için nftables kuralı:
```text
iif "lo" accept
ip saddr 127.0.0.0/8 iif != "lo" drop
```
"Eğer arayüz lo ise kabul et; ama kaynak adresi 127.0.0.0/8 olup da lo DIŞINDAKİ bir arayüzden geliyorsa derhal DROP et!"

---

## 7. Tehlikeli Portlar ve Kaba Kuvvet Sınırlandırması (Rate Limiting)

CIS Benchmark ve kurumsal standartlara göre:
- Port 23 (Telnet), Port 445 (SMB), Port 3389 (RDP), Port 21 (FTP) gibi servisler kesinlikle tüm internete açılmamalıdır.
- SSH (Port 22) açılacaksa, kaba kuvvet saldırılarına karşı hız sınırlandırması (rate-limit) uygulanmalıdır:
  ```text
  tcp dport 22 ct state new limit rate 10/minute accept
  ```
  veya UFW ile:
  ```bash
  ufw limit 22/tcp
  ```
  *(Bu komut 30 saniye içinde 6'dan fazla bağlantı denemesi yapan IP'leri otomatik bloklar).*

---

## 8. Ustanın Çırağa Öğüdü

Evlat! Bir sunucuya bağlandığında ilk bakacağın şey güvenlik duvarının durumudur.
- `ufw status` veya `nft list ruleset` yazdığında karşına `policy accept` çıkıyorsa, bil ki o sunucu rüzgara açık bir tarladır.
- Önce `policy drop` çekeceksin.
- Sonra `lo` ve `conntrack` kurallarını yerleştireceksin.
- Ardından sadece ve sadece hizmet vermen gereken portları, mümkünse kaynak IP kısıtlamasıyla açacaksın.
- Ve son olarak engellenen paketleri loglayacaksın ki kapını kimlerin zorladığını bilesin.

Bugün geliştirdiğimiz motor ve araçlar, hem nftables hem de UFW dünyasında bu kuralları otomatik denetleyip sana raporlayacak güçtedir.
