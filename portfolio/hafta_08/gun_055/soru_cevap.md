# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

# Gün 055: DHCP ve IP Ataması — Soru, Cevap ve Senaryo Analizleri

Bu dokümanda, kurumsal ağlarda karşılaşılan DHCP zafiyetleri, Sahte Sunucu (Rogue DHCP) saldırıları, Starvation tükenme senaryoları ve Katman-2 savunma mimarisi derinlemesine incelenmektedir.

---

## Senaryo G055-SC1: Sahte (Rogue) DHCP Sunucusu ve TunnelVision (Option 121) ile Trafik Kaçırma

### Soru / Senaryo
Kurumsal bir şirkette Ar-Ge departmanında çalışan bir mühendis, test amacıyla masasının altına küçük bir tüketici sınıfı Wi-Fi yönlendirici bağlamış ve yönlendiricinin LAN portunu kurumsal anahtar prizine takmıştır. Cihazın varsayılan DHCP servisi devrededir. Kısa bir süre sonra, aynı kattaki birçok çalışanın şirket içi intranet sistemlerine erişemediği, internet çıkışlarının yavaşladığı ve bazı kullanıcıların sahte SSL sertifikası uyarıları aldığı bildirilmiştir. Dahası, VPN kullanan uzaktan erişim kullanıcılarının bile trafiğinin VPN tüneli dışına sızdığı (TunnelVision / Option 121) tespit edilmiştir. Bu saldırı mekanizması nasıl çalışır ve kurumsal ağda nasıl engellenir?

### Ustanın Cevabı / Çözüm Yaklaşımı
Evladım, burada gerçekleşen olay klasik bir **Rogue (Sahte/Yetkisiz) DHCP Sunucusu** vakasıdır. Cihaz masum bir niyetle takılmış olsa bile, ağ güvenliği açısından tam teşekküllü bir Ortadaki Adam (MitM) saldırısı oluşturmuştur.

Olayın adımları şöyledir:
1. **Yarış Durumu (Race Condition):** Kullanıcı cihazları ağa bağlandığında DHCP DISCOVER broadcast yayınlar. Tüketici tipi küçük router hemen aynı broadcast alanında olduğu için kurumsal ana çekirdek DHCP sunucusundan mikrosaniyeler daha hızlı bir DHCP OFFER döner.
2. **Kötücül Parametre Enjeksiyonu:** Bu teklifte `Option 3 (Router)` ve `Option 6 (DNS)` olarak masanın altındaki cihazın kendi IP'si (`192.168.1.199`) verilir. Kurban istemciler bu teklifi kabul edip DHCP REQUEST gönderir ve sahte cihaz ACK basar.
3. **TunnelVision (Option 121) Baypası:** Eğer bu cihaz veya arkasındaki bir saldırgan `Option 121 (Classless Static Route)` parametresini aktif ederse; istemciye `0.0.0.0/1` ve `128.0.0.0/1` olmak üzere iki spesifik rota enjekte eder. Yönlendirme tablolarında en uzun önek eşleşmesi kuralı (Longest Prefix Match) geçerli olduğundan, VPN yazılımının oluşturduğu varsayılan `0.0.0.0/0` rotası ezilir! VPN şifrelemesi açık olmasına rağmen tüm paketler saldırganın ağ geçidine yönelir.

Çözüm:
Ağ anahtarlarında **DHCP Snooping** derhal devreye alınmalıdır. Mühendisin takıldığı kenar erişim portu (access port) varsayılan olarak `untrusted` kabul edilir. Anahtar, bu porttan içeri giren herhangi bir DHCP OFFER veya ACK paketini donanım seviyesinde (ASIC) bloke eder ve portu `err-disable` durumuna çeker.

### Kritik Güvenlik Çıkarımı
DHCP doğası gereği kimlik doğrulaması içermeyen bir güven tabanlı protokoldür. İstemci kendisine ilk gelen teklife güvenme eğilimindedir. Ağ mimarisinde Katman-2 seviyesinde sınır denetimi (DHCP Snooping) uygulanmazsa, içerideki tek bir yetkisiz cihaz tüm segmentin internet ve VPN güvenliğini sıfırlayabilir.

### Savunma / Uygulama Kontrol Listesi
- [ ] Kenar anahtarların tümünde genel olarak `ip dhcp snooping` özelliğini aktif edin.
- [ ] İlgili VLAN'ları snooping kapsamına alın (`ip dhcp snooping vlan 10,20,30`).
- [ ] Yalnızca yetkili DHCP sunucusunun ve kurumsal uplink portlarının bulunduğu arayüzleri `ip dhcp snooping trust` olarak işaretleyin.
- [ ] Kullanıcı erişim portlarını (access ports) istisnasız `untrusted` bırakın.
- [ ] Yetkisiz DHCP yanıtı üreten portların otomatik kapatılması için `errdisable recovery cause dhcp-rate-limit` veya ihlal aksiyonlarını yapılandırın.
- [ ] İstemci işletim sistemlerinde gerekmedikçe `Option 121` rotalarını otomatik kabul eden DHCP istemci ayarlarını devre dışı bırakın veya VPN yazılımlarını TunnelVision yamalarıyla güncelleyin.

---

## Senaryo G055-SC2: DHCP Starvation (Havuz Tükenme) Saldırısı ve Port Security Birlikteliği

### Soru / Senaryo
Bir sızma testi uzmanı (veya kötü niyetli bir saldırgan), toplantı odasındaki açık bir ethernet prizine dizüstü bilgisayarını takmış ve saniyede 150 adet sahte MAC adresi üreterek ağa DHCP DISCOVER seli göndermiştir. 2 dakika içerisinde, kurumsal DHCP sunucusundaki `/24` alt ağının 250 adetlik IP havuzunun tamamı kiralandı olarak işaretlenmiş ve tüketilmiş durumdadır. Yeni gelen hiçbir personel IP adresi alamamakta ve internete bağlanamamaktadır. Saldırgan havuzu tükettikten hemen sonra kendi Rogue DHCP sunucusunu açarak yeni gelen tüm cihazları ele geçirmeyi planlamaktadır. Bu tükenme (Starvation) saldırısı nasıl engellenir?

### Ustanın Cevabı / Çözüm Yaklaşımı
Evladım, bu saldırı **DHCP Starvation (Aç Bırakma / Havuz Tüketme)** olarak adlandırılır. DHCP sunucusu gelen her DISCOVER isteğinde farklı bir `chaddr` (Client Hardware Address) gördüğü için her birine havuzundan bir IP tahsis eder (veya rezervasyon teklifi oluşturur).

Bu saldırının başarılı olmasının iki temel sebebi vardır:
1. Anahtar portunda tek bir fiziksel porttan sınırsız sayıda farklı kaynak MAC adresinin geçmesine izin verilmesi.
2. Anahtar portunda birim zamanda gönderilebilecek DHCP paket sayısına (rate limit) kota konulmaması.

Savunma Yaklaşımı (İki Kademeli Kalkan):
1. **DHCP Rate Limiting (Hız Sınırlaması):**
   Erişim portlarında DHCP Snooping hız sınırı belirlenir (ör. `ip dhcp snooping limit rate 15`). Bir porttan saniyede 15'ten fazla DHCP paketi gelirse, anahtar bu portu bir saldırı kaynağı olarak görür ve portu derhal kapatır (`err-disable`).
2. **Switchport Port Security (MAC Sayısı Sınırlaması):**
   Kullanıcı portlarına `switchport port-security maximum 2` ve `switchport port-security violation shutdown` kuralı konulur. Tek bir fiziksel prizden 3. bir farklı MAC adresi görüldüğü anda anahtar donanımı portu anında kapatır. Saldırgan sahte MAC üretemez hale gelir.
3. **DHCP Snooping Chaddr Doğrulaması:**
   Anahtar, Ethernet çerçevesinin Layer-2 kaynak MAC adresi ile DHCP yükü içindeki Layer-7 `chaddr` alanının uyuşup uyuşmadığını kontrol eder (`ip dhcp snooping verify mac-address`). Saldırgan L2 MAC'i değiştirmeden sadece DHCP içindeki MAC'i sahtelese bile paket doğrudan düşürülür!

### Kritik Güvenlik Çıkarımı
DHCP Starvation, genellikle Rogue DHCP saldırısının hazırlık aşamasıdır. Meşru sunucu devreden çıkarılmadan kurbanların sahte sunucuya gitmesi garanti edilemez. Dolayısıyla DHCP paket oranını (rate) ve MAC adres sayısını sınırlamak, hem Hizmet Engelleme (DoS) hem de Ortadaki Adam (MitM) zincirini başlangıcında kırar.

### Savunma / Uygulama Kontrol Listesi
- [ ] Tüm kenar erişim portlarında `ip dhcp snooping limit rate 10` veya `15` komutunu uygulayın.
- [ ] Ethernet çerçeve MAC'i ile DHCP `chaddr` uyuşmazlığını denetleyen `ip dhcp snooping verify mac-address` kuralını etkinleştirin.
- [ ] Kullanıcı portlarında Port Security aktif ederek maksimum izin verilen MAC sayısını sınırlandırın (ör. `maximum 2`).
- [ ] SIEM sistemine anahtarlardan gelen `DHCP_SNOOPING-5-DHCP_SNOOPING_NON_MATCH` ve port-security ihlal loglarını (Syslog) bağlayarak anlık alarm kurun.
- [ ] DHCP sunucusunda kiralama sürelerini (lease time) dinamik ortamlarda makul sürelerde (ör. 2-8 saat) tutarak terk edilen IP'lerin hızla havuza geri dönmesini sağlayın.

---

## Senaryo G055-SC3: DHCP Snooping Binding Tablosu ile Sıfır Güven (DAI ve IPSG Entegrasyonu)

### Soru / Senaryo
Güvenlik mimarı olarak çalıştığınız bir finans kurumunda, L2 seviyesindeki ARP Zehirleme (ARP Spoofing / Poisoning) ve IP Spoofing (IP Sahteciliği) saldırılarının tamamen önlenmesi istenmektedir. Sistem yöneticileri tek tek binlerce cihazın IP ve MAC adreslerini statik olarak anahtarlara girmelerinin imkansız olduğunu ve ağın dinamik DHCP kullandığını belirtmektedir. Dinamik bir ortamda statik tanımlamalar yapmadan L2 Sıfır Güven (Zero Trust) güvenliği nasıl sağlanır?

### Ustanın Cevabı / Çözüm Yaklaşımı
Evladım, modern Katman-2 ağ güvenliğinde sihirli değnek **DHCP Snooping Binding Tablosu**'dur. Bu tablo sadece DHCP'yi korumakla kalmaz, Katman-2'nin diğer tüm güvenlik protokollerinin omurgasını oluşturur.

Mekanizma şöyle işler:
1. **Binding Tablosunun Otomatik İnşası:**
   İstemci güvenilir DHCP sunucusundan meşru bir IP aldığında, anahtar üzerindeki DHCP Snooping motoru bu paketleri gizlice izler ve hafızasında şu kaydı oluşturur:
   `MAC: 00:0c:29:4f:8e:35 | IP: 192.168.1.100 | Port: Fa0/5 | VLAN: 10 | Kira: 86400s`
   Hiçbir statik tanımlama yapmanıza gerek kalmaz; tablo tamamen dinamik ve canlıdır!
2. **Dynamic ARP Inspection (DAI) Entegrasyonu:**
   Anahtarda `ip arp inspection vlan 10` açıldığında; anahtar geçen her ARP isteğini ve yanıtını inceler. Eğer bir porttan gelen ARP paketindeki IP-MAC ikilisi DHCP Snooping Binding tablosundaki kayıtla uyuşmuyorsa (örneğin kurban istemci ağ geçidinin IP'sini kendi MAC'iyle anons ediyorsa), anahtar paketi anında çöpe atar! ARP Poisoning imkansız hale gelir.
3. **IP Source Guard (IPSG) Entegrasyonu:**
   Anahtarda `ip verify source` açıldığında; anahtar port seviyesinde dinamik bir ACL (Erişim Kontrol Listesi) uygular. Porttan çıkan IP paketinin kaynak IP ve MAC adresi DHCP Binding tablosuyla tam eşleşmiyorsa paket düşürülür. İstemci başka bir cihazın IP adresini çalarak (IP Spoofing) ağda tek bir paket bile gönderemez.

### Kritik Güvenlik Çıkarımı
Katman-2 güvenliği parçalı değil, zincirleme bir bütündür. DHCP Snooping olmadan DAI ve IPSG dinamik olarak çalışamaz. DHCP Snooping tablosu, ağa bağlanan cihazın kimliğini (MAC), konumunu (Port/VLAN) ve yetkisini (tahsis edilen IP) birbirine mühürleyen bir kriptografik olmayan kimlik doğrulama çıpasıdır.

### Savunma / Uygulama Kontrol Listesi
- [ ] DHCP Snooping'i açtıktan sonra `ip dhcp snooping database flash:dhcp_snoop.db` komutuyla anahtarın yeniden başlamasında tablonun kaybolmaması için kalıcı veritabanı tanımlayın.
- [ ] Tüm kullanıcı VLAN'larında Dynamic ARP Inspection (DAI) etkinleştirin (`ip arp inspection vlan <vlan-id>`).
- [ ] Kenar kullanıcı portlarında IP Source Guard aktif edin (`ip verify source mac-check`).
- [ ] Statik IP kullanan sunucular ve yazıcılar için `arp access-list` tanımlayarak DHCP tablosuna istisna oluşturun.
- [ ] Süresi dolan kiralama kayıtlarının tablodan otomatik düşürüldüğünü ve yetkisiz paketlerin düşüş sayaçlarını (`show ip arp inspection statistics`) periyodik denetleyin.
