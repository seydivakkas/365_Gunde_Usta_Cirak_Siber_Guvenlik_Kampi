# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

# Gün 055: DHCP ve Dinamik IP Ataması — Protokol Mimarisi, DORA Süreci ve Katman-2 Güvenliği

## Usta-Çırak Başlangıç Hasbihali
Evladım, yerel ağda bir cihaz ethernet kablosunu taktığı veya Wi-Fi ağına bağlandığı anda dünyayla nasıl konuşacağını nereden bilir? Cihazın elinde henüz ne bir IP adresi, ne alt ağ maskesi, ne varsayılan ağ geçidi, ne de DNS sunucusu vardır. İşte bu körlük anında devreye giren mekanizma **DHCP (Dynamic Host Configuration Protocol)** protokolüdür.

Fakat güvenlik gözlüğüyle baktığında DHCP, yerel ağın en zayıf karnıdır! Neden mi? Çünkü doğası gereği istemci kim olduğunu ve kime güveneceğini bilmediği için ağa avazı çıktığı kadar bağırır: **Broadcast (Yayın)** yapar. Eğer ağında bir saldırgan pusuya yatmışsa, meşru DHCP sunucusundan daha önce cevap vererek kurbana kendi IP'sini varsayılan ağ geçidi (Gateway) veya DNS olarak yutturur. Tüm internet trafiği saldırganın cihazından akmaya başlar (Ortadaki Adam / MitM). Bugün seninle DHCP'nin ikili (binary) başlık yapısını, 4 adımlı DORA yaşam döngüsünü, kira zamanlayıcılarını ve Katman-2 anahtarlarda uygulanan **DHCP Snooping** zırhını en ince ayrıntısına kadar inşa edeceğiz.

---

## 1. DHCP Protokolünün Kökleri ve İkili (Binary) Paket Mimarisi

DHCP, tarihi BOOTP (Bootstrap Protocol - RFC 951) protokolü üzerine inşa edilmiş ve RFC 2131 / RFC 2132 ile modernize edilmiştir. İstemci UDP 68, sunucu ise UDP 67 portunu dinler.

### 236 Baytlık Sabit BOOTP Başlığı
DHCP paketinin ilk 236 baytı sabit bir yapıya sahiptir:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
+---------------+---------------+---------------+---------------+
|                            xid (4)                            |
+-------------------------------+-------------------------------+
|           secs (2)            |           flags (2)           |
+-------------------------------+-------------------------------+
|                          ciaddr (4)                           |
+---------------------------------------------------------------+
|                          yiaddr (4)                           |
+---------------------------------------------------------------+
|                          siaddr (4)                           |
+---------------------------------------------------------------+
|                          giaddr (4)                           |
+---------------------------------------------------------------+
|                          chaddr (16)                          |
+---------------------------------------------------------------+
|                          sname (64)                           |
+---------------------------------------------------------------+
|                          file (128)                           |
+---------------------------------------------------------------+
|                    Magic Cookie (4) (0x63825363)              |
+---------------------------------------------------------------+
|                       DHCP Options (TLV)                      |
```

1. **op (1B):** Mesaj operasyon kodu. `1 = BOOTREQUEST` (İstemciden Sunucuya), `2 = BOOTREPLY` (Sunucudan İstemciye).
2. **htype (1B) & hlen (1B):** Donanım tipi (`1 = 10Mb/100Mb/1Gb Ethernet`) ve donanım adresi uzunluğu (`6 = MAC boyutu`).
3. **hops (1B):** DHCP Relay Agent (Röle) atlama sayısı. İstemci 0 olarak başlatır.
4. **xid (4B):** Transaction ID (İşlem Kimliği). İstemci tarafından rastgele üretilen ve istekle yanıtı eşleştiren 32-bitlik değer.
5. **secs (2B):** İstemcinin adres arayışına başlamasından bu yana geçen saniye.
6. **flags (2B):** 16-bitlik alan. En soldaki bit (0x8000) `Broadcast Flag`'dir. İstemci henüz IP almadığı için sunucuya yanıtı broadcast olarak dönmesini söyler.
7. **ciaddr (4B):** Client IP. İstemcinin zaten geçerli bir IP'si varsa (RENEW / REBIND) buraya yazar. Başlangıçta `0.0.0.0`'dır.
8. **yiaddr (4B):** Your (Client) IP. Sunucunun istemciye tahsis ettiği IP adresi.
9. **siaddr (4B):** Next Server IP. PXE veya TFTP önyükleme sunucusunun IP adresi.
10. **giaddr (4B):** Relay Agent IP. Farklı bir alt ağdan gelen isteklerde DHCP Relay cihazının IP adresi.
11. **chaddr (16B):** Client Hardware Address. İstemcinin MAC adresi ilk 6 bayta yazılır, geri kalan 10 bayt sıfırlanır (`0x00`).
12. **sname (64B) & file (128B):** İsteğe bağlı sunucu ana makine adı ve önyükleme imajı dosya adı.
13. **Magic Cookie (4B):** `0x63, 0x82, 0x53, 0x63` (noktalı ondalık olarak `99.130.83.99`). DHCP seçeneklerinin başladığını bildiren sihirli çerez.

---

## 2. DORA Döngüsü (Discover, Offer, Request, ACK)

Bir istemcinin ağa dahil olup IP adresini alma süreci 4 temel adımdan oluşur:

```
[ İSTEMCİ ]                                            [ SUNUCU ]
     |                                                      |
     | ----- (1) DHCP DISCOVER (Broadcast) ---------------> |
     |       Src: 0.0.0.0:68  Dst: 255.255.255.255:67       |
     |                                                      |
     | <---- (2) DHCP OFFER (Unicast/Broadcast) ----------- |
     |       Src: 192.168.1.1:67  Dst: 255.255.255.255:68   |
     |       yiaddr: 192.168.1.100                          |
     |                                                      |
     | ----- (3) DHCP REQUEST (Broadcast) ----------------> |
     |       Src: 0.0.0.0:68  Dst: 255.255.255.255:67       |
     |       Option 50: 192.168.1.100, Option 54: 1.1       |
     |                                                      |
     | <---- (4) DHCP ACK (Unicast/Broadcast) ------------- |
     |       Src: 192.168.1.1:67  Dst: 255.255.255.255:68   |
     |       Kira Onayı ve Ağ Parametreleri                 |
```

### Neden DHCP Request Hâlâ Broadcast Gönderilir?
Çırakların en sık düştüğü yanılgı: *"İstemci Offer aldı, sunucunun IP'sini öğrendi, neden Request'i unicast göndermiyor?"*
Çünkü ağda birden fazla DHCP sunucusu olabilir! İstemci birden fazla OFFER alabilir ve bunlardan birini seçer. Seçtiği sunucuyu `Option 54 (Server Identifier)` alanına yazar ve paketi **Broadcast** atar. Bu sayede diğer teklif veren sunucular istemcinin başka bir sunucuyu seçtiğini anlar ve rezerve ettikleri IP'leri derhal havuzlarına iade ederler!

---

## 3. Kira Yaşam Döngüsü ve Zamanlayıcılar (T1 ve T2)

DHCP'de IP adresleri mülkiyet olarak değil, **kira (lease)** olarak verilir. Standart kira süresi $T$ (ör. 86400 saniye = 24 saat) olsun:
1. **T1 Zamanlayıcısı (Renewal Timer - 0.5 * T):**
   Kira süresinin %50'si dolduğunda (12. saatte), istemci doğrudan IP'yi kiralayan sunucuya **Unicast DHCPREQUEST** gönderir. Sunucu yanıt verirse (DHCPACK), kiralama süresi sıfırlanır.
2. **T2 Zamanlayıcısı (Rebinding Timer - 0.875 * T):**
   Kira süresinin %87.5'i dolduğunda (21. saatte), eğer ilk sunucudan yanıt alınamadıysa istemci tüm ağa **Broadcast DHCPREQUEST** yayını yapar. Ağdaki herhangi bir yetkili DHCP sunucusundan kirayı yenilemesini talep eder.
3. **Lease Expiration (T):**
   Kira süresi biterse ve hiçbir sunucudan onay gelmemişse, istemci IP adresini anında bırakır (DROP) ve en başa dönerek sıfırdan **DHCP DISCOVER** sürecini başlatır.

---

## 4. Tehdit Modelleri ve Güvenlik Açıkları

### A. Sahte DHCP Sunucusu (Rogue DHCP Server & MitM)
Saldırgan ağa yetkisiz bir DHCP sunucusu bağlar. İstemci DISCOVER attığında, meşru sunucudan daha hızlı yanıt (OFFER) dönerek kurbana kendi IP'sini varsayılan ağ geçidi (Default Gateway) ve DNS sunucusu olarak atar.
- **Tehlike:** İstemcinin tüm internet ve intranet trafiği saldırganın üzerinden geçer. Şifresiz oturumlar çalınır, DNS zehirlemesiyle bankacılık siteleri sahte sayfalara yönlendirilir.
- **TunnelVision (CVE-2024-3661):** Saldırgan DHCP Option 121 (Classless Static Route) kullanarak `/0` rotası yerine `/1` iki adet daha spesifik rota tanımlar. En uzun önek eşleşmesi (Longest Prefix Match) kuralı nedeniyle VPN tünelleri tamamen baypas edilir ve trafik saldırgana sızar!

### B. DHCP Havuz Tükenme Saldırısı (DHCP Starvation)
Saldırgan, scapy veya benzeri araçlarla saniyede yüzlerce sahte rastgele MAC adresi üreterek ağa DHCP DISCOVER seli (flood) basar.
- **Tehlike:** Yetkili DHCP sunucusu tüm IP havuzunu (ör. 250 IP) bu sahte istemcilere tahsis eder ve havuz tükenir (Denial of Service). Ağdaki meşru cihazlar IP alamaz hale gelir. Ardından saldırgan kendi Rogue DHCP sunucusunu devreye sokar!

---

## 5. Katman-2 Savunma Mimarisi: DHCP Snooping

Katman-2 anahtarlar üzerinde çalışan **DHCP Snooping**, DHCP trafiğini donanım seviyesinde denetleyen en etkili kalkandır:

1. **Trusted (Güvenilir) Portlar:**
   Yalnızca yetkili DHCP sunucusunun veya kurumsal uplink kablosunun bağlı olduğu portlar "trusted" yapılır. Sunucu yanıtları (OFFER, ACK, NAK) yalnızca bu portlardan geçebilir.
2. **Untrusted (Güvenilmeyen) Portlar:**
   Kullanıcıların, çalışma istasyonlarının ve erişim noktalarının bağlı olduğu tüm portlar "untrusted" olarak işaretlenir.
   - **Kural:** Eğer untrusted bir porttan DHCP OFFER, ACK veya NAK paketi gelirse, anahtar paketi **anında donanımda düşürür (DROP)** ve güvenlik uyarısı (SNMP trap) üretir!
3. **DHCP Snooping Binding Table:**
   Anahtar, güvenilir porttan geçen meşru ACK paketlerini dinleyerek bir veritabanı oluşturur:
   `MAC Adresi <---> IP Adresi <---> VLAN <---> Fiziksel Port <---> Kiralama Süresi`
   Bu tablo daha sonra **Dynamic ARP Inspection (DAI)** ve **IP Source Guard (IPSG)** teknolojilerinin çekirdeğini oluşturarak ağdaki ARP Poisoning ve IP Spoofing saldırılarını sıfıra indirir!

---

## Ustanın Öğüdü
Evladım; ağ güvenliği çevre güvenlik duvarında (firewall) değil, kullanıcının kabloyu taktığı anahtar portunda (switchport) başlar. DHCP Snooping kurmadığın bir yerel ağda, 100 bin dolarlık firewall koysan dahi içerideki bir stajyerin laptopundan başlatılacak basit bir Rogue DHCP saldırısıyla tüm kurumsal ağın kontrolünü kaybedersin!
