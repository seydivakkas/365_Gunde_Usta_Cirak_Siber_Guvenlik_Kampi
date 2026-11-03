# G062: VLAN, Ağ Segmentasyonu ve DMZ Mimarisi — Usta Dersi

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya ticari olarak kullanılamaz.
```

---

## 1. Giriş: Düz Ağ (Flat Network) Felaketi ve Segmentasyonun Doğuşu

Evlat, düne kadar tekil cihazların nasıl vekil sunucular, NAT ve durum takipli güvenlik duvarları arkasında korunduğunu inceledik. Ancak bir kurumun yerel ağının (LAN) fiziksel ve mantıksal mimarisi doğru kurgulanmazsa, en pahalı güvenlik duvarı bile işe yaramaz hale gelir.

Geçmişte kurumsal ağlar **"Düz Ağ" (Flat Network)** modeliyle kurulurdu. Yani muhasebe memurunun bilgisayarı, insan kaynakları laptopu, kamuya açık web sunucusu ve müşteri veritabanı aynı fiziksel anahtarlara (switch) takılıydı ve aynı IP alt ağını (`192.168.1.0/24`) paylaşırdı.
Bu düz ağ tasarımının doğurduğu iki ölümcül siber güvenlik felaketi şudur:
1. **Devasa Yayın Etki Alanı (Broadcast Domain):** Bir cihaz ağda bir ARP veya DHCP broadcast paketi (`FF:FF:FF:FF:FF:FF`) yayınladığında, bu paket o anahtardaki istisnasız TÜM cihazların ağ kartlarına çarpar. Bir cihazda başlayan broadcast fırtınası (broadcast storm) veya döngü (loop), yüzlerce bilgisayarı aynı anda kilitler.
2. **Sıfır İzolasyon ve Kolay Yanal Yayılım (Lateral Movement):** Dışarıdan internete açık web sunucusuna sızan bir saldırgan, hiçbir güvenlik duvarı engeline takılmadan aynı L2 yayın alanındaki diğer tüm iş istasyonlarına ve hassas veritabanlarına ARP zehirlemesi (ARP Poisoning), dinleme (sniffing) ve SMB/RDP saldırılarıyla doğrudan sıçrayabilir.

İşte **VLAN (Virtual Local Area Network - Sanal Yerel Alan Ağı)** ve **Ağ Segmentasyonu**, tek bir fiziksel anahtarlama altyapısını mantıksal olarak birbirinden tamamen yalıtılmış sanal yayın etki alanlarına bölmek için icat edilmiştir.

---

## 2. IEEE 802.1Q Standartı ve İkili Etiketleme (VLAN Tagging)

Farklı departmanlar için ayrı ayrı fiziksel anahtarlar satın alıp kablo çekmek devasa bir maliyet ve karmaşadır. Bunun yerine tek bir yönetilebilir anahtar (Managed Switch) üzerinde VLAN'lar tanımlanır.

### 2.1. IEEE 802.1Q Çerçeve Mimarisi
Normal bir Ethernet II çerçevesi etiketsizdir (untagged). Bir çerçeve anahtarlar arasındaki ortak omurga hattından (**Trunk Link**) geçerken, hangi VLAN'a ait olduğunu belirtmek için çerçevenin Kaynak MAC ile EtherType alanlarının arasına **4 baytlık IEEE 802.1Q etiketi** eklenir.

```
+-------------------------------------------------------------------------+
| IEEE 802.1Q 4 Baytlık VLAN Etiketi (VLAN Tag) Yapısı                   |
+-------------------------------------------------------------------------+
| TPID (Tag Protocol Identifier): 16-bit (Her zaman 0x8100)               |
+-------------------------------------------------------------------------+
| TCI (Tag Control Information): 16-bit                                   |
|   - PCP (Priority Code Point): 3-bit (0-7 arası Hizmet Kalitesi / QoS)  |
|   - DEI (Drop Eligible Indicator): 1-bit (Yoğunlukta düşürülebilirlik)  |
|   - VID (VLAN Identifier): 12-bit (1 ile 4094 arası VLAN Kimliği)       |
+-------------------------------------------------------------------------+
```

### 2.2. 12-Bit VLAN ID (VID) Sınırları:
- **12-bitlik alan:** $2^{12} = 4096$ olası değer sunar.
- **VLAN 0:** Öncelikli etiketleme (Priority tagging) için ayrılmıştır; VID taşımaz.
- **VLAN 1:** Varsayılan fabrika çıkış VLAN'ıdır (Default VLAN).
- **VLAN 1 - 4094:** Standart ve genişletilmiş kullanılabilir VLAN kimlikleridir.
- **VLAN 4095:** İlerideki standart geliştirmeleri için rezerve edilmiştir.

---

## 3. Anahtar Port Tipleri: Access Port vs Trunk Port

Bir yönetilebilir anahtardaki portlar temel olarak iki farklı modda çalışır:

### 3.1. Erişim Portu (Access Port)
- **Kime Bağlanır:** Son kullanıcı bilgisayarlarına, yazıcılara, IP kameralara veya tekil sunuculara.
- **Çalışma Prensibi:** Yalnızca **tek bir VLAN'a** aittir (`switchport access vlan 10`).
- **Etiket Davranışı:** Cihazdan anahtara gelen paket etiketsizdir; anahtar paketi içeri alırken o porta atanan VLAN damgasını vurur. Paketi porta geri gönderirken ise 802.1Q etiketini **soyup (strip)** temiz bir Ethernet paketi olarak teslim eder. Son kullanıcı cihazları etiketlerden habersizdir.

### 3.2. Omurga Portu (Trunk Port)
- **Kime Bağlanır:** Anahtarlar arasına (Switch-to-Switch) veya anahtar ile yönlendirici/güvenlik duvarı arasına (Switch-to-Router).
- **Çalışma Prensibi:** Tek bir fiziksel kablo üzerinden **onlarca farklı VLAN'ın paketlerini** taşır (`switchport mode trunk`).
- **İzinli VLAN Listesi (Allowed VLANs):** Güvenlik gereği trunk port üzerinde yalnızca tanımlı VLAN'ların geçişine izin verilmelidir (`switchport trunk allowed vlan 10,20,30`).
- **Yerel VLAN (Native VLAN):** Trunk porta gelen etiketsiz paketlerin atandığı varsayılan VLAN'dır (Varsayılan olarak VLAN 1'dir; ancak bu durum güvenlik açığı doğurur!).

---

## 4. DMZ (Demilitarized Zone / Arındırılmış Bölge) Mimarisi

Ağ güvenliğinin en kritik kalesi **DMZ (Çevre Ağ)** tasarımıdır. DMZ, kamusal internet ile kurumun en gizli iç ağı arasında tampon görevi gören izole bir ağ segmentidir.

```
                   [ KAMUSAL İNTERNET ]
                            |
                   [ Dış Güvenlik Duvarı ]
                            |
           +----------------+----------------+
           |                                 |
           v                                 v
   [ DMZ (VLAN 20) ]             [ İÇ AĞ GÜVENLİK DUVARI ]
   - Web Sunucusu (Port 443)                 |
   - E-Posta / DNS Sunucu          +---------+---------+
   - Reverse Proxy                 |                   |
                                   v                   v
                          [ KULLANICI AĞI ]    [ VERİTABANI AĞI ]
                             (VLAN 10)            (VLAN 30)
```

### DMZ Güvenlik Kurallarının Temel İlkeleri (Altın Prensipler):
1. **İnternetten Yalnızca DMZ'ye:** İnternetten gelen hiçbir trafik doğrudan iç ağa (VLAN 10) veya veritabanına (VLAN 30) ulaşamaz! Yalnızca DMZ'deki ilgili servis portuna (ör. port 443) izin verilir.
2. **DMZ'den İç Ağa Sıfır İzin (Default Deny):** DMZ'deki sunucu hacklense dahi, iç kullanıcı ağına doğru **hiçbir yeni bağlantı başlatamaz!**
3. **DMZ'den Veritabanına Minimum Yetki (Least Privilege):** DMZ'deki web sunucusu, veritabanına yalnızca tek bir port üzerinden (ör. PostgreSQL 5432) ve yalnızca durum takipli olarak erişebilir. SSH (port 22) veya RDP gibi yönetim portları DMZ'den iç ağa kesinlikle yasaktır.

---

## 5. VLAN Saldırı Vektörleri ve Güvenlik Sertleştirmesi

Bir saldırgan L2 katmanında VLAN sınırlarını aşmak ve diğer segmentlere sızmak için iki ana **VLAN Hopping (VLAN Atlama)** tekniği kullanır:

### 5.1. Anahtar Sahteciliği (Switch Spoofing / DTP İstismarı)
Cisco gibi üreticilerin anahtarlarında varsayılan olarak **DTP (Dynamic Trunking Protocol)** açıktır. Portlar fabrikasyon olarak `Dynamic Desirable` veya `Dynamic Auto` modundadır.
- **Saldırı:** Saldırgan, bilgisayarından anahtara DTP müzakere paketleri göndererek "Ben de bir anahtarım, gel trunk kuralım" der.
- **Sonuç:** Anahtar portu bir anda Trunk moduna geçirir. Saldırgan artık ağdaki TÜM VLAN'ların paketlerini dinleyebilir ve paket enjekte edebilir!
- **Savunma:** Tüm kullanıcı portlarında DTP kesin olarak kapatılmalı ve port statik access yapılmalıdır:
  ```text
  Switch(config-if)# switchport mode access
  Switch(config-if)# switchport nonegotiate
  ```

### 5.2. Çift Etiketleme Saldırısı (Double Tagging / QinQ Exploit)
Bu saldırı, anahtarın Native VLAN davranışındaki bir mantık hatasını sömürür:
- **Saldırı Adımları:**
  1. Saldırgan, portunun ait olduğu Native VLAN (ör. VLAN 1) etiketini dışa, hedef veritabanı VLAN'ını (ör. VLAN 30) içe koyarak **çift etiketli** bir Ethernet paketi üretir.
  2. İlk anahtar paketi alır; dış etiketin kendi Native VLAN'ı ile aynı olduğunu görür. Trunk porta basarken kural gereği Native VLAN etiketini **soyar** ve paketi etiketsiz sanarak yollar.
  3. Ancak paketin içinde hala ikinci etiket (VLAN 30) durmaktadır!
  4. İkinci anahtar paketi aldığında, paketin en başında VLAN 30 etiketini görür ve paketi doğrudan hedef veritabanı segmentine teslim eder!
  5. Saldırgan yönlendiriciyi ve L3 güvenlik duvarını tamamen atlamıştır!
- **Savunma:**
  1. Native VLAN olarak asla kullanıcıların bulunduğu VLAN 1 kullanılmamalıdır! Tamamen ayrık ve kullanılmayan kukla bir VLAN (ör. VLAN 99) Native VLAN yapılmalıdır.
  2. Trunk portlarda Native VLAN paketlerinin de etiketlenmesi zorunlu kılınmalıdır:
     ```text
     Switch(config)# vlan dot1q tag native
     ```

---

## 6. Usta-Çırak Öğütleri ve Sektörel Pratik

1. **Ağ Tasarımında:** Asla düz ağ kurmayacaksın. En küçük ofiste bile Misafir Ağı (Guest), Personel Ağı (User) ve Yönetim Ağı (Management) en az 3 ayrı VLAN olarak ayrılmalıdır.
2. **Kullanılmayan Portlarda:** Anahtarda boşta duran tüm portları `shutdown` edecek ve kullanılmayan bir karantina VLAN'ına (ör. VLAN 999) atacaksın.
3. **DMZ İncelemesinde:** "Web sunucusu veritabanına bağlanıyor, o halde DMZ ile DB arasında tam erişim açalım" diyen tembel sistem yöneticisine asla izin vermeyeceksin; yalnızca tekil IP ve tekil port (ör. 5432) kuralı yazacaksın.
4. **Zero Trust Mikrosegmentasyonda:** VLAN'lar L2 sınırıdır; güvenlik duvarı kuralları olmadan VLAN tek başına güvenlik sağlamaz. Inter-VLAN yönlendirme mutlaka bir Güvenlik Duvarı (Firewall) üzerinden geçirilmelidir.

---
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
ÖZEL LİSANS — Bu ders notu yalnızca görüntüleme ve eğitim amacıyla hazırlanmıştır.
