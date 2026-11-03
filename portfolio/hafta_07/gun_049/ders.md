# Gün 049: Mini Proje 6 — Ağ Adresleme Çalışma Kitabı ve Güvenlik Denetimi

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## 1. Ustanın Girişi: 7. Haftanın Zirvesi ve Büyük Resim

Evlat, dinle beni. Bu hafta seninle ağ dünyasının en temel, en hayati yapıtaşlarını döşedik. 
- 43. Günde OSI ve TCP/IP katmanlarının soyut basamaklarını araladık.
- 44. Günde Ethernet çerçevelerini, MAC adreslerini ve Katman-2 anahtarlama mantığını inceledik.
- 45. Günde IPv4 adreslemesini, ikili (binary) matematiği ve CIDR/VLSM alt ağ bölme sanatını kavradık.
- 46. Günde yeni nesil IPv6 dünyasına adım atıp 128-bitlik devasa adres uzayını ve EUI-64 mekanizmasını gördük.
- 47. Günde Katman-3 ile Katman-2 arasındaki köprüyü kuran ARP protokolünü ve ARP önbellek zehirleme saldırılarını inceledik.
- 48. Günde ise ağın sinir sistemi olan ICMP protokolünü, Echo döngülerini, PMTUD dinamiklerini ve ICMP tünelleme tehditlerini inceledik.

Bugün, 7. Haftanın taçlandığı gündür: **Mini Proje 6 — Ağ Adresleme Çalışma Kitabı**. 

Sahaya çıktığında bir güvenlik mühendisi veya SOC analisti olarak karşına binlerce cihazdan oluşan karmaşık bir ağ topolojisi gelecek. Eğer bir alt ağın CIDR sınırını, varsayılan ağ geçidini, DNS adreslerini, MAC-IP eşleşmelerini ve olası çakışmaları tek bir bütünsel "çalışma kitabı" (workbook) içinde haritalandıramazsan; ne bir sızma testini doğru yönetebilirsin ne de bir siber saldırı anında anomalileri ayırt edebilirsin.

Bugün geliştirdiğimiz araç; yalnızca teorik bir hesap makinesi değil, kurumsal ağ topolojilerini denetleyen, çakışan alt ağları (overlapping subnets), yetkisiz ağ geçitlerini, kural dışı IP atamalarını ve IPv6 gizlilik sızıntılarını yakalayan bir güvenlik denetim motorudur.

---

## 2. Ağ Teşhisi ve Çalışma Kitabı Mantığı: Neden Hepsi Aynı Tabloda?

Bir ağda bir problem çıktığında—örneğin bir finans sunucusuna erişilemediğinde—çıraklar hemen panikle rastgele komutlar çalıştırır. Usta ise sakin bir şekilde ağ haritasını açar. 

Bir cihazın ağda sağlıklı ve güvenli çalışabilmesi için Katman-2 ve Katman-3 parametrelerinin birbiriyle kusursuz bir ahenk içinde olması şarttır:
1. **IP Adresi ve Alt Ağ Maskesi (CIDR):** Cihazın kendi yerel ağ sınırını belirler. Cihaz bir paketi yerel ağdaki bir komşusuna mı göndereceğini, yoksa dış dünyaya mı yönlendireceğini bu maske sayesinde anlar (Bit düzeyinde AND işlemi).
2. **Varsayılan Ağ Geçidi (Default Gateway):** Yerel alt ağın dışındaki hedeflere (örneğin İnternet'e veya diğer VLAN'lara) gidecek tüm paketlerin teslim edileceği yönlendirici bacağının IP'sidir. **Kritik kural:** Ağ geçidi IP'si kesinlikle ve kesinlikle cihazın kendi alt ağ sınırları içinde olmalıdır! Eğer cihaz `10.10.10.99/24` ağındaysa ve ağ geçidi `192.168.1.1` yazılmışsa, cihaz bu ağ geçidine Katman-2 seviyesinde ARP ile erişemez ve tüm dış dünya iletişimi kilitlenir.
3. **DNS Sunucuları (Birincil ve İkincil):** Alan adlarını IP adreslerine çeviren mekanizma. Kurumsal ağlarda DNS'in rastgele dış sunucular (örneğin 8.8.8.8) yerine kurumsal Domain Controller / Resolver sunucularına yönlendirilmesi, DNS tünelleme ve veri sızıntılarını önlemek için zorunludur.
4. **Fiziksel MAC Adresi ve VLAN ID:** Cihazın hangi anahtar (switch) portunda ve hangi mantıksal izolasyon bölgesinde (VLAN) yer aldığını belgeler.

İşte bu dört unsuru aynı tabloda tutmazsan; bir rota hatasını DNS arızası sanır, bir IP çakışmasını kablo kopması zanneder, günlerce debelenirsin!

---

## 3. Alt Ağ Matematiği: VLSM ve Supernetting (/23) Sırrı

Çalışma kitabımızın kalbinde `IPv4SubnetCalculator` sınıfı yer alır. Bu sınıf, herhangi bir IPv4/önek bilgisini alır ve bit düzeyinde şu değerleri hesaplar:

### Ağ ve Yayın Adresi Hesabı
Herhangi bir IP adresi ile alt ağ maskesi ikili (binary) düzeyde `AND` işlemine tabi tutulduğunda **Ağ Kimlik Adresi (Network Address)** elde edilir:
$$\text{Network ID} = \text{IP} \ \& \ \text{Subnet Mask}$$

Alt ağ maskesinin tersi (bit NOT işlemi) **Joker Maske (Wildcard Mask)** olarak adlandırılır. Ağ kimliği ile wildcard maskesi bit düzeyinde `OR` işlemine tabi tutulduğunda ise o alt ağın **Yayın Adresi (Broadcast Address)** bulunur:
$$\text{Broadcast Address} = \text{Network ID} \ | \ \sim\text{Subnet Mask}$$

### 2 Adres Düşme Kuralı (-2)
Geleneksel alt ağlarda toplam adres sayısı $2^{(32 - \text{prefix})}$ formülüyle bulunur. Ancak konaklara atanabilecek **Kullanılabilir IP Sayısı** her zaman 2 eksiktir:
$$\text{Kullanılabilir Host} = 2^{(32 - \text{prefix})} - 2$$
Çünkü ilk adres ağın kendisini temsil eder, son adres ise tüm düğümlere aynı anda haykırmak (broadcast) için ayrılmıştır.

### İstisnalar: /31 ve /32
Ustanın sana özel notu: RFC 3021 standardı, yönlendiriciler arasındaki noktadan noktaya (Point-to-Point) seri/fiber bağlantılarda IPv4 adres israfını önlemek için `/31` alt ağlara izin verir. `/31` maskesinde yalnızca 2 IP vardır ve -2 kuralı işletilmez; her iki IP de yönlendirici bacaklarına verilebilir. `/32` ise tek bir ana bilgisayarı veya döngü (loopback) arayüzünü temsil eder.

### Supernetting (/23 Mantığı)
Çalışma kitabımızdaki `NET-03` ağını incele: `192.168.30.0/23`.
Burada 23 bit ağa, 9 bit hostlara ayrılmıştır ($32 - 23 = 9$).
- Toplam IP: $2^9 = 512$
- Kullanılabilir Host: $512 - 2 = 510$
- Alt Ağ Maskesi: `255.255.254.0`
- Ağ Aralığı: `192.168.30.0` ile `192.168.31.255` arası!
Gördün mü evlat? Üçüncü oktet hem `30` hem de `31` değerini kapsar. İşte bu yüzden `192.168.31.200` adresi bu ağ için tamamen geçerli bir yerel konak adresidir!

---

## 4. Katman-2 & Katman-3 Güvenlik Denetimleri: Neleri Yakalıyoruz?

Geliştirdiğimiz denetim motoru (`run_audits()`), sahada sistem yöneticilerinin ve saldırganların sebep olduğu 5 kritik güvenlik ve mimari ihlalini otomatik olarak tespit eder:

### 1. Çakışan Alt Ağlar (Overlapping Subnets)
İki farklı VLAN veya arayüze birbiriyle kesişen IP blokları atandığında meydana gelir. Örneğin `NET-03 (192.168.30.0/23)` tanımlıyken, bir yöneticinin gidip `NET-OVERLAP-01 (192.168.31.0/24)` tanımlaması. 
- **Risk:** Yönlendiriciler "Longest Prefix Match" (En Uzun Önek Eşleşmesi) kuralına göre `/24` ağına öncelik verir. Paketler yanlış VLAN'a akar, asimetrik yönlendirme ve paket kara delikleri (packet blackhole) oluşur.

### 2. Alt Ağ Dışında Ağ Geçidi (Gateway Out of Subnet)
Bir cihaza kendi alt ağ bloğunun dışında bir varsayılan ağ geçidi verilmesi (Örn. `10.10.10.99` cihazına `192.168.1.1` verilmesi).
- **Risk:** Cihaz Katman-3'te dışarı çıkmak istediğinde ağ geçidinin MAC adresini öğrenmek için ARP yayını yapar. Ancak ağ geçidi fiziksel olarak o VLAN/yayın etki alanında (broadcast domain) olmadığı için ARP yanıtı asla gelmez; cihaz izole kalır.

### 3. Kullanılamaz IP Atamaları (Network ID / Broadcast)
Bir sunucuya veya cihaza `172.16.20.0` (Network ID) veya `172.16.20.255` (Broadcast) IP'sinin statik atanması.
- **Risk:** İşletim sistemlerinin TCP/IP yığınlarında kilitlenmelere, yönlendirici döngülerine ve broadcast fırtınalarına neden olur.

### 4. IP ve MAC Çakışmaları (Duplicate Conflict & Spoofing)
Aynı IP'nin iki farklı cihazda bulunması (`IP_CAKISMASI`) veya tek bir MAC'in farklı cihazlarda görünmesi.
- **Risk:** Yerel ağda anahtarların MAC tablosunda çırpınmaya (MAC flap) ve ARP önbelleklerinin sürekli ezilerek bağlantı kopmalarına (DoS veya MitM) yol açar.

### 5. IPv6 EUI-64 MAC Gizlilik Sızıntısı
IPv6 Stateless Address Autoconfiguration (SLAAC) kullanılırken 64-bitlik arayüz kimliğinin doğrudan cihazın 48-bitlik fiziksel MAC adresinden türetilmesi.
- **Risk:** Cihaz dünyanın neresine giderse gitsin, IPv6 adresinin son 64 biti fiziksel donanımını ve üreticisini ifşa eder. Siber saldırganlar ve reklam takipçileri cihazı küresel düzeyde izleyebilir. Çözüm: **RFC 4941 Privacy Extensions** (Geçici rastgele adresleme).

---

## 5. Savunma ve Mimari Sıkılaştırma Kuralları

Bir kaleyi savunmak istiyorsan kapıyı kilitlemek yetmez; iç odaları da kalın duvarlarla ayırmalısın:

1. **Sıkı Ağ Segmentasyonu ve VLAN Ayrımı:** Yönetim (Management), Sunucu (DMZ), İstemci (User) ve Misafir (Guest) ağları kesinlikle aynı Katman-2 yayın etki alanında tutulamaz. Her biri ayrı bir VLAN kimliğine sahip olmalıdır.
2. **Yönlendirici ACL ve Güvenlik Duvarı Politikaları:** VLAN'lar arası geçişler (Inter-VLAN routing) yalnızca yetkili port ve protokollerle sınırlandırılmalıdır. Misafir VLAN'ın iç ağlara erişimi tamamen engellenmelidir.
3. **Switch Seviyesinde Doğrulama:**
   - **DHCP Snooping:** Yalnızca yetkili DHCP sunucusundan IP dağıtılmasına izin verir ve güvenilir IP-MAC-Port bağlama tablosu tutar.
   - **Dynamic ARP Inspection (DAI):** Bu tabloya uymayan tüm sahte ARP anonslarını donanım hızında çöpe atar.
4. **Statik ve Rezerve IP Disiplini:** Sunucu ve ağ geçidi gibi kritik altyapı bileşenleri IPAM (IP Address Management) sistemlerinde kayıt altına alınmalı; ağ kimlik ve yayın adresleri güvenlik kurallarıyla izole edilmelidir.

---

## 6. Ustanın Öğüdü

Evlat, ağ adresleme tablosu bir siber güvenlik uzmanının haritasıdır. Haritayı okuyamayan komutan savaşı yönetemez; topolojiyi bilmeyen analist olayı çözemez. 

Bugün yazdığın bu çalışma kitabı ve denetim aracı, sana sadece bir ders ödevi değil, ömür boyu kullanacağın bir ağ analiz felsefesi kazandırdı. Bu titizliği, satır satır yazdığın didaktik açıklamaları ve negatif kontrolleri hiçbir zaman elden bırakma!
