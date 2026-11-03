# Gün 046: IPv6 Temel Kavramlar, Adresleme ve Ağ Güvenliği Mimarisi

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## 1. Usta Girişi: Çırağa Zihinsel Model ve Paradigma Değişimi

Bak çırak, çoğu amatör "IPv6 sadece daha uzun bir IP adresidir" sanır. Bu çok tehlikeli bir yanılgıdır. IPv6 bir adres uzatması değil, **baştan sona yeniden tasarlanmış bir ağ paradigmasıdır.**

IPv4'te yıllarca NAT (Network Address Translation) arkasına sığındık. Birçok sistem yöneticisi NAT'ı bir güvenlik kalkanı sandı; oysa NAT sadece bir yama, IP yetersizliğini örtbas eden bir hileydi. IPv6 ile birlikte:
1. **Adres Alanı Devasa Boyuta Ulaştı:** 32 bitten 128 bite çıktık. $2^{128}$ adres, dünyadaki her bir kum tanesine trilyonlarca IP düşmesi demektir.
2. **Yayın (Broadcast) Trafiği Tamamen Öldü:** Artık ağdaki tüm cihazları gürültüye boğan broadcast paketleri yok. Bunun yerine akıllı **Çok Noktaya Yayın (Multicast)** ve **En Yakına Yayın (Anycast)** mimarisi geldi.
3. **ARP Çöpe Atıldı:** Yerel ağda MAC adresi bulmak için yayın fırtınası koparan ARP yerine, ICMPv6 üzerinde koşan **Komşu Keşif Protokolü (Neighbor Discovery Protocol - NDP)** geldi.
4. **SLAAC ile Sıfır Dokunuş (Zero-Touch):** Bir cihaza DHCP sunucusu olmasa dahi, yönlendiriciden aldığı tek bir anonsla (Router Advertisement) kendi IP adresini otomatik üretme yeteneği kazandırıldı.

Fakat madalyonun diğer yüzünde devasa güvenlik tehditleri yatar. Şimdi kulaklarını dört aç, adım adım bu mimariyi sökeceğiz.

---

## 2. 128-Bitlik Adres Yapısı ve RFC 5952 Kanonik Sıkıştırması

IPv6 adresi 128 bitten oluşur ve 16'şar bitlik 8 bloğa (**hextet**) ayrılır. Her hextet 4 basamaklı onaltılık (hexadecimal) sayılarla yazılır ve iki nokta (`:`) ile ayrılır:
$$\text{2001:0db8:85a3:0000:0000:8a2e:0370:7334}$$

İnsanların bu adresleri okuyup yazabilmesi için **RFC 5952** ile katı kanonik sıkıştırma kuralları belirlenmiştir:
1. **Öncü Sıfırların Atılması (Leading Zeros):** Hextet başındaki gereksiz sıfırlar atılır (`0db8` -> `db8`, `0000` -> `0`, `0370` -> `370`).
2. **Çift İki Nokta (::) Kuralı:** Ardışık en uzun sıfır hextetleri tek bir `::` ile değiştirilir.
   - Örnek: `2001:0db8:85a3:0000:0000:8a2e:0370:7334` -> `2001:db8:85a3::8a2e:370:7334`
3. **Tek Sıfırın Kısaltılamaması:** Eğer sadece bir hextet sıfırsa (`2001:db8:0:1:1:1:1:1`), bu `::` ile kısaltılamaz; aynen `:0:` olarak bırakılır.
4. **Eşitlik Bozucusu (Tie-Breaker):** Eşit uzunlukta birden fazla sıfır dizisi varsa, kural gereği **ilk görülen** dizi `::` ile kısaltılır.
5. **Karakter Formatı:** Harfler kesinlikle küçük harf (`a-f`) olmalıdır.

---

## 3. Adres Sınıfları ve Etki Alanları (Scopes)

IPv6'da adresler rastgele dağıtılmaz; her bloğun katı bir amacı vardır:

| Blok / CIDR | Standart | Tür ve Anlamı | Kapsam (Scope) | Güvenlik / Yönlendirme Notu |
|---|---|---|---|---|
| `2000::/3` | RFC 4291 | Global Unicast (GUA) | Global | Genel internette yönlendirilebilir genel IP. |
| `fe80::/10` | RFC 4291 | Link-Local Unicast | Bağlantı Yerel | Yönlendirilemez; sadece aynı Layer-2 anahtarında geçerlidir. |
| `fc00::/7` | RFC 4193 | Unique Local (ULA) | Yerel Kurumsal | IPv4'teki RFC 1918 karşılığı; şirket içi yönlendirilebilir. |
| `ff00::/8` | RFC 4291 | Multicast (Çok Noktaya) | Değişken | Belirli gruplara (Örn: `ff02::1` tüm düğümler) yayın. |
| `::1/128` | RFC 4291 | Loopback | Düğüm Yerel | IPv4 `127.0.0.1` karşılığı geri döngü adresi. |
| `::/128` | RFC 4291 | Unspecified | Tanımsız | Başlangıçta henüz IP almamış cihazın adresi (`0.0.0.0`). |
| `::ffff:0:0/96` | RFC 4291 | IPv4-Mapped IPv6 | Çift Yığın (Dual) | IPv4 adresini IPv6 soketinde taşıma geçiş mekanizması. |

---

## 4. EUI-64 Dönüşümü ve Cihaz Takibi (Privacy) Riski

Geleneksel IPv6'da arayüz kimliği (Interface ID - IID), ağ kartının 48-bitlik MAC adresinden **EUI-64** algoritmasıyla türetiliyordu:
1. 48 bitlik MAC adresinin tam ortasına `FF:FE` baytları yerleştirilir (64 bite çıkar).
2. İlk baytın 7. biti (Universal/Local - U/L biti) ters çevrilir (`XOR 0x02`).
   - Örnek: `00:1A:2B:3C:4D:5E` MAC adresi, `021a:2bff:fe3c:4d5e` IID'sine ve `fe80::21a:2bff:fe3c:4d5e/64` Link-Local IP'sine dönüşür.

### Siber Güvenlik Riski (Privacy Threat):
Evlat, bu mekanizma bir felakettir! Çünkü kullanıcının fiziksel donanım MAC adresi, bağlandığı her IPv6 adresinin içine doğrudan kazınır. Bir çalışan evinde, kafede veya iş yerinde internete bağlansa dahi, MAC adresi genel internet IP'sinin son 64 bitinde açıkça görünür; saldırganlar ve reklam ağları bu cihazı coğrafi olarak adım adım takip edebilir!

**Çözüm (RFC 4941 - Privacy Extensions):**  
Modern işletim sistemlerinde (Windows, Linux, macOS) EUI-64 varsayılan olarak terk edilmiş, yerine belirli aralıklarla değişen kriptografik rastgele geçici adresler (Temporary Addresses) getirilmiştir.

---

## 5. SLAAC ve Komşu Keşfi (NDP) Mekanizması

IPv6'da cihazlar ağa katıldığında şu adımları izler:
1. **Link-Local Üretimi:** Cihaz önce kendine bir `fe80::/64` adresi atar.
2. **DAD (Duplicate Address Detection):** `ICMPv6 Type 135 (Neighbor Solicitation)` göndererek ağda bu adresi kullanan başka biri olup olmadığını sorar. Yanıt gelmezse adres geçerli olur.
3. **Router Solicitation (RS - Type 133):** İstemci, tüm yönlendiricilerin dinlediği `ff02::2` multicast grubuna "Ağda yönlendirici var mı?" diye sorar.
4. **Router Advertisement (RA - Type 134):** Yönlendirici, istemciye ağın genel önekini (`2001:db8:acad:1::/64`) ve varsayılan ağ geçidini fısıldar.
5. **Adres Oluşumu:** İstemci, aldığı bu /64 önekinin sonuna kendi 64-bit IID'sini yapıştırarak genel internet adresini oluşturur (SLAAC).

---

## 6. Kritik IPv6 Güvenlik Tehditleri ve Savunma Tedbirleri

### 6.1. Rogue RA Saldırısı (Yetkisiz Yönlendirici Duyurusu)
Saldırgan iç ağda bir makineden sahte Router Advertisement (RA) paketleri anons eder:
- "Ben yeni yönlendiriciyim, önceliğim YÜKSEK, DNS sunucum benim IP'm!" der.
- Ağdaki tüm Windows ve Linux istemciler yönlendirme tablolarını saldırgana çevirir; tüm trafik saldırgan üzerinden akar (Man-in-the-Middle - MitM).
- **Savunma:** Anahtarlarda (Switch) **RA Guard (RFC 6105)** aktifleştirilmelidir. Switch, kullanıcı portlarından gelen RA paketlerini (ICMPv6 Type 134) anında imha eder; yalnızca yetkili yönlendirici portundan geçişe izin verir.

### 6.2. Gölge Ağ Zafiyeti (Dual-Stack Shadow Network)
Birçok kurum "Biz sadece IPv4 kullanıyoruz, IPv6'ya geçmedik" der; ancak modern işletim sistemlerinde IPv6 varsayılan olarak açıktır!
- Saldırgan ağa sahte bir IPv6 yönlendiricisi (Rogue RA) kurar.
- İstemciler otomatik olarak IPv6 adresi alır.
- Modern işletim sistemleri RFC 6724 gereği IPv6'yı IPv4'e tercih eder (Happy Eyeballs).
- Kurumun güvenlik duvarı ve IDS'i yalnızca IPv4'ü denetlediği için, tüm saldırı ve veri sızıntısı IPv6 tüneli üzerinden denetimsizce gerçekleşir!
- **Savunma:** Ya IPv6 şirket genelinde tamamen kapatılmalı (hardening) ya da güvenlik duvarında IPv4 ile eşit sıkılıkta IPv6 kuralları tanımlanmalıdır.

### 6.3. ICMPv6 Filtreleme Hataları
IPv4'te sistem yöneticileri güvenliği artırmak için ICMP'yi (ping) komple engellerdi. IPv6'da bunu yaparsan ağın tamamen çöker!
Çünkü ARP kalktığı için komşuların birbirini bulması (NDP), MTU boyutu keşfi (PMTUD) ve yönlendirici bulma (SLAAC) tamamen ICMPv6 üzerinden yürür. Sadece dış sınırda belirli mesaj tipleri filtrelenmeli, iç ağda NDP paketlerine asla dokunulmamalıdır.

---

## 7. Ustanın Çırağa Tavsiyeleri

Evlat, bu laboratuvarda yazdığın `ipv6_analyzer.py` betiğini iyi incele:
- 128 bitlik adresi hextet hextet nasıl ayrıştırdığımıza,
- RFC 5952 standart sıkıştırma algoritmasının kurallarına,
- EUI-64 ile MAC adresinin nasıl tersyüz edilip IP'ye gömüldüğüne dikkat et.

Bu mantığı kavradığında, yarın bir gün çift yığın (dual-stack) bir kurumsal ağı yönetirken hiçbir saldırgan arkandan dolaşamaz!
