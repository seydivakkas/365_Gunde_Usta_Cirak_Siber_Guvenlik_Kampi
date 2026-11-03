# G044 — Ethernet, MAC ve Çerçeve Yapısı: Yerel Ağ İletişiminin Anatomisi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

---

## 1. Giriş ve Usta-Çırak Sohbeti

> **Usta:**  
> *"Evlat, dünkü dersimizde büyük resmi gördük; 7 katmanlı gökdelenin tepesinden tabanına baktık.  
> Bugün ise o gökdelenin beton zeminine, **Katman 2'ye (Veri Bağlantısı Katmanı)** iniyoruz.  
> Siber güvenlikte en büyük yanılgılardan biri, 'İletişimi IP adresleri sağlar' zannetmektir. Hayır evlat! IP adresleri mantıksal haritadır; şehirler arası otoyol tabelasıdır. Ama o yolda tekerleğin yere bastığı, paketi bir cihazdan yanındaki ağ anahtarına (switch) fiziksel olarak taşıyan şey **Ethernet Çerçevesi (Frame)** ve **MAC Adresidir**.  
> Eğer aynı yerel ağdaysan (LAN), senin bilgisayarın hedef bilgisayarla konuşurken IP adresine değil, onun ağ kartının donanımsal MAC adresine bakar. İşte bu yüzden Katman 2, bir siber güvenlik korsanının en sevdiği oyun alanıdır. Çünkü Ethernet protokolü 1970'lerde güvenliğin hiç düşünülmediği, herkesin birbirine güvendiği bir laboratuvarda doğdu.  
> Bugün Ethernet çerçevesini bayt bayt parçalayacak, MAC adresinin bit seviyesindeki sırlarını çözecek ve ağ anahtarlarının bu çerçeveleri nasıl işlediğini öğreneceğiz!"*

---

## 2. MAC Adresinin Bit Seviyesinde Mimarisi

Bir MAC (Media Access Control) adresi, **48 bit (6 bayt)** uzunluğunda onaltılık (hexadecimal) bir tanıtıcıdır (Örn: `00:50:56:C0:00:08`). Ancak rastgele sayılardan oluşmaz; içerisinde çok hassas iki kontrol biti ve kurumsal üretici bilgisi barındırır:

```
+-----------------------------------+-----------------------------------+
|     OUI (İlk 24 Bit / 3 Bayt)     |    NIC ID (Son 24 Bit / 3 Bayt)   |
|     Üretici Tanıtım Kodu          |    Cihaza Özel Seri Numarası      |
+-----------------------------------+-----------------------------------+
                |
                v
İlk Baytın Bit Anatomisi (Örn: 0x00 -> 00000000_2):
  Bit 0 (LSB - En Sağdaki Bit):  I/G (Individual / Group) Biti
    -> 0: Unicast (Tekil Cihaz Adresi)
    -> 1: Multicast (Çok Noktaya Yayın) veya Broadcast (FF:FF:FF:FF:FF:FF)
  Bit 1 (Sondan İkinci Bit):     U/L (Universal / Local) Biti
    -> 0: Universally Administered (IEEE tarafından üreticiye tescilli)
    -> 1: Locally Administered (Yönetici tarafından elle verilmiş veya yazılımla sahtelenmiş / Spoofed)
```

### Kritik Güvenlik Kuralı: Kaynak MAC Multicast Olamaz!
IEEE 802.3 Ethernet standardına göre, bir çerçevenin **Kaynak MAC (Source MAC)** adresi her zaman tek bir fiziksel cihazı temsil etmek zorundadır. Bu nedenle kaynak MAC adresinde **I/G biti DAİMA 0 (Unicast)** olmak zorundadır. Eğer bir ağda kaynak MAC adresi `01:00:5E:...` veya `FF:FF:FF:FF:FF:FF` olan bir çerçeve yakalanırsa, bu elektriksel bir donanım arızası veya kötü niyetli bir saldırganın ağ anahtarını şaşırtmak için ürettiği sahte (spoofed/malformed) bir pakettir!

---

## 3. Standart Ethernet II Çerçeve Başlığı Alanları

Ethernet II (DIX Ethernet), günümüz IP ağlarının fiili çerçeve standardıdır. Bir çerçeve şu alanlardan oluşur:

| Alan Adı | Boyut (Bayt) | Görevi ve Güvenlik Önemi |
|---|---|---|
| **Preamble & SFD** | 7 + 1 Bayt | Alıcı ağ kartının saatini senkronize eden `10101010` serisi ve çerçevenin başladığını bildiren `10101011` (SFD) biti. Donanım seviyesindedir. |
| **Hedef MAC (Destination MAC)** | 6 Bayt | Çerçevenin teslim edileceği fiziksel kart adresi. Switch CAM tablosunda bu adrese bakarak çerçevenin gideceği portu seçer. |
| **Kaynak MAC (Source MAC)** | 6 Bayt | Çerçeveyi üreten cihazın kart adresi. Switch bu adresi okuyarak CAM tablosunu öğrenir (MAC Learning). |
| **EtherType** | 2 Bayt | Çerçevenin taşıdığı üst katman protokolünü belirtir (`0x0800` IPv4, `0x0806` ARP, `0x86DD` IPv6, `0x8100` 802.1Q). |
| **Veri Yükü (Payload)** | 46 – 1500 Bayt | Üst katman PDU'su (IP paketi veya ARP mesajı). Standart MTU 1500 bayttır. |
| **Dolgu (Padding)** | 0 – 18 Bayt | Eğer veri yükü 46 baytın altındaysa (örneğin 28 baytlık ARP), çerçeve otomatik olarak sıfırlarla 46 bayta tamamlanır. |
| **FCS (CRC-32)** | 4 Bayt | Çerçevenin kablodan geçerken bozulup bozulmadığını doğrulayan 32-bit döngüsel artıklık denetimi (Frame Check Sequence). |

### Neden Asgari 64 Bayt Kuralı Vardır?
Klasik Ethernet'in temelinde yer alan **CSMA/CD (Carrier Sense Multiple Access with Collision Detection)** mekanizmasında; kablonun en ucundaki cihaz çerçeve gönderirken, kablonun öbür ucundaki cihaz da aynı anda gönderim yaparsa bir çarpışma (collision) meydana gelir. Gönderici cihazın bu çarpışmayı henüz iletimi bitmeden algılayabilmesi için, çerçevenin kabloyu belirli bir süre meşgul etmesi gerekir. Standart Ethernet kablo uzunluklarında bu süre **en az 64 baytlık (512 bit zamanı)** bir çerçeveye karşılık gelir. 64 baytın altındaki çerçevelere **Runt Frame** denir ve switch'ler tarafından doğrudan çöpe atılır.

---

## 4. IEEE 802.1Q VLAN Etiketleme Mimarisi

Büyük kurumsal ağlarda güvenlik izolasyonu sağlamak amacıyla tek bir fiziksel anahtar birden fazla mantıksal ağa bölünür (**VLAN - Virtual Local Area Network**). Switch'ler arası omurga hatlarında (Trunk) taşınan çerçevelerin hangi VLAN'a ait olduğunu belirtmek için araya **4 baytlık 802.1Q etiketi** eklenir:

```
[Standart Ethernet]  [Hedef MAC: 6B] [Kaynak MAC: 6B] [EtherType: 2B] [Veri...]
                                           |
                                           v
[802.1Q Etiketli]   [Hedef MAC: 6B] [Kaynak MAC: 6B] [TPID: 2B] [TCI: 2B] [EtherType: 2B] [Veri...]
                                                       |         |
                                                       |         +--> PCP (3 Bit QoS) + DEI (1 Bit) + VID (12 Bit: 1-4094)
                                                       +------------> 0x8100 (VLAN Etiketi Göstergesi)
```
- **VLAN ID (VID):** 12 bitlik alan sayesinde 1 ile 4094 arasında sanal ağ kimliği tanımlanır.
- **Güvenlik Önemi:** Farklı VLAN'daki kullanıcılar Katman 2 seviyesinde birbirlerini göremez ve broadcast yayınlarını alamaz; iletişim ancak bir Katman 3 yönlendirici veya güvenlik duvarı üzerinden kontrol altında gerçekleşebilir.

---

## 5. Katman 2 Güvenlik Tehditleri ve Savunma Mekanizmaları

| Tehdit / Saldırı Vektörü | Saldırı Mekanizması | Etkili Savunma Kontrolü |
|---|---|---|
| **MAC Flooding** | Saldırgan rastgele sahte kaynak MAC adresleriyle binlerce çerçeve göndererek switch'in CAM (MAC) tablosunu doldurur. Hafızası dolan switch tüm trafiği her porta yaymaya (hub moduna geçme / Fail-Open) başlar. | **Port Security:** Port başına izin verilen maksimum MAC adresi sınırlandırılır (örn: max 1); ihlalde port otomatik kapatılır (`shutdown`). |
| **MAC Spoofing** | Saldırgan kendi MAC adresini yetkili bir sunucunun veya ağ geçidinin MAC adresiyle değiştirerek kimlik taklidi yapar. | **802.1X (EAP-TLS) & Port Security:** Ağ kartının fiziksel MAC'ine değil, sertifika tabanlı kullanıcı kimliğine göre porta erişim verilir. |
| **ARP Poisoning / Spoofing** | Saldırgan "Ağ geçidinin IP'si benim bu MAC adresimdedir" diye sahte ARP yanıtları basarak trafiği kendi üzerine çeker (MitM). | **Dynamic ARP Inspection (DAI):** Switch, DHCP Snooping tablosuna bakarak IP-MAC eşleşmesini doğrular; sahte ARP yanıtlarını engeller. |
| **VLAN Hopping** | Saldırgan çift 802.1Q etiketi (Double Tagging) veya switch port anlaşması (DTP) zafiyetlerini kullanarak yetkisi olmayan başka bir VLAN'a paket enjekte eder. | **Trunk Hardening:** DTP (Dynamic Trunking Protocol) kapatılır (`switchport nonegotiate`), native VLAN kullanılmayan ayrık bir ID yapılır. |

---

## 6. Usta-Çırak İpuçları ve Laboratuvar Notu

> **Usta Diyor ki:**  
> *"Evlat, bir yerel ağa bağlandığında Wireshark'ı açtığın an gördüğün ilk şey Ethernet çerçeveleridir.  
> Eğer hedef MAC `FF:FF:FF:FF:FF:FF` ise bil ki bir cihaz bağırarak ağdaki herkesi rahatsız ediyordur (Broadcast).  
> Eğer kaynak MAC'in ilk 3 oktetine (`OUI`) bakarsan, o cihazın bir VMware mi, bir Raspberry Pi mi yoksa bir iPhone mu olduğunu daha IP paketini açmadan anlarsın.  
> Ama sakın unutma: MAC adresi fiziksel kartın üzerine lazerle kazınmış olsa bile, işletim sistemi seviyesinde tek satırlık bir komutla (`ip link set dev eth0 address 00:11:22:33:44:55`) sahtelenebilir. Bu yüzden profesyonel güvenlik mimarı, asla tek başına MAC adresine güvenmez; 802.1X sertifikasını ve şifreli tünelleri şart koşar!"*
