# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

# Gün 056: Mini Proje 7 — Protokol Haritası ve Paket Çözümleme Çalışma Kitabı

## Usta-Çırak Başlangıç Hasbihali
Evladım, geride bıraktığımız Hafta 08 boyunca ağın kalbine indik. TCP üçlü el sıkışmasını (Gün 50), sıra numaralarını ve kayıp paketlerin yeniden iletimini (Gün 51), UDP'nin hafif ama kritik hafifliğini (Gün 52), işletim sisteminin soket ve port durumlarını (Gün 53), internetin telefon rehberi olan DNS kayıtlarını (Gün 54) ve bir cihazın ağa gözlerini açmasını sağlayan DHCP protokolünü (Gün 55) tek tek inceledik.

Bugün, bu parçalı bilgileri bir **Siber Güvenlik Analisti ve Ağ Mimarı** gibi tek bir çatı altında birleştirme günüdür! Bir SOC analisti veya olay müdahale uzmanı (Incident Responder), eline bir `.pcap` dosyası verildiğinde ona sadece bayt yığını olarak bakmaz. Katman 2'deki Ethernet çerçevesinden başlar, Katman 3 IP başlığına soyar, Katman 4 TCP/UDP segmentine iner ve en nihayetinde Katman 7 uygulama yükünü analiz eder. Bu süreçte tüm ağın bir **Protokol Haritasını (Protocol Hierarchy)** çıkarır, cihazlar arasındaki konuşmaları **5'li Demet (5-Tuple Flow Matrix)** oturumlarına dönüştürür ve gizlenen saldırıları (Port Scan, DNS Tünelleme, Rogue DHCP) suçüstü yakalar. Bugün kendi protokol haritalama ve paket çözümleme motorumuzu sıfırdan inşa ediyoruz.

---

## 1. Paket Kapsülleme (Encapsulation) ve Çözümleme (Dissection) Sanatı

Ağda akan her paket bir Rus Matruşka bebeği gibidir. En dış kabuk fiziksel ağa temas eden Katman-2 Ethernet çerçevesidir:

```
[ Ethernet II (14 Bayt) ]
|-- Hedef MAC (6B) | Kaynak MAC (6B) | EtherType (2B) --|
    |
    +--> EtherType == 0x0800 (IPv4)
         |
         v
    [ IPv4 Başlığı (20 Bayt) ]
    |-- Version/IHL (1B) | Total Length (2B) | TTL (1B) | Protocol (1B) | Src IP (4B) | Dst IP (4B) --|
        |
        +--> Protocol == 6 (TCP)
        |    |
        |    v
        |    [ TCP Başlığı (20 Bayt) ]
        |    |-- Src Port (2B) | Dst Port (2B) | Seq (4B) | Ack (4B) | Flags (1B) | Window (2B) --|
        |        |
        |        v
        |        [ Uygulama Yükü: HTTP GET / POST ]
        |
        +--> Protocol == 17 (UDP)
             |
             v
             [ UDP Başlığı (8 Bayt) ]
             |-- Src Port (2B) | Dst Port (2B) | Length (2B) | Checksum (2B) --|
                 |
                 +--> Port 53 =====> [ DNS Sorgusu / Yanıtı ]
                 +--> Port 67/68 ==> [ DHCP DORA Mesajları ]
```

### Çözümleme (Dissection) Kuralları
1. **Sınır Denetimi (Boundary Validation):** Veri akışı minimum başlık boyutunu (Ethernet için 14B, IPv4 için 20B, TCP için 20B, UDP için 8B) karşılamıyorsa işlem hemen durdurulmalı ve `PacketParsingError` fırlatılmalıdır. Aksi halde tampon bellek aşımı (buffer overflow) veya dil seviyesinde IndexError patlar.
2. **Protokol Tanımlayıcıları:** EtherType alanı (`0x0800` IPv4, `0x0806` ARP), IPv4 Protocol alanı (`6` TCP, `17` UDP, `1` ICMP) ve Port numaraları (`80` HTTP, `53` DNS, `67/68` DHCP) hiyerarşide bir sonraki katmanın nasıl çözümleneceğini dikte eder.

---

## 2. İletişim Akış Matrisi (5-Tuple Flow Matrix) ve Oturum Takibi

Bir ağ analizinde paketleri tekil olarak saymak yeterli değildir. İletişimin mantıksal birimini **5'li Demet (5-Tuple)** oluşturur:
$$\text{Flow} = (\text{Kaynak IP}, \text{Kaynak Port}, \text{Hedef IP}, \text{Hedef Port}, \text{Protokol})$$

### İki Yönlü Akış Eşleştirme (Bidirectional Flow Matching)
İstemci `192.168.1.100:54321 -> 192.168.1.10:80` isteğinde bulunurken, sunucu `192.168.1.10:80 -> 192.168.1.100:54321` şeklinde yanıt döner. Gelişmiş bir analiz motoru, bu iki yönü tek bir mantıksal oturumda birleştirir:
- **Paket ve Bayt Hacmi:** Her iki yöndeki toplam trafik toplanır.
- **TCP Durum Takibi:**
  - `SYN` görüldüğünde -> `HANDSHAKE_INIT`
  - `SYN+ACK` ve `ACK` tamamlandığında -> `ESTABLISHED`
  - `FIN` veya `RST` görüldüğünde -> `CLOSED`
- **Yeniden İletim (Retransmission) Tespiti:** Aynı TCP oturumunda, aynı `Seq` numarası ve veri yüküyle mükerrer bir paket yakalanırsa, bu ağdaki paket kaybının (packet loss) veya tıkanıklığın doğrudan göstergesidir.

---

## 3. Protokol Dağılım Hiyerarşisi (Protocol Hierarchy)

Wireshark'taki `Statistics -> Protocol Hierarchy` menüsünü andıran bu harita, ağ yöneticisine ağın genel sağlığını gösterir:
- Toplam paketlerin yüzde kaçı TCP, yüzde kaçı UDP?
- Beklenmedik oranda ARP yayını var mı? (ARP Storm veya ARP Poisoning belirtisi)
- DNS trafiği normalden yüksek mi? (DNS Amplification veya Tünelleme belirtisi)

Örnek Konsol Çıktısı:
```
======================================================================
PROTOKOL DAĞILIM HİYERARŞİSİ (PROTOCOL HIERARCHY MAP)
======================================================================
Protokol        | Paket Sayısı    | Toplam Hacim (Bayt)  | Yüzde (%) 
----------------------------------------------------------------------
Ethernet        | 15              | 1503                 | %100.0   
ARP             | 1               | 42                   | %6.7     
IPv4            | 14              | 1461                 | %93.3    
TCP             | 8               | 518                  | %53.3    
UDP             | 6               | 943                  | %40.0    
HTTP            | 2               | 192                  | %13.3    
DNS             | 3               | 262                  | %20.0    
DHCP            | 3               | 973                  | %20.0    
======================================================================
```

---

## 4. Tehdit Avcılığı (Threat Hunting) Algoritmaları

Çalışma kitabımız yalnızca istatistik üretmez; akan trafiği gerçek zamanlı güvenlik filtrelerinden geçirir:

### A. Port Tarama (SYN Scan) Dedektörü
Bir saldırgan hedef sistemdeki açık portları tespit etmek için ardı ardına `SYN` paketleri gönderir. El sıkışmayı tamamlamaz (Stealth Scan).
- **Kural:** Tek bir kaynak IP adresinden, kısa bir zaman aralığında birden fazla farklı hedef porta yalnızca `SYN` bayraklı paket geliyorsa ve el sıkışma tamamlanmıyorsa, sistem anında `PORT_SCAN_SYN_FLOOD` alarmı üretir.

### B. DNS Tünelleme (Data Exfiltration) Dedektörü
Güvenlik duvarlarını ve DLP (Veri Sızıntısı Önleme) sistemlerini aşmak isteyen zararlı yazılımlar, çalınan verileri heksadesimal veya base64 kodlayarak DNS sorgu alt alanlarına (subdomain) yerleştirir: `v9b27a810f44bcde77189a2b001.exfil.attacker.net`.
- **Kural:** DNS sorgu uzunluğu $\ge 25$ karakter ve **Shannon Entropisi** $H \ge 2.8$ bit/karakter ise sistem `DNS_TUNNELING_EXFILTRATION` alarmı verir.

### C. Sahte DHCP Sunucusu (Rogue DHCP) Dedektörü
Yerel ağda yetkisiz bir sunucu tarafından yayılan DHCP OFFER veya ACK paketleri, ağ geçidini saldırganın IP'si olarak göstererek Ortadaki Adam (MitM) saldırısı başlatır.
- **Kural:** Port 67/68 üzerinden gelen sunucu yanıtlarının `Server Identifier` veya `Kaynak IP` bilgisi yetkili DHCP sunucu listesiyle uyuşmuyorsa, derhal `ROGUE_DHCP_SERVER` alarmı fırlatılır.

---

## Ustanın Öğüdü
Evladım; ağ trafiğini okumak bir cerrahın MR görüntüsünü incelemesine benzer. Sıradan biri ekranda sadece anlamsız siyah-beyaz lekeler görür; usta cerrah ise o lekelerin içindeki tümörü, kanamayı ve doku hasarını milimetrik olarak tespit eder. Bir ağ paketindeki bayrakların (SYN, RST), sıra numaralarının ve entropi değerlerinin sana anlattığı hikayeyi dinlemeyi öğrendiğin gün, gerçek bir siber savunma ustası olursun!
