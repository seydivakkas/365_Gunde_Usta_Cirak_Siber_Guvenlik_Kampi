# Gün 047: Adres Çözümleme Protokolü (ARP), Yerel Ağ Komşuluğu ve Güvenlik

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## 1. Usta Girişi: Çırağa Katmanlar Arası Köprü Öğüdü

Bak evlat, dün ve önceki gün IP adreslerini ve alt ağları konuştuk. Ancak sana acı bir gerçeği söyleyeyim: **İki cihaz aynı yerel ağda (LAN) haberleşirken IP adresleri kablo üstünde doğrudan fiziksel iletimi sağlayamaz!**

Bir Ethernet kartı, kablodan veya kablosuz havadan gelen bitleri dinlerken "Bu paketin hedef IP'si benim mi?" diye bakmaz; ilk baktığı yer Katman 2 Ethernet başlığındaki **Hedef MAC Adresidir**. Eğer hedef MAC kendi adresi değilse (veya yayın/multicast değilse), kart paketi işlemciye iletmeden donanım seviyesinde çöpe atar.

İşte Katman 3'ün mantıksal dünyası (IP) ile Katman 2'nin fiziksel dünyası (MAC) arasındaki bu köprüyü kuran protokol **ARP (Address Resolution Protocol - RFC 826)** protokolüdür.

Fakat ARP, 1982 yılında "ağdaki herkes birbirine güvenir" varsayımıyla yazılmıştır. İçinde hiçbir kimlik doğrulama, imza veya doğruluk denetimi yoktur. Bu saflık, yerel ağların en yıkıcı saldırılarından biri olan **ARP Zehirleme (Cache Poisoning / Man-in-the-Middle)** zafiyetinin doğmasına yol açmıştır. Şimdi bu protokolün anatomisini ve savunmasını iliklerine kadar öğreneceksin.

---

## 2. ARP Protokolü Anatomisi (RFC 826)

Bir cihaz, yerel ağdaki bir IP'ye (örneğin varsayılan ağ geçidi `192.168.1.1`) paket göndermek istediğinde kendi ARP önbelleğine (ARP Cache) bakar. Eğer aradığı IP orada yoksa bir ARP İstek (Request) paketi hazırlar:

### 2.1. ARP Paket Alanları
- **Hardware Type (2 bayt):** Ağ donanım türü (Ethernet için `1`).
- **Protocol Type (2 bayt):** Çözümlenen üst katman protokolü (IPv4 için `0x0800`).
- **Hardware Address Length (1 bayt):** Donanım adresi uzunluğu (MAC için `6`).
- **Protocol Address Length (1 bayt):** Protokol adresi uzunluğu (IPv4 için `4`).
- **Opcode (İşlem Kodu - 2 bayt):**
  - `1`: ARP Request (İstek)
  - `2`: ARP Reply (Yanıt)
  - `3`: RARP Request
  - `4`: RARP Reply
- **Sender Hardware Address (SHA - 6 bayt):** Gönderenin MAC adresi.
- **Sender Protocol Address (SPA - 4 bayt):** Gönderenin IP adresi.
- **Target Hardware Address (THA - 6 bayt):** Hedef MAC adresi (İstekte bilinmediği için `00:00:00:00:00:00` yazılır).
- **Target Protocol Address (TPA - 4 bayt):** MAC adresi aranan hedef IP adresi.

### 2.2. İstek ve Yanıt Döngüsü
1. **İstek (Request):** Ethernet başlığında `FF:FF:FF:FF:FF:FF` (Broadcast) olarak tüm ağa basılır: *"192.168.1.1 kimdeyse bana MAC adresini söylesin!"*
2. **Yanıt (Reply):** Sadece o IP'ye sahip cihaz isteği üstlenir ve doğrudan soran cihaza tekil (Unicast) bir yanıt çerçevesi yollar: *"192.168.1.1 benim, MAC adresim 00:1A:2B:3C:4D:01'dir."*
3. **Önbelleğe Alma:** İsteyen cihaz bu eşlemeyi ARP tablosuna yazar ve iletişimi başlatır.

---

## 3. ARP Önbelleği (Cache) ve Gratuitous ARP (GARP)

İşletim sistemleri her paket için ağa yayın basıp ARP sormaz; bu performansı mahveder. Öğrenilen eşlemeler bellekte (ARP Cache) saklanır:
- **Dinamik Girişler:** Ağ trafiğinden öğrenilir; işletim sistemine göre birkaç dakika (Linux'ta `arp_timeout`, Windows'ta 20-30 saniye) sonra silinir (aging).
- **Statik Girişler:** Sistem yöneticisi tarafından elle sabitlenir (`arp -s 192.168.1.1 00-1a-2b-3c-4d-01`); dinamik paketlerle üzerine yazılamaz.

### Gratuitous ARP (GARP) Nedir?
Bir cihaz kimse ona soru sormadan, ağa *"Benim IP'm 192.168.1.50 ve MAC adresim budur!"* diyerek yayın atarsa buna **Gratuitous ARP** denir.
- **Amacı 1:** IP çakışması tespiti (Ağda aynı IP'yi kullanan başkası varsa yanıt verir ve alarm oluşur).
- **Amacı 2:** Ağ kartı değiştiğinde veya kümeleme (Clustering / VRRP / HSRP) geçişlerinde yeni yönlendiricinin MAC adresini anında tüm ağa bildirmek.

---

## 4. Ölümcül Zafiyet: Durumsuz (Stateless) Tasarım ve ARP Zehirleme

Şimdi felaketin başladığı yere geldik: **ARP durumsuz (stateless) bir protokoldür!**
Bu ne demektir çırak?
Bir istemci, **hiç ARP isteği göndermemiş olsa dahi**, sokaktan gelen bir ARP Yanıt (Reply) paketini alır ve önbelleğindeki eşlemeyi hiç sorgulamadan günceller!

### Saldırı Senaryosu (ARP Cache Poisoning / Spoofing)
Saldırgan (MAC: `AA:BB:CC:DD:EE:FF`), kurban bilgisayara sürekli sahte ARP yanıtları yollar:
> *"Ben 192.168.1.1'im (Ağ Geçidi) ve MAC adresim AA:BB:CC:DD:EE:FF'tir."*

Aynı anda gerçek ağ geçidine de sahte paket yollar:
> *"Ben 192.168.1.50'yim (Kurban) ve MAC adresim AA:BB:CC:DD:EE:FF'tir."*

**Sonuç:**
- Kurban internete çıkmak istediğinde paketleri saldırganın MAC adresine gönderir.
- Ağ geçidi kurbana döneceği zaman paketleri saldırgana gönderir.
- Saldırgan tam ortaya oturur: **Man-in-the-Middle (MitM)!**
- Şifresiz HTTP trafiğini okur, DNS isteklerini zehirler, SSL Strip ile HTTPS'i düşürür veya tüm paketleri çöpe atarak hizmet kesintisi (Blackholing / Denial of Service) yaratır!

---

## 5. Kurumsal Katman-2 Savunma ve Sertleştirme Prensipleri

Bir siber güvenlik uzmanı ARP zehirlemesine karşı asla çaresiz değildir. Çözümler ağ anahtarı (Switch) seviyesinde uygulanır:

1. **Dynamic ARP Inspection (DAI):**
   Kurumsal anahtarların en güçlü savunma mekanizmasıdır. Switch, **DHCP Snooping** veritabanına bakar. Hangi porttan hangi IP ve MAC eşleşmesinin meşru olarak dağıtıldığını bilir. Eğer bir kullanıcı portundan gelen ARP paketi bu veritabanıyla çelişiyorsa (örneğin Port 3'teki bir istemci ağ geçidinin IP'sini sahiplenmeye kalkıyorsa), switch paketi donanım düzeyinde **DROP** eder ve güvenlik ihlali logu üretir.
2. **Statik ARP Eşlemesi:**
   Kritik sunucularda ve sınır yönlendiricilerinde ağ geçidi MAC adresi statik olarak sabitlenir. Dinamik ARP paketlerinin bu kaydı değiştirmesi işletim sistemi çekirdeğince engellenir.
3. **Port Security ve 802.1X:**
   Her bir anahtar portuna bağlanabilecek maksimum MAC adresi sınırlandırılır (örneğin port başına 1 MAC). Saldırganın tek bir porttan onlarca sahte MAC adresi yayması (MAC Flooding / Spoofing) anında engellenir.
4. **Private VLANs (PVLAN) ve Segmentasyon:**
   Aynı alt ağdaki istemcilerin birbirleriyle doğrudan Katman 2 seviyesinde konuşması engellenir (Isolated VLAN); böylece bir istemci yanındaki çalışma arkadaşını zehirleyemez.

---

## 6. Ustanın Laboratuvar Notu

Evlat, bugün yazdığımız `arp_neighbor_analyzer.py` kodunda:
- Dinamik ve statik önbellek ayrımını,
- Bir IP'nin MAC adresinin aniden değişmesini (MAC Flip),
- Tek bir saldırgan MAC'inin birden fazla kurumsal IP'yi sahiplenmesini,
- Ve DHCP Snooping ile Dynamic ARP Inspection (DAI) doğrulaması mantığını bizzat kodladın.

Bu analitik bakış açısı, yarın bir gün SOC merkezinde "Gateway unreachable" alarmı aldığında sorunun fiziksel kabloda mı yoksa bir MitM saldırısında mı olduğunu saniyeler içinde anlamanı sağlayacaktır!
