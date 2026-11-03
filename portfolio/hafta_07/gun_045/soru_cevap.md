# Gün 045: Soru-Cevap ve Kavramsal Pekiştirme

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## Soru 1 (G045-SC1): IPv4 Adresleme ve CIDR Mekanizması ve Güvenlik Önemi

### Temel Mekanizma ve Güvenlik Önemi
IPv4 adresleri, her biri 8 bit olan 4 oktetten meydana gelen 32 bitlik işaretsiz tamsayılardır. CIDR (Classless Inter-Domain Routing - RFC 1519), sınıflı ağ (Class A, B, C) kısıtlamalarını ortadan kaldırarak ağ maskesinin bit uzunluğu (/0 ile /32) ile ağ sınırlarının dinamik olarak belirlenmesini sağlar. CIDR önek uzunluğu, 32 bitlik adresin kaç bitinin Ağ Kimliği (Network ID) ve kaç bitinin Konak Kimliği (Host ID) olduğunu tanımlar.

Güvenlik açısından CIDR öneki, saldırı yüzeyinin ve etki alanının (blast radius) fiziksel ve mantıksal sınırını çizer:
1. **Mikro-Segmentasyon:** Geniş bir ağın (/16 veya /24) ihtiyaç doğrultusunda /28 (14 konak) veya /29 (6 konak) gibi küçük bloklara bölünmesi, saldırganın ele geçirdiği bir sistemden diğer kritik varlıklara doğru yanal hareketini (lateral movement) engeller.
2. **Yayın Fırtınası ve Smurf DDoS Koruması:** Standart alt ağlarda ağın en son adresi tüm cihazları hedef alan Yayın Adresidir (Broadcast). Saldırganların sahte kaynak IP ile ICMP yayın paketleri göndererek ağı felç ettiği "Smurf Saldırıları", kontrolsüz büyük alt ağlarda yıkıcıdır.
3. **Özel Standart İstisnaları:** RFC 3021 (/31) standardı noktadan noktaya yönlendirici linklerinde yayın adresini tamamen kaldırarak 2 hostun doğrudan haberleşmesini sağlar; böylece hem IP israfını önler hem de yayın kaynaklı zafiyetleri yok eder. /32 ise tekil bir konak rotasıdır ve güvenlik duvarlarında en dar yetkilendirme (least privilege) kuralını yazmak için elzemdir.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:** Farklı senaryoları temsil eden CIDR dizgeleri: `192.168.1.10/24` (standart C sınıfı özel ağ), `10.50.0.1/16` (geniş kurumsal ağ), `172.16.100.45/28` (mikro-segmentasyon DMZ), `192.0.2.1/31` (RFC 3021 noktasal link), `198.51.100.5/32` (tekil host rotası).
- **İşlem:** Bitsel `AND` işlemiyle Ağ Adresi (`IP & Netmask`), bitsel `OR` ve `NOT` ile Yayın Adresi (`IP | (~Netmask)`), ilk/son kullanılabilir konaklar, toplam ve net konak kapasiteleri ve IETF standartlarına göre Bogon/RFC 1918 sınıflandırması hesaplanır.
- **Beklenen Çıktı:** Her girdi için doğru ağ, yayın, konak sınırları ve güvenlik etiketleri; /31 için yayının "Yok (RFC 3021)", /32 için "Yok (/32 Tekil Host)" olarak işaretlenmesi.
- **Negatif Kontrol:** `256.1.1.1/24` (oktet taşması), `192.168.01.1/24` (geçersiz sıfır), `192.168.1.1/33` (önek taşması) ve `255.255.0.255` (bitişik olmayan maske) girdilerinin `IPv4ValidationError` ile yakalanması.

### Risk Analizi ve Tehdit Senaryoları
Yanlış alt ağ varsayımları ve maske yapılandırma hataları doğrudan şu riskleri doğurur:
- **Trafik Sızıntısı ve Yönlendirme Kaçakları:** Örneğin bir DMZ sunucusuna `/28` yerine sehven `/24` maskesi verilmesi, sunucunun yerel alt ağ sanarak aynı VLAN'daki diğer kritik sunuculara güvenlik duvarını atlayarak doğrudan Layer-2 üzerinden erişebilmesine yol açar.
- **Bogon / IP Spoofing Sızıntısı:** Genel internete bakan arayüzlerde RFC 1918 (10.0.0.0/8 vb.) veya CGNAT (100.64.0.0/10) gibi ayrılmış blokların filtrelenmemesi, saldırganların sahte kaynak IP ile iç ağ kaynaklarına sızmasına zemin hazırlar.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:** Kenar yönlendirici ve güvenlik duvarı günlüklerinde WAN arayüzünden gelen Bogon kaynaklı paketlerin loglanması (`log drop on WAN from {RFC1918, RFC6598, 127/8}`).
- **Önleme (BCP 38 / RFC 2827):** Ingress ve Egress filtreleme kuralları ile kurum dışından gelen ve geçerli genel IP taşımayan paketlerin düşürülmesi; yönlendiricilerde `ip verify unicast source reachable-via rx` (Strict uRPF) aktifleştirilmesi.

---

## Soru 2 (G045-SC2): Bağımsız Laboratuvarın Girdisi, İşlemi, Beklenen Sonucu ve Negatif Kontrolü

### Temel Mekanizma ve Güvenlik Önemi
Bir ağ analiz modülü, harici ağ kaynaklarına veya önceki günlerin durumlarına bağımlı olmadan, verilen herhangi bir IPv4 ve CIDR gösterimini katı matematiksel ve biçimsel kurallarla doğrulayabilmelidir. Girdinin doğrulanması (input sanitization), sınır dışı oktetlerin engellenmesi ve RFC istisnalarının doğru uygulanması ağ otomasyonunda sıfır hata toleransı gerektirir.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:** `portfolio/hafta_07/gun_045/ornek_veri/sample_subnets.json` içerisinde yer alan 8 yapılandırılmış test vakası ve `invalid_subnets.json` içerisindeki 8 negatif vaka.
- **İşlem:**
  1. Girdi ayrıştırılır, 4 oktet ve sayısal değer kontrolleri yapılır.
  2. Sayısal oktetler 32 bitlik işaretsiz tamsayıya (`ip_int`) dönüştürülür.
  3. CIDR önek uzunluğu 32 bitlik alt ağ maskesine dönüştürülür ve bitişikliği doğrulanır.
  4. Bitsel matematik (`AND`, `OR`, `NOT`) ile ağ ve yayın adresleri hesaplanır.
  5. Konak kapasiteleri standart ve uç durum formülleriyle (/31, /32) üretilir.
- **Beklenen Çıktı:** 14 adet birim testin (10 pozitif fonksiyonel test + 4 negatif doğrulama testi) 0.1 saniyenin altında `PASSED` olarak tamamlanması.
- **Negatif Kontrol:** 8 farklı geçersiz formatın (oktet > 255, eksik oktet, fazla oktet, leading zero, önek > 32, negatif önek, sayısal olmayan önek, eksik '/') her birinin `IPv4ValidationError` fırlatması ve `kanit/gercek/negatif_kontrol_sonuclari.txt` dosyasına eksiksiz yazılması.

### Risk Analizi ve Tehdit Senaryoları
Ağ yönetim yazılımlarında girdi doğrulama eksikliği:
- `192.168.01.1` gibi girdilerin C kütüphanelerinde veya bazı dillerde sekizli (octal) sayı sistemi olarak yorumlanıp `192.168.1.1` yerine `192.168.1.1` veya `192.168.0.1` olarak yanlış ayrıştırılmasına ve ACL zaafiyetine yol açar.
- Negatif veya 32'den büyük öneklerin tampon taşması veya sonsuz döngü yaratması riskini doğurur.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:** Otomasyon loglarında `IPv4ValidationError` fırlatan hatalı giriş denemelerinin SIEM üzerinde izlenmesi.
- **Önleme:** Girdi ayrıştırma katmanında katı regex ve oktet aralık denetimi uygulanması; leading zero içeren oktetlerin anında reddedilmesi.

---

## Soru 3 (G045-SC3): Risk Oluşumu, Tespiti ve Savunma Kontrolleri

### Temel Mekanizma ve Güvenlik Önemi
IPv4 protokolü tasarım gereği paket başlığında kaynak IP adresinin gerçekliğini doğrulayan bir kriptografik imza içermez. Bu durum, katman 3 seviyesinde "IP Spoofing" (Kaynak IP Sahteciliği) riskinin doğmasına neden olur. Bir saldırgan, ham soketler (raw sockets) kullanarak paketin kaynak IP alanına herhangi bir IP adresini (kurbanın IP'si veya bir iç ağ IP'si) yazarak paketi ağa bırakabilir.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:** Laboratuvarda modellenen `is_bogon` ve `is_private` bayrakları; harici arayüzlerden gelen sahte paket temsilleri.
- **İşlem:** Paketlerin kaynak IP adresleri RFC 1918 ve Bogon listeleriyle kıyaslanır; yönlendirme tablosu ile gelen arayüz eşleştirmesi yapılır.
- **Beklenen Çıktı:** WAN arayüzünden gelen RFC 1918 ve Bogon etiketli tüm IP'lerin filtrelenmesi ve uRPF tarafından reddedilmesi.
- **Negatif Kontrol:** Sahte kaynak IP'ye sahip paketlerin iç ağa iletilmeden sınır yönlendiricisinde düşürüldüğünün kanıtlanması.

### Risk Analizi ve Tehdit Senaryoları
1. **DDoS Yansıtma ve Yükseltme (Reflection / Amplification):** Saldırgan, DNS veya NTP gibi UDP tabanlı protokollere kurbanın kaynak IP'siyle sorgu atar; sunucular devasa yanıtları kurbana yönlendirerek hedefin hattını kilitler.
2. **IP Güvenine Dayalı Servisleri Atlama (Bypass Trust Relationships):** Bazı eski yönetim servisleri (rsh, rlogin) veya yetersiz yapılandırılmış API'ler belirli bir IP'den gelen isteklere şifresiz güvenir. Saldırgan bu IP'yi taklit ederek yetkisiz işlem gerçekleştirebilir.
3. **Alt Ağ Kaçakları (Subnet Leaks):** Şirket içi VPN veya bulut VPC bağlantılarında çakışan veya yanlış duyurulan CIDR blokları trafiğin yanlış yönlendirilmesine ve veri sızıntısına yol açar.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:**
  1. Sınır cihazlarında `deny ip any any log` kuralı altında Bogon bloklarından gelen paketlerin eşleşme sayaçlarının artması.
  2. Wireshark / Zeek üzerinde dış arayüzde görülen RFC 1918 kaynaklı gelen trafik alarmları.
- **Önleme:**
  1. **BCP 38 / RFC 2827:** Kenar yönlendiricilerde katı Ingress Access-List uygulanması:
     ```text
     access-list 100 deny ip 10.0.0.0 0.255.255.255 any
     access-list 100 deny ip 172.16.0.0 0.15.255.255 any
     access-list 100 deny ip 192.168.0.0 0.0.255.255 any
     access-list 100 deny ip 127.0.0.0 0.255.255.255 any
     access-list 100 deny ip 169.254.0.0 0.0.255.255 any
     access-list 100 permit ip any any
     ```
  2. **Unicast RPF (uRPF):** `ip verify unicast source reachable-via rx` komutuyla yönlendiricinin, gelen paketin kaynak IP'sine geri dönüş rotasının aynı arayüz üzerinde olduğunu teyit etmesi.
  3. **Mikro-Segmentasyon:** Kritik varlıkların /28 veya /29 gibi daraltılmış alt ağlara alınarak aralarına yeni nesil güvenlik duvarı (NGFW) ve sıfır güven (Zero Trust) mimarisi konumlandırılması.
