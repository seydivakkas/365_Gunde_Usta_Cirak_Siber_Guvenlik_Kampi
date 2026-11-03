# Gün 048: ICMP Protokolü, Ağ Teşhisi ve Tünelleme Güvenlik Mimarisi

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## 1. Usta Girişi: Çırağa "Ağın Sinir Sistemi" Öğüdü

Bak evlat, IP protokolü tasarım gereği "en iyi çaba" (best-effort) ile çalışır. Yani bir yönlendirici bir paketi düşürdüğünde, kuyruğu taştığında veya hedefe giden yol çöktüğünde IP'nin kendi içinde göndericiye haber verecek tek bir mekanizması dahi yoktur.

İşte ağın bu dilsizliğini ortadan kaldıran, internetin sinir sistemi rolünü üstlenen protokol **ICMP (Internet Control Message Protocol - RFC 792)** protokolüdür.

Ancak sahadaki en büyük yanılgılardan biri şudur: Acemi yöneticiler güvenlik sağladıklarını zannederek "Ping'i (ICMP) her yerden kapattım, artık görünmeziz!" derler.
Bu iki büyük faciaya yol açar:
1. **Sistemin Gerçekte Açık Olması:** Ping yanıt vermeyen bir sunucu kapalı demek değildir. Bir Nmap SYN taraması veya TCP el sıkışması, açık bir HTTP veya SSH portu üzerinden sistemin ayakta olduğunu saniyeler içinde kanıtlar.
2. **Path MTU Discovery (PMTUD) Çöküşü:** ICMP'yi körlemesine kapatırsan, büyük paketlerin parçalanması gerektiğini bildiren `Type 3 Code 4 (Fragmentation Needed)` mesajlarını da çöpe atarsın. Sonuç: Kullanıcıların web sayfaları yarıda donar, TCP tünelleri kilitlenir ve ağda "Black Hole Router" felaketi yaşanır!

Bu derste ICMP'nin sadece teşhis tarafını değil, saldırganların güvenlik duvarlarını delmek için kullandığı **ICMP Tünelleme (Covert Channel)** silahını ve bunun nasıl engelleneceğini öğreneceksin.

---

## 2. RFC 792 ICMP Başlık Anatomisi ve Sağlama Toplamı

ICMP, doğrudan IP başlığının (Protokol Numarası `1`) hemen ardından gelir. Temel başlık 8 bayttır:

| Bayt Ofseti | Alan Adı | Boyut | Açıklama |
|---|---|---|---|
| `0` | **Type (Tip)** | 1 Bayt | Mesajın genel kategorisi (Örn: 8 = Request, 0 = Reply, 3 = Unreachable, 11 = Time Exceeded). |
| `1` | **Code (Kod)** | 1 Bayt | Tipin alt detay ve nedeni (Örn: Type 3 için Code 1 = Host, Code 3 = Port Unreachable). |
| `2 - 3` | **Checksum** | 2 Bayt | RFC 1071 Bir'in Tümleyeni (1's complement) internet sağlama toplamı. |
| `4 - 5` | **Identifier** | 2 Bayt | İstek ile yanıtı birbiriyle eşleştiren süreç/PID kimliği. |
| `6 - 7` | **Sequence Number** | 2 Bayt | Her ping isteğinde 1 artan paket sıra numarası. |
| `8+` | **Data / Payload** | Değişken | Standart test verisi (Windows: 32B, Linux: 56B). |

### RFC 1071 İnternet Sağlama Toplamı (Checksum)
ICMP başlığı ve veri alanı 16 bitlik kelimeler halinde toplanır, taşmalar alt 16 bite eklenir ve sonuç ters çevrilir (`~sum`). Alıcı taraf paketi aldığında başlık dahil tüm veriyi toplar; eğer sonuç `0x0000` (veya `0xFFFF`) değilse paket kabloda bozulmuş veya sahte enjekte edilmiştir!

---

## 3. Traceroute Nasıl Çalışır? (TTL Tükenme Sanatı)

Traceroute bir sihirbazlık değildir; IP başlığındaki **TTL (Time to Live)** alanının bilinçli olarak tüketilmesi kurnazlığına dayanır:

1. **Hop 1 (TTL=1):** Gönderici paketi `TTL=1` ile çıkarır. İlk yönlendiriciye (Gateway) geldiğinde yönlendirici TTL'i 1 azaltır (`TTL=0`). Kural gereği TTL'i sıfıra inen paket yönlendirilemez ve imha edilir. Yönlendirici göndericiye şunu yollar:
   $$\text{ICMP Type 11 Code 0: Time to Live exceeded in Transit}$$
   Gönderici, bu hata mesajının kaynak IP'sine bakarak ilk yönlendiricinin kim olduğunu öğrenir!
2. **Hop 2 (TTL=2):** Gönderici yeni paketi `TTL=2` ile atar. İlk yönlendirici TTL'i 1'e indirip geçirir, ikinci yönlendirici TTL'i 0 yapıp paketi öldürür ve yine `Type 11 Code 0` döner.
3. **Hedefe Ulaşım:** TTL hedefe yetecek büyüklüğe ulaştığında, hedef sunucu paketi alır ve `Type 0 (Echo Reply)` döner. Böylece kaynaktan hedefe giden tüm yönlendirici zinciri tek tek haritalanır.

---

## 4. Path MTU Discovery (PMTUD) ve Ağ Sağlığı

Ethernet ağlarında standart MTU 1500 bayttır. Ancak aradaki bir VPN tüneli (IPsec, GRE) veya PPPoE hattı MTU'yu 1400 bayta düşürmüş olabilir.
Eğer gönderici paketinde `DF=1 (Don't Fragment - Parçalama)` bayrağını işaretlemişse ve paket 1400 baytlık hatta sığmıyorsa, yönlendirici paketi çöpe atar ve göndericiye şu hayati mesajı döner:
$$\text{ICMP Type 3 Code 4: Fragmentation Needed and DF set (Next-Hop MTU: 1400)}$$

Gönderici bu mesajı aldığında paket boyutunu 1400 bayta çeker ve iletişim kesintisiz sürer. **Eğer güvenlik duvarında Type 3 Code 4'ü engellersen, istemci paketlerinin neden kaybolduğunu anlayamaz ve bağlantı sonsuz döngüye girerek kopar!**

---

## 5. Siber Tehdit Boyutu: ICMP Tünelleme (Covert Channel)

Saldırganlar kurumsal ağlara sızdıklarında, dışarıya TCP (SSH, RDP) veya UDP bağlantılarının güvenlik duvarı tarafından engellendiğini görürler. Ancak birçok gevşek güvenlik duvarı "Ping zararsızdır" diyerek dışarıya ICMP Echo Request çıkışına izin verir!

### Saldırı Mekanizması:
- Saldırgan sistem içine bir zararlı yazılım (örneğin `ptunnel`, `icmpsh`) yerleştirir.
- Zararlı yazılım, çalınan verileri (parolalar, API anahtarları, belgeler) standart bir ping paketinin **Payload (Veri)** alanına gömer.
- Dışarıdaki C2 sunucusuna `Type 8 Code 0 (Echo Request)` olarak gönderir.
- C2 sunucusu yanıt olarak `Type 0 Code 0 (Echo Reply)` dönerken, yanıtın payload kısmına saldırganın çalıştırmak istediği terminal komutlarını (`CMD=WHOAMI`) iliştirir!
- Güvenlik duvarı bunu masum bir pingleşme sanır; oysa içeride çift yönlü şifreli bir komuta-kontrol tüneli (Covert Channel) akmaktadır!

---

## 6. Kurumsal Savunma ve Sıkılaştırma Prensipleri

1. **Derin Paket İnceleme (DPI) ve Payload Boyut Denetimi:**
   Güvenlik duvarında kural yazılır: Standart ping yükü 32-64 bayttır. Eğer bir Echo Request paketi 64 bayttan büyükse veya payload içinde rastgele entropili şifreli veri/metin taşıyorsa paket derhal **DROP** edilmeli ve SOC'a alarm iletilmelidir.
2. **ICMP Redirect (Type 5) Engellemesi:**
   Saldırganların yerel ağda yönlendirme tablolarını manipüle ederek MitM yapmasını engellemek için tüm Type 5 mesajları hem anahtarlarda hem de işletim sistemlerinde (`net.ipv4.conf.all.accept_redirects = 0`) kesinlikle kapatılmalıdır.
3. **Akıllı ve Seçici İzin Politikası:**
   - Dışarıdan içeriye gelen anlamsız ping istekleri engellenebilir.
   - Ancak PMTUD için `Type 3 Code 4` ve giden pinglerin yanıtı için `Type 0 Code 0` durum denetimli (stateful) olarak kesinlikle açık tutulmalıdır.
4. **Hız Sınırlaması (Rate Limiting):**
   ICMP Flood ve Smurf benzeri DDoS taşkınlarına karşı arayüzlerde saniyede izin verilen ICMP paket sayısı (örneğin 10 pkt/sec) ile sınırlandırılmalıdır.

---

## 7. Çırağa Öğüt

Evlat, bugün geliştirdiğin `icmp_diagnostic_analyzer.py` modülünde:
- Checksum'ın bayt bayt nasıl doğrulandığını,
- Traceroute'un adım adım nasıl çalıştığını,
- Ve 97 baytlık şüpheli payload taşıyan bir paketin nasıl anında güvenlik alarmı ürettiğini gördün.

Ağ teşhisi sadece "ping atıp yanıt beklemek" değildir; o yanıtın her bir bitini güvenlik gözlüğüyle okumaktır!
