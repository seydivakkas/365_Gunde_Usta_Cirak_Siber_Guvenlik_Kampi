# G043 — OSI ve TCP/IP Modellerinin Katmanları ve Paket Kapsülleme Mimarisi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

---

## 1. Giriş ve Usta-Çırak Aşama 03 Açılışı

> **Usta:**  
> *"Evlat, kutunun içinden çıkma vakti geldi!  
> İlk 6 hafta boyunca (Gün 01-42) tek bir bilgisayarın, bir işletim sisteminin içinde neler döndüğünü inceledik. Çekirdeği, süreçleri, dosya izinlerini ve güvenli yapılandırmayı öğrendin.  
> Bugünden itibaren **Aşama 03: Ağ Temelleri ve Ağ Güvenliği** dünyasına adım atıyoruz. Artık bilgisayarlar yalnız değil; aralarında binlerce kilometre olan sistemler fiber optik kablolarla, radyo dalgalarıyla ve yönlendiricilerle konuşuyor.  
> Bir web sitesine tıkladığında ekranda beliren veri, sihirle gelmez. O veri, gökyüzünden yere inen bir bina gibi katman katman paketlenir (Encapsulation), kablo boyunca milyonlarca elektrik veya ışık darbesi olarak akar ve karşı tarafta aynı katmanlar tersine açılarak (Decapsulation) işletim sisteminin belleğine yerleşir.  
> Bugün iki büyük modeli anlayacağız: Teorinin anayasası olan **7 Katmanlı OSI Modeli** ve yaşayan pratik olan **4 Katmanlı TCP/IP Modeli**. Katmanları bilmeyen bir güvenlikçi, trafiği okuyamaz; trafiği okuyamayan ise ağı savunamaz!"*

---

## 2. Neden İki Farklı Model Var? (OSI vs. TCP/IP)

Ağ mühendisliğinde ve siber güvenlikte sıkça karşılaşılan kafa karışıklıklarından biri OSI ve TCP/IP modellerinin ilişkisidir:
1. **OSI Referans Modeli (Open Systems Interconnection):**
   - 1980'lerde ISO (International Organization for Standardization) tarafından geliştirilmiştir.
   - **Kavramsal ve Mimari Bir Standarttır.** Ağ iletişiminin hangi aşamalardan geçmesi gerektiğini 7 katmanda eksiksiz ve teorik olarak tanımlar.
   - Eğitimde, standart geliştirmede ve güvenlik mimarisi tasarlamada bir "ortak dil" olarak kullanılır (Örn: "Katman 3 Güvenlik Duvarı", "Katman 7 WAF").
2. **TCP/IP Modeli (İnternet Protokol Kümesi):**
   - 1970'lerde ABD Savunma Bakanlığı (DARPA / ARPANET) tarafından geliştirilmiştir.
   - **Uygulamalı ve Yaşayan Bir Protokol Takımıdır.** İnternetin üzerinde çalıştığı gerçek dünya modelidir.
   - OSI'nin üst üç katmanını (Uygulama, Sunum, Oturum) tek bir **Uygulama Katmanı** altında birleştirir; alt iki katmanını (Veri Bağlantısı ve Fiziksel) ise **Ağ Erişimi (Network Access / Link)** olarak konsolide eder.

---

## 3. 7 Katmanlı OSI Modeli ve PDU (Protokol Veri Birimi)

Her katman, üstündeki katmandan aldığı veriye kendi başlık (Header) bilgilerini ekleyerek yeni bir veri birimi oluşturur. Bu birimlere **PDU (Protocol Data Unit)** denir:

| Katman No | Katman Adı | PDU Adı | Tipik Protokoller | Temel Görevi |
|---|---|---|---|---|
| **7** | **Uygulama (Application)** | Data (Veri) | HTTP, DNS, SSH, SMTP | Kullanıcı veya uygulama ile doğrudan arayüz. |
| **6** | **Sunum (Presentation)** | Data (Biçim/Şifre) | TLS, SSL, JPEG, ASCII | Verinin formatlanması, şifrelenmesi ve sıkıştırılması. |
| **5** | **Oturum (Session)** | Data (Oturum) | TLS Session, RPC, NetBIOS | İki uç nokta arasındaki bağlantı oturumunun idaresi. |
| **4** | **Taşıma (Transport)** | **Segment** (TCP) / Datagram (UDP) | TCP, UDP, SCTP, QUIC | Uçtan uca güvenilir/hızlı veri iletimi ve port yönetimi. |
| **3** | **Ağ (Network)** | **Packet** (Paket) | IPv4, IPv6, ICMP, IPsec | Mantıksal adresleme (IP) ve yönlendirme (Routing). |
| **2** | **Veri Bağlantısı (Data Link)** | **Frame** (Çerçeve) | Ethernet, 802.11 Wi-Fi, ARP | Aynı yerel ağdaki (L2) donanımlar arası MAC iletimi. |
| **1** | **Fiziksel (Physical)** | **Bit** (Sinyal) | Bakır RJ45, Fiber, Radyo | Bitlerin elektriksel, optik veya radyo dalgasına dönüşümü. |

---

## 4. Kapsülleme (Encapsulation) Süreci: Bir HTTPS İsteğinin Yolculuğu

Bir kullanıcının tarayıcısından kurumsal API'ye gönderilen `GET /api/v1/auth/session` isteği şu kapsülleme adımlarından geçer:

```
[Katman 7: Uygulama]     GET /api/v1/auth/session HTTP/2
                                     |
                                     v
[Katman 6: Sunum]        TLS 1.3 ile Şifrelenmiş Kayıt (AES-256-GCM)
                                     |
                                     v
[Katman 5: Oturum]       Oturum ID ve Bağlantı Durumu Eşleşmesi
                                     |
                                     v
[Katman 4: Taşıma]       [TCP Başlığı | Kaynak Port: 52144 -> Hedef Port: 443 | PSH, ACK] + [Veri]
                                     |
                                     v
[Katman 3: Ağ]           [IP Başlığı | Kaynak IP: 192.168.1.105 -> Hedef IP: 104.21.35.88] + [TCP Segment]
                                     |
                                     v
[Katman 2: Veri Bağ.]    [Ethernet Başlığı | Kaynak MAC -> Ağ Geçidi MAC] + [IP Paketi] + [FCS CRC32 Kuyruğu]
                                     |
                                     v
[Katman 1: Fiziksel]     01010110... Elektriksel Sinyaller (1000BASE-T Bakır Kablo)
```

Hedef sunucuya ulaşıldığında bu süreç tam tersi yönde **Kapsül Açma (Decapsulation)** olarak işler:
1. Donanım kartı (NIC) bitleri alır, Ethernet çerçevesine dönüştürür.
2. CRC32 sağlama toplamı kontrol edilir; hata yoksa Ethernet başlığı atılır ve IP paketi çekirdeğe verilir.
3. Çekirdek hedef IP'yi doğrular, IP başlığını atar ve TCP segmentini taşıma katmanına sunar.
4. TCP sıralama (sequence) ve port (443) kontrolünü yapar, başlığı sıyırır ve TLS sürecine iletir.
5. TLS katmanı oturum anahtarlarıyla şifreyi çözer.
6. Web sunucusu (Nginx/Apache) saf `GET` isteğini alarak işler.

---

## 5. Katman Katman Siber Güvenlik Saldırı ve Savunma Haritası

Siber güvenlik uzmanları için her katman, farklı bir **Saldırı Vektörü (Attack Vector)** ve farklı bir **Savunma Mekanizması (Defense Mechanism)** demektir:

| Katman | Olası Saldırı Tehditleri | Uygulanan Savunma Kontrolleri |
|---|---|---|
| **Katman 7 (Uygulama)** | SQL Injection, XSS, API suistimali, Brute-Force | Web Application Firewall (WAF), Girdi Doğrulama, Rate Limiting |
| **Katman 6 (Sunum)** | SSL Stripping, Eski Şifre Paketi İstismarı (POODLE, BEAST) | TLS 1.3 Zorunluluğu, HSTS, Güçlü Şifre Kümeleri (AES-GCM/CHACHA20) |
| **Katman 5 (Oturum)** | Session Hijacking, Man-in-the-Middle (MitM) | Güvenli Çerez Bayrakları (Secure, HttpOnly, SameSite), Kısa Oturum Ömrü |
| **Katman 4 (Taşıma)** | TCP SYN Flood, Port Taraması (SYN Scan), RST Enjeksiyonu | SYN Cookies, Stateful Firewall, Port Knocking, Rate Limiting |
| **Katman 3 (Ağ)** | IP Spoofing, Smurf Saldırısı, BGP Route Hijacking | RPF (Reverse Path Forwarding), IPsec, Alt Ağ Yönlendirme ACL'leri |
| **Katman 2 (Veri Bağ.)** | ARP Zehirlenmesi (ARP Spoofing), MAC Flooding, VLAN Hopping | Dynamic ARP Inspection (DAI), Port Security, 802.1X Ağ Kimlik Denetimi |
| **Katman 1 (Fiziksel)** | Kablo Dinleme (Wiretapping), Sinyal Karıştırma (Jamming) | Fiziksel Kilitli Sunucu Odaları, Ekranlı Kablolama (STP/FTP), Port İptali |

---

## 6. Usta-Çırak İpuçları ve Laboratuvar Notu

> **Usta Diyor ki:**  
> *"Evlat, bir güvenlik ihlali yaşandığında ilk soru şudur: 'Hangi katmandayız?'  
> Eğer saldırgan ARP zehirliyorsa, sen sunucuya gidip TLS ayarı yaparak o saldırıyı durduramazsın; çünkü sorun Katman 2'dedir.  
> Eğer saldırgan SQL Injection yapıyorsa, güvenlik duvarında IP engellemek geçici bir pansumandır; asıl sorun Katman 7'dedir.  
> Bu yüzden bir güvenlik mühendisi paketin başlığını eline aldığında, MAC adresinden HTTP payload'una kadar her baytın hangi katmana ait olduğunu bir cerrah titizliğiyle teşhis edebilmelidir. Bugün geliştirdiğin `osi_tcpip_packet_inspector.py` motoru, senin bu cerrahideki ilk neşterindir!"*
