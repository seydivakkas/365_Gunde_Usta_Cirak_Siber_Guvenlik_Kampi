# Gün 050: TCP Üçlü El Sıkışma, Bayraklar ve Bağlantı Güvenliği

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## 1. Ustanın Girişi: Katman-4 Taşıma Dünyasına Hoş Geldin

Evlat, toplan bakalım. 7. Hafta boyunca seninle yerel ağın zeminini, Ethernet çerçevelerini, IP adresleme mimarisini, ARP çözümlemesini ve ICMP teşhis mekanizmalarını inceledik. Orada kurduğumuz Katman-3 dünyası (IP protokolü) "en iyi gayret" (best-effort) esasına göre çalışır; yani paket kaybolmuş mu, sırası mı karışmış, hedefe ulaşmış mı hiç umursamaz.

İşte bugün 8. Haftaya, **Katman-4 Taşıma Katmanı'nın (Transport Layer)** zirvesine adım atıyoruz: **TCP (Transmission Control Protocol - RFC 793 ve RFC 9293)**.

İnternet'i ayakta tutan web siteleri (HTTP/HTTPS), veritabanı bağlantıları, dosya transferleri (SFTP), e-postalar (SMTP/IMAP) ve güvenli kabuk oturumları (SSH) bütünüyle TCP'nin sağladığı güvenilir, sıralı ve çift yönlü (full-duplex) veri akışına güvenir. Bu güvenin temel taşı ise iki ucun birbiriyle tanışmasını ve senkronize olmasını sağlayan **Üç Aşamalı El Sıkışma (Three-Way Handshake)** mekanizmasıdır.

Bir güvenlik uzmanı TCP el sıkışmasını ve bayraklarını avucunun içi gibi bilmezse; ne bir port taramasını analiz edebilir, ne SYN Flood saldırısını durdurabilir, ne de oturum kaçırma (TCP Session Hijacking) zafiyetini anlayabilir. Can kulağıyla dinle.

---

## 2. TCP Başlığı Anatomisi (RFC 793 / RFC 9293)

TCP segmenti, Katman-3 IP paketinin veri (payload) kısmına yerleşir. Standart bir TCP başlığı en az **20 bayttır** (seçenekler varsa 60 bayta kadar uzayabilir).

Geliştirdiğimiz motorda ikili (binary) düzeyde modellediğimiz bu 20 baytın içinde ne var, tek tek inceleyelim:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Kaynak Port          |          Hedef Port           |  (0-3. Baytlar)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sıra Numarası (Sequence Number)        |  (4-7. Baytlar)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Onay Numarası (Acknowledgment Number)      |  (8-11. Baytlar)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Veri | Ayrılmış|C|E|U|A|P|R|S|F|                             |
| Ofseti|  Alan   |W|C|R|C|S|S|Y|I|       Pencere Boyutu        |  (12-15. Baytlar)
| (4b)  |  (4b)   |R|E|G|K|H|T|N|N|        (Window Size)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Sağlama Toplamı (Checksum)|   Acil Durum İşaretçisi     |  (16-19. Baytlar)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Seçenekler (İsteğe Bağlı - MSS vb.)        |  (20-60. Baytlar)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Kritik Alanların Görevleri:
1. **Kaynak ve Hedef Port (16'şar Bit):** İletişimin hangi uygulamalar arasında yürüdüğünü belirler (Örn. Kaynak: 54321, Hedef: 80 HTTP).
2. **Sıra Numarası (Sequence Number - 32 Bit):** Gönderilen baytların akıştaki yerini takip eder. İlk bağlantıda rastgele bir **ISN (Initial Sequence Number)** atanır.
3. **Onay Numarası (Acknowledgment Number - 32 Bit):** Alıcı tarafın bir sonraki adımda almayı beklediği bayt numarasını gösterir. Yalnızca ACK bayrağı set edildiğinde anlamlıdır.
4. **Veri Ofseti (Data Offset - 4 Bit):** Başlığın kaç adet 32-bitlik kelimeden oluştuğunu söyler. Minimum değer `5`'tir ($5 \times 4 = 20\text{ bayt}$).
5. **Kontrol Bayrakları (Flags - 8 Bit):**
   - **SYN (Synchronize):** Bağlantıyı başlatır, ISN değerini senkronize eder.
   - **ACK (Acknowledgment):** Onay numarasının geçerli olduğunu belirtir.
   - **FIN (Finish):** Göndericinin veri gönderimini bitirdiğini, oturumu kapatmak istediğini bildirir.
   - **RST (Reset):** Bağlantıyı zorla sıfırlar veya reddeder (Kapalı porta paket geldiğinde döner).
   - **PSH (Push):** Tamponda (buffer) beklemeden veriyi derhal uygulama katmanına teslim et emridir.
   - **URG (Urgent):** Acil durum işaretçisinin geçerli olduğunu gösterir.
6. **Pencere Boyutu (Window Size - 16 Bit):** Alıcının tamponunda ne kadar boş yer kaldığını söyler (Akış Kontrolü - Flow Control).
7. **Sağlama Toplamı (Checksum - 16 Bit):** IPv4 Sahte Başlığı (Pseudo Header) + TCP Başlığı + Veri üzerinden hesaplanır.

---

## 3. Üç Aşamalı El Sıkışma (Three-Way Handshake) Yaşam Döngüsü

İki bilgisayar TCP üzerinden konuşmaya başlamadan önce mutlaka bir el sıkışma protokolü yürütür.

```
İSTEMCİ (Client)                                          SUNUCU (Server)
[SYN_SENT]                 1. ADIM: SYN                     [LISTEN]
   |  --------------------------------------------------------> |
   |  Flags: SYN=1, ACK=0                                      |  (Kayıt açılır:
   |  Seq = ISN_c (Örn: 1000), Ack = 0                         |   SYN_RECEIVED)
   |  Payload: 0 Bayt                                          |
   |                                                           |
   |                 2. ADIM: SYN-ACK                          |
[ESTABLISHED] <------------------------------------------------ |
   |  Flags: SYN=1, ACK=1                                      |
   |  Seq = ISN_s (Örn: 5000), Ack = ISN_c + 1 (1001)          |
   |  Payload: 0 Bayt                                          |
   |                                                           |
   |                 3. ADIM: ACK                              |
   |  --------------------------------------------------------> | [ESTABLISHED]
   |  Flags: SYN=0, ACK=1                                      |  (Bağlantı kuruldu,
   |  Seq = 1001, Ack = ISN_s + 1 (5001)                       |   uygulama verisine
   |  Payload: 0 Bayt                                          |   hazır)
```

### Ustanın Altın Kuralı:
> **Handshake paketleri uygulama verisi taşımaz!**
> 1. ve 2. adımdaki `SYN` bayrağı, mantıksal olarak 1 baytlık sıra numarası tüketir. Bu yüzden sunucu `Ack = ISN_c + 1` döner; istemci de 3. adımda `Ack = ISN_s + 1` yanıtı verir. Ancak bu paketlerin yük (payload) boyutu kesinlikle **0 bayttır**. Eğer bir SYN paketinde veri yükü görürsen, orada sıra dışı bir durum (örneğin TFO - TCP Fast Open veya bir saldırı aracı anomalisi) vardır!

---

## 4. Sıra Numarası Matematiği ve ISN Güvenliği

Neden her bağlantıda Sıra Numarası (Seq) `0`'dan başlamaz da rastgele bir ISN (Initial Sequence Number) seçilir?

Geçmişte (1990'larda) işletim sistemleri ISN değerlerini basit bir zaman sayacı veya sabit artışlarla üretiyordu. 1995 yılında Kevin Mitnick, Tsutomu Shimomura'nın sistemine saldırırken bu açığı kullandı (**TCP Blind Spoofing / Hijacking**):
1. Saldırgan güvenilir bir sunucunun IP'sini taklit etti (IP Spoofing).
2. Hedef sunucuya sahte IP ile bir SYN gönderdi.
3. Sunucunun gönderdiği SYN-ACK cevabı sahte IP'ye gittiği için saldırgan cevabı göremedi (Kör Saldırı).
4. Ancak sunucunun seçeceği `ISN_s` değerini matematiksel olarak tahmin edebildiği için, 3. adımdaki `ACK (Seq=ISN_c+1, Ack=Tahmin_Edilen_ISN_s+1)` paketini üreterek sunucuya yolladı!
5. Sunucu el sıkışmanın tamamlandığını varsayarak oturumu açtı ve saldırganın sahte komutlarını çalıştırdı!

Bu felaketten sonra **RFC 6528** standardı getirildi. Günümüz modern işletim sistemleri ISN değerini kriptografik bir karma (HMAC/PRF) ve gizli bir çekirdek anahtarı (secret key) ile üretir:
$$\text{ISN} = M + F(\text{Kaynak IP}, \text{Hedef IP}, \text{Kaynak Port}, \text{Hedef Port}, \text{Gizli Anahtar})$$
Böylece saldırganın bir sonraki sıra numarasını tahmin etmesi imkansız hale getirilmiştir.

---

## 5. TCP Tabanlı Tehditler ve Saldırı Türleri

### 1. SYN Flood (Hizmet Engelleme / DoS)
Saldırgan sahte veya ulaşılamaz kaynak IP'lerle hedefe saniyede binlerce `SYN` paketi yağdırır. Sunucu her SYN için belleğinde bir TCB (Transmission Control Block) kaydı açar ve `SYN_RECEIVED` durumuna geçerek `SYN Backlog Queue` kuyruğuna koyar. Karşıdan hiçbir zaman 3. adımdaki `ACK` gelmediği için sunucunun kuyruğu dolar ve meşru kullanıcıların bağlantı talepleri düşürülür.

### 2. Port Tarama Teknikleri (Nmap Bayrak Hileleri)
- **Stealth SYN Taraması (`-sS`):** Saldırgan SYN atar, sunucu SYN-ACK dönerse portun açık olduğunu anlar; ancak el sıkışmayı tamamlamamak ve işletim sistemi loglarına düşmemek için derhal `RST` yollayarak bağlantıyı koparır.
- **XMAS Taraması (`-sX`):** `FIN + PSH + URG` bayrakları aynı anda set edilir (Noel ağacı gibi tüm ışıklar yanar). RFC 793 kuralına göre kapalı portlar `RST` dönerken açık portlar paketi sessizce düşürür.
- **NULL Taraması (`-sN`):** Hiçbir bayrak set edilmez (`Flags = 0`). Yine kapalı portlar RST döner, açık portlar tepkisiz kalır.
- **Kural Dışı Bayraklar (`SYN + FIN`):** Hem bağlantı kur hem bağlantı kapat demek bir mantık hatasıdır. Yalnızca tespit sistemlerini şaşırtmak için saldırganlarca üretilir.

---

## 6. Savunma Mimarisi: SYN Cookies ve Durum Denetimi

Saldırganların bu hilelerini engellemek için iki temel kale kapımız vardır:

1. **SYN Cookies (RFC 4987):**
   Sunucu bir SYN paketi aldığında **belleğinde hiçbir kayıt açmaz**. Sıra numarasını (`ISN_s`), istemcinin IP/port bilgileri, zaman damgası ve MSS değerini şifreleyerek üretir. İstemci 3. adımda `ACK` döndüğünde, sunucu bu onay numarasından cookie'yi doğrular; eğer matematik tutuyorsa oturum belleğini o an açar. Böylece SYN Flood saldırısı sunucunun belleğini tüketemez!
2. **Durum Denetimli Güvenlik Duvarı (Stateful Inspection):**
   Güvenlik duvarı tüm üçlü el sıkışma sürecini izler (Connection Tracking - `conntrack`). 3. adımdaki geçerli `ACK` paketi görülmeden oturum `ESTABLISHED` sayılmaz ve iç ağdaki sunuculara hiçbir veri segmentinin geçmesine izin verilmez.

---

## 7. Ustanın Öğüdü

Evlat, TCP el sıkışması ağın tokalaşmasıdır. Tokalaşırken karşındakinin gözünün içine bakacaksın; sırasına, onayına, bayrağına dikkat edeceksin. 

Bugün yazdığın motor, her paketin ikili matematiğini ve durum geçişlerini denetliyor. Bu mantığı iyi kavra; çünkü yarın TCP oturum sonlandırmayı (FIN/RST), akış kontrolünü ve TLS şifrelemesini bunun üzerine inşa edeceğiz!
