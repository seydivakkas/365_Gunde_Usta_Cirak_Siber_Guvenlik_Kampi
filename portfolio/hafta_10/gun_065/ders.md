# G065: Hafta 10 Gün 65 — Follow TCP Stream ve Yeniden Birleştirme (TCP Stream Reassembly)
**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*

---

## 1. Usta-Çırak Girişi: TCP Bir "Paket" Değil, Kesintisiz Bir "Bayt Akışı"dır

Evlat, IP katmanında ağ dünyası bağımsız paketlerden (datagram) oluşur; her paket farklı yollardan gidebilir, gecikebilir veya kaybolabilir. Ancak bir uygulama (web tarayıcı, veritabanı istemcisi, SSH istemcisi) paketlerle değil, bir dosya okur gibi **kesintisiz bir bayt akışı (byte stream)** ile konuşmak ister.

İşte TCP'nin (Transmission Control Protocol) mucizesi budur: Parçalanmış, sırası bozulmuş, yinelenmiş ve kaybolmuş IP paketlerini alır; alıcı tarafta bunları milimetrik bir hassasiyetle yan yana dizerek tek ve bütün bir veri akışı haline getirir.

Wireshark'ta bir pakete sağ tıklayıp **"Follow TCP Stream"** dediğinde gördüğün o temiz istemci-sunucu diyaloğu (istemci kırmızı, sunucu mavi), arka planda devasa bir **TCP Yeniden Birleştirme (Reassembly) Motoru** tarafından inşa edilir. Bugün bu motorun iç yapısını, sıra dışı segment arabelleklerini ve IDS atlatmaya yönelik örtüşme saldırılarını derinlemesine inceleyeceğiz.

---

## 2. TCP Sıra Numarası (Sequence Number) Matematiği

TCP'de sıra numarası paketleri değil, **her bir baytı** numaralandırır.

1. **Başlangıç Sıra Numarası (ISN - Initial Sequence Number):**
   Bağlantı kurulurken istemci ve sunucu rastgele bir ISN seçer ($ISN_c$ ve $ISN_s$).
   - İstemci SYN gönderir: $SEQ = ISN_c$ (Örn: 1.000.000). SYN bayrağı sanal olarak 1 bayt tüketir; veri için bir sonraki beklenen sıra $1.000.001$ olur.
   - Sunucu SYN-ACK döner: $SEQ = ISN_s$ (Örn: 2.000.000), $ACK = 1.000.001$.
   - İstemci ACK döner: $SEQ = 1.000.001$, $ACK = 2.000.001$.

2. **Göreceli Sıra Numaraları (Relative Sequence Numbers):**
   Wireshark, analistlerin 10 haneli devasa sayıları zihinsel olarak takip etmesini kolaylaştırmak için $SEQ_{\text{rel}} = SEQ - ISN$ formülünü kullanır. Böylece akış her iki yönde de 0'dan başlar.

3. **Bayt Yükü İlerlemesi:**
   $SEQ = 1.000.001$ olan bir segment $38$ bayt veri taşıyorsa, bir sonraki segmentin sıra numarası tam olarak $1.000.001 + 38 = 1.000.039$ olmak zorundadır.

---

## 3. Yeniden Birleştirme Motorunun 3 Temel Durumu

Birleştirici motor, gelen her segment için şu üç durumdan birini işletir:

### Durum 1: Sıralı Segment (In-Order)
- Koşul: $SEQ == Expected\_SEQ$
- Eylem: Segmentin taşıdığı veri yükü doğrudan akış dizesine eklenir. $Expected\_SEQ$ veri boyutu kadar artırılır. Hemen ardından arabellekte bekleyen sıra dışı segmentlerin kilidi açılmış mı diye arabellek taranır (`_flush_out_of_order_buffer`).

### Durum 2: Gecikmiş / Kopya Segment (Retransmission / Overlap)
- Koşul: $SEQ < Expected\_SEQ$
- **A) Tam Kopya (Full Duplicate):** $SEQ + Len \le Expected\_SEQ$ ise paket daha önce zaten birleştirilmiştir. Ağdaki bir yeniden iletimdir (retransmission). Sayaç artırılır ve paket sessizce atılır (drop).
- **B) Kısmi Örtüşme (Partial Overlap):** $SEQ + Len > Expected\_SEQ$ ise segmentin baş tarafı önceden gelmiş, ancak kuyruk tarafında yeni veri bulunmaktadır. Motor örtüşen kısmı inceler ve kalan yeni veriyi akışa ekler.

### Durum 3: Sıra Dışı Segment (Out-of-Order - OOO)
- Koşul: $SEQ > Expected\_SEQ$
- Eylem: Segment henüz eklenemez çünkü arada eksik baytlar (gap) vardır! Segment, `out_of_order_buffer` kuyruğuna alınır. Aradaki eksik parçalar gelip $Expected\_SEQ$ bu segmentin sırasına ulaştığı anda arabellekten otomatik olarak çekilip akışa monte edilir.

---

## 4. Örtüşen Segmentler ve Saldırı Tespiti (Ptacek & Newsham 1998)

Siber güvenlik tarihinde Thomas Ptacek ve Timothy Newsham'ın 1998 tarihli çığır açan makalesi (*Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection*), TCP yeniden birleştirme mekanizmalarındaki farklılıkların nasıl IDS atlatmak için kullanıldığını göstermiştir.

Saldırgan aynı sıra numarası aralığına iki farklı veri gönderir:
- Segment 1 ($SEQ=1000, Len=9$): `USER_ROOT`
- Segment 2 ($SEQ=1005, Len=8$): `GUEST_NO` (Örtüşen kısım: `_ROOT` yerine `GUEST`)

Farklı işletim sistemleri farklı birleştirme politikalarına sahiptir:
- **First-Write-Wins (BSD / Cisco):** İlk gelen segment geçerlidir, sonrakinin örtüşen kısmı atılır.
- **Last-Write-Wins (Linux / Windows):** Son gelen segment eskisinin üzerine yazar.

Bir IDS/IPS sistemi bu politikayı hedef sunucuyla birebir eşleştiremezse, IDS zararsız bir komut görürken hedef sunucu saldırganın enjekte ettiği zararlı komutu çalıştırır. Geliştirdiğimiz motor, örtüşen parçalarda veri çelişkisi saptadığında derhal `OverlappingPayloadConflictError` fırlatarak bu saldırıyı tespit eder.

---

## 5. Mühendislik Çıkarımları

Wireshark "Follow TCP Stream", adli bilişimde (Digital Forensics) şu avantajları sağlar:
1. Paket başlıklarının gürültüsünü temizleyerek yalnızca uygulama katmanı verisine (HTTP istek/yanıt, SMTP e-posta gövdesi, FTP komutları, veritabanı sorguları) odaklanmayı sağlar.
2. Sıra dışı gelen paketlerin insan hatasıyla yanlış yorumlanmasını engeller.
3. TCP seviyesindeki bozulmaları, ağ gecikmelerini ve yeniden iletim oranlarını (`retransmission_count`) net bir şekilde ortaya koyar.
