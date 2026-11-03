# Gün 051: Soru-Cevap ve Kavramsal Pekiştirme (TCP Sıralama ve Yeniden İletim)

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## Soru 1 (G051-SC1): TCP Sıralama, Yeniden İletim Mekanizması ve Güvenlik Önemi

### Temel Mekanizma ve Güvenlik Önemi
TCP (RFC 793 ve RFC 9293), güvenilmez Katman-3 IP ağı üzerinde güvenilir ve sıralı bir bayt akışı (byte-stream) inşa etmek için Sıra Numaraları (Sequence Numbers), Kümülatif Onaylar (Cumulative ACK) ve Yeniden İletim (Retransmission) algoritmalarını kullanır:
1. **Sıra Numarası ve Kümülatif Onay:** Gönderilen her veri baytı bir sıra numarasına sahiptir. Alıcı taraf, kesintisiz olarak aldığı son baytın bir fazlasını ACK paketinde bildirir (`Next Expected Sequence`).
2. **Kayıp Tespiti ve Yeniden İletim:**
   - **RTO (Retransmission Timeout):** Gönderici belirli bir süre içinde ACK alamazsa zaman aşımı tetiklenir ve kayıp segment tekrar gönderilir.
   - **Fast Retransmit (Hızlı Yeniden İletim):** Aradaki bir segment kaybolup sonraki segmentler alıcıya ulaştığında, alıcı aynı onay numarasını yineler (Duplicate ACK). Gönderici peş peşe **3 Yinelenen Onay (Triple Duplicate ACK)** aldığında, RTO zaman aşımını beklemeden kayıp segmenti derhal tekrar iletir.
3. **Güvenlik Önemi ve Temel İlke:** "Yinelenen paketler ve yeniden iletimler tek başına bir siber saldırı değildir." Ağ gecikmesi (latency), hatlardaki paket seğirmesi (jitter), Wi-Fi sinyal bozulması veya çok yollu yönlendirme (multipath routing) meşru yeniden iletimlere (Spurious Retransmissions) yol açabilir. Bir SOC analistinin yeniden iletimleri DoS saldırısı sanarak hatalı engellemeler (false-positive blocking) yapmaması hayati önemdedir.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:** `portfolio/hafta_08/gun_051/ornek_veri/sample_retransmit_packets.json` içerisinde tanımlı 14 segmentlik TCP akışı (Segment 1 ve 2 normal iletim, Segment 3 kayıp, Segment 4, 5, 6 sıra dışı iletim, 3 Dup ACK, Fast Retransmit, Kümülatif Onay, Sıfır Pencere ve Blind RST saldırısı).
- **İşlem:**
  1. `TCPStreamSegment` ile bayt uzunlukları ve `next_seq` sınırları hesaplanır.
  2. `TCPFlowTracker` motoru ile sıralı veri, sıra dışı boşluklar (gaps), yinelenen onaylar ve Fast Retransmit tetiklenmesi adım adım yürütülür.
  3. Kayar pencere içi Blind RST enjeksiyonu ve Sıfır Pencere (Zero Window) kilitlenmesi analiz edilir.
- **Beklenen Çıktı:** 14 birim testin 0.05 saniyenin altında `PASSED` olması; 1 adet Fast Retransmit, 3 adet sıra dışı paket ve 2 adet güvenlik anomalisinin eksiksiz tespit edilmesi.
- **Negatif Kontrol:** Negatif yük uzunluğu (-50 bayt), 32-bit tamsayı taşması (Seq > 4294967295), negatif pencere boyutu (-1024), 16-bit pencere taşması (70000) ve geçersiz IP formatının `TCPSequenceError` ile engellenmesi.

### Risk Analizi ve Tehdit Senaryoları
- **Blind TCP Reset (RST) Injection:** Bir saldırganın istemci ile sunucu arasındaki aktif akışı koklamadan (veya kaba kuvvetle) tahmin ettiği bir Sequence numarasıyla sahte RST paketi enjekte etmesi. Geleneksel TCP yığınlarında, gelen RST pencere boyutu içindeyse oturum derhal düşürülür (BGP oturum koparma veya dosya transferi sabote etme).
- **Zero Window DoS (Window Squeeze):** Saldırgan istemcinin sunucuya veri talebi gönderip hemen ardından `Window=0` anons etmesi ve sunucuyu tampon belleğinde veriyi tutmaya zorlayarak kaynak tüketmesi.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:**
  1. SIEM ve IDS üzerinde `TCP Dup ACK` sayısının belirli bir bağlantıda aniden yükselmesi.
  2. Aktif bir TCP oturumu sırasında kaynak IP'si veya MAC adresi uyumsuz olan `RST` paketlerinin yakalanması.
- **Önleme:**
  1. **RFC 5961 TCP Sıkılaştırması:** Pencere içi gelen RST paketlerinde doğrudan oturumu kapatmak yerine karşı tarafa **Challenge ACK** gönderilerek oturum bütünlüğünün doğrulanması.
  2. **Agresif Zero Window Zaman Aşımları:** Sıfır pencerede bekleyen soketlerin `tcp_retries2` ve probe limitleriyle sınırlandırılması.

---

## Soru 2 (G051-SC2): Bağımsız Laboratuvarın Girdisi, İşlemi, Beklenen Sonucu ve Negatif Kontrolü

### Temel Mekanizma ve Güvenlik Önemi
TCP akış takip motorları, canlı paket yakalama aygıtlarına bağımlı olmaksızın, ikili düzeyde sıra ve onay numaralarını modelleyebilmeli, kayar pencere sınırlarını hesaplayabilmeli ve sıra dışı paket akışlarını sentetik test verileriyle doğrulayabilmelidir.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:**
  1. `sample_retransmit_packets.json`: 14 sıralı TCP paketi (Sıralı veri, Dup ACK zinciri, Fast Retransmit, Zero Window ve RST enjeksiyonu).
  2. `invalid_sequence_inputs.json`: 8 adet biçimsel negatif test senaryosu.
- **İşlem:**
  1. `TCPStreamSegment` ile Seq, Ack, Payload ve Window alanları doğrulanır.
  2. `TCPFlowTracker.process_segment()` fonksiyonu ile çift yönlü akışın kümülatif durumu güncellenir.
  3. `TCPSequenceRetransmitAnalyzer.load_and_analyze_json()` ile tüm akışlar otomatik olarak taranır.
  4. Analiz bulguları `kanit/gercek/tcp_siralama_ve_retransmit_raporu.txt` dosyasına Markdown olarak yazılır.
- **Beklenen Çıktı:** 
  - 14 birim testin 0.03 saniyede `14 passed` olarak tamamlanması.
  - Akış istatistiğinde 14 segment, 3 sıra dışı paket, 1 yeniden iletim, 1 Fast Retransmit olayı ve 2 güvenlik alarmının tam doğrulanması.
- **Negatif Kontrol:**
  - 8 farklı geçersiz girdinin (negatif payload, 32-bit seq taşması, 32-bit ack taşması, negatif window, window > 65535, port 0, bozuk IP, string timestamp) tamamının `TCPSequenceError` fırlatması ve `kanit/gercek/negatif_kontrol_sonuclari.txt` dosyasına "%100 DOĞRULAMA BAŞARILI" şeklinde kaydedilmesi.

### Risk Analizi ve Tehdit Senaryoları
Yetersiz sıra ve pencere denetimi:
- Güvenlik duvarının sıra dışı paket enjeksiyonlarını ve yetkisiz RST paketlerini filtreleyememesine, kritik VPN veya BGP tünellerinin üçüncü şahıslar tarafından düşürülmesine neden olur.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:** Wireshark'ta `tcp.analysis.retransmission`, `tcp.analysis.duplicate_ack` ve `tcp.flags.reset == 1` filtreleriyle trafik anomalilerinin incelenmesi.
- **Önleme:** Durum denetimli güvenlik duvarlarında (Stateful Firewall) TCP Sequence Window Tracking mekanizmasının aktif edilmesi.

---

## Soru 3 (G051-SC3): Risk Oluşumu, Tespiti ve Savunma Kontrolleri

### Temel Mekanizma ve Güvenlik Önemi
TCP sıra numaraları tahmin edilebilir olduğunda veya pencere sınırları katı denetlenmediğinde, saldırganlar oturumu koparabilir (RST Injection), yetkisiz veri enjekte edebilir (TCP Data Injection) veya akış kontrolünü kötüye kullanarak sunucuyu kilitleyebilir (Zero Window DoS).

### Bağımsız Laboratuvar ve Doğrulama Adımları
Laboratuvarımızda bu risklerin simülasyonu ve tespiti kod düzeyinde gerçekleştirilmiştir:
1. **Risk 1: 3 Dup ACK Sonrası Hızlı Yeniden İletim:** Ağdaki paket kaybı sonucunda alıcının arka arkaya 3 kez aynı onay numarasını göndermesi ve göndericinin `HIZLI_YENIDEN_ILETIM_TETIKLENDI` olayı ile kayıp parçayı başarıyla kapatması doğrulanmıştır.
2. **Risk 2: Blind RST Oturum Koparma:** İstemci ile sunucu arasındaki aktif akışta, geçerli pencere aralığına denk düşen sahte bir RST segmenti enjekte edilmiş; motorumuz bunu `TCP_BLIND_RST_INJECTION_SALDIRISI` alarmı ile KRİTİK seviyede yakalamıştır.
3. **Risk 3: Sıfır Pencere Kilitlenmesi:** Alıcının `Window=0` anons etmesiyle sunucu akışının dondurulması `TCP_ZERO_WINDOW_DOS_RISKI` ile tespit edilmiştir.

### Risk Analizi ve Tehdit Senaryoları
- **BGP ve Veritabanı Oturum Koparma Saldırısı:** İnternet servis sağlayıcıları arasındaki BGP yönlendirme oturumları TCP 179 portu üzerinden çalışır. Bir saldırgan BGP komşuluğuna sahte RST paketleri enjekte ederek yönlendirme tablolarını düşürebilir ve geniş çaplı internet kesintilerine yol açabilir.
- **Hatalı Güvenlik Alarmları (Alert Fatigue):** Meşru yeniden iletimlerin saldırı sanılarak engellenmesi, kullanıcıların web sitelerine veya kurumsal sunuculara erişimini engelleyerek iş sürekliliğini bozar.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:**
  1. Ağ izleme araçlarında normal TCP yeniden iletim oranının (%1-2) aniden %20'lerin üzerine çıkması.
  2. BGP ve kritik TCP oturumlarında sebepsiz RST bayraklı kapanışların loglanması.
- **Önleme:**
  1. **RFC 5961 Challenge ACK:** Beklenmeyen RST paketlerinde oturumu kapatmadan önce karşı tarafa teyit ACK'i yollanması.
  2. **TCP MD5 / AO (Authentication Option):** BGP ve kritik sunucu oturumlarında TCP başlığına kriptografik imza (RFC 2385 / RFC 5925) eklenmesi.
  3. **IPsec / TLS Kriptolama:** Katman-4 TCP verisinin Katman-3 IPsec veya Katman-7 TLS ile şifrelenerek üçüncü taraflarca okunmasının ve taklit edilmesinin önlenmesi.
