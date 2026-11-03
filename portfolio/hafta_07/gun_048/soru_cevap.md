# Gün 048: Soru-Cevap ve Kavramsal Pekiştirme

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## Soru 1 (G048-SC1): ICMP Mekanizması, Hata/Denetim Mesajları ve Güvenlik Önemi

### Temel Mekanizma ve Güvenlik Önemi
İnternet Denetim Mesajı Protokolü (ICMP - RFC 792), IP protokolünün güvenilmez ve durumsuz (best-effort) yapısını tamamlamak amacıyla geliştirilmiş hata bildirim ve operasyonel denetim mekanizmasıdır. Ağda yönlendirilemeyen paketler, zaman aşımına uğrayan TTL değerleri, MTU boyutu uyuşmazlıkları ve erişilebilirlik testleri ICMP üzerinden iletilir:
1. **Teşhis ve Ağ Haritalama:** Echo Request (Type 8, Code 0) ve Echo Reply (Type 0, Code 0) temel ping döngüsünü oluşturur. Traceroute ise IP başlığındaki TTL alanını 1'den başlatıp artırarak yönlendiricilerin `Type 11 Code 0 (Time to Live exceeded in Transit)` hata mesajı dönmesini sağlar ve rota üzerindeki tüm cihazları keşfeder.
2. **Path MTU Discovery (PMTUD):** Ağda büyük paketlerin parçalanmadan taşınabilmesi için yönlendiricilerin döndüğü `Type 3 Code 4 (Fragmentation Needed and DF set)` mesajı, TCP oturumlarının kilitlenmesini önleyen en kritik denetim mekanizmasıdır.
3. **Güvenlik Boyutu ve Yanılgılar:** "Ping yanıtı vermeyen sistem kapalıdır veya güvendedir" varsayımı temel bir güvenlik yanılgısıdır. Bir güvenlik duvarı ICMP Echo isteklerini düşürse dahi, açık olan TCP/UDP portları üzerinden sistemin ayakta olduğu kolayca tespit edilebilir. Dahası, ICMP'nin veri taşıma kabiliyeti, saldırganlar tarafından güvenlik duvarlarını atlatıp veri sızdırmak amacıyla gizli kanal (covert channel) olarak suistimal edilebilir.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:** `portfolio/hafta_07/gun_048/ornek_veri/sample_icmp_packets.json` içerisinde yer alan 8 farklı ICMP paketi (Echo Request, Echo Reply, Destination Host/Port Unreachable, PMTUD Fragmentation Needed, TTL Exceeded, ICMP Redirect, Şüpheli Covert Channel paketi).
- **İşlem:**
  1. RFC 792 başlık yapısı ayrıştırılır (Tip, Kod, Checksum, Identifier, Sequence Number).
  2. RFC 1071 Bir'in Tümleyeni (1's complement) sağlama toplamı doğrulanır.
  3. Traceroute TTL tükenme simülasyonu çalıştırılır.
  4. 64 bayttan büyük yükler ve C2 anahtar kelimeleri taranarak tünelleme anomalisi tespit edilir.
- **Beklenen Çıktı:** 14 birim testin 0.05 saniyenin altında `PASSED` olması; Covert Channel ve Redirect paketlerinde anomali alarmlarının üretilmesi.
- **Negatif Kontrol:** Checksum hatası, tanımsız tip (Type 255), tip-kod uyuşmazlığı (Type 0 Code 5), negatif kimlik (-1) ve 8 bayttan kısa bozuk paketlerin `ICMPValidationError` ile yakalanması.

### Risk Analizi ve Tehdit Senaryoları
- **ICMP Tünelleme / Veri Sızıntısı (Covert Channel Data Exfiltration):** İç ağa sızan bir zararlının, giden TCP/UDP portları kapalıyken güvenlik duvarından izinli ICMP Echo isteklerinin payload alanına şirket sırlarını veya API anahtarlarını gömerek dışarı aktarması.
- **ICMP Redirect ile Rotalama Manipülasyonu (Type 5 MitM):** Yerel ağdaki bir saldırganın istemcilere sahte Redirect mesajları göndererek trafiği kendi üzerine çekmesi.
- **Black Hole Router Sorunu:** Yöneticinin ICMP'yi körlemesine kapatması sebebiyle PMTUD (Type 3 Code 4) paketlerinin engellenmesi ve büyük paketli TCP oturumlarının sebepsiz yere donması.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:**
  1. SIEM ve IDS (Suricata/Snort) üzerinde standart dışı büyüklükte (>64 bayt) Echo Request paketlerinin loglanması.
  2. Paket veri alanında şifreli entropi veya metin tabanlı C2 komutlarının (`CMD=`, `TOKEN=`) yakalanması.
- **Önleme:**
  1. **Derin Paket İnceleme (DPI):** Güvenlik duvarında ICMP payload boyutuna katı sınır (maksimum 64 bayt) getirilmesi.
  2. **Type 5 Redirect Engellemesi:** Hem sınır yönlendiricilerde hem de işletim sistemi çekirdeğinde ICMP Redirect kabulünün kapatılması.
  3. **PMTUD İzni:** Güvenlik duvarlarında `Type 3 Code 4` mesajlarına açıkça izin verilerek ağ sağlığının korunması.

---

## Soru 2 (G048-SC2): Bağımsız Laboratuvarın Girdisi, İşlemi, Beklenen Sonucu ve Negatif Kontrolü

### Temel Mekanizma ve Güvenlik Önemi
Ağ protokol analiz motorları, canlı işletim sistemi soketlerine veya harici kütüphanelere bağımlı olmaksızın, ikili düzeyde (binary) ICMP başlıklarını inşa edebilmeli, sağlama toplamlarını hesaplayabilmeli ve paketlerdeki anormallikleri matematiksel kesinlikle ortaya koyabilmelidir.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:** JSON formatında tanımlanmış 8 meşru/anormal paket şablonu ve 8 geçersiz negatif paket girdisi.
- **İşlem:**
  1. `build_icmp_packet` ile 8 baytlık başlık (Type, Code, Checksum=0, ID, Seq) ve payload birleştirilerek RFC 1071 checksum hesaplanır.
  2. `parse_and_analyze_icmp` ile ikili bayt dizisi çözülür; verinin toplamı üzerinden checksum'ın sıfırlandığı doğrulanır.
  3. `simulate_traceroute` ile kaynaktan hedefe doğru TTL artımı simüle edilir.
  4. Anomali kuralları (aşırı boyut, yönlendirme, zararlı kelime) işletilir.
- **Beklenen Çıktı:** 14 birim testin hatasız tamamlanması; Type 8 Code 0 için 97 baytlık paketin `Aşırı büyük ICMP Payload` ve `ICMP Tünelleme` alarmlarını tetiklemesi.
- **Negatif Kontrol:** 8 farklı geçersiz formatın (bozuk checksum, tanımsız tip 255, Type 0 Code 5, Type 8 Code 1, Type 11 Code 9, negatif ID, sequence > 65535, geçersiz IP) her birinin `ICMPValidationError` fırlatması ve `kanit/gercek/negatif_kontrol_sonuclari.txt` dosyasına kaydedilmesi.

### Risk Analizi ve Tehdit Senaryoları
Yetersiz başlık ve checksum denetimi:
- Hatalı veya saldırgan tarafından enjekte edilmiş sahte ICMP hata mesajlarının kabul edilerek meşru TCP oturumlarının erken sonlandırılmasına (Blind Connection Reset Zafiyeti) yol açar.
- Biçimsel kontrolleri yapılmayan tünelleme paketlerinin fark edilmeden kurum dışına gigabaytlarca veri kaçırmasına zemin hazırlar.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:** Uygulama seviyesinde checksum uyumsuzluğu ve format istisnalarının alarm olarak kaydedilmesi.
- **Önleme:** Ağ giriş noktalarında donanım tabanlı checksum offloading ve katı protokol doğrulama denetimlerinin uygulanması.

---

## Soru 3 (G048-SC3): Risk Oluşumu, Tespiti ve Savunma Kontrolleri

### Temel Mekanizma ve Güvenlik Önemi
Geleneksel paket filtreleyici güvenlik duvarları (Stateless Firewalls), ICMP paketlerini yalnızca başlığındaki IP ve Tip/Kod alanlarına bakarak geçirir; veri (payload) alanının içeriğini incelemez. Bu denetim eksikliği, saldırganların güvenlik duvarını tamamen aşarak iç ağdaki bir ajanla şifreli iletişim kurmasını mümkün kılar.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:** Saldırganın iç ağdan dışarıya veri kaçırmak için oluşturduğu 97 baytlık şifreli anahtar taşıyan sahte Echo Request paketi ve hedef yönlendirme manipülasyonu içeren Type 5 Redirect paketi.
- **İşlem:** Paketler derinlemesine taranır; payload boyutu (64 bayt eşiği) ve içerik analizi yapılır.
- **Beklenen Çıktı:** Her iki anormal paketin de güvenlik alarmı üretmesi, meşru paketlerin ise normal olarak işaretlenmesi.
- **Negatif Kontrol:** Sahte ve bozulmuş sağlama toplamına sahip paketlerin sisteme kabul edilmeden atılması.

### Risk Analizi ve Tehdit Senaryoları
1. **Gizli C2 İletişimi (Covert Command & Control):** Saldırgan, işletim sisteminin yerel ping komutunu veya özel bir ham soket aracını kullanarak C2 sunucusuyla tamamen ICMP üzerinden haberleşir; hiçbir TCP/UDP portu açmadığı için standart port tarayıcılar ve güvenlik duvarları tarafından fark edilmez.
2. **ICMP Flood / Ping of Death (DoS):** Hedef sisteme saniyede on binlerce Echo Request gönderilerek işlemci ve ağ bant genişliğinin tüketilmesi; veya 65.535 baytı aşan parçalanmış devasa paketlerle eski işletim sistemlerinin çökertilmesi.
3. **Yönlendirme Tablosu Zehirlemesi (ICMP Redirect Attack):** Yerel ağdaki saldırganın kurbana "Gateway'e gitmek için trafiği bana gönder" diyerek rota tablosunu zehirlemesi.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:**
  1. Ağ telemetrisinde (NetFlow / IPFIX) giden ICMP trafiğinde alışılmışın dışında yüksek bayt transferi ve oturum sürekliliği gözlenmesi.
  2. SOC alarmlarında `ICMP_TUNNEL_EXFILTRATION` veya `UNUSUAL_ICMP_PAYLOAD_SIZE` kurallarının tetiklenmesi.
- **Önleme:**
  1. **Yeni Nesil Güvenlik Duvarı (NGFW) ve DPI:** ICMP paketlerinin veri alanı incelenmeli; standart dışı boyut ve şüpheli veri taşıyan paketler bloklanmalıdır.
  2. **Hız Sınırlaması (Rate Limiting):** Sınır yönlendiricilerinde `rate-limit input icmp` kuralı ile saniyede izin verilen paket sayısı sınırlandırılmalıdır.
  3. **İstemci Sertleştirmesi:** İşletim sistemlerinde `net.ipv4.conf.all.accept_redirects = 0` yapılarak ICMP Redirect kabulü tamamen kapatılmalıdır.
  4. **Durum Denetimi (Stateful Filtering):** İçeriden başlatılmamış dış kaynaklı hiçbir Echo Reply paketine izin verilmemelidir.
