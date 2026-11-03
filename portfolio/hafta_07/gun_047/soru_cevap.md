# Gün 047: Soru-Cevap ve Kavramsal Pekiştirme

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## Soru 1 (G047-SC1): ARP Mekanizması, Yerel Ağ Komşuluğu ve Güvenlik Önemi

### Temel Mekanizma ve Güvenlik Önemi
Adres Çözümleme Protokolü (ARP - RFC 826), Katman 3 mantıksal IPv4 adreslerini Katman 2 fiziksel Ethernet MAC adreslerine eşleyen temel yerel ağ protokolüdür. Yerel bir ağ segmentinde (broadcast domain) iki düğümün haberleşebilmesi için, göndericinin hedef IP'nin hangi fiziksel MAC donanımına ait olduğunu bilmesi zorunludur. ARP, hedef MAC bilinmediğinde tüm ağa basılan bir Yayın İstek (Broadcast Request: `FF:FF:FF:FF:FF:FF`) ve ilgili IP'nin sahibi tarafından döndürülen Tekil Yanıt (Unicast Reply) ile çalışır.

Güvenlik açısından ARP:
1. **Durumsuz (Stateless) ve Kimlik Doğrulamasız Tasarım:** Protokolde şifreleme, dijital imza veya durum takibi yoktur. Bir ana bilgisayar, daha önce hiç ARP isteği göndermemiş olsa bile ağdan gelen bir ARP yanıtını koşulsuz kabul eder ve yerel önbelleğini (ARP Cache) günceller.
2. **Yerel Ağın Güvenlik Sınırı:** ARP yalnızca aynı yerel alt ağda (VLAN) çalışır; yönlendiricilerden dışarı geçemez. Ancak bir saldırgan yerel ağ segmentine bir kez sızdığında, ARP zehirlemesi ile ağ geçidini (Default Gateway) taklit ederek tüm trafiği kendi üzerine çekebilir (Man-in-the-Middle).
3. **Gratuitous ARP İstismarı:** Ağ kartı değişiklikleri ve IP çakışma kontrolü için tasarlanan karşılıksız (unsolicited) Gratuitous ARP paketleri, saldırganlar tarafından tüm ağın önbelleğini tek seferde zehirlemek amacıyla kötüye kullanılabilir.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:** `portfolio/hafta_07/gun_047/ornek_veri/sample_arp_tables.json` dosyasında yer alan meşru ARP önbellek kayıtları (Ağ geçidi, sunucu, istemci, broadcast, multicast) ve trafik olay dizisi (İstek, Yanıt, Sahte Yanıt, Zararlı Gratuitous ARP).
- **İşlem:**
  1. IP ve MAC adres formatları doğrulanarak önbelleğe dinamik/statik girişler eklenir.
  2. Gelen ARP paketleri işlenir; mevcut meşru MAC ile gelen MAC arasındaki tutarsızlıklar (MAC Flip) izlenir.
  3. Dynamic ARP Inspection (DAI) simülasyonu ile gelen paketler güvenilir DHCP Snooping tablosu ile doğrulanır.
  4. Tek bir MAC adresinin birden fazla farklı IP'yi sahiplenme durumu taranır.
- **Beklenen Çıktı:** 14 birim testin 0.05 saniyenin altında `PASSED` olması; sahte ağ geçidi anonsunun `DAI_DHCP_SNOOPING_VIOLATION` ve `ARP_CACHE_POISONING_MAC_FLIP` alarmları üreterek engellenmesi.
- **Negatif Kontrol:** `192.168.1.300` (oktet taşması), `00:1A:2B:3C:4D` (5 oktet MAC), `00:00:00:00:00:00` (geçersiz tekil MAC) ve `INVALID_OPCODE_99` (geçersiz opcode) girdilerinin `ARPValidationError` ile yakalanması.

### Risk Analizi ve Tehdit Senaryoları
- **Ortadaki Adam (Man-in-the-Middle - MitM) Saldırısı:** Saldırganın hem kurbana hem de varsayılan ağ geçidine sahte ARP paketleri göndererek iki yönlü iletişimi kendi arayüzü üzerinden geçirmesi.
- **Kimlik Bilgisi ve Oturum Çalma (Credential Harvesting / Session Hijacking):** Şifrelenmemiş HTTP, FTP, Telnet veya DNS sorgularının saldırgan tarafından okunması, değiştirilmesi ve DNS Spoofing ile sahte sitelere yönlendirilmesi.
- **Hizmet Reddi (Denial of Service - Blackholing):** Saldırganın ağ geçidi trafiğini dinlemek yerine doğrudan düşürmesi sonucu kurbanın internet bağlantısının tamamen kesilmesi.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:**
  1. SIEM veya arpmwatch araçlarında aynı IP için kısa zaman aralığında değişen MAC adresi alarmları (`MAC Flip Detected`).
  2. Ağda aşırı frekansta ve talep edilmemiş (unsolicited) Gratuitous ARP paketlerinin yakalanması.
- **Önleme:**
  1. **Dynamic ARP Inspection (DAI):** Anahtarlarda (Switch) DHCP Snooping veritabanıyla uyuşmayan sahte ARP yanıtlarının donanım seviyesinde atılması (DROP).
  2. **Statik ARP Kaydı:** Kritik sunucularda ağ geçidi MAC adresinin statik olarak sabitlenmesi.

---

## Soru 2 (G047-SC2): Bağımsız Laboratuvarın Girdisi, İşlemi, Beklenen Sonucu ve Negatif Kontrolü

### Temel Mekanizma ve Güvenlik Önemi
Ağ izleme ve analiz araçları, harici bir ağ kartına veya canlı ağ paketlerine bağımlı kalmadan, biçimsel kuralları tanımlanmış sentetik ARP tablolarını ve paket dizilerini ayrıştırabilmeli; meşru trafik ile saldırı modellerini hatasız ayırt edebilmelidir.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:** JSON formatında modellenmiş 5 önbellek girişi (dinamik, statik, broadcast, multicast) ve 4 farklı ARP olay kaydı.
- **İşlem:**
  1. `ARPCacheManager` sınıfı başlatılır ve güvenilir DHCP bağları tanımlanır.
  2. Girdilerdeki IP ve MAC formatları (Cisco noktalı, Windows tireli, standart iki noktalı) normalize edilir.
  3. Gelen paketler işlem koduna (Opcode) ve gönderici IP/MAC ikilisine göre denetlenir.
  4. İhlal durumunda `ARPSpoofingAlert` üretilerek detaylar raporlanır.
- **Beklenen Çıktı:** 14 birim testin (10 pozitif fonksiyonel test + 4 negatif doğrulama testi) hatasız tamamlanması; statik olarak kilitlenmiş bir IP kaydının dinamik saldırı paketiyle ezilemediğinin doğrulanması.
- **Negatif Kontrol:** 8 farklı geçersiz formatın (oktet > 255, eksik oktet, geçersiz hex, tamamen sıfır MAC, boş IP, boş MAC, boş arayüz, bilinmeyen opcode) her birinin `ARPValidationError` fırlatması ve `kanit/gercek/negatif_kontrol_sonuclari.txt` dosyasına kaydedilmesi.

### Risk Analizi ve Tehdit Senaryoları
Girdi doğrulama ve önbellek kilit mekanizması eksik olan yazılımlarda:
- Boş veya hatalı biçimlendirilmiş MAC adreslerinin önbelleği bozması sonucu ağ yığınının çökmesi (Kernel Panic / Network Stack Crash).
- Statik olarak tanımlanmış kurumsal sunucu eşlemelerinin dinamik saldırı paketleriyle ezilmesi (Cache Override Zafiyeti).

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:** Doğrulama istisnalarının ve format hatalarının uygulama hata loglarına düşmesi.
- **Önleme:** Girdi işleme aşamasında katı regex, oktet aralığı ve karakter seti doğrulaması uygulanması; statik önbellek girişlerinin dinamik paketlerle güncellenmesine çekirdek düzeyinde izin verilmemesi.

---

## Soru 3 (G047-SC3): Risk Oluşumu, Tespiti ve Savunma Kontrolleri

### Temel Mekanizma ve Güvenlik Önemi
Yerel ağlarda güvenlik duvarları (Firewall) genellikle alt ağlar (VLAN'lar) arasındaki Katman 3 trafiğini denetler; ancak aynı alt ağdaki Katman 2 komşuluk trafiğini doğrudan denetleyemez. Bu durum, yerel ağ segmentini saldırgan için en cazip yatay hareket (lateral movement) ve dinleme sahası haline getirir.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:** Saldırganın ağ geçidi (`192.168.1.1`) ve yerel sunucu (`192.168.1.10`) IP'lerini kendi MAC adresine bağlamak için yaydığı zehirli ARP Reply paketleri.
- **İşlem:** Paketler DAI kontrol noktasından geçirilir; meşru DHCP bağları ve önbellek geçmişiyle karşılaştırılır.
- **Beklenen Çıktı:** Sahte anonsların anında tespit edilmesi, kritik seviyeli alarmların üretilmesi ve paketin düşürülmesi.
- **Negatif Kontrol:** İhlal içeren sahte paketlerin önbelleği kirletemediğinin doğrulanması.

### Risk Analizi ve Tehdit Senaryoları
1. **SSL/TLS İndirgeme ve Oturum Ele Geçirme (SSL Stripping):** Saldırgan MitM konumunu aldıktan sonra kurbanın HTTPS bağlantı isteklerini şifresiz HTTP'ye indirgeyerek kullanıcı adı, parola ve oturum çerezlerini ele geçirir.
2. **DNS Zehirleme ile Sahte Yönlendirme:** Kurbanın yerel DNS sorgularını araya girerek sahte IP'lerle yanıtlar; kullanıcıları zararlı bankacılık veya oltalama (phishing) sitelerine yönlendirir.
3. **Yanal Ağ Sızması (Lateral Movement):** Güvenli kabul edilen bir kullanıcı bilgisayarını ele geçiren saldırgan, ARP zehirlemesi ile aynı VLAN'daki muhasebe veya veritabanı sunucusunun trafiğini izler.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:**
  1. Anahtarlarda (Switch) loglanan `%SEC-8-DYNAMIC_ARP_INSPECTION_VIOLATION` olayları.
  2. İstemcilerde `arp -a` komutu çalıştırıldığında ağ geçidi ile bir başka yerel cihazın aynı MAC adresine sahip olduğunun görülmesi.
- **Önleme:**
  1. **Dynamic ARP Inspection (DAI):** Anahtarların erişim portlarında DAI açılarak sahte ARP paketlerinin switch ASIC donanımında anında düşürülmesi.
  2. **Port Security:** Switch portunda izin verilen MAC adresi sayısının sınırlandırılması (`switchport port-security maximum 1`).
  3. **Özel VLAN (Private VLAN - PVLAN):** İstemci portlarının izole (isolated) modda çalıştırılarak aynı alt ağdaki cihazların birbirleriyle Katman 2 seviyesinde doğrudan konuşmasının engellenmesi.
  4. **Uçtan Uca Şifreleme (mTLS / IPsec):** Katman 2 dinlense dahi uygulama katmanında TLS 1.3 ve sertifika doğrulamasının (certificate pinning) zorunlu tutulması.
