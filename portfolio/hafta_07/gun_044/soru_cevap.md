# G044 — Ethernet, MAC ve Çerçeve: Soru ve Çözüm Analizleri

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

---

## [G044-SC1] Katman 2 Adreslemesi: MAC ile IP Adreslerinin Görev Ayrımı

### Temel Kavram ve Güvenlik Mekanizması
Bilgisayar ağlarında veri aktarımı çift katmanlı bir adresleme hiyerarşisi üzerinden yürütülür:
1. **IP Adresi (Katman 3 - Ağ Katmanı):** Mantıksal ve hiyerarşik bir adrestir. Paketin dünya genelinde hangi ağa ve hangi nihai hedef bilgisayara gideceğini belirler (Uçtan uca adresleme).
2. **MAC Adresi (Katman 2 - Veri Bağlantısı Katmanı):** Donanımsal ve yerel bir adrestir. Paketin sadece aynı yerel yayın etki alanındaki (Broadcast Domain / LAN) komşu cihaza veya varsayılan ağ geçidine (Gateway) fiziksel olarak teslim edilmesini sağlar (Sekme sekme / Hop-by-hop adresleme).

Bir paket farklı ağlar arasında yönlendirilirken (Routing), kaynak ve hedef IP adresleri değişmez; ancak her yönlendirici (Router) sekmesinde Katman 2 başlığı sökülür ve yeni yerel ağın MAC adresleriyle yeniden çerçevelenir.

---

### Soru ve Didaktik Çözüm
**Soru:**  
"Ethernet, MAC ve çerçeve" bağlamında temel mekanizmayı ve güvenlik önemini açıkla. Neden "MAC adresleri bağlantı katmanında yerel iletimi adresler; IP adresiyle aynı yönlendirme rolünü görmez" ilkesini bilmek yerel ağ güvenliğinin temelidir?

**Didaktik Çözüm:**  
- **Mekanizma Farkı:** Eğer bir güvenlik uzmanı MAC adresinin internette yönlendirilebilir bir adres olduğunu varsayarsa, ağ sınırlarını yanlış kurar. Bir anahtar (switch), IP adresini bilmez; gelen çerçevenin hedef MAC adresine bakar ve dahili CAM (Content Addressable Memory) tablosunda o MAC hangi porta kayıtlıysa paketi sadece o porta iletir.
- **Güvenlik Önemi:** Katman 2 seviyesinde varsayılan bir kimlik doğrulama veya şifreleme yoktur. Saldırgan aynı fiziksel ağ kablosuna veya Wi-Fi ağına bağlandığı an, hedef cihazın MAC adresini taklit edebilir (MAC Spoofing) veya switch'i sahte adreslerle boğarak (MAC Flooding) trafiği kendi üzerine çekebilir. Bu ayrımı bilmek, ağ güvenliğinin sadece IP/güvenlik duvarı düzeyinde değil, switch portu seviyesinde de sıkılaştırılması gerektiğini gösterir.

---

### Savunma ve Tespit Kılavuzu
- **Tespit Mekanizmaları:**
  - `arp -a` veya `ip neigh`: Yerel ARP tablosundaki IP-MAC eşleşmelerini kontrol edin. Aynı MAC adresine sahip birden fazla IP adresi varsa ARP zehirlenmesi şüphesi doğar.
  - Switch üzerinde MAC tablosunu denetleyin: `show mac address-table`. Tek bir fiziksel portta anormal sayıda MAC adresi görülüyorsa MAC Flooding saldırısı gerçekleşiyor olabilir.
- **Savunma Stratejisi:**
  - Switch portlarında **Port Security** özelliğini devreye alarak port başına izin verilen MAC sayısını sınırlayın.
  - **Dynamic ARP Inspection (DAI)** ve **DHCP Snooping** kullanarak sahte MAC-IP eşleştirmelerini donanım seviyesinde engelleyin.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, IP adresi bir mektubun üzerindeki 'Şehir ve Posta Kodu' gibidir; MAC adresi ise mektubu elden teslim alan 'Postacının Kimlik Kartı' gibidir. Mektup İstanbul'dan Ankara'ya giderken posta kodu değişmez; ama mektubu taşıyan araçlar ve görevliler her transfer merkezinde değişir. Katman 2'yi korumazsan, postacı sahtesi çıkar ve mektubu daha şehirden çıkmadan çalar!"*

---

## [G044-SC2] PCAP ve Ethernet Çerçeve Alanlarının Etiketlenmesi: Bağımsız Doğrulama Döngüsü

### Temel Kavram ve Güvenlik Mekanizması
Bir Ethernet çerçevesi analizi; kontrollü girdi (frame JSON veya PCAP), deterministik işlem (bit seviyesinde ayrıştırma), gözlenebilir çıktı (ayrıntılı alan etiketleme) ve negatif kontrollerden oluşan bir doğrulama döngüsüne tabidir.

Standart bir Ethernet II çerçevesinde doğrulanması gereken temel alanlar:
- **Hedef MAC (6 Bayt):** Unicast, Multicast veya Broadcast ayrımı.
- **Kaynak MAC (6 Bayt):** Bireysel cihaz adresi; I/G biti kesinlikle 0 olmalıdır.
- **EtherType (2 Bayt):** Üst katman protokol belirteci (`0x0800` IPv4, `0x0806` ARP vb.).
- **Veri Yükü ve Dolgulama (46-1500 Bayt):** 46 baytın altındaki veriler için otomatik padding.
- **FCS (CRC-32, 4 Bayt):** Çerçeve bütünlük sağlama toplamı.

---

### Soru ve Didaktik Çözüm
**Soru:**  
Kendi PCAP veya sentetik veri setinde Ethernet başlığı alanlarını açıklamalarıyla etiketleyen bağımsız bir denetim motoru için girdiler, işlemler, beklenen çıktılar ve negatif kontroller nelerdir? Önceki günlerin dosyalarına bağımlılık neden yasaktır?

**Didaktik Çözüm:**  
- **Laboratuvar Girdisi:** `sample_ethernet_frames.json` dosyası. İçerisinde Unicast IPv4 (ETH-001), Broadcast ARP (ETH-002) ve 802.1Q VLAN etiketli (ETH-003) çerçeveler yer alır.
- **Laboratuvar İşlemi:** `ethernet_frame_analyzer.py` motoru; her bir çerçevenin MAC formatını, I/G ve U/L bitlerini, EtherType değerini ve asgari 64 bayt sınırını (padding dahil) doğrular.
- **Beklenen Çıktı:** `kanit/gercek/ethernet_cerceve_analiz_raporu.txt` ve `kanit/gercek/komut_ve_cikis.txt` dosyaları.
- **Negatif Kontroller:** 14 adet unittest (`test_ethernet_frame_analyzer.py`) ile doğrulanır:
  - Kaynak MAC adresinde I/G bitinin 1 olması (Multicast Source MAC) kural ihlali olarak reddedilir.
  - Onaltılık taban dışı MAC formatları (`00:1A:2B:3C:4D:ZZ`) yakalanır.
  - Hatalı EtherType (`0x08`) reddedilir.
  - 64 baytın altındaki dolgusuz cüce çerçeveler (Runt Frame) tespit edilir.
  - Eksik zorunlu alanlar yakalanır.
- **Bağımsızlık Şartı:** G044 modülü kendi veri seti ve test süiti ile bağımsız çalışır; böylece Katman 2 analiz motoru herhangi bir harici kütüphane veya önceki gün bağımlılığı olmaksızın test edilebilir.

---

### Savunma ve Tespit Kılavuzu
- **Wireshark Filtreleme Kuralları:**
  - Yalnızca Broadcast çerçeveleri yakalamak: `eth.dst == ff:ff:ff:ff:ff:ff`
  - Yalnızca Multicast çerçeveleri yakalamak: `eth.ig == 1 && eth.dst != ff:ff:ff:ff:ff:ff`
  - Geçersiz kaynak MAC tespiti: `eth.src[0] & 1` (Kaynakta I/G biti 1 olan anormal paketler).

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, geliştirdiğimiz denetim motorundaki `analyze_mac_address` fonksiyonuna iyi bak. İlk baytın en sağındaki bit 1 mi? Eğer kaynak MAC'te bu bit 1 çıkarsa, o paketi üreten ağ kartı standartları çiğnemiştir ya da bir saldırgan sahte paket enjekte ediyordur. Gerçek bir analist, sadece adresi okumaz; o adresin bitlerinin ne anlama geldiğini bilir!"*

---

## [G044-SC3] Katman 2 Risk Analizi: Hatalı Varsayımlar, Güvensiz Bağlantı ve Savunma Stratejisi

### Temel Kavram ve Güvenlik Mekanizması
Yerel ağlarda en yaygın güvenlik riski, **"Fiziksel olarak yerel ağa bağlı olan herkes yetkilidir ve dürüsttür"** şeklindeki hatalı varsayımdır. 

Bu varsayımın yol açtığı temel Katman 2 zafiyetleri şunlardır:
1. **CAM Tablosu Taşması (MAC Flooding):** Bir saldırganın switch portuna saniyede on binlerce rastgele sahte MAC adresi göndermesi. Switch hafızası dolduğunda, tüm portları birbirine bağlayan güvensiz bir Hub gibi çalışmaya başlar ve saldırgan tüm ağ trafiğini dinleyebilir.
2. **MAC Spoofing & Yetkisiz Erişim:** Statik MAC adresine izin veren bir filtrelemenin (MAC Filtering), saldırganın kendi adresini hedef MAC ile değiştirmesiyle saniyeler içinde aşılması.
3. **VLAN Atlama (VLAN Hopping):** Çift 802.1Q etiketi kullanarak yalıtılmış yönetim VLAN'ına yetkisiz paket gönderme.

---

### Soru ve Didaktik Çözüm
**Soru:**  
"Ethernet, MAC ve çerçeve" bağlamında risk nasıl oluşur? İzinli trafik alanları, protokol sırası ve negatif paket örneğiyle bu risk nasıl tespit edilir? Protokol doğrulaması, TLS ve segmentasyon ile savunma nasıl inşa edilir?

**Didaktik Çözüm:**  
- **Risk Oluşumu:** Katman 2 doğası gereği açık ve yayılmacıdır (Broadcast). Saldırgan yerel ağda hiçbir kimlik doğrulamasına tabi tutulmadan istediği MAC adresini kaynak göstererek çerçeve basabilir.
- **Tespit Yöntemi:**
  - *İzinli Trafik Alanları:* Switch portlarında izin verilen MAC adresleri önceden tanımlanır (Sticky MAC).
  - *Negatif Paket Örneği:* Kaynak adresi multicast olan çerçeveler veya portta tanımlı olmayan yabancı MAC adresleri güvenlik uyarısına dönüştürülür.
  - *CAM Tablosu Anomalisi:* Bir portta aniden yüzlerce yeni MAC belirmesi IDS tarafından alarm olarak yakalanır.
- **Savunma Mimarisi (Defense-in-Depth):**
  - *Port Security:* Port başına azami MAC sayısı (örneğin 1) belirlenir; ihlal anında port kilitlenir (`err-disable`).
  - *802.1X (EAP-TLS):* Fiziksel kablo takılsa dahi, kullanıcı sertifikası doğrulanmadan switch portu açılmaz.
  - *Segmentasyon ve TLS:* Katman 2 güvenliği ihlal edilse dahi, ağ VLAN'lara bölünerek saldırganın erişim alanı kısıtlanır; üst katmanda TLS 1.3 zorunlu kılınarak paket dinleme (sniffing) etkisiz hale getirilir.

---

### Savunma ve Tespit Kılavuzu
- **Switch Sıkılaştırma Komutları (Cisco IOS / Standart Managed Switch):**
  ```text
  interface GigabitEthernet0/1
   switchport mode access
   switchport port-security
   switchport port-security maximum 1
   switchport port-security violation shutdown
   switchport port-security mac-address sticky
  ```
- Bu komut dizisi, porta bağlanan ilk meşru cihazın MAC adresini kilitler; ikinci bir cihaz (veya MAC sahtelemesi) bağlandığı anda portu fiziksel olarak kapatır.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
> **Usta Diyor ki:**  
> *"Evlat, 'Bizim ofis çok güvenli, yabancı kimse giremez' diyen yöneticiye güvenme. Temizlik görevlisi, kargo çalışanı veya bir ziyaretçi boş bir Ethernet prizine cebinden çıkardığı küçük bir Raspberry Pi'yi takıverir. Eğer switch portunda Port Security ve 802.1X yoksa, o küçük kutu tüm şirket ağını dinler. Güvenlik binanın kapısında değil, switch'in portunda başlar!"*
