# GÜN 011: Soru & Cevap Bankası — Laboratuvar Ağ Sınırları

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Soru Sayısı](https://img.shields.io/badge/sorular-3%20Soru-blue?style=flat-square)
![Format](https://img.shields.io/badge/format-4%20B%C3%B6l%C3%BCml%C3%BC%20Kat%C4%B1%20Standart-success?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

### Soru 1 (G011-SC1): Laboratuvar ağ sınırları: Temel mekanizmayı ve güvenlik önemini açıkla.

#### 1. Kavramsal Açıklama (Analoji & Zihinsel Model)
Laboratuvar ağ sınırları; askeri bir denizaltının gövdesindeki **Su Geçirmez Çelik Bölmeler (Bulkheads) ve Bulaşıcı Hastalıklar Hastanesindeki Negatif Basınçlı Hava Kilitleridir (Airlocks)**. Denizaltı bir torpido ile vurulduğunda tüm gövde açık bir hangar olsaydı (Düz Ağ - Flat Network), su saniyeler içinde tüm bölmelere dolar ve gemi batardı. Oysa su geçirmez bölmeler kapatıldığında, hasar alan oda izole edilir ve denizaltı batmaktan kurtulur. Bir siber güvenlik laboratuvarında da kurban makineler (malware analiz ortamı), saldırı düğümleri (Kali) ve izleme sunucuları (SIEM) birbirinden VLAN'lar ve güvenlik duvarı sınırlarıyla ayrılmazsa; kurbanda patlatılan bir fidye yazılımı doğrudan şirketin veya evin fiziksel ağına sıçrayarak felakete yol açar.

#### 2. Güvenlik Mekanizması & Savunma Mimarisi
Ağ sınırları mimarisi 4 temel sütundan oluşur:
* **Mikro-Segmentasyon (VLAN İzolasyonu):** Ağ; Karantina (VLAN 66), Kırmızı Takım (VLAN 10), Mavi Takım / SIEM (VLAN 20) ve Yönetim (VLAN 99) olarak 4 bağımsız yayın alanına (broadcast domain) bölünür. ARP zehirlenmesi ve ağ koklama sınır ötesine geçemez.
* **Durum Takipli (Statefull Conntrack) Asimetrik Yönlendirme:** Güvenlik duvarı bağlantı durumlarını (`NEW`, `ESTABLISHED`, `RELATED`) takip eder. Saldırgandan kurbana doğru `NEW` bağlantılara izin verilirken; kurbandan saldırgana doğru yalnızca `ESTABLISHED,RELATED` paketler kabul edilir. Kurbandan dışarıya başlatılan hiçbir `NEW` oturuma izin verilmez (Tersine kabuk / Reverse Shell engeli).
* **DNS Sinkholing (Sahte Yanıtlayıcı):** Karantina bölgesinin dış DNS (8.8.8.8) sorguları bloke edilir; tüm 53 portu içerideki sahte DNS sunucusuna (INetSim / FakeNet) yönlendirilir. Zararlı yazılım canlı C2 sunucusuna asla ulaşamaz.
* **Sıfır Çıkış Rotası (Strict Egress Blackholing):** Karantina bölgesinin yönlendirme tablosunda internete (`0.0.0.0/0`) giden bir rota bulunmaz; dışarıya yönelen tüm kaçak paketler loglanır ve anında düşürülür (`DROP`).

#### 3. Saldırgan Perspektifi & İstismar Senaryosu
Saldırgan kurban makineyi exploit ettikten sonra komuta kontrol merkezine tersine bağlantı (Reverse Shell) açmak ister. Kurban makineden dışarıya TCP/4444 üzerinden bir paket fırlatır. Eğer laboratuvarda durum takipsiz bir güvenlik duvarı varsa veya çıkış (egress) serbestse; paket saldırganın dinleyicisine ulaşır ve tersine kabuk açılır. Ancak durum takipli (conntrack) ağ sınırımız bu paketi `state NEW` olarak yakalar, gelen oturumla ilişkili olmadığını tespit eder ve tek bir bayt bile dışarı sızdırmadan bağlantıyı çöpe atar.

#### 4. Gerçek Dünya Başarısızlık Senaryosu & Çıkarılan Ders
2017 yılında WannaCry fidye yazılımı salgını sırasında; bir antivirüs şirketinin genç araştırmacısı, analiz için zararlıyı şirket içi yerel ağa köprülenmiş (Bridged) bir sanal makinede çalıştırmıştır. Zararlı yazılım sanal makinenin dışına çıkmaya bile gerek duymadan, kurban sanal makinenin aynı ağda olduğu şirketin diğer test ve dosya sunucularına SMB (Port 445) üzerinden yayılmış ve onlarca sunucuyu şifrelemiştir.  
**Çıkarılan Ders:** Analiz ve patlatma laboratuvarları asla fiziksel ağa bağlanamaz ve düz bir ağda çalıştırılamaz. Mikro-segmentasyon ve sıkı ağ sınırları bir lüks değil, siber güvenliğin vazgeçilmez emniyet kilididir.

---

### Soru 2 (G011-SC2): Laboratuvar ağ sınırları: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

#### 1. Kavramsal Açıklama (Analoji & Zihinsel Model)
Bir baraj kapağının ve su tahliye kanallarının stres testini düşün: Girdi olarak su debisi ve kanal haritasını verirsin; işlem olarak kapakların su sızdırıp sızdırmadığını, geri tepme vanalarının ters yönde su akışını engelleyip engellemediğini denetlersin; beklenen sonuç barajın suyu tam kontrollü tutması ve taşkın olmamasıdır; negatif kontrol ise bilerek ters yönde tazyikli su verdiğinde baraj kapağının ters akışı sıfır toleransla mühürlemesidir. Laboratuvar ağ denetleyicimiz de ağ paketlerini aynı katılıkla test eder.

#### 2. Güvenlik Mekanizması & Savunma Mimarisi
Geliştirdiğimiz `lab_network_boundary_auditor.py` ve `test_lab_network_boundary_auditor.py` altyapısı bu 4 adımı şu standartlarda işletir:
* **Girdi (Input):** Laboratuvar ağ topolojisini, VLAN bölgelerini, CIDR alt ağlarını, DNS sinkhole ayarlarını ve güvenlik duvarı durum tablosunu içeren makinece okunabilir JSON dosyası (`laboratuvar_ag_topolojisi.json`).
* **İşlem (Process):** Denetim motorunun ağ sınırlarını 4 seviyede incelemesi:
  1. *Segmentasyon Analizi:* Ağın düz olup olmadığının (en az 3 bağımsız bölge) ve CIDR çakışmalarının denetimi.
  2. *Karantina Sızıntı Analizi:* Karantina bölgesinde doğrudan internet çıkışının (`0.0.0.0/0`) ve harici genel DNS (8.8.8.8) erişiminin engellendiğinin teyidi.
  3. *Güvenlik Duvarı Yönlendirme Analizi:* Varsayılan politikanın `FORWARD DROP` olduğunun ve durum takibinin (conntrack) aktifliğinin doğrulanması.
  4. *Tersine Kabuk Analizi:* Kurbandan saldırgana doğru `NEW` bağlantı kurallarının yasaklandığının teyidi.
* **Beklenen Sonuç (Expected Output):** Sertleştirilmiş `TOPOLOGY-SEC-01` profili için 100/100 güvenlik skoru, sıfır sızıntı bulgusu, "GÜVENLİ (MİKRO-SEGMENTE İZOLE LAB)" onay kararı ve üretime hazır `iptables_rules.sh` kural betiğinin üretilmesi.
* **Negatif Kontrol (Negative Control):** Kasıtlı olarak karantina bölgesine açık internet izni verildiğinde (`internet_cikis_izni=True`) veya kurbandan saldırgana `NEW` bağlantı kuralı eklendiğinde; sistemin anında 30-50 puan ceza keserek durumu "KRİTİK FELAKET" olarak raporlaması ve işlemi reddetmesidir.

#### 3. Saldırgan Perspektifi & İstismar Senaryosu
Saldırgan ele geçirdiği kurban makineden dışarıya doğru DNS Tünelleme yazılımı (`dnscat2`) çalıştırır. Eğer savunmacı kural setinde DNS sorgularını yerel sinkhole'a hapsetmemişse; saldırganın gizli verileri içeren DNS paketleri 8.8.8.8 üzerinden internetteki saldırgan alan adına kaçar. Negatif kontrol testimiz, bu DNS sızıntı kuralını daha test başlamadan yakalar ve engeller.

#### 4. Gerçek Dünya Başarısızlık Senaryosu & Çıkarılan Ders
Bir finans kuruluşunun siber tatbikatında kırmızı takım, kurban sunucuya sızdıktan sonra kurban sunucunun güvenlik duvarı kurallarında çıkış trafiğinin filtrelenmediğini (Egress Any Any Allow) keşfetmiştir. Kırmızı takım, kurban makineden doğrudan internetteki kendi dinleyicisine HTTPS tüneli açarak müşteri veri tabanını dışarıya aktarmış ve mavi takımı mağlup etmiştir.  
**Çıkarılan Ders:** Ağ sınırları çift yönlü düşünülmelidir. İçeriye girişi kapatıp dışarıya çıkışı açık bırakmak, pencereleri kilitleyip yangın merdivenini ardına kadar açık bırakmaya benzer.

---

### Soru 3 (G011-SC3): 'Laboratuvar ağ sınırları' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Kavramsal Açıklama (Analoji & Zihinsel Model)
Risk, bir akvaryumda pirana balığı ile süs balıklarını aynı cam fanusa koyup *"Umarım pirana acıkmaz"* diye beklemeye benzer. Düz bir ağda kurban zararlı ile analistin cihazlarını yan yana koymak piranayla süs balığını aynı suya atmaktır. Risk; ağın fiziksel veya mantıksal olarak cam panellerle (VLAN'lar) ayrılmamasından ve vanaların (güvenlik duvarı kurallarının) tek yönlü ayarlanmamasından doğar.

#### 2. Güvenlik Mekanizması & Savunma Mimarisi
* **Risk Nasıl Oluşur?**
  1. *Düz Ağ Mimarisi:* Tüm laboratuvar cihazlarının tek bir alt ağda olması nedeniyle ARP zehirlenmesi ve broadcast sızıntısı riskinin doğması.
  2. *Karantina İnternet Sızıntısı:* Zararlının dış C2 ile iletişim kurarak gerçek IP adresini ifşa etmesi ve dış dünyaya saldırı başlatması.
  3. *DNS Tünelleme Açığı:* DNS trafiğinin harici sunuculara izinli olması sebebiyle veri kaçırma kanalı oluşması.
  4. *Durum Takipsiz Güvenlik Duvarı:* Kurbandan saldırgana doğru tersine kabuk (Reverse Shell) paketlerinin engellenememesi.
* **Risk Nasıl Tespit Edilir?**
  * Yönlendirme Tablosu Analizi: `ip route` veya `route print` ile kurban makinenin varsayılan ağ geçidinde internet rotası olup olmadığının kontrolü.
  * Ağ Dinleme (Packet Sniffing): Sanal köprüde `tcpdump -i any -n "dst net not 192.168.0.0/16"` komutuyla iç ağ dışına çıkan kaçak paketlerin izlenmesi.
  * Güvenlik Duvarı Kural Taraması: `iptables -L -v -n` çıktısında `FORWARD` zincirinin `DROP` olup olmadığının ve `NEW` bağlantı kurallarının taranması.
* **Hangi Kontrolle Önlenir?**
  * *NIST CSF PR.AC (Ağ İzolasyonu):* 4 bağımsız VLAN (Karantina, Kırmızı, Mavi, Yönetim) ile mikro-segmentasyon.
  * *NIST CSF PR.PT (Koruyucu Teknoloji):* Durum takipli (Statefull conntrack) iptables kuralları ve DNS Sinkholing (INetSim).
  * *NIST CSF DE.CM (Sürekli İzleme):* Karantinadan dışarıya çıkan tüm yetkisiz paketlerin loglanıp SIEM'e alarm olarak düşürülmesi.

#### 3. Saldırgan Perspektifi & İstismar Senaryosu
Saldırgan kurban makineye sızdığında `netstat -rn` komutunu çalıştırır. Eğer ağ geçidi `192.168.1.1` üzerinden internete erişebildiğini görürse; hemen şifreli bir Telegram Bot API veya Discord Webhook çağrısı yaparak makinedeki tüm parola dosyalarını internete basar. Eğer ağ sınırları doğru kapatılmışsa, bu çağrı ağ geçidinde anında çöpe atılır ve saldırganın veri sızdırma girişimi başarısız olur.

#### 4. Gerçek Dünya Başarısızlık Senaryosu & Çıkarılan Ders
2013 yılında Target perakende devine yapılan 40 milyon kredi kartı hırsızlığı vakasında; saldırganlar bir havalandırma (HVAC) tedarikçisinin kimlik bilgilerini kullanarak Target'ın iç ağına sızmış ve ağda hiçbir mikro-segmentasyon olmadığı için havalandırma ağından doğrudan POS (Ödeme Noktası) terminallerinin olduğu ağa sıçramışlardır (Pivoting).  
**Çıkarılan Ders:** İster kurumsal şirket ağı olsun ister siber güvenlik laboratuvarı; farklı amaca hizmet eden sistemler asla aynı ağda bulundurulamaz. Ağ sınırları mikro-segmentasyonla mühürlenmeli ve bölgeler arası geçişler en katı güvenlik duvarı filtreleriyle kilitlenmelidir.
