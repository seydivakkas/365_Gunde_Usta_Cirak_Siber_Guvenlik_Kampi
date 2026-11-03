# GÜN 008: Soru & Cevap Bankası — Sanallaştırmanın Güvenlikteki Rolü

![Lisans](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Soru Sayısı](https://img.shields.io/badge/sorular-3%20Soru-blue?style=flat-square)
![Format](https://img.shields.io/badge/format-4%20B%C3%B6l%C3%BCml%C3%BC%20Kat%C4%B1%20Standart-success?style=flat-square)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

### Soru 1 (G008-SC1): Sanallaştırmanın güvenlikteki rolü: Temel mekanizmayı ve güvenlik önemini açıkla.

#### 1. Kavramsal Açıklama (Analoji & Zihinsel Model)
Sanallaştırma; siber güvenlik mühendisliğinde tehlikeli biyolojik virüslerin (örneğin Ebola veya Şarbon) incelendiği **BSL-4 (Biyolojik Güvenlik Seviye 4) hermetik eldivenli cam kabinidir (Glovebox)**. Nasıl ki bir mikrobiyolog ölümcül virüse çıplak elle dokunmayıp onu hava sızdırmaz, negatif basınçlı cam kabinin içine koyup kalın eldivenlerle inceliyorsa; bir siber güvenlik analisti de fidye yazılımlarını, casus yazılımları veya sızma testi araçlarını kendi fiziksel işletim sisteminde (Host OS) değil, donanımsal olarak izole edilmiş sanal makine (Guest VM) kabininde çalıştırır. İşlem bittiğinde tek bir komutla kabin sterilize edilir (Snapshot Revert) ve sistem ilk temiz anına döner.

#### 2. Güvenlik Mekanizması & Savunma Mimarisi
Mekanizmanın temelinde işlemci seviyesindeki **Donanım Destekli Sanallaştırma (Intel VT-x / AMD-V)** ve süper ayrıcalıklı **Ring -1 (Root Mode / VMM - Virtual Machine Monitor)** katmanı yer alır:
* **Ayrıcalık Hapsi:** Misafir işletim sisteminin çekirdeği (Kernel), kendini Ring 0'da sansa da aslında *Non-Root Ring 0* moduna hapsedilmiştir. Donanıma (bellek sayfaları, fiziksel disk blokları, kesmeler) doğrudan dokunamaz.
* **VM-Exit & Giriş Kontrolü:** Misafir çekirdek ayrıcalıklı bir işlemci talimatı yürütmeye çalıştığında CPU donanımsal olarak bir `VM-Exit` kesmesi üretir ve kontrolü Ring -1'deki Hypervisor'a bırakır. Hypervisor bu çağrıyı denetler, emüle eder ve sınır dışına taşmasına izin vermez.
* **Patlatma Alanı (Blast Radius) İzolasyonu:** Bir sanal makine tamamen şifrelense veya çökertilse bile, tahribat yalnızca o sanal diskin (.vmdk / .vdi) sınırları içinde hapsolur; konak işletim sistemi ve fiziksel donanım zarar görmez.

#### 3. Saldırgan Perspektifi & İstismar Senaryosu
Gelişmiş bir tehdit aktörü (APT), hedef sisteme sızdığında ortamın bir sanal makine olup olmadığını anlamaya çalışır (**Anti-VM Evasion**). Saldırgan `CPUID` assembly talimatını yürütür veya ağ kartı MAC adresinin `08:00:27` (VirtualBox) ya da `00:05:69` (VMware) olduğunu görürse; analiz edildiğini fark eder. Zararlı yazılım hiçbir kötü niyetli hareket yapmayarak uyku moduna geçer (`Sleep`) ve analiste dosyanın "temiz" olduğu izlenimini verir. İkinci bir senaryoda saldırgan, hypervisor'ın konakla paylaştığı çevre birimi sürücülerindeki (3D grafik hızlandırma, paylaşılan pano) tampon bellek taşması zafiyetlerini istismar ederek sanal makineden konak işletim sistemine sıçrar (**VM Escape**).

#### 4. Gerçek Dünya Başarısızlık Senaryosu & Çıkarılan Ders
2019 yılında Oracle VirtualBox üzerinde keşfedilen ve Pano Paylaşımı (Shared Clipboard) entegrasyonundaki bellek yönetim hatasından kaynaklanan zafiyette (**CVE-2019-0836**); misafir sanal makinede root/admin olan bir saldırgan, panoya özel olarak hazırlanmış bozuk bir veri kopyalayarak konak işletim sisteminde (Host Windows/Linux) SYSTEM yetkisiyle kod çalıştırmayı başarmıştır.  
**Çıkarılan Ders:** Sanallaştırma tek başına mutlak bir kalkan değildir. Konak ile misafir arasındaki kolaylık sağlayan entegrasyonlar (Pano, Sürükle-Bırak, Paylaşılan Klasörler, 3D Grafik Hızlandırma) saldırı yüzeyini genişletir. Güvenli analiz ortamlarında bu kanallar tamamen devre dışı bırakılmalıdır (**Hardened Isolation**).

---

### Soru 2 (G008-SC2): Sanallaştırmanın güvenlikteki rolü: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

#### 1. Kavramsal Açıklama (Analoji & Zihinsel Model)
Bir binanın yangın güvenlik denetimini düşün: Giriş olarak binanın mimari yangın kaçış planını verirsin; işlem olarak yangın kapılarının kilitli olup olmadığını, duman tahliye bacalarının açık olup olmadığını ve yangın anında yangının diğer dairelere sıçrayıp sıçramayacağını denetlersin; beklenen sonuç binanın "Yangına Karşı Tam Korumalı" sertifikası almasıdır; negatif kontrol ise bilerek bir yangın kapısını zincirleyip denetçinin bu ölümcül hatayı yakalayıp binayı anında mühürlediğini (redfettiğini) kanıtlamaktır. Sanallaştırma laboratuvarı da sanal makine konfigürasyonunu aynı katılıkla inceler.

#### 2. Güvenlik Mekanizması & Savunma Mimarisi
Geliştirdiğimiz `vm_security_auditor.py` ve `test_vm_security_auditor.py` laboratuvar altyapısı bu dört adımı şu mekanizmalarla işletir:
* **Girdi (Input):** İncelenecek sanal makinenin donanım, ağ, entegrasyon, kurtarma ve anti-VM ayarlarını tanımlayan makinece okunabilir JSON profili (`vm_guvenlik_profili.json`).
* **İşlem (Process):** Denetim motorunun 4 çekirdek güvenlik katmanını işletmesi:
  1. *Ağ Sınırı Analizi:* Adaptör modunun Bridged mı yoksa Internal/Host-Only mı olduğunun tespiti.
  2. *Hypervisor Escape Analizi:* Pano, sürükle-bırak, paylaşılan klasör yazma izinleri ve 3D GPU emülasyonunun tespiti.
  3. *Kalıcılık Analizi:* Anlık görüntü (Snapshot) politikası ve disk modunun (Persistent vs Non-Persistent) denetimi.
  4. *Anti-VM Evasion Analizi:* MAC önekleri ve CPUID bayraklarının incelenmesi.
* **Beklenen Sonuç (Expected Output):** Tam sertleştirilmiş altın standart VM için 100/100 güvenlik skoru, sıfır açık bulgu ve "GÜVENLİ (SERTLEŞTİRİLMİŞ)" onay kararı.
* **Negatif Kontrol (Negative Control):** Kasıtlı olarak konfigürasyona köprülenmiş ağ (`Bridged`), konak `C:\` dizini yazılabilir paylaşımı (`ReadWrite`) veya çift yönlü pano (`Bidirectional`) eklendiğinde; denetleyicinin derhal 40-50 puan ceza keserek durumu "KRİTİK FELAKET" olarak raporlaması ve CLI yürütmesinde sıfır olmayan hata koduyla (`Exit Code 2`) işlemi reddetmesidir.

#### 3. Saldırgan Perspektifi & İstismar Senaryosu
Saldırgan bir ağa girdiğinde ilk olarak "Bridged" yapılandırılmış bir sanal analiz makinesi arar. Eğer araştırmacı VM'in ağ kartını fiziksel ağa köprülemişse, sanal makinede patlayan fidye yazılımı (örneğin EternalBlue zafiyeti kullanan bir SMB solucanı), sanal makineden kaçmaya bile ihtiyaç duymadan doğrudan fiziksel ağdaki etki alanı denetleyicisine (Domain Controller) saldırır. Negatif kontrol mekanizması işte bu açıklığı daha test başlamadan yakalar.

#### 4. Gerçek Dünya Başarısızlık Senaryosu & Çıkarılan Ders
Bir finans kuruluşunda çalışan acemi bir adli bilişim analisti, phishing e-postasında gelen şüpheli Word belgesini analiz etmek için VMware Workstation üzerinde bir Windows VM açmıştır. Analist, hızlı dosya kopyalayabilmek için ağ modunu "Bridged" yapmış ve konak `C:\Users\Analyst` klasörünü "ReadWrite" olarak sanal makineye bağlamıştır. Word makrosu çalıştırıldığı anda arkasındaki Ryuk fidye yazılımı tetiklenmiş; yazılım sadece VM'i değil, paylaşılan klasör üzerinden analistin ana bilgisayarını ve Bridged ağ üzerinden şirketin muhasebe sunucularını şifrelemiştir.  
**Çıkarılan Ders:** Bir analiz sanal makinesi asla fiziksel ağa bağlanmamalı ve konak işletim sistemine yazma yetkisi olan paylaşılan klasör verilmemelidir. Negatif kontrol testleri bu tür yapılandırmaların üretime geçmesini kesin olarak engeller.

---

### Soru 3 (G008-SC3): 'Sanallaştırmanın güvenlikteki rolü' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Kavramsal Açıklama (Analoji & Zihinsel Model)
Risk, zırhlı bir kalenin kapısını ardına kadar kapatıp duvara gizli bir servis penceresi açmaya benzer. Kale (Hypervisor) dışarıdan gelebilecek top atışlarına (doğrudan donanım saldırılarına) karşı aşılmaz bir taştan yapılmıştır; ancak kale içindekilere kolaylık olsun diye mutfaktan dışarıya bir yemek penceresi (Pano / Paylaşılan Klasör / 3D Emülasyon) açılmıştır. Düşman ana kapıyı zorlamak yerine o küçük yemek penceresine zehirli duman sıkarak tüm kaleyi teslim alır. Sanallaştırmada risk; kullanıcı kolaylığı ile güvenlik izolasyonu arasındaki ödünleşimden (trade-off) doğar.

#### 2. Güvenlik Mekanizması & Savunma Mimarisi
* **Risk Nasıl Oluşur?**
  1. *Aşırı Yetkili Ağ Yapılandırması:* Bridged adaptör veya promiscuous mod açılarak sanal makinenin fiziksel yerel ağa ve diğer izole sanal makinelere sızmasına yol açılması.
  2. *Entegrasyon Kanalları (VM Escape Yüzeyi):* Çift yönlü pano paylaşımı, sürükle-bırak ve konak diski paylaşımı ile konak ve misafir arasındaki izolasyon duvarının delinmesi.
  3. *Durum Kaybı (State Pollution):* Snapshot mekanizması kurulmadığı için analiz edilen zararlının diske veya BIOS/NVRAM'e kalıcı arka kapı bırakması.
  4. *Tespitten Kaçınma Açığı:* Sanallaştırma parmak izlerinin (MAC, CPUID) gizlenmemesi nedeniyle zararlının analizi atlatması (Evasion).
* **Risk Nasıl Tespit Edilir?**
  * Statik Konfigürasyon Denetimi: Hypervisor XML/VBOX/VMX yapılandırma dosyalarının otomatik denetim scriptleriyle (ör. `vm_security_auditor.py`) taranması.
  * Ağ Dinleme (Virtual Network Sniffing): Sanal anahtar seviyesinde kaçak ARP, DHCP ve DNS paketlerinin izlenmesi.
  * Host Bütünlük Kontrolleri: Konak işletim sisteminde misafir makinelerle paylaşılan dizinlerin dosya bütünlük izleme (FIM) sistemleriyle takip edilmesi.
* **Hangi Kontrolle Önlenir?**
  * *NIST CSF PR.AC (Erişim Kontrolü):* Pano ve sürükle-bırakın devre dışı bırakılması (`Disabled`), konak dosya sistemi paylaşımlarının tamamen yasaklanması.
  * *NIST CSF PR.DS (Veri Güvenliği):* Non-persistent disk modu ve her analiz oturumu sonrası otomatik snapshot geri yükleme (`Rollback`) şartı.
  * *NIST CSF PR.PT (Koruyucu Teknoloji):* Ağ bağdaştırıcısının `Internal_Isolated` veya `Host_Only` yapılması; internete çıkış yerine sahte yerel ağ simülatörlerinin (INetSim) kullanılması.

#### 3. Saldırgan Perspektifi & İstismar Senaryosu
Saldırgan sanal makine içerisinde yetki yükselttikten sonra konak işletim sistemindeki hypervisor servisine (örneğin VMware Tools veya VirtualBox Guest Additions) özel RPC (Remote Procedure Call) mesajları gönderir. Bu mesajlarda bellek sınırlarını aşan uzun argümanlar kullanarak konak çekirdeğindeki hypervisor sürücüsünü (Ring 0) çökerterek rastgele kod çalıştırır. Eğer savunmacı konfigürasyonda bu misafir araçlarını sertleştirmemişse ve paylaşılan klasörleri açık bırakmışsa, saldırgan tek bir komutla konak sistemin yöneticisi haline gelir.

#### 4. Gerçek Dünya Başarısızlık Senaryosu & Çıkarılan Ders
Pwn2Own yarışmalarında her yıl üst üste gösterilen "VM Escape" gösterilerinde (örneğin 2021 ve 2024 yıllarında VMware Workstation ve ESXi üzerinde gerçekleştirilen sıfır-gün zincirleri); araştırmacılar misafir sanal makineden yola çıkarak yalnızca hypervisor'ın 3D grafik emülasyon kodundaki (`DirectX / SVGA3D shader parser`) bir tamsayı taşması (integer overflow) açığını kullanarak doğrudan konak işletim sisteminde SYSTEM yetkisi elde etmişlerdir.  
**Çıkarılan Ders:** Bir analiz veya güvenlik laboratuvarı kurulurken "nasılsa sanal makine içindeyim, bana bir şey olmaz" rehavetine asla kapılınmamalıdır. 3D grafik hızlandırma kapatılmalı, hypervisor yazılımları en son güvenlik yamalarıyla güncellenmeli ve sanal makineye BSL-4 seviyesinde sıfır güven (Zero-Trust) uygulanmalıdır.
