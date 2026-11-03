# Gün 049: Soru-Cevap ve Kavramsal Pekiştirme (Mini Proje 6)

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## Soru 1 (G049-SC1): Ağ Adresleme Çalışma Kitabı Mekanizması ve Güvenlik Önemi

### Temel Mekanizma ve Güvenlik Önemi
Ağ teşhisi, siber güvenlik olay müdahalesi ve mimari denetimlerde; IP adresi, alt ağ maskesi (CIDR öneki), varsayılan ağ geçidi (Default Gateway), DNS sunucuları ve fiziksel MAC adreslerinin tek bir merkezi çalışma kitabında tutulması operasyonel bir zorunluluktur:
1. **Bütünsel Adresleme ve Yönlendirme Tutarlılığı:** Katman-3 IP adresi, cihazın yerel alt ağ maskesi ile bit düzeyinde `AND` işlemine tabi tutularak yerel ağ kimliği belirlenir. Dış ağ hedeflerine erişim için varsayılan ağ geçidi kullanılır. Eğer ağ geçidi cihazın kendi alt ağ sınırları içinde değilse, Katman-2 seviyesinde ARP çözümlemesi yapılamaz ve paketler yerel arayüzde düşürülür.
2. **Güvenlik Segmentasyonu ve İzolasyon:** Kurumsal ağlarda farklı işlevlere sahip bölgeler (Yönetim, Sunucular, Kullanıcılar, Misafirler) bağımsız VLAN'lar ve CIDR blokları ile izole edilmelidir. Bir IP çalışma kitabı, izinli ve yetkisiz geçişlerin, çakışan alt ağların (overlapping subnets) ve asimetrik rotalama risklerinin haritasını çıkarır.
3. **DNS ve Ad Çözümleme Güvenliği:** Bir cihazın DNS yapılandırması yerel ağ çalışma kitabında doğrulanmalıdır. Şirket içi yetkili çözümleyiciler yerine rastgele dış DNS sunucularının kullanılması, DNS tünelleme ile veri sızıntılarına veya sahte DNS yanıtlarıyla kimlik avı (phishing) saldırılarına kapı aralar.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:** `portfolio/hafta_07/gun_049/ornek_veri/sample_topology_workbook.json` dosyası içinde tanımlı 4 kurumsal alt ağ (VLAN 10 Yönetim, VLAN 20 Sunucu/DMZ, VLAN 30 İstemciler /23, VLAN 40 Misafir) ve 8 meşru uç nokta cihazı.
- **İşlem:**
  1. `NetworkAddressingWorkbook` motoru veriyi yükler ve her alt ağ için `IPv4SubnetCalculator` nesnesi oluşturur.
  2. Ağ kimliği, yayın adresi, ağ maskesi, wildcard maskesi ve kullanılabilir host aralığı hesaplanır.
  3. Tüm alt ağ ikilileri arasında IP uzayı çakışması (`overlaps_with`) kontrol edilir.
  4. Cihaz IP'lerinin kendi alt ağlarında olup olmadığı ve ağ/broadcast IP'si olup olmadığı denetlenir.
- **Beklenen Çıktı:** 14 birim testin 0.05 saniyenin altında `PASSED` olması; başlangıç temiz topolojisinde 0 anomali, anomali enjeksiyonu sonrasında ise tam 5 kritik güvenlik bulgusunun yakalanması.
- **Negatif Kontrol:** Geçersiz CIDR öneki (/33), 255'ten büyük oktet (300), geçersiz MAC karakterleri (ZZ), çift iki noktalı IPv6 ve 4094'ten büyük VLAN kimliğinin `WorkbookValidationError` ile engellenmesi.

### Risk Analizi ve Tehdit Senaryoları
- **Çakışan Alt Ağlar ve Rota Belirsizliği:** İki farklı ağ birimine birbiriyle çakışan IP aralıkları verildiğinde (örn. `192.168.30.0/23` ile `192.168.31.0/24`), yönlendiriciler "Longest Prefix Match" kuralına göre trafiği yanlış alt ağa yönlendirir; bu durum veri sızıntılarına veya paket kara deliklerine (black hole) yol açar.
- **Kullanılamaz IP Atamaları:** Ağ kimliği (.0) veya Broadcast (.255) adresinin bir sunucuya atanması, işletim sistemi TCP/IP yığınlarında istikrarsızlıklara ve broadcast fırtınalarına neden olur.
- **IP Çakışması (Duplicate IP):** Bir saldırganın meşru bir sunucunun IP'sini sahte bir cihaza ataması durumunda ARP tablosunda çırpınma (ARP flap) meydana gelir ve DoS saldırısı gerçekleşir.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:**
  1. Alt ağ planlama tablolarında ve yönlendirici yönlendirme tablolarında (RIB/FIB) çakışan öneklerin taranması.
  2. Anahtarlar üzerinde `IP duplicate detected` sistem günlüklerinin (syslog) izlenmesi.
- **Önleme:**
  1. **IPAM (IP Address Management) Sistemleri:** Manuel Excel/metin dosyaları yerine otomatik çakışma önleyici merkezi IP yönetim yazılımlarının kullanılması.
  2. **DHCP Snooping & Dynamic ARP Inspection (DAI):** Anahtar donanımında IP-MAC bağlama tablosunun zorunlu kılınması.
  3. **Katı VLAN ve VRF Segmentasyonu:** Ağların mantıksal olarak ayrılması ve güvenlik duvarı üzerinden denetlenmesi.

---

## Soru 2 (G049-SC2): Bağımsız Laboratuvarın Girdisi, İşlemi, Beklenen Sonucu ve Negatif Kontrolü

### Temel Mekanizma ve Güvenlik Önemi
Ağ adresleme ve topoloji analiz motorları harici bir ağ cihazına veya internete bağımlı olmaksızın, tamamen yerel, matematiksel ve sentetik girdi setleriyle çalışabilmeli; her bir Katman-2 ve Katman-3 parametresini doğrulayabilmelidir.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:**
  1. `sample_topology_workbook.json`: 4 alt ağ, 8 cihaz ve 5 enjekte edilen hata senaryosu (çakışan alt ağ, geçersiz ağ geçidi, network ID ataması, broadcast ataması, duplicate IP).
  2. `invalid_topology_inputs.json`: 8 adet biçimsel negatif test senaryosu.
- **İşlem:**
  1. `IPv4SubnetCalculator` ile bit düzeyinde maskeleme ve IP aralık denetimi yürütülür.
  2. `IPv6SubnetCalculator` ile IPv6 blokları ve EUI-64 MAC sızıntısı matematiksel olarak çözülür.
  3. `NetworkAddressingWorkbook.run_audits()` fonksiyonu ile 5 aşamalı güvenlik ve yapılandırma denetimi işletilir.
  4. Sonuçlar profesyonel Markdown raporu olarak derlenir (`kanit/gercek/ag_adresleme_calisma_kitabi_raporu.txt`).
- **Beklenen Çıktı:** 
  - 14 birim testin 0.03 saniyede `14 passed` olarak tamamlanması.
  - Enjekte edilen 5 anomalinin tamamının KRİTİK seviyede yakalanması.
- **Negatif Kontrol:**
  - 8 farklı geçersiz girdinin tamamının `WorkbookValidationError` fırlatması ve `kanit/gercek/negatif_kontrol_sonuclari.txt` dosyasına "%100 DOĞRULAMA BAŞARILI" şeklinde kaydedilmesi.

### Risk Analizi ve Tehdit Senaryoları
Yetersiz girdi doğrulama ve statik analiz eksikliği:
- Yanlış yapılandırılmış bir alt ağın üretim ortamına dağıtılmasına izin verilmesi, kurum genelinde kesintiye ve güvenlik duvarı kurallarının bypass edilmesine sebep olur.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:** CI/CD aşamasında ağ altyapı kodlarının (Infrastructure as Code - Terraform / Ansible) statik analiz araçlarıyla denetlenmesi.
- **Önleme:** Ağ şablonlarında katı şema (JSON Schema) doğrulaması işletilmesi ve birim testler ile otomasyonun desteklenmesi.

---

## Soru 3 (G049-SC3): Risk Oluşumu, Tespiti ve Savunma Kontrolleri

### Temel Mekanizma ve Güvenlik Önemi
Ağ adresleme düzeyindeki zafiyetler ve mimari hatalar, saldırganların güvenlik duvarlarını aşmasını, yerel ağda ortadaki adam (MitM) konumuna geçmesini ve cihazların küresel ölçekte parmak izinin çıkarılmasını mümkün kılar.

### Bağımsız Laboratuvar ve Doğrulama Adımları
Laboratuvarımızda bu risklerin oluşumu ve tespiti kod seviyesinde modellenmiştir:
1. **Risk 1: Alt Ağ Çakışması ve Rota Sızması:** Farklı erişim seviyelerine sahip iki VLAN çakıştığında (örneğin Misafir VLAN ile Sunucu VLAN), paketler yanlış güvenlik bölgesine teslim edilir.
2. **Risk 2: EUI-64 MAC Adresi Sızıntısı:** IPv6 SLAAC adreslemesinde donanımın MAC adresi küresel IPv6 adresine dönüştürülür. Motorumuz `is_eui64_mac_leakage` fonksiyonuyla bu sızıntıyı OUI ve NIC parçalarını ters çevirerek tespit eder.
3. **Risk 3: Sahte Ağ Geçidi ve ARP Çatışması:** Cihaza yanlış veya saldırgan kontrolündeki bir ağ geçidi atandığında giden tüm trafik çalınabilir.

### Risk Analizi ve Tehdit Senaryoları
- **Kurumsal Parmak İzi Çıkarma:** EUI-64 kullanan bir şirketin çalışanları dizüstü bilgisayarlarıyla evden veya otelden bağlandığında dahi aynı arayüz kimliğini kullanmaya devam eder. Hedefli saldırganlar bu sayede üst düzey yöneticilerin fiziksel cihazlarını internet üzerinden takip edebilir.
- **Asimetrik Yönlendirme ve Güvenlik Duvarı Baypas:** Çakışan alt ağlar sebebiyle giden trafik güvenlik duvarından geçerken, dönen trafik doğrudan hedefe ulaşabilir; durum bilgisi (stateful inspection) kurulamadığı için bağlantılar düşer veya denetimden kaçar.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:**
  1. SIEM ve EDR üzerinde uç noktaların IPv6 adreslerinin son 64 bitinde `FF:FE` paterni taranması.
  2. Ağ anahtarlarında ARP/NDP çakışma ve anomali uyarılarının merkezi loglara aktarılması.
- **Önleme:**
  1. **RFC 4941 Privacy Extensions:** Tüm istemcilerde EUI-64 yerine geçici ve rastgele IPv6 adreslerinin zorunlu kılınması.
  2. **802.1X Port Güvenliği:** Ağ anahtarı portlarında kimlik doğrulaması olmadan hiçbir cihaza IP ve ağ erişimi verilmemesi.
  3. **Sıkı Mikrosegmentasyon:** Sunucular arası yatay trafiğin (East-West traffic) dahi güvenlik duvarı veya sanal anahtar ACL'leri ile kısıtlanması.
