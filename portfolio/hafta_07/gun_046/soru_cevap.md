# Gün 046: Soru-Cevap ve Kavramsal Pekiştirme

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## Soru 1 (G046-SC1): IPv6 Temel Mekanizması, SLAAC ve Güvenlik Önemi

### Temel Mekanizma ve Güvenlik Önemi
IPv6, 128 bitlik adres mimarisi kullanarak $2^{128}$ adet benzersiz adres alanı sağlar. IPv4'teki sınırlı adres havuzu, katı alt ağ yapısı ve NAT zorunluluğunu ortadan kaldıran IPv6, temel protokol düzeyinde köklü değişiklikler barındırır:
1. **Yayın (Broadcast) Mekanizmasının Kaldırılması:** IPv6'da broadcast trafiği tamamen kaldırılmış; yerini Çok Noktaya Yayın (Multicast) ve En Yakına Yayın (Anycast) almıştır. Bu sayede yerel ağ segmentinde tüm ana bilgisayarları meşgul eden gereksiz trafik yükü ve Smurf benzeri broadcast tabanlı DDoS vektörleri ortadan kaldırılmıştır.
2. **Komşu Keşif Protokolü (NDP - RFC 4861):** Katman 2 MAC adresi çözümlemesi için kullanılan ARP protokolü yerine, ICMPv6 mesajları (Neighbor Solicitation - NS ve Neighbor Advertisement - NA) ve Solicited-Node Multicast grupları üzerinden çalışan NDP mekanizması getirilmiştir.
3. **Durumsuz Adres Otomatik Yapılandırması (SLAAC):** Cihazlar merkezi bir DHCP sunucusuna ihtiyaç duymadan, yerel yönlendiriciden aldıkları Router Advertisement (RA - ICMPv6 Type 134) anonsları ile ağ önekini öğrenip kendi 64-bitlik Arayüz Kimliklerini (IID) ekleyerek geçerli bir genel IPv6 adresi oluşturabilirler.

Güvenlik açısından IPv6; SLAAC ve NDP'nin doğası gereği güven ilişkisine dayanması sebebiyle Rogue RA ve Neighbor Spoofing gibi yeni katman 2 saldırı yüzeyleri yaratır. Bu mekanizmaların doğru modellenmesi kurumsal ağ savunmasında kritik öneme sahiptir.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:** 7 farklı IPv6 adres ve CIDR senaryosu (`2001:0db8:85a3::.../64` GUA, `fe80::.../64` Link-Local, `fd00::.../64` ULA, `::1/128` Loopback, `::/128` Unspecified, `ff02::1/16` Multicast, `::ffff:c000:280/96` IPv4-Mapped).
- **İşlem:**
  1. Hextet doğrulama ve 128-bitlik açılım (`expanded_address`).
  2. RFC 5952 kanonik sıkıştırma (en uzun sıfır bloğunun tek bir `::` ile değiştirilmesi, tek sıfırın kısaltılmaması).
  3. Adres türü (GUA, ULA, Link-Local) ve kapsam (Scope) sınıflandırması.
  4. RFC 4291 uyumlu Solicited-Node Multicast adresi türetimi (`ff02::1:ffXX:XXXX`).
  5. 48-bit MAC adresinden EUI-64 IID ve Link-Local IP türetimi (U/L bit ters çevirme ve FF:FE ekleme).
- **Beklenen Çıktı:** 14 birim testin 0.05 saniyenin altında `PASSED` olması; EUI-64 türetiminde `00:1A:2B:3C:4D:5E` MAC adresinin `fe80::21a:2bff:fe3c:4d5e/64` adresine dönüşmesi.
- **Negatif Kontrol:** `2001::db8::1` (birden fazla `::`), `2001:0db8:85g3::1` (geçersiz hex), `2001:00db8::1` (5 karakterli hextet), `1:2:3:4:5:6:7:8:9` (9 hextet) ve `2001:db8::1/129` (önek taşması) girdilerinin `IPv6ValidationError` ile yakalanması.

### Risk Analizi ve Tehdit Senaryoları
- **Rogue RA Saldırıları (Sahte Yönlendirici Duyurusu):** Yerel ağa bağlanan bir saldırganın yüksek öncelikli sahte RA paketleri yayarak ağdaki tüm cihazların varsayılan ağ geçidi (Default Gateway) ve DNS sunucusu haline gelmesi (Man-in-the-Middle).
- **EUI-64 Kaynaklı Cihaz Takibi (Device Tracking):** EUI-64 ile üretilen IPv6 adreslerinin son 64 bitinde ağ kartının değişmeyen fiziksel MAC adresinin yer alması sebebiyle, kullanıcının farklı ağlara taşınsa dahi internet genelinde anonim kalamaması ve fiziksel cihaz takibine uğraması.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:** Yerel ağ anahtarında veya IDS üzerinde yetkili olmayan portlardan gelen ICMPv6 Type 134 (Router Advertisement) paketlerinin yakalanması ve alarm üretilmesi.
- **Önleme:**
  1. Anahtarlarda (Switch) **RA Guard (RFC 6105)** özelliğinin devreye alınarak kullanıcı erişim portlarından gelen RA paketlerinin donanım seviyesinde atılması.
  2. İstemcilerde **RFC 4941 Privacy Extensions** aktifleştirilerek EUI-64 yerine düzenli aralıklarla değişen rastgele geçici arayüz adreslerinin zorunlu tutulması.

---

## Soru 2 (G046-SC2): Bağımsız Laboratuvarın Girdisi, İşlemi, Beklenen Sonucu ve Negatif Kontrolü

### Temel Mekanizma ve Güvenlik Önemi
IPv6 adres işleme ve denetleme yazılımları, kullanıcı girdilerindeki biçimsel hataları, çift `::` ihlallerini ve hextet sınır taşmalarını dış kütüphanelere dayanmadan katı standartlarla doğrulayabilmelidir. RFC 5952 standardı, bir IPv6 adresinin ekranda tek ve kesin (kanonik) bir biçimde gösterilmesini sağlayarak log analizinde ve SIEM arama kurallarında adres eşleşmeme zafiyetlerini önler.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:** `portfolio/hafta_07/gun_046/ornek_veri/sample_ipv6_addresses.json` ve `invalid_ipv6_addresses.json` veri setleri.
- **İşlem:**
  1. Ham adres dizesi iki nokta (`:`) karakterlerine göre hextet bloklarına ayrılır.
  2. '::' varlığı ve adedi kontrol edilir (maksimum 1 adet).
  3. Eksik hextetler sıfırlarla tamamlanarak 8 elemanlı 16-bit tamsayı listesi oluşturulur.
  4. RFC 5952 kuralları işletilerek kanonik metin üretilir.
  5. Adresin son 24 biti alınarak Solicited-Node Multicast adresi hesaplanır.
- **Beklenen Çıktı:** 14 adet birim testin (11 pozitif fonksiyonel test + 3 negatif hata yakalama testi) hatasız tamamlanması.
- **Negatif Kontrol:** 8 adet geçersiz adres formatının (çift `::`, geçersiz harf, uzun hextet, eksik hextet, fazla hextet, negatif önek, >128 önek, metin önek) her birinin `IPv6ValidationError` fırlatması ve `kanit/gercek/negatif_kontrol_sonuclari.txt` dosyasına kaydedilmesi.

### Risk Analizi ve Tehdit Senaryoları
Kanonik sıkıştırma standartlarına uyulmaması:
- Güvenlik duvarı ve IPS kural setlerinde `2001:db8::1` ile `2001:0db8:0000:0000:0000:0000:0000:0001` adreslerinin farklı metinler olarak algılanması sonucu saldırganın engelleme kurallarını (ACL bypass) atlatabilmesine yol açar.
- Hatalı regex doğrulayıcıların 9 hextetli veya çift `::` içeren adresleri kabul etmesi sistem çökmelerine ve ayrıştırıcı tampon taşmalarına (parser buffer overflow) zemin hazırlar.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:** Güvenlik loglarında standart dışı biçimlendirilmiş IPv6 girişlerinin ve doğrulama istisnalarının loglanması.
- **Önleme:** Tüm loglama, filtreleme ve analiz sistemlerinde RFC 5952 kanonik formatlayıcısının standart olarak işletilmesi.

---

## Soru 3 (G046-SC3): Risk Oluşumu, Tespiti ve Savunma Kontrolleri

### Temel Mekanizma ve Güvenlik Önemi
Modern kurumsal bilişim altyapılarında en yaygın ve tehlikeli IPv6 riski **"Gölge Ağ" (Dual-Stack Shadow Network)** zafiyetidir. Ağ yöneticileri kurumun sadece IPv4 kullandığını varsayarak güvenlik duvarı, vekil sunucu (proxy) ve IDS/IPS sistemlerini yalnızca IPv4 trafiğini denetleyecek şekilde yapılandırır. Oysa Windows, Linux ve macOS istemcilerinde IPv6 protokol yığını varsayılan olarak açıktır.

### Bağımsız Laboratuvar ve Doğrulama Adımları
- **Girdi:** Yerel ağda duyurulan sahte RA paketleri, EUI-64 tabanlı sızıntılar ve filtrelenmemiş ICMPv6 mesajları.
- **İşlem:** Paketlerin kaynak adresleri ve ICMPv6 tip alanları taranır; yetkisiz yönlendirici duyuruları ve Link-Local sınırını aşan trafikler tespit edilir.
- **Beklenen Çıktı:** Yetkisiz RA anonslarının tespit edilmesi, istemcilerin sahte varsayılan ağ geçitlerini kabul etmesinin engellenmesi.
- **Negatif Kontrol:** Yetkisiz portlardan gelen RA paketlerinin düşürüldüğünün doğrulanması.

### Risk Analizi ve Tehdit Senaryoları
1. **Gölge Ağ İstismarı (Dual-Stack Bypass):** Saldırgan iç ağda zararlı bir IPv6 Router kurarak istemcilere IPv6 adresi ve DNS sunucusu dağıtır. İstemciler RFC 6724 (Happy Eyeballs) gereği IPv6'yı IPv4'e tercih ettiğinden, tüm web ve şirket trafiği IPv4 güvenlik duvarını tamamen atlayarak saldırgan üzerinden şifresiz/denetimsiz akar.
2. **NDP Zehirleme (Neighbor Discovery Cache Poisoning):** IPv4 ARP zehirlemesine benzer şekilde, sahte Neighbor Advertisement (NA) paketleriyle istemcilerin komşuluk tabloları tahrif edilerek aradaki adam (MitM) konumu elde edilir.
3. **Körlemesine ICMPv6 Engellemesi Nedeniyle Hizmet Kesintisi (DoS):** Ağ yöneticisinin "güvenlik" amacıyla tüm ICMPv6 trafiğini engellemesi sonucu, NDP ve PMTUD çalışamaz hale gelir ve kurumun tüm IPv6 haberleşmesi çöker.

### Tespit Sinyalleri ve Önleme Kontrolleri
- **Tespit:**
  1. Ağ izleme araçlarında (Wireshark, Zeek, Snort) yetkili omurga yönlendiricileri haricindeki IP'lerden yayılan `ICMPv6 Type 134 (Router Advertisement)` ve `Type 135/136` mesajlarının alarm üretmesi.
  2. İstemcilerin yönlendirme tablolarında bilinmeyen `fe80::` varsayılan ağ geçidi girişlerinin belirmesi.
- **Önleme:**
  1. **RA Guard (RFC 6105):** Kurumsal anahtarların tüm kenar portlarında `ipv6 nd raguard` etkinleştirilerek yetkisiz RA'ların switch donanımında yok edilmesi.
  2. **DHCPv6 Guard:** Sahte DHCPv6 sunucu paketlerinin engellenmesi.
  3. **Çift Yığın Güvenlik Duvarı Eşitliği:** Kurumda IPv6 kullanılmasa dahi, ya işletim sistemi seviyesinde IPv6 tamamen kapatılmalı (GPO/Ansible ile devre dışı bırakma) ya da güvenlik duvarlarında IPv4 ile birebir eşdeğer IPv6 güvenlik kuralları yazılmalıdır.
  4. **Seçici ICMPv6 Filtreleme:** İç ağda NDP mesajlarına (Type 133-136) kesinlikle izin verilmeli; dış WAN sınırında ise yalnızca gerekli ICMPv6 hata mesajlarına geçit tanınmalıdır.
