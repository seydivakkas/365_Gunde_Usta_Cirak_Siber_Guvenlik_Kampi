# Gün 045: IPv4 Adresleme, Alt Ağlar (Subnetting) ve CIDR Mimarisi

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## 1. Usta Girişi: Çırağa Zihinsel Model Öğüdü

Bak evlat, ağ dünyasında amatörler ile gerçek siber güvenlik mühendislerini ayıran ilk büyük eşik burasıdır: **IPv4 adreslerini metin olarak mı görüyorsun, yoksa 32 bitlik bir tam sayı olarak mı?**

Ekranda gördüğün `192.168.1.1` metni, insan gözü rahat etsin diye icat edilmiş bir kabuktur (dotted-decimal notation). Bir yönlendirici (router), bir güvenlik duvarı (firewall) ya da bir saldırganın ham paket enjeksiyon aracı için bu adres bir metin dizisi değildir; yalnızca `0xC0A80101` yani `3232235777` tamsayı değeridir.

Eğer bu 32 bitin neresinin **Ağ Kimliği (Network ID)**, neresinin ise **Konak Kimliği (Host ID)** olduğunu bit düzeyinde hesaplayamazsan;
- Güvenlik duvarına yazdığın bir ACL kuralının neden hedef dışı 250 sunucuyu da dış dünyaya açtığını anlayamazsın,
- DMZ bölgeni izole ettiğini zannederken alt ağ maskesi çakışması yüzünden veritabanı VLAN'ının saldırgana nasıl yol verdiğini göremezsin,
- Sahte IP (IP Spoofing) saldırılarında sınır yönlendiricinde BCP 38 filtresini doğru kuramazsın.

Bu derste ezber yok; bitleri yerine oturtacağız ve alt ağların matematiğini bir cerrah hassasiyetiyle öğreneceksin.

---

## 2. Sınıflı Ağlardan (Classful) CIDR Devrimine Geçiş

İnternetin ilk yıllarında adresler katı sınıflarla yönetiliyordu (RFC 791):
- **A Sınıfı (0.0.0.0 - 127.255.255.255):** İlk oktet ağ (/8), kalan 24 bit konak (16 milyon host). Bir kuruma A sınıfı verildiğinde binlerce IP boş yere çürüyordu.
- **B Sınıfı (128.0.0.0 - 191.255.255.255):** İlk 16 bit ağ (/16), 65.534 host.
- **C Sınıfı (192.0.0.0 - 223.255.255.255):** İlk 24 bit ağ (/24), yalnızca 254 host.

1993 yılına gelindiğinde, küresel yönlendirme tabloları patlama noktasına geldi ve IPv4 havuzu hızla tükendi. Çözüm, **CIDR (Classless Inter-Domain Routing - Sınıfsız Alanlar Arası Yönlendirme, RFC 1519)** devrimiyle geldi.

CIDR ile birlikte sınıflar çöpe atıldı. Bir ağın sınırını artık adresin başladığı sayı değil, yanına koyduğumuz **Önek Uzunluğu (/Prefix)** belirler. `/28`, `/20`, `/13` gibi ara değerlerle ağlar tam ihtiyaç duyulan ölçekte dilimlenebilir hale geldi.

---

## 3. Bitsel Mantık Operasyonları: Subnetting Matematiği

Alt ağ hesaplaması tamamen üç temel mantık kapısından ibarettir: **AND (&)**, **OR (|)** ve **NOT (~)**.

### 3.1. Ağ Adresi (Network Address) Hesabı
Yönlendirici bir paketi aldığında, hedef IP adresi ile kendi arayüzündeki alt ağ maskesini bitsel `AND` işlemine tabi tutar:
$$\text{Ağ Adresi} = \text{IP Adresi} \ \& \ \text{Alt Ağ Maskesi}$$

`AND` kuralı basittir: Maskede `1` olan bitler IP adresindeki karşılığını olduğu gibi geçirir; maskede `0` olan bitler ise sıfırlanır. Böylece IP'nin konak kısmı temizlenir ve geriye yalnızca o ağın kimliği (Network ID) kalır.

### 3.2. Ters Maske (Wildcard Mask) ve Yayın Adresi (Broadcast)
Güvenlik duvarlarında (özellikle Cisco ASA ve IOS ACL'lerinde) alt ağ maskesi yerine **Wildcard Mask** kullanılır. Wildcard, maskenin bitsel tersidir:
$$\text{Wildcard} = \sim \text{Alt Ağ Maskesi} \ \& \ \text{0xFFFFFFFF}$$
Yayın adresi ise IP adresi ile Wildcard maskesinin bitsel `OR` işlemine sokulmasıyla elde edilir:
$$\text{Yayın Adresi} = \text{IP Adresi} \ | \ \text{Wildcard}$$

### 3.3. Konak Kapasitesi Formülü
Bir alt ağda konaklara ayrılan bit sayısı $H = 32 - \text{Prefix}$ ise:
- Toplam Adres Sayısı: $2^H$
- Kullanılabilir Konak Sayısı: $2^H - 2$ (Ağ adresi ve Yayın adresi konaklara atanamaz).

---

## 4. Kritik Uç Durumlar: RFC 3021 (/31) ve /32 İstisnaları

Usta dediğin, genel kuralları bildiği kadar istisnalara da hakim olandır.

### 4.1. RFC 3021 (/31 - Noktadan Noktaya Linkler)
Geleneksel kurala göre `/30` ağlarında 4 IP bulunur, ancak yalnızca 2'si host olarak kullanılabilir (Ağ ve Yayın adresleri rezerve olduğu için %50 IP israfı).
Modern omurga yönlendiricileri arasında **RFC 3021** standardı devreye girer:
- `/31` önekinde toplam 2 adres vardır ($2^{32-31} = 2$).
- Bu iki adres doğrudan iki yönlendirici bacağına atanır.
- **Yayın (Broadcast) adresi YOKTUR.** Bu durum yayın fırtınası (broadcast storm) riskini sıfıra indirir ve IP israfını tamamen ortadan kaldırır.

### 4.2. /32 Tekil Konak Rotası (Host Route)
- Maskesi: `255.255.255.255`
- Konak bit sayısı 0'dır ($2^0 = 1$).
- Alt ağ yayılımı yoktur; tek bir cihazı, VPN uç noktasını veya yönlendiricinin Loopback arayüzünü temsil eder. Güvenlik kurallarında en katı ve dar kural tanımlamak için kullanılır.

---

## 5. Adres Sınıflandırması ve Güvenlik Filtreleri (Bogon / Martian IP)

Siber savunmada sınır koruması, adres bloklarının meşruiyetini bilmekten geçer:

| Blok | RFC | Tanım | WAN Sınır Kuralı |
|---|---|---|---|
| `10.0.0.0/8` | RFC 1918 | Özel Yerel Ağ (A Sınıfı) | ⛔ WAN'dan gelirse AT (Spoofing) |
| `172.16.0.0/12` | RFC 1918 | Özel Yerel Ağ (B Sınıfı) | ⛔ WAN'dan gelirse AT (Spoofing) |
| `192.168.0.0/16` | RFC 1918 | Özel Yerel Ağ (C Sınıfı) | ⛔ WAN'dan gelirse AT (Spoofing) |
| `100.64.0.0/10` | RFC 6598 | CGNAT Paylaşımlı Alan | ⛔ WAN'dan gelirse AT |
| `127.0.0.0/8` | RFC 1122 | Geri Döngü (Loopback) | ⛔ WAN'dan gelirse AT |
| `169.254.0.0/16` | RFC 3927 | Link-Local (APIPA) | ⛔ WAN'dan gelirse AT |
| `224.0.0.0/4` | RFC 5771 | Çok Noktaya Yayın (Multicast) | ⛔ Kaynak IP olarak gelirse AT |
| `240.0.0.0/4` | RFC 1112 | Gelecek Kullanım (E Sınıfı) | ⛔ WAN'dan gelirse AT |

Bu adres bloklarının genel internet omurgasında yönlendirilmesi yasaktır; bunlara **Bogon** veya **Martian** paketler denir.

---

## 6. Güvenlik Savunma Prensipleri

1. **BCP 38 / RFC 2827 (Ingress Filtering):**
   Kenar yönlendiriciniz, WAN bacağından içeri giren bir paketin kaynak adresinin iç ağınızdaki bir IP veya Bogon listesindeki bir IP olduğunu görürse bu paketi sorgusuz sualsiz düşürmelidir. Bu kontrol yapılmazsa saldırganlar IP Spoofing ile DDoS amplifikasyonu yapabilir.
2. **Mikro-Segmentasyon:**
   Tüm şirketi tek bir `/16` veya `/24` içine tıkıştırmak intihardır. Saldırgan tek bir istemciyi ele geçirdiğinde tüm ağda yanal hareket (lateral movement) edebilir. Sunucuları `/28` (14 host) veya `/29` (6 host) alt ağlarına bölerek aralarına stateful firewall kurmalısınız.
3. **uRPF (Unicast Reverse Path Forwarding):**
   Yönlendirici, paketin geldiği arayüzün o kaynak IP'ye giden en iyi rota olup olmadığını doğrular; sahte paketleri anında eler.

---

## 7. Çırağa Öğüt: Bu Bilgiyi Sahada Nasıl Kullanacaksın?

Evlat, yarın bir gün bir sızma testi raporu okuduğunda veya bir SOC alarmı incelediğinde:
- "Gelen paketin IP'si 100.64.1.5 idi" dediklerinde, hemen CGNAT bloğu olduğunu ve bir operatör arkasından geldiğini bileceksin.
- Bir ACL kuralı yazarken `permit ip 192.168.1.0 0.0.0.15 any` yazdığında, `/28` bloğunu yani sadece ilk 16 adresi izinli kıldığını zihninde canlandıracaksın.
- Kod yazarken her zaman kullanıcı girdisindeki oktetleri sınır denetiminden geçireceksin.

Şimdi laboratuvar kodlarına ve test kanıtlarına geç, öğrendiklerini doğrula!
