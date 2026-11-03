# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

"""
G055 - DHCP ve IP Ataması Protokol Yöneticisi, Sahte Sunucu ve Tükenme Tespit Motoru.

Bu modül, RFC 2131 (DHCP) ve RFC 2132 (DHCP Seçenekleri) standartlarına tam uyumlu
ikili paket ayrıştırma/üretme, DORA (Discover, Offer, Request, ACK) akış mantığı,
IP kiralama havuzu yönetimi, Sahte (Rogue) DHCP Sunucusu tespiti, DHCP Tükenme
(Starvation) saldırısı engelleme ve L2 Anahtar DHCP Snooping denetimini gerçekleştirir.
"""

# Ağ bayt sırası paketleme ve açma işlemleri için standart struct kütüphanesi
import struct
# IPv4 adresi ve ağ maskesi matematiksel doğrulamaları için ipaddress kütüphanesi
import ipaddress
# Kiralama süreleri ve zaman aşımı hesaplamaları için time kütüphanesi
import time
# Tip güvenliği ve zengin veri yapıları için dataclass, typing araçları
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any


class DHCPValidationError(Exception):
    """DHCP ikili başlık veya alan doğrulama hatalarında fırlatılan özel istisna sınıfı."""
    pass


class DHCPSecurityAlert(Exception):
    """Rogue DHCP veya Starvation gibi güvenlik ihlallerinde fırlatılan özel istisna sınıfı."""
    pass


# BOOTP / DHCP Temel Sabitleri
BOOTREQUEST: int = 1   # İstemciden sunucuya gönderilen istek op kodu
BOOTREPLY: int = 2     # Sunucudan istemciye gönderilen yanıt op kodu
HTYPE_ETHERNET: int = 1  # 10Mb/100Mb/1Gb Ethernet donanım tipi (RFC 1700)
HLEN_ETHERNET: int = 6   # Ethernet MAC adresi uzunluğu (6 bayt)
DHCP_MAGIC_COOKIE: bytes = bytes([0x63, 0x82, 0x53, 0x63])  # RFC 1497 / RFC 2131 sihirli çerezi (99.130.83.99)

# DHCP Mesaj Tipleri (Seçenek 53 Değerleri)
DHCP_DISCOVER: int = 1  # Ağda DHCP sunucusu arama (Broadcast)
DHCP_OFFER: int = 2     # Sunucunun istemciye sunduğu IP teklifi
DHCP_REQUEST: int = 3   # İstemcinin sunulan IP'yi talep etmesi
DHCP_DECLINE: int = 4   # İstemcinin sunulan IP'yi reddetmesi (ör. IP çakışması)
DHCP_ACK: int = 5       # Sunucunun tahsisi onaylaması ve parametreleri iletmesi
DHCP_NAK: int = 6       # Sunucunun talebi reddetmesi (ör. geçersiz kiralama)
DHCP_RELEASE: int = 7   # İstemcinin IP adresini erken serbest bırakması
DHCP_INFORM: int = 8    # İstemcinin sadece konfigürasyon istemesi (IP atanmışken)

# DHCP Standart Seçenek Kodları (RFC 2132)
OPT_PAD: int = 0                  # Boşluk doldurma seçeneği
OPT_SUBNET_MASK: int = 1          # Alt ağ maskesi (4 bayt)
OPT_ROUTER: int = 3               # Varsayılan ağ geçidi yönlendirici IP listesi
OPT_DNS_SERVERS: int = 6          # DNS sunucuları IP listesi
OPT_REQUESTED_IP: int = 50        # İstemcinin talep ettiği IP adresi
OPT_LEASE_TIME: int = 51          # Kiralama süresi (saniye cinsinden 4 bayt tamsayı)
OPT_DHCP_MESSAGE_TYPE: int = 53   # DHCP mesaj tipi (1 bayt)
OPT_SERVER_IDENTIFIER: int = 54   # Sunucu IP adresi tanımlayıcısı
OPT_PARAMETER_REQUEST_LIST: int = 55  # İstemcinin istediği parametre kodları listesi
OPT_END: int = 255                # Seçenekler bloğu sonu işareti (0xFF)


@dataclass
class DHCPPacket:
    """
    RFC 2131 uyumlu 236 baytlık BOOTP başlığı + 4 bayt Magic Cookie + TLV Seçenekleri.
    """
    op: int = BOOTREQUEST                     # 1 bayt: 1=İstek, 2=Yanıt
    htype: int = HTYPE_ETHERNET               # 1 bayt: Donanım tipi (1=Ethernet)
    hlen: int = HLEN_ETHERNET                 # 1 bayt: Donanım adresi uzunluğu (6=MAC)
    hops: int = 0                             # 1 bayt: Röle atlama sayısı (başlangıçta 0)
    xid: int = 0x3903f326                     # 4 bayt: Benzersiz işlem kimliği (Transaction ID)
    secs: int = 0                             # 2 bayt: İstemcinin istekten bu yana geçen saniyesi
    flags: int = 0x0000                       # 2 bayt: Bayraklar (0x8000=Broadcast, 0x0000=Unicast)
    ciaddr: str = "0.0.0.0"                   # 4 bayt: İstemci IP (Client IP)
    yiaddr: str = "0.0.0.0"                   # 4 bayt: Sizin IP (Your IP - Sunucunun önerdiği)
    siaddr: str = "0.0.0.0"                   # 4 bayt: Sonraki sunucu IP (Next Server IP)
    giaddr: str = "0.0.0.0"                   # 4 bayt: Ağ geçidi/Röle IP (Relay Agent IP)
    chaddr: str = "00:00:00:00:00:00"         # 16 bayt: İstemci donanım adresi (MAC)
    sname: str = ""                           # 64 bayt: İsteğe bağlı sunucu ana makine adı
    file: str = ""                            # 128 bayt: Önyükleme dosyası adı (PXE vb.)
    magic_cookie: bytes = DHCP_MAGIC_COOKIE   # 4 bayt: DHCP Sihirli Çerez (0x63825363)
    options: Dict[int, Any] = field(default_factory=dict)  # Seçenekler (TLV)

    def __post_init__(self) -> None:
        """Alanların kural ve standartlara uygunluğunu sıkı biçimde denetler."""
        # Opcode değeri yalnızca BOOTREQUEST (1) veya BOOTREPLY (2) olabilir
        if self.op not in (BOOTREQUEST, BOOTREPLY):
            # Geçersiz op kodunda hata fırlatılır
            raise DHCPValidationError(f"Gecersiz BOOTP op kodu: {self.op}. Yalnizca 1 veya 2 desteklenir.")
        # Donanım tipi Ethernet (1) olmalıdır
        if self.htype != HTYPE_ETHERNET:
            # Standart dışı donanım tipinde hata üretilir
            raise DHCPValidationError(f"Gecersiz donanim tipi: {self.htype}. Standart Ethernet icin 1 olmalidir.")
        # Donanım uzunluğu Ethernet için tam 6 bayt olmalıdır
        if self.hlen != HLEN_ETHERNET:
            # Hatalı MAC uzunluğunda istisna fırlatılır
            raise DHCPValidationError(f"Gecersiz donanim adresi uzunlugu: {self.hlen}. Ethernet icin 6 olmalidir.")
        # Sihirli çerez doğrulanır (0x63825363)
        if self.magic_cookie != DHCP_MAGIC_COOKIE:
            # Çerez uyuşmazlığında güvenlik ve standart hatası verilir
            raise DHCPValidationError(
                f"Gecersiz DHCP Magic Cookie: 0x{self.magic_cookie.hex()}. Standart 0x63825363 olmalidir."
            )
        # MAC adresi biçimi denetlenir
        self._validate_mac(self.chaddr)
        # Eğer seçenekler varsa ve kiralama süresi verilmişse negatif olamaz
        if OPT_LEASE_TIME in self.options:
            # Kiralama süresi sayısal ve pozitif olmalıdır
            lease = self.options[OPT_LEASE_TIME]
            # Negatif değer kontrolü yapılır
            if not isinstance(lease, int) or lease <= 0:
                # Geçersiz kiralama süresinde hata fırlatılır
                raise DHCPValidationError(f"Gecersiz kira suresi: {lease}. Sure pozitif bir tamsayi olmalidir.")

    @staticmethod
    def _validate_mac(mac_str: str) -> None:
        """MAC adresinin 6 baytlık geçerli bir heksadesimal dize olduğunu doğrular."""
        # MAC adresindeki iki nokta işaretleri temizlenir
        temiz = mac_str.replace(":", "").replace("-", "")
        # Uzunluk 12 karakter (6 bayt) olmalıdır
        if len(temiz) != 12:
            # Hatalı uzunlukta hata fırlatılır
            raise DHCPValidationError(f"Gecersiz MAC adresi uzunlugu: '{mac_str}'.")
        # Karakterlerin tümü onaltılık (hex) rakam olmalıdır
        try:
            # Dönüşüm denenerek hex doğruluğu test edilir
            int(temiz, 16)
        except ValueError:
            # Hex dışı karakter tespit edildiğinde hata fırlatılır
            raise DHCPValidationError(f"Bozuk MAC adresi formati: '{mac_str}'. 6 baytlik hex olmalidir.")

    def serialize(self) -> bytes:
        """
        DHCP paket nesnesini ikili (binary) bayt akışına dönüştürür.
        BOOTP 236 bayt başlık + 4 bayt Magic Cookie + Seçenekler TLV + 1 bayt 0xFF (End).
        """
        # IP adres dizgilerini 4 baytlık ikili ağ gösterimine çeviririz
        ci_b = ipaddress.IPv4Address(self.ciaddr).packed
        yi_b = ipaddress.IPv4Address(self.yiaddr).packed
        si_b = ipaddress.IPv4Address(self.siaddr).packed
        gi_b = ipaddress.IPv4Address(self.giaddr).packed

        # 6 baytlık MAC adresini ikiliye çevirip 16 bayta sıfırla doldururuz (chaddr)
        mac_bytes = bytes.fromhex(self.chaddr.replace(":", "").replace("-", ""))
        chaddr_b = mac_bytes.ljust(16, b"\x00")

        # 64 baytlık sunucu adını sıfır baytlarla doldururuz
        sname_b = self.sname.encode("ascii")[:64].ljust(64, b"\x00")
        # 128 baytlık önyükleme dosya adını sıfır baytlarla doldururuz
        file_b = self.file.encode("ascii")[:128].ljust(128, b"\x00")

        # 236 baytlık standart BOOTP başlığını big-endian formatında paketleriz
        bootp_baslik = struct.pack(
            "!BBBBLHH4s4s4s4s16s64s128s",
            self.op,
            self.htype,
            self.hlen,
            self.hops,
            self.xid,
            self.secs,
            self.flags,
            ci_b,
            yi_b,
            si_b,
            gi_b,
            chaddr_b,
            sname_b,
            file_b
        )

        # Seçenekler bloğunu oluşturmaya başlarız
        secenekler_bayt = bytearray()
        # DHCP sihirli çerezi seçeneklerin en başına eklenir (4 bayt)
        secenekler_bayt.extend(self.magic_cookie)

        # Sözlükteki tüm seçenekler TLV (Tag-Length-Value) olarak kodlanır
        for tag, val in self.options.items():
            # Mesaj tipi seçeneği (Seçenek 53, 1 bayt)
            if tag == OPT_DHCP_MESSAGE_TYPE:
                # 1 bayt uzunluğunda tip değeri yazılır
                secenekler_bayt.extend(bytes([OPT_DHCP_MESSAGE_TYPE, 1, int(val)]))
            # Kiralama süresi seçeneği (Seçenek 51, 4 bayt uint32)
            elif tag == OPT_LEASE_TIME:
                # Süre 4 bayt tamsayı olarak paketlenir
                secenekler_bayt.extend(bytes([OPT_LEASE_TIME, 4]))
                secenekler_bayt.extend(struct.pack("!I", int(val)))
            # Sunucu tanımlayıcısı (Seçenek 54, 4 bayt IPv4)
            elif tag == OPT_SERVER_IDENTIFIER:
                # Sunucu IP adresi 4 bayta dönüştürülür
                ip_b = ipaddress.IPv4Address(str(val)).packed
                secenekler_bayt.extend(bytes([OPT_SERVER_IDENTIFIER, 4]))
                secenekler_bayt.extend(ip_b)
            # Talep edilen IP adresi (Seçenek 50, 4 bayt IPv4)
            elif tag == OPT_REQUESTED_IP:
                # Talep edilen IP 4 bayta çevrilir
                ip_b = ipaddress.IPv4Address(str(val)).packed
                secenekler_bayt.extend(bytes([OPT_REQUESTED_IP, 4]))
                secenekler_bayt.extend(ip_b)
            # Alt ağ maskesi (Seçenek 1, 4 bayt IPv4)
            elif tag == OPT_SUBNET_MASK:
                # Ağ maskesi 4 bayta dönüştürülür
                ip_b = ipaddress.IPv4Address(str(val)).packed
                secenekler_bayt.extend(bytes([OPT_SUBNET_MASK, 4]))
                secenekler_bayt.extend(ip_b)
            # Yönlendirici / Ağ Geçidi (Seçenek 3, IPv4 listesi veya tekil)
            elif tag == OPT_ROUTER:
                # Tekil veya liste kontrolü yapılır
                routers = [val] if isinstance(val, str) else list(val)
                # Her IP 4 bayt yer kaplar
                secenekler_bayt.extend(bytes([OPT_ROUTER, len(routers) * 4]))
                for r in routers:
                    # Yönlendirici IP baytları eklenir
                    secenekler_bayt.extend(ipaddress.IPv4Address(str(r)).packed)
            # DNS Sunucuları (Seçenek 6, IPv4 listesi veya tekil)
            elif tag == OPT_DNS_SERVERS:
                # Tekil veya liste kontrolü yapılır
                dns_list = [val] if isinstance(val, str) else list(val)
                # Her DNS adresi 4 bayttır
                secenekler_bayt.extend(bytes([OPT_DNS_SERVERS, len(dns_list) * 4]))
                for d in dns_list:
                    # DNS IP baytları eklenir
                    secenekler_bayt.extend(ipaddress.IPv4Address(str(d)).packed)
            # Parametre talep listesi (Seçenek 55, bayt dizisi)
            elif tag == OPT_PARAMETER_REQUEST_LIST:
                # İstenen parametre kodları eklenir
                p_list = list(val)
                secenekler_bayt.extend(bytes([OPT_PARAMETER_REQUEST_LIST, len(p_list)]))
                secenekler_bayt.extend(bytes(p_list))

        # Seçeneklerin bittiğini bildiren 255 (0xFF) baytı eklenir
        secenekler_bayt.append(OPT_END)

        # Başlık ve seçenekler birleştirilerek tam ikili paket döndürülür
        return bootp_baslik + bytes(secenekler_bayt)

    @classmethod
    def parse(cls, data: bytes) -> "DHCPPacket":
        """
        Ham bayt akışından 236 baytlık BOOTP başlığını ve TLV seçeneklerini ayrıştırır.
        """
        # Minimum BOOTP başlığı 236 bayttır
        if len(data) < 236:
            # Yetersiz uzunlukta hata fırlatılır
            raise DHCPValidationError(
                f"Paket uzunlugu yetersiz: {len(data)} bayt. Minimum BOOTP basligi 236 bayt olmalidir."
            )

        # 236 baytlık başlık alanları ayrıştırılır
        (
            op, htype, hlen, hops,
            xid, secs, flags,
            ci_b, yi_b, si_b, gi_b,
            chaddr_b, sname_b, file_b
        ) = struct.unpack("!BBBBLHH4s4s4s4s16s64s128s", data[:236])

        # IP adresleri bayttan dizeye çevrilir
        ciaddr = str(ipaddress.IPv4Address(ci_b))
        yiaddr = str(ipaddress.IPv4Address(yi_b))
        siaddr = str(ipaddress.IPv4Address(si_b))
        giaddr = str(ipaddress.IPv4Address(gi_b))

        # 16 baytlık alandan ilk hlen baytı alınıp MAC adresine çevrilir
        mac_raw = chaddr_b[:hlen]
        chaddr = ":".join(f"{b:02x}" for b in mac_raw)

        # Sunucu adı ve dosya adı sıfır baytlardan arındırılarak okunur
        sname = sname_b.split(b"\x00")[0].decode("ascii", errors="ignore")
        file_str = file_b.split(b"\x00")[0].decode("ascii", errors="ignore")

        # Kalan baytlar seçenekler için ayrılır
        options_data = data[236:]
        magic_cookie = DHCP_MAGIC_COOKIE
        options_dict: Dict[int, Any] = {}

        # Seçenekler varsa önce Magic Cookie kontrol edilir (4 bayt)
        if len(options_data) >= 4:
            # İlk 4 bayt sihirli çerezdir
            cookie_candidate = options_data[:4]
            # Standart sihirli çerez ile karşılaştırılır
            if cookie_candidate != DHCP_MAGIC_COOKIE:
                # Standart dışı çerezde hata verilir
                raise DHCPValidationError(
                    f"Gecersiz DHCP Magic Cookie: 0x{cookie_candidate.hex()}. Standart 0x63825363 olmalidir."
                )
            # Çerez geçerlidir
            magic_cookie = cookie_candidate
            idx = 4
            # Seçenekler TLV formatında okunur
            while idx < len(options_data):
                tag = options_data[idx]
                idx += 1
                # Son bayt 255 (0xFF) ise seçenekler sona ermiştir
                if tag == OPT_END:
                    break
                # Boşluk doldurma (PAD 0) seçeneği atlanır
                if tag == OPT_PAD:
                    continue
                # Eğer kalan uzunluk okunamıyorsa döngü kırılır
                if idx >= len(options_data):
                    break
                # Uzunluk baytı okunur
                opt_len = options_data[idx]
                idx += 1
                # Değer baytları dilimlenir
                val_bytes = options_data[idx: idx + opt_len]
                idx += opt_len

                # Mesaj tipi (Option 53)
                if tag == OPT_DHCP_MESSAGE_TYPE and opt_len >= 1:
                    options_dict[OPT_DHCP_MESSAGE_TYPE] = val_bytes[0]
                # Kiralama süresi (Option 51)
                elif tag == OPT_LEASE_TIME and opt_len >= 4:
                    options_dict[OPT_LEASE_TIME] = struct.unpack("!I", val_bytes[:4])[0]
                # Sunucu IP (Option 54)
                elif tag == OPT_SERVER_IDENTIFIER and opt_len >= 4:
                    options_dict[OPT_SERVER_IDENTIFIER] = str(ipaddress.IPv4Address(val_bytes[:4]))
                # Talep edilen IP (Option 50)
                elif tag == OPT_REQUESTED_IP and opt_len >= 4:
                    options_dict[OPT_REQUESTED_IP] = str(ipaddress.IPv4Address(val_bytes[:4]))
                # Alt ağ maskesi (Option 1)
                elif tag == OPT_SUBNET_MASK and opt_len >= 4:
                    options_dict[OPT_SUBNET_MASK] = str(ipaddress.IPv4Address(val_bytes[:4]))
                # Ağ Geçidi / Router (Option 3)
                elif tag == OPT_ROUTER and opt_len >= 4:
                    # 4 baytlık parçalar halinde yönlendiriciler çıkarılır
                    routers = [
                        str(ipaddress.IPv4Address(val_bytes[i: i + 4]))
                        for i in range(0, opt_len, 4)
                        if i + 4 <= opt_len
                    ]
                    options_dict[OPT_ROUTER] = routers[0] if len(routers) == 1 else routers
                # DNS Sunucuları (Option 6)
                elif tag == OPT_DNS_SERVERS and opt_len >= 4:
                    # DNS IP adresleri 4 baytlık bloklar halinde ayrıştırılır
                    dns_servers = [
                        str(ipaddress.IPv4Address(val_bytes[i: i + 4]))
                        for i in range(0, opt_len, 4)
                        if i + 4 <= opt_len
                    ]
                    options_dict[OPT_DNS_SERVERS] = dns_servers
                # Parametre talep listesi (Option 55)
                elif tag == OPT_PARAMETER_REQUEST_LIST:
                    options_dict[OPT_PARAMETER_REQUEST_LIST] = list(val_bytes)
                else:
                    # Tanınmayan diğer seçenekler ham bayt listesi olarak saklanır
                    options_dict[tag] = list(val_bytes)

        # Yeni DHCPPacket nesnesi döndürülür
        return cls(
            op=op,
            htype=htype,
            hlen=hlen,
            hops=hops,
            xid=xid,
            secs=secs,
            flags=flags,
            ciaddr=ciaddr,
            yiaddr=yiaddr,
            siaddr=siaddr,
            giaddr=giaddr,
            chaddr=chaddr,
            sname=sname,
            file=file_str,
            magic_cookie=magic_cookie,
            options=options_dict
        )


@dataclass
class DHCPLease:
    """Tek bir istemci MAC adresine tahsis edilen IP kiralama kaydı."""
    mac_address: str         # Kiracı cihazın MAC adresi
    ip_address: str          # Tahsis edilen IPv4 adresi
    lease_time: int          # Saniye cinsinden kiralama süresi
    start_time: float        # Kiralamanın başladığı zaman damgası (time.time())
    state: str = "ACTIVE"    # Kiralama durumu: OFFERED, ACTIVE, EXPIRED, RELEASED

    @property
    def is_expired(self) -> bool:
        """Kiralama süresinin dolup dolmadığını zaman damgasıyla karşılaştırarak döner."""
        # Şimdiki zaman başlangıç zamanı + kiralama süresini aştıysa true döner
        return time.time() > (self.start_time + self.lease_time)


class DHCPLeasePool:
    """
    IP Adres Havuzu ve Kiralama Yaşam Döngüsü Yöneticisi.
    Belirlenen aralıktaki IP adreslerini kiralar, yeniler, serbest bırakır ve süresi dolanları geri kazanır.
    """
    def __init__(
        self,
        start_ip: str,
        end_ip: str,
        subnet_mask: str = "255.255.255.0",
        router_ip: str = "192.168.1.1",
        dns_servers: Optional[List[str]] = None,
        default_lease_time: int = 86400
    ) -> None:
        # Havuzun başlangıç ve bitiş IP adresleri kaydedilir
        self.start_ip = ipaddress.IPv4Address(start_ip)
        self.end_ip = ipaddress.IPv4Address(end_ip)
        # Başlangıç IP'si bitiş IP'sinden büyük olamaz
        if self.start_ip > self.end_ip:
            raise DHCPValidationError("Baslangic IP adresi bitis IP adresinden buyuk olamaz.")
        # Ağ parametreleri atanır
        self.subnet_mask = subnet_mask
        self.router_ip = router_ip
        self.dns_servers = dns_servers or ["8.8.8.8", "1.1.1.1"]
        self.default_lease_time = default_lease_time

        # Havuzdaki tüm kullanılabilir IP adresleri kümesi oluşturulur
        self.available_ips: Set[str] = set()
        curr = int(self.start_ip)
        end = int(self.end_ip)
        # Döngüyle aralıktaki tüm IP'ler havuza dahil edilir
        while curr <= end:
            self.available_ips.add(str(ipaddress.IPv4Address(curr)))
            curr += 1

        # Aktif kiralamalar sözlüğü: MAC -> DHCPLease
        self.leases: Dict[str, DHCPLease] = {}
        # Geçici teklifler sözlüğü: MAC -> {ip, offer_time}
        self.offers: Dict[str, Tuple[str, float]] = {}

    def clean_expired_leases(self) -> int:
        """Süresi dolmuş kiralamaları temizleyip IP adreslerini havuza iade eder."""
        now = time.time()
        expired_macs = []
        # Tüm kiralamalar kontrol edilir
        for mac, lease in self.leases.items():
            # Eğer süre aşılmışsa listeye eklenir
            if lease.state == "ACTIVE" and (now > lease.start_time + lease.lease_time):
                expired_macs.append(mac)

        # Süresi dolanlar havuza geri kazandırılır
        for mac in expired_macs:
            lease = self.leases[mac]
            lease.state = "EXPIRED"
            # IP adresi kullanılabilir havuza geri eklenir
            self.available_ips.add(lease.ip_address)
            del self.leases[mac]

        # Temizlenen kiralama adedi döndürülür
        return len(expired_macs)

    def process_discover(self, packet: DHCPPacket) -> DHCPPacket:
        """
        DHCP Discover paketini karşılar ve istemciye uygun bir DHCP Offer paketi üretir.
        """
        # Gelen paketin mesaj tipi Seçenek 53 üzerinden kontrol edilir
        msg_type = packet.options.get(OPT_DHCP_MESSAGE_TYPE)
        # Mesaj tipi DISCOVER (1) değilse hata fırlatılır
        if msg_type != DHCP_DISCOVER:
            raise DHCPValidationError(f"Beklenen mesaj tipi DISCOVER (1), alinan: {msg_type}")

        mac = packet.chaddr
        # Önceden kiralanmış aktif IP varsa istemciye tekrar aynı IP önerilir
        if mac in self.leases and self.leases[mac].state == "ACTIVE":
            offered_ip = self.leases[mac].ip_address
        # Daha önce verilmiş aktif teklif varsa aynı IP korunur
        elif mac in self.offers:
            offered_ip = self.offers[mac][0]
        else:
            # Havuzda boş IP adresi var mı kontrol edilir
            if not self.available_ips:
                # Havuz tükendiğinde hata fırlatılır (Starvation durumu)
                raise DHCPValidationError("DHCP IP havuzu tukendi, yeni istemciye teklif sunulamiyor.")
            # Havuzdan sıralı ilk boş IP seçilir
            offered_ip = sorted(list(self.available_ips))[0]
            # IP geçici teklif listesine alınır
            self.offers[mac] = (offered_ip, time.time())

        # İstemciye sunulacak DHCP Offer paketi inşa edilir
        offer_packet = DHCPPacket(
            op=BOOTREPLY,
            htype=HTYPE_ETHERNET,
            hlen=HLEN_ETHERNET,
            hops=0,
            xid=packet.xid,
            secs=0,
            flags=0x0000,
            ciaddr="0.0.0.0",
            yiaddr=offered_ip,
            siaddr=self.router_ip,
            giaddr="0.0.0.0",
            chaddr=mac,
            magic_cookie=DHCP_MAGIC_COOKIE,
            options={
                OPT_DHCP_MESSAGE_TYPE: DHCP_OFFER,
                OPT_SERVER_IDENTIFIER: self.router_ip,
                OPT_LEASE_TIME: self.default_lease_time,
                OPT_SUBNET_MASK: self.subnet_mask,
                OPT_ROUTER: self.router_ip,
                OPT_DNS_SERVERS: self.dns_servers
            }
        )
        return offer_packet

    def process_request(self, packet: DHCPPacket) -> DHCPPacket:
        """
        DHCP Request paketini değerlendirir ve kiralama onayını (DHCP ACK) üretir.
        """
        msg_type = packet.options.get(OPT_DHCP_MESSAGE_TYPE)
        # Mesaj tipi REQUEST (3) olmalıdır
        if msg_type != DHCP_REQUEST:
            raise DHCPValidationError(f"Beklenen mesaj tipi REQUEST (3), alinan: {msg_type}")

        mac = packet.chaddr
        # İstemcinin talep ettiği IP adresi Seçenek 50 veya ciaddr üzerinden alınır
        req_ip = packet.options.get(OPT_REQUESTED_IP, packet.ciaddr)
        if req_ip == "0.0.0.0":
            req_ip = packet.yiaddr

        # Talep edilen IP doğrulanır
        if not req_ip or req_ip == "0.0.0.0":
            # Talep edilen IP belirtilmediyse NAK üretilmelidir
            return self._build_nak(packet)

        # Teklifler veya mevcut kiralamalar arasında bu IP ve MAC eşleşiyor mu?
        valid_request = False
        if mac in self.offers and self.offers[mac][0] == req_ip:
            valid_request = True
            # Teklifi temizleriz
            del self.offers[mac]
        elif mac in self.leases and self.leases[mac].ip_address == req_ip:
            valid_request = True
        elif req_ip in self.available_ips:
            # Havuzda boşta ise ve teklifsiz geldiyse kabul edilebilir
            valid_request = True

        if not valid_request:
            # Geçersiz talepte NAK yanıtı verilir
            return self._build_nak(packet)

        # IP adresi kullanılabilirler kümesinden çıkartılır
        if req_ip in self.available_ips:
            self.available_ips.remove(req_ip)

        # Yeni aktif kiralama kaydı oluşturulur
        lease = DHCPLease(
            mac_address=mac,
            ip_address=req_ip,
            lease_time=self.default_lease_time,
            start_time=time.time(),
            state="ACTIVE"
        )
        self.leases[mac] = lease

        # Onay (DHCP ACK) paketi hazırlanır
        ack_packet = DHCPPacket(
            op=BOOTREPLY,
            htype=HTYPE_ETHERNET,
            hlen=HLEN_ETHERNET,
            hops=0,
            xid=packet.xid,
            secs=0,
            flags=0x0000,
            ciaddr="0.0.0.0",
            yiaddr=req_ip,
            siaddr=self.router_ip,
            giaddr="0.0.0.0",
            chaddr=mac,
            magic_cookie=DHCP_MAGIC_COOKIE,
            options={
                OPT_DHCP_MESSAGE_TYPE: DHCP_ACK,
                OPT_SERVER_IDENTIFIER: self.router_ip,
                OPT_LEASE_TIME: self.default_lease_time,
                OPT_SUBNET_MASK: self.subnet_mask,
                OPT_ROUTER: self.router_ip,
                OPT_DNS_SERVERS: self.dns_servers
            }
        )
        return ack_packet

    def process_release(self, packet: DHCPPacket) -> bool:
        """
        DHCP Release paketini karşılar ve kiralanmış IP'yi havuza iade eder.
        """
        msg_type = packet.options.get(OPT_DHCP_MESSAGE_TYPE)
        # Mesaj tipi RELEASE (7) olmalıdır
        if msg_type != DHCP_RELEASE:
            raise DHCPValidationError(f"Beklenen mesaj tipi RELEASE (7), alinan: {msg_type}")

        mac = packet.chaddr
        # Eğer bu MAC aktif kiralamalarımızda varsa serbest bırakılır
        if mac in self.leases:
            released_ip = self.leases[mac].ip_address
            self.leases[mac].state = "RELEASED"
            # IP adresi kullanılabilir havuza iade edilir
            self.available_ips.add(released_ip)
            del self.leases[mac]
            return True
        return False

    def _build_nak(self, packet: DHCPPacket) -> DHCPPacket:
        """Talebin reddedildiğini bildiren DHCP NAK paketi üretir."""
        return DHCPPacket(
            op=BOOTREPLY,
            htype=HTYPE_ETHERNET,
            hlen=HLEN_ETHERNET,
            hops=0,
            xid=packet.xid,
            secs=0,
            flags=0x0000,
            ciaddr="0.0.0.0",
            yiaddr="0.0.0.0",
            siaddr="0.0.0.0",
            giaddr="0.0.0.0",
            chaddr=packet.chaddr,
            magic_cookie=DHCP_MAGIC_COOKIE,
            options={
                OPT_DHCP_MESSAGE_TYPE: DHCP_NAK,
                OPT_SERVER_IDENTIFIER: self.router_ip
            }
        )


class RogueDHCPDetector:
    """
    Ağ üzerinde yetkisiz (Sahte / Rogue) DHCP sunucularını tespit eden güvenlik denetçisi.
    Ortadaki Adam (MitM) saldırılarını ve yetkisiz Gateway/DNS enjeksiyonunu engeller.
    """
    def __init__(self, authorized_servers: List[str]) -> None:
        # İzin verilen yetkili DHCP sunucu IP adresleri kümesi
        self.authorized_servers: Set[str] = set(authorized_servers)
        # Tespit edilen güvenlik alarmları kaydı
        self.detected_alerts: List[Dict[str, Any]] = []

    def inspect_packet(self, packet: DHCPPacket, source_ip: str) -> bool:
        """
        Gelen paketin yetkili bir sunucudan gelip gelmediğini denetler.
        Rogue sunucu tespit edilirse DHCPSecurityAlert fırlatır.
        """
        msg_type = packet.options.get(OPT_DHCP_MESSAGE_TYPE)
        # Yalnızca sunucu yanıt paketleri (Offer ve ACK) denetlenir
        if msg_type in (DHCP_OFFER, DHCP_ACK):
            server_id = packet.options.get(OPT_SERVER_IDENTIFIER, source_ip)
            # Eğer sunucu IP'si izinli listede yer almıyorsa saldırı vardır
            if server_id not in self.authorized_servers and source_ip not in self.authorized_servers:
                alert = {
                    "tip": "ROGUE_DHCP_DETECTED",
                    "kaynak_ip": source_ip,
                    "sunucu_tanimlayici": server_id,
                    "onerilen_ip": packet.yiaddr,
                    "sahte_gateway": packet.options.get(OPT_ROUTER),
                    "sahte_dns": packet.options.get(OPT_DNS_SERVERS),
                    "zaman": time.time()
                }
                self.detected_alerts.append(alert)
                raise DHCPSecurityAlert(
                    f"TEHLIKE: Sahte (Rogue) DHCP Sunucusu Tespit Edildi! Kaynak: {source_ip}, "
                    f"Server ID: {server_id}, Kurban MAC: {packet.chaddr}"
                )
        return True


class DHCPStarvationDetector:
    """
    DHCP Havuz Tükenme (Starvation) Saldırısı Tespit ve Engelleme Motoru.
    Kısa sürede sahte MAC adresleriyle havuzun bitirilmesini engeller.
    """
    def __init__(self, max_discovers_per_second: int = 4, sliding_window_seconds: float = 1.0) -> None:
        self.max_rate = max_discovers_per_second
        self.window = sliding_window_seconds
        # Son gelen isteklerin zaman damgaları ve MAC adresleri: [(timestamp, mac)]
        self.request_history: List[Tuple[float, str]] = []
        # Engellenen saldırgan MAC veya IP adresleri
        self.blocked_entities: Set[str] = set()

    def inspect_discover(self, packet: DHCPPacket) -> bool:
        """
        Gelen DISCOVER paketinin sıklığını ve benzersiz MAC sayısını ölçerek DoS saldırısını yakalar.
        """
        now = time.time()
        mac = packet.chaddr

        # Zaman penceresi dışındaki eski kayıtlar filtrelenir
        self.request_history = [
            (t, m) for (t, m) in self.request_history if now - t <= self.window
        ]
        # Yeni istek geçmişe kaydedilir
        self.request_history.append((now, mac))

        # Pencere içerisindeki benzersiz MAC adresi adedi hesaplanır
        unique_macs = set(m for (_, m) in self.request_history)

        # Eğer istek sayısı veya benzersiz MAC eşik değerini aşarsa Starvation alarmı verilir
        if len(self.request_history) > self.max_rate and len(unique_macs) > 2:
            self.blocked_entities.add(mac)
            raise DHCPSecurityAlert(
                f"SALDIRI ALARMI: DHCP Starvation (Havuz Tukenme) Saldirisi Algilandi! "
                f"Son {self.window}s icinde {len(self.request_history)} istek ve {len(unique_macs)} farkli MAC goruldu."
            )
        return True


class DHCPSnoopingSwitch:
    """
    Katman-2 Anahtar (L2 Switch) DHCP Snooping Öykünüm Motoru.
    Güvenilmeyen (Untrusted) portlardan gelen sunucu yanıtlarını (Offer/ACK) filtreler
    ve dinamik 'DHCP Snooping Binding Database' tablosunu inşa eder.
    """
    def __init__(self) -> None:
        # Port konfigürasyonları: PortNo -> "trusted" | "untrusted"
        self.port_roles: Dict[str, str] = {}
        # DHCP Snooping Bağlama Veritabanı (Binding Table): MAC -> Binding Bilgisi
        self.binding_database: Dict[str, Dict[str, Any]] = {}
        # Engellenen ihlal olayları günlüğü
        self.snooping_violations: List[Dict[str, Any]] = []

    def configure_port(self, port_name: str, role: str) -> None:
        """Port rolünü 'trusted' (güvenilir) veya 'untrusted' (güvenilmeyen) olarak tanımlar."""
        if role not in ("trusted", "untrusted"):
            raise DHCPValidationError(f"Gecersiz port rolu: '{role}'. 'trusted' veya 'untrusted' olmalidir.")
        self.port_roles[port_name] = role

    def filter_packet(self, port_name: str, packet: DHCPPacket) -> bool:
        """
        Port üzerinden geçen DHCP paketini inceler. Güvenilmeyen porttan gelen
        DHCP OFFER veya ACK paketlerini engeller.
        """
        role = self.port_roles.get(port_name, "untrusted")
        msg_type = packet.options.get(OPT_DHCP_MESSAGE_TYPE)

        # Sunucu mesajları yalnızca TRUSTED portlardan geçebilir!
        if msg_type in (DHCP_OFFER, DHCP_ACK, DHCP_NAK):
            if role == "untrusted":
                violation = {
                    "port": port_name,
                    "ihlal_nedeni": "Guvenilmeyen porttan sunucu yaniti",
                    "mesaj_tipi": msg_type,
                    "yiaddr": packet.yiaddr,
                    "mac": packet.chaddr,
                    "zaman": time.time()
                }
                self.snooping_violations.append(violation)
                raise DHCPSecurityAlert(
                    f"DHCP Snooping Guvenlik Alarmi: Port {port_name} (untrusted) uzerinden "
                    f"sunucu yanit paketi ({msg_type}) engellendi!"
                )

        # Başarılı bir ACK paketi TRUSTED porttan geçerse binding tablosu güncellenir
        if msg_type == DHCP_ACK and role == "trusted":
            self.binding_database[packet.chaddr] = {
                "mac": packet.chaddr,
                "ip": packet.yiaddr,
                "lease_time": packet.options.get(OPT_LEASE_TIME, 86400),
                "port": port_name,
                "zaman": time.time()
            }
        return True
