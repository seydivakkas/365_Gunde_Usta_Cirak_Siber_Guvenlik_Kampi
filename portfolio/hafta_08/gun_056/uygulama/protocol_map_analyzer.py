# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

"""
G056 - Mini Proje 7: Protokol Haritası ve Paket Çözümleme Çalışma Kitabı.

Bu modül, Katman-2 (Ethernet/ARP), Katman-3 (IPv4), Katman-4 (TCP/UDP) ve Katman-7
(DNS/DHCP/HTTP) protokollerinin ikili ve yapılandırılmış paket akışlarını ayrıştırır;
katmanlar arası protokol dağılım haritasını (Protocol Hierarchy), 5'li demet (5-tuple)
iletişim akış matrisini (Flow Matrix), TCP durum takibini ve güvenlik tehditlerini
(Port Scan, DNS Tünelleme, Rogue DHCP, Yeniden İletim Anomalisi) tespit eder.
"""

# İkili ağ baytları paketleme ve açma işlemleri için standart struct modülü
import struct
# IPv4 adresi matematiksel doğrulamaları ve alt ağ denetimleri için ipaddress
import ipaddress
# Shannon Entropisi hesaplamalarında logaritma işlemleri için math modülü
import math
# Zaman damgaları ve akış süreleri hesaplaması için time modülü
import time
# Tip güvenliği ve zengin veri yapıları için dataclass, typing araçları
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any


class PacketParsingError(Exception):
    """Paket başlığı veya alan ayrıştırma hatalarında fırlatılan özel istisna sınıfı."""
    pass


class SecurityAnomalyAlert(Exception):
    """Protokol analizinde tespit edilen güvenlik tehditlerinde fırlatılan özel istisna sınıfı."""
    pass


# Standart EtherType Tanımlayıcıları (Katman-2)
ETHERTYPE_IPV4: int = 0x0800  # IPv4 Protokolü
ETHERTYPE_ARP: int = 0x0806   # Adres Çözümleme Protokolü (ARP)

# Katman-3 Standart Protokol Numaraları (RFC 790)
PROTO_ICMP: int = 1   # Internet Denetim Mesajı Protokolü
PROTO_TCP: int = 6    # İletim Denetim Protokolü (TCP)
PROTO_UDP: int = 17   # Kullanıcı Datagram Protokolü (UDP)


@dataclass
class EthernetFrame:
    """Ethernet II Çerçevesi (14 baytlık standart başlık: Hedef MAC, Kaynak MAC, EtherType)."""
    dst_mac: str         # 6 bayt: Hedef donanım adresi
    src_mac: str         # 6 bayt: Kaynak donanım adresi
    ethertype: int       # 2 bayt: Üst katman protokol türü (0x0800, 0x0806 vb.)
    payload: bytes       # Çerçeve yükü


@dataclass
class IPv4Header:
    """IPv4 Paket Başlığı (20 baytlık standart başlık)."""
    version: int         # 4 bit: IP sürümü (4)
    ihl: int             # 4 bit: İnternet Başlık Uzunluğu (32-bitlik kelime sayısı, min 5)
    total_length: int    # 16 bit: Toplam paket boyutu (başlık + veri)
    ttl: int             # 8 bit: Yaşam süresi (Time to Live)
    protocol: int        # 8 bit: Üst katman protokol numarası (6=TCP, 17=UDP, 1=ICMP)
    src_ip: str          # 32 bit: Kaynak IPv4 adresi
    dst_ip: str          # 32 bit: Hedef IPv4 adresi
    payload: bytes       # IP veri yükü


@dataclass
class TCPHeader:
    """TCP Segment Başlığı (20 baytlık temel başlık)."""
    src_port: int        # 16 bit: Kaynak port numarası
    dst_port: int        # 16 bit: Hedef port numarası
    seq: int             # 32 bit: Sıra numarası (Sequence Number)
    ack: int             # 32 bit: Onay numarası (Acknowledgment Number)
    data_offset: int     # 4 bit: TCP başlık uzunluğu (4 baytlık birimlerle)
    flags: str           # TCP Kontrol bayrakları (SYN, ACK, PSH, FIN, RST, URG)
    window: int          # 16 bit: Alıcı pencere boyutu (Flow Control)
    payload: bytes       # TCP veri yükü


@dataclass
class UDPHeader:
    """UDP Datagram Başlığı (8 baytlık sabit başlık)."""
    src_port: int        # 16 bit: Kaynak port numarası
    dst_port: int        # 16 bit: Hedef port numarası
    length: int          # 16 bit: Başlık + veri uzunluğu (minimum 8 bayt)
    payload: bytes       # UDP veri yükü


@dataclass
class ParsedPacket:
    """Tüm katmanları çözümlenmiş birleşik paket veri nesnesi."""
    packet_id: int                    # Analiz sırasındaki benzersiz paket numarası
    size_bytes: int                   # Paketin toplam bayt boyutu
    l2_frame: Optional[EthernetFrame] = None  # Katman-2 Ethernet çerçevesi
    l3_ipv4: Optional[IPv4Header] = None      # Katman-3 IPv4 başlığı
    l4_tcp: Optional[TCPHeader] = None        # Katman-4 TCP başlığı
    l4_udp: Optional[UDPHeader] = None        # Katman-4 UDP başlığı
    l7_protocol: str = "UNKNOWN"              # Katman-7 uygulama protokolü (HTTP, DNS, DHCP)
    l7_data: Dict[str, Any] = field(default_factory=dict)  # Uygulama katmanı meta verileri
    is_retransmission: bool = False           # Yeniden iletim bayrağı


@dataclass
class CommunicationFlow:
    """İki uç nokta arasındaki 5'li demet (5-tuple) iletişim oturumu."""
    src_ip: str                   # Kaynak IP adresi
    src_port: int                 # Kaynak port numarası
    dst_ip: str                   # Hedef IP adresi
    dst_port: int                 # Hedef port numarası
    protocol: str                 # Katman-4 protokolü (TCP, UDP, ICMP)
    packet_count: int = 0         # Akışta iletilen toplam paket adedi
    byte_count: int = 0           # Akışta iletilen toplam bayt hacmi
    tcp_flags_seen: Set[str] = field(default_factory=set)  # Görülen TCP bayrakları
    retransmission_count: int = 0 # Tespit edilen yeniden iletim adedi
    state: str = "INIT"           # Oturum durumu: SYN_SENT, ESTABLISHED, CLOSED, UDP_STREAM


class ProtocolDissector:
    """
    İkili bayt dizilerini ve yapılandırılmış sözlükleri L2-L4 katmanlarına ayıran çözümleyici.
    """
    @staticmethod
    def validate_mac(mac: str) -> None:
        """MAC adresinin 6 baytlık geçerli bir heksadesimal dize olduğunu doğrular."""
        # İki nokta ve tire işaretleri temizlenir
        temiz = mac.replace(":", "").replace("-", "")
        # Uzunluk 12 karakter (6 bayt) olmalıdır
        if len(temiz) != 12:
            raise PacketParsingError(f"Gecersiz MAC adresi uzunlugu: '{mac}'.")
        # Karakterlerin tümü onaltılık (hex) rakam olmalıdır
        try:
            int(temiz, 16)
        except ValueError:
            raise PacketParsingError(f"Bozuk MAC adresi formati: '{mac}'. 6 baytlik hex olmalidir.")

    @staticmethod
    def validate_ipv4(ip: str) -> None:
        """IPv4 adresinin standart noktalı ondalık formatta ve 0-255 aralığında olduğunu doğrular."""
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            raise PacketParsingError(f"Gecersiz IPv4 adresi: '{ip}'. Oktet degerleri 0-255 araliginda olmalidir.")

    @classmethod
    def dissect_ethernet_raw(cls, data: bytes) -> EthernetFrame:
        """14 baytlık ham Ethernet II başlığını ikili formatta açar."""
        # Ethernet başlığı en az 14 bayt olmalıdır
        if len(data) < 14:
            raise PacketParsingError(
                f"Ethernet cercevesi cok kisa: {len(data)} bayt. Minimum baslik uzunlugu 14 bayttir."
            )
        # Hedef MAC (6B), Kaynak MAC (6B) ve EtherType (2B) açılır
        dst_b, src_b, ethertype = struct.unpack("!6s6sH", data[:14])
        # Baytlar okunabilir MAC dizgisine çevrilir
        dst_mac = ":".join(f"{b:02x}" for b in dst_b)
        src_mac = ":".join(f"{b:02x}" for b in src_b)
        # Desteklenen EtherType kontrolü yapılır
        if ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_ARP):
            raise PacketParsingError(f"Desteklenmeyen veya gecersiz EtherType: 0x{ethertype:04x}.")
        return EthernetFrame(dst_mac=dst_mac, src_mac=src_mac, ethertype=ethertype, payload=data[14:])

    @classmethod
    def dissect_ipv4_raw(cls, data: bytes) -> Tuple[IPv4Header, bytes]:
        """20 baytlık ham IPv4 başlığını açar ve veri yükünden ayırır."""
        # IPv4 başlığı en az 20 bayt olmalıdır
        if len(data) < 20:
            raise PacketParsingError(f"IPv4 basligi yetersiz: {len(data)} bayt. Minimum uzunluk 20 bayt olmalidir.")
        # İlk bayt sürüm ve IHL bilgisini taşır
        ver_ihl = data[0]
        version = ver_ihl >> 4
        ihl = ver_ihl & 0x0F
        # Sürüm kesinlikle 4 olmalıdır
        if version != 4:
            raise PacketParsingError(f"Gecersiz IP versiyonu: {version}. IPv4 icin versiyon 4 olmalidir.")
        # IHL en az 5 (5 * 4 = 20 bayt) olmalıdır
        if ihl < 5:
            raise PacketParsingError(f"Gecersiz IPv4 IHL degeri: {ihl}. Minimum 5 olmalidir.")
        # Başlık uzunluğu bayt cinsinden hesaplanır
        hdr_len = ihl * 4
        # Veri akışı başlık boyutunu karşılamalıdır
        if len(data) < hdr_len:
            raise PacketParsingError(f"Kirpikli IPv4 paketi: {len(data)} bayt, beklenen baslik: {hdr_len} bayt.")
        # Başlık alanları unpack edilir
        _, _, total_len, _, _, ttl, proto, _, src_b, dst_b = struct.unpack("!BBHHHBBH4s4s", data[:20])
        # Protokol kodu kontrol edilir
        if proto not in (PROTO_TCP, PROTO_UDP, PROTO_ICMP):
            raise PacketParsingError(f"Desteklenmeyen L4 protokol kodu: {proto}. Yalnizca TCP, UDP, ICMP desteklenir.")
        src_ip = str(ipaddress.IPv4Address(src_b))
        dst_ip = str(ipaddress.IPv4Address(dst_b))
        header = IPv4Header(
            version=version,
            ihl=ihl,
            total_length=total_len,
            ttl=ttl,
            protocol=proto,
            src_ip=src_ip,
            dst_ip=dst_ip,
            payload=data[hdr_len:]
        )
        return header, data[hdr_len:]

    @classmethod
    def dissect_tcp_raw(cls, data: bytes) -> Tuple[TCPHeader, bytes]:
        """20 baytlık ham TCP başlığını açar."""
        if len(data) < 20:
            raise PacketParsingError(f"TCP basligi yetersiz: {len(data)} bayt. Minimum TCP basligi 20 bayttir.")
        src_port, dst_port, seq, ack, offset_reserved, flags_num, window, _, _ = struct.unpack("!HHLLBBHHH", data[:20])
        data_offset = offset_reserved >> 4
        tcp_hdr_len = data_offset * 4
        if len(data) < tcp_hdr_len:
            raise PacketParsingError(f"Kirpikli TCP segmenti: {len(data)} bayt, beklenen baslik: {tcp_hdr_len} bayt.")
        # Bayraklar metin formatına çevrilir
        flag_list = []
        if flags_num & 0x02: flag_list.append("SYN")
        if flags_num & 0x10: flag_list.append("ACK")
        if flags_num & 0x08: flag_list.append("PSH")
        if flags_num & 0x01: flag_list.append("FIN")
        if flags_num & 0x04: flag_list.append("RST")
        if flags_num & 0x20: flag_list.append("URG")
        flags_str = ",".join(flag_list) if flag_list else "NONE"
        header = TCPHeader(
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            data_offset=data_offset,
            flags=flags_str,
            window=window,
            payload=data[tcp_hdr_len:]
        )
        return header, data[tcp_hdr_len:]

    @classmethod
    def dissect_udp_raw(cls, data: bytes) -> Tuple[UDPHeader, bytes]:
        """8 baytlık ham UDP başlığını açar."""
        if len(data) < 8:
            raise PacketParsingError(f"UDP basligi yetersiz: {len(data)} bayt. Minimum UDP basligi 8 bayttir.")
        src_port, dst_port, length, _ = struct.unpack("!HHHH", data[:8])
        header = UDPHeader(
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            payload=data[8:]
        )
        return header, data[8:]


class ProtocolMapWorkbench:
    """
    Mini Proje 7: Protokol Haritalandırma, Oturum Takip ve Güvenlik Denetim Çalışma Kitabı.
    """
    def __init__(self, authorized_dhcp_server: str = "192.168.1.1") -> None:
        self.authorized_dhcp_server = authorized_dhcp_server
        # Çözümlenen tüm paketlerin listesi
        self.packets: List[ParsedPacket] = []
        # İletişim Akış Matrisi: FlowKey (5-tuple) -> CommunicationFlow
        self.flow_matrix: Dict[Tuple[str, int, str, int, str], CommunicationFlow] = {}
        # Protokol Hiyerarşisi İstatistikleri: Protokol Adı -> {paket_sayisi, bayt_hacmi}
        self.layer_stats: Dict[str, Dict[str, int]] = {
            "Ethernet": {"paket": 0, "bayt": 0},
            "ARP": {"paket": 0, "bayt": 0},
            "IPv4": {"paket": 0, "bayt": 0},
            "TCP": {"paket": 0, "bayt": 0},
            "UDP": {"paket": 0, "bayt": 0},
            "HTTP": {"paket": 0, "bayt": 0},
            "DNS": {"paket": 0, "bayt": 0},
            "DHCP": {"paket": 0, "bayt": 0}
        }
        # Güvenlik Olayları Günlüğü
        self.security_incidents: List[Dict[str, Any]] = []
        # Port Tarama Takibi için Kaynak IP -> Set(Hedef Port) eşlemesi
        self.syn_scan_tracker: Dict[str, Set[int]] = {}

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Bir dizginin Shannon Entropisini hesaplar (DNS Tünelleme tespiti için)."""
        if not text:
            return 0.0
        uzunluk = len(text)
        frekanslar: Dict[str, int] = {}
        for char in text:
            frekanslar[char] = frekanslar.get(char, 0) + 1
        entropi = 0.0
        for f in frekanslar.values():
            p = f / uzunluk
            entropi -= p * math.log2(p)
        return entropi

    def ingest_frame_dict(self, frame_dict: Dict[str, Any]) -> ParsedPacket:
        """
        JSON tabanlı paket çerçeve sözlüğünü ayrıştırır ve çalışma kitabına kaydeder.
        """
        pkt_id = frame_dict.get("id", len(self.packets) + 1)
        pkt_size = frame_dict.get("boyut", 60)
        is_retrans = frame_dict.get("yeniden_iletim", False)

        # Katman-2 Ethernet Bilgisi
        k2 = frame_dict.get("katman2", {})
        src_mac = k2.get("src_mac", "00:00:00:00:00:00")
        dst_mac = k2.get("dst_mac", "ff:ff:ff:ff:ff:ff")
        ethertype_str = k2.get("ethertype", "0x0800")
        ProtocolDissector.validate_mac(src_mac)
        ProtocolDissector.validate_mac(dst_mac)
        ethertype_val = int(ethertype_str, 16)
        if ethertype_val not in (ETHERTYPE_IPV4, ETHERTYPE_ARP):
            raise PacketParsingError(f"Desteklenmeyen veya gecersiz EtherType: {ethertype_str}.")

        l2_frame = EthernetFrame(dst_mac=dst_mac, src_mac=src_mac, ethertype=ethertype_val, payload=b"")
        self.layer_stats["Ethernet"]["paket"] += 1
        self.layer_stats["Ethernet"]["bayt"] += pkt_size

        l3_ipv4: Optional[IPv4Header] = None
        l4_tcp: Optional[TCPHeader] = None
        l4_udp: Optional[UDPHeader] = None
        l7_proto = "UNKNOWN"
        l7_data: Dict[str, Any] = {}

        # Katman-2 ARP Kontrolü
        if ethertype_val == ETHERTYPE_ARP:
            self.layer_stats["ARP"]["paket"] += 1
            self.layer_stats["ARP"]["bayt"] += pkt_size
            arp_data = frame_dict.get("katman3_arp", {})
            l7_proto = "ARP"
            l7_data = arp_data
            parsed = ParsedPacket(
                packet_id=pkt_id,
                size_bytes=pkt_size,
                l2_frame=l2_frame,
                l7_protocol="ARP",
                l7_data=l7_data
            )
            self.packets.append(parsed)
            return parsed

        # Katman-3 IPv4 Kontrolü
        if ethertype_val == ETHERTYPE_IPV4:
            self.layer_stats["IPv4"]["paket"] += 1
            self.layer_stats["IPv4"]["bayt"] += pkt_size
            k3 = frame_dict.get("katman3_ip", {})
            src_ip = k3.get("src_ip", "0.0.0.0")
            dst_ip = k3.get("dst_ip", "0.0.0.0")
            ProtocolDissector.validate_ipv4(src_ip)
            ProtocolDissector.validate_ipv4(dst_ip)
            proto_val = k3.get("protocol", 6)
            ttl_val = k3.get("ttl", 64)
            l3_ipv4 = IPv4Header(
                version=4, ihl=5, total_length=pkt_size - 14, ttl=ttl_val,
                protocol=proto_val, src_ip=src_ip, dst_ip=dst_ip, payload=b""
            )

            # Katman-4 TCP Kontrolü
            if proto_val == PROTO_TCP:
                self.layer_stats["TCP"]["paket"] += 1
                self.layer_stats["TCP"]["bayt"] += pkt_size
                k4 = frame_dict.get("katman4_tcp", {})
                sport = k4.get("src_port", 0)
                dport = k4.get("dst_port", 0)
                flags = k4.get("flags", "")
                seq = k4.get("seq", 0)
                ack = k4.get("ack", 0)
                window = k4.get("window", 65535)
                l4_tcp = TCPHeader(
                    src_port=sport, dst_port=dport, seq=seq, ack=ack,
                    data_offset=5, flags=flags, window=window, payload=b""
                )
                # HTTP Katman-7 Tespiti
                if sport == 80 or dport == 80 or "HTTP" in frame_dict.get("katman7_payload", ""):
                    l7_proto = "HTTP"
                    self.layer_stats["HTTP"]["paket"] += 1
                    self.layer_stats["HTTP"]["bayt"] += pkt_size
                    l7_data["payload"] = frame_dict.get("katman7_payload", "")

                # 5-Tuple Akış Güncellemesi
                flow_key = (src_ip, sport, dst_ip, dport, "TCP")
                self._update_flow(flow_key, pkt_size, flags, is_retrans)

                # Güvenlik Denetimi: Port Tarama (SYN Scan) Tespiti
                if flags == "SYN":
                    if src_ip not in self.syn_scan_tracker:
                        self.syn_scan_tracker[src_ip] = set()
                    self.syn_scan_tracker[src_ip].add(dport)
                    if len(self.syn_scan_tracker[src_ip]) >= 3:
                        incident = {
                            "tip": "PORT_SCAN_SYN_FLOOD",
                            "saldirgan_ip": src_ip,
                            "hedef_ip": dst_ip,
                            "hedef_portlar": sorted(list(self.syn_scan_tracker[src_ip])),
                            "mesaj": f"Port Tarama Saldırısı Algılandı: {src_ip} -> {dst_ip} ({len(self.syn_scan_tracker[src_ip])} farklı port)"
                        }
                        self.security_incidents.append(incident)

            # Katman-4 UDP Kontrolü
            elif proto_val == PROTO_UDP:
                self.layer_stats["UDP"]["paket"] += 1
                self.layer_stats["UDP"]["bayt"] += pkt_size
                k4 = frame_dict.get("katman4_udp", {})
                sport = k4.get("src_port", 0)
                dport = k4.get("dst_port", 0)
                length = k4.get("length", 8)
                l4_udp = UDPHeader(src_port=sport, dst_port=dport, length=length, payload=b"")

                # DNS Tespiti (Port 53)
                if sport == 53 or dport == 53 or "katman7_dns" in frame_dict:
                    l7_proto = "DNS"
                    self.layer_stats["DNS"]["paket"] += 1
                    self.layer_stats["DNS"]["bayt"] += pkt_size
                    l7_data = frame_dict.get("katman7_dns", {})
                    # DNS Tünelleme / Veri Sızıntısı Analizi
                    qname = l7_data.get("qname", "")
                    if qname:
                        entropy = self.calculate_entropy(qname)
                        if (entropy >= 2.8 and len(qname) >= 25) or (len(qname) >= 35):
                            incident = {
                                "tip": "DNS_TUNNELING_EXFILTRATION",
                                "kaynak_ip": src_ip,
                                "hedef_dns": dst_ip,
                                "sorgu_adi": qname,
                                "entropi": round(entropy, 3),
                                "mesaj": f"Şüpheli DNS Tünelleme / Veri Sızıntısı: '{qname}' (Entropi: {round(entropy, 3)})"
                            }
                            self.security_incidents.append(incident)

                # DHCP Tespiti (Port 67/68)
                elif sport in (67, 68) or dport in (67, 68) or "katman7_dhcp" in frame_dict:
                    l7_proto = "DHCP"
                    self.layer_stats["DHCP"]["paket"] += 1
                    self.layer_stats["DHCP"]["bayt"] += pkt_size
                    l7_data = frame_dict.get("katman7_dhcp", {})
                    # Sahte (Rogue) DHCP Sunucusu Tespiti
                    msg_type = l7_data.get("msg_type")
                    if msg_type in ("OFFER", "ACK"):
                        srv_id = l7_data.get("server_id", src_ip)
                        if srv_id != self.authorized_dhcp_server and src_ip != self.authorized_dhcp_server:
                            incident = {
                                "tip": "ROGUE_DHCP_SERVER",
                                "sahte_sunucu_ip": src_ip,
                                "yetkili_sunucu": self.authorized_dhcp_server,
                                "onerilen_gateway": l7_data.get("router", "Bilinmiyor"),
                                "mesaj": f"Sahte (Rogue) DHCP Sunucusu Algılandı! Kaynak: {src_ip}, ServerID: {srv_id}"
                            }
                            self.security_incidents.append(incident)

                # 5-Tuple Akış Güncellemesi
                flow_key = (src_ip, sport, dst_ip, dport, "UDP")
                self._update_flow(flow_key, pkt_size, "UDP", False)

        parsed = ParsedPacket(
            packet_id=pkt_id,
            size_bytes=pkt_size,
            l2_frame=l2_frame,
            l3_ipv4=l3_ipv4,
            l4_tcp=l4_tcp,
            l4_udp=l4_udp,
            l7_protocol=l7_proto,
            l7_data=l7_data,
            is_retransmission=is_retrans
        )
        self.packets.append(parsed)
        return parsed

    def _update_flow(self, flow_key: Tuple[str, int, str, int, str], size: int, flags: str, is_retrans: bool) -> None:
        """Akış tablosunu günceller veya yeni bir oturum başlatır."""
        src_ip, sport, dst_ip, dport, proto = flow_key
        # Ters yön anahtarı (Reverse flow)
        rev_key = (dst_ip, dport, src_ip, sport, proto)
        target_key = flow_key if flow_key in self.flow_matrix else (rev_key if rev_key in self.flow_matrix else flow_key)

        if target_key not in self.flow_matrix:
            flow = CommunicationFlow(
                src_ip=src_ip,
                src_port=sport,
                dst_ip=dst_ip,
                dst_port=dport,
                protocol=proto,
                packet_count=1,
                byte_count=size,
                tcp_flags_seen=set(flags.split(",")) if flags else set(),
                state="HANDSHAKE_INIT" if "SYN" in flags else ("UDP_STREAM" if proto == "UDP" else "DATA")
            )
            self.flow_matrix[target_key] = flow
        else:
            flow = self.flow_matrix[target_key]
            flow.packet_count += 1
            flow.byte_count += size
            if flags:
                for f in flags.split(","):
                    flow.tcp_flags_seen.add(f)
            if is_retrans:
                flow.retransmission_count += 1
            # TCP Durum Geçişleri
            if "SYN" in flow.tcp_flags_seen and "ACK" in flow.tcp_flags_seen:
                flow.state = "ESTABLISHED"
            if "FIN" in flow.tcp_flags_seen or "RST" in flow.tcp_flags_seen:
                flow.state = "CLOSED"

    def generate_protocol_hierarchy_report(self) -> str:
        """Protokol dağılım hiyerarşisini gösteren ASCII metin raporu üretir."""
        lines = []
        lines.append("=" * 70)
        lines.append("PROTOKOL DAĞILIM HİYERARŞİSİ (PROTOCOL HIERARCHY MAP)")
        lines.append("=" * 70)
        lines.append(f"{'Protokol':<15} | {'Paket Sayısı':<15} | {'Toplam Hacim (Bayt)':<20} | {'Yüzde (%)':<10}")
        lines.append("-" * 70)

        total_pkts = len(self.packets) if self.packets else 1
        for proto, stats in self.layer_stats.items():
            pkts = stats["paket"]
            bytes_vol = stats["bayt"]
            pct = (pkts / total_pkts) * 100 if total_pkts > 0 else 0.0
            lines.append(f"{proto:<15} | {pkts:<15} | {bytes_vol:<20} | %{pct:<8.1f}")
        lines.append("=" * 70)
        return "\n".join(lines)

    def generate_flow_matrix_report(self) -> str:
        """Aktif iletişim akışlarını tablo halinde sunan ASCII matrisi üretir."""
        lines = []
        lines.append("=" * 95)
        lines.append("İLETİŞİM AKIŞ MATRİSİ (COMMUNICATION FLOW MATRIX - 5-TUPLE)")
        lines.append("=" * 95)
        lines.append(f"{'Kaynak IP:Port':<25} <-> {'Hedef IP:Port':<25} | {'Proto':<5} | {'Paket':<5} | {'Bayt':<7} | {'Durum':<12}")
        lines.append("-" * 95)

        for (sip, sp, dip, dp, proto), flow in self.flow_matrix.items():
            src_str = f"{sip}:{sp}"
            dst_str = f"{dip}:{dp}"
            lines.append(f"{src_str:<25} <-> {dst_str:<25} | {proto:<5} | {flow.packet_count:<5} | {flow.byte_count:<7} | {flow.state:<12}")
        lines.append("=" * 95)
        return "\n".join(lines)
