# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# 
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
# amaçlı olarak paylaşılmıştır.
# 
# YASAKLAR:
#   1. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
#   2. Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
#   3. Alt lisanslanamaz, satılamaz veya devredilemez.
#   4. Tersine mühendislik yapılamaz.
# 
# İZİN VERİLEN KULLANIM:
#   - GitHub üzerinde görüntüleme ve okuma.
#   - Kişisel öğrenim amacıyla kodu inceleme (kopyalamadan).
# 
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
# İzin talepleri için: GitHub @seydivakkas
# ==============================================================================
"""
G061: Proxy, NAT ve Güvenlik Duvarı Analiz ve Simülasyon Motoru.

Bu modül;
  1. Durum takipli (Stateful Inspection / Conntrack) güvenlik duvarı kurallarını,
  2. Port Adres Dönüşümü (PAT / NAPT) tablosu ve port tükenme yönetimini,
  3. İleri (Forward) ve Ters (Reverse) vekil sunucu mekanizmalarını,
  4. X-Forwarded-For IP sahteciliği ve gizli TCP tarama (SYN+FIN, Null Scan) savunmalarını
modeller ve denetler.
"""

# Veri yapılarını tip güvenliğiyle oluşturmak için dataclass
from dataclasses import dataclass, field
# Tip ipuçları ve koleksiyon türleri
from typing import Dict, List, Optional, Set, Tuple, Any
# IP adresi doğrulaması için ipaddress kütüphanesi
import ipaddress
# Zaman damgaları ve zaman aşımı hesaplamaları için time modülü
import time


# ------------------------------------------------------------------------------
# ÖZEL HATA SINIFLARI (EXCEPTION HIERARCHY)
# ------------------------------------------------------------------------------

class NetworkSecurityError(Exception):
    """Ağ güvenliği analiz motorunun temel hata sınıfı."""
    # Üst sınıf istisnası olarak kalıtım sağlar
    pass


class NetworkValidationError(NetworkSecurityError):
    """Ağ parametreleri veya IP adresleri biçimsel olarak hatalı olduğunda fırlatılır."""
    # Biçim doğrulama hatalarında fırlatılır
    pass


class InvalidPacketFlagsError(NetworkValidationError):
    """RFC 793 standardına aykırı TCP bayrak kombinasyonlarında fırlatılır."""
    # Geçersiz bayrak taramalarında (SYN+FIN, Null Scan vb.) fırlatılır
    pass


class FirewallDropError(NetworkSecurityError):
    """Güvenlik duvarı kuralları veya durum tablosu uyarınca paket düşürüldüğünde fırlatılır."""
    # Paket engellendiğinde veya düşürüldüğünde fırlatılır
    pass


class ConntrackOverflowError(NetworkSecurityError):
    """Durum tablosunun (Conntrack Table) maksimum kapasitesi aşıldığında fırlatılır."""
    # Durum tablosu taşma taşkınlarında fırlatılır
    pass


class NATExhaustionError(NetworkSecurityError):
    """PAT port havuzunda kullanılabilir boş port kalmadığında fırlatılır."""
    # Port tükenmesi durumlarında fırlatılır
    pass


class ProxySecurityViolationError(NetworkSecurityError):
    """Vekil sunucu üzerinde sahte başlık veya güvenlik ihlali tespit edildiğinde fırlatılır."""
    # X-Forwarded-For sahteciliği veya güvenlik ihlalinde fırlatılır
    pass


class ProxyAccessDeniedError(NetworkSecurityError):
    """Forward proxy üzerinden yasaklı bir porta erişim talep edildiğinde fırlatılır."""
    # İzin verilmeyen CONNECT tünel isteklerinde fırlatılır
    pass


# ------------------------------------------------------------------------------
# VERİ YAPILARI (DATACLASSES)
# ------------------------------------------------------------------------------

@dataclass
class TCPPacket:
    """TCP Katmanı Ağ Paketi Modeli."""
    # Gönderen istemcinin IPv4 adresi
    src_ip: str
    # Gönderen port numarası (1 - 65535)
    src_port: int
    # Hedef sunucunun IPv4 adresi
    dst_ip: str
    # Hedef port numarası (1 - 65535)
    dst_port: int
    # TCP bayrakları listesi (ör. ["SYN"], ["ACK"], ["SYN", "ACK"], ["RST"])
    flags: List[str] = field(default_factory=list)
    # Taşınan yük verisi
    payload: bytes = b""


@dataclass
class NATMapping:
    """PAT (Port Adres Dönüştürme) Oturum Kaydı Modeli."""
    # İç ağdaki istemcinin özel (private) IP adresi
    internal_ip: str
    # İç ağdaki istemcinin kaynak portu
    internal_port: int
    # Dış dünyaya sunulan genel (public) IP adresi
    public_ip: str
    # Dış dünyada bu oturum için tahsis edilen dönüştürülmüş genel port
    translated_port: int
    # İstemcinin erişmek istediği hedef IP adresi
    destination_ip: str
    # İstemcinin erişmek istediği hedef port
    destination_port: int
    # Kaydın oluşturulma zaman damgası
    created_at: float = field(default_factory=time.time)
    # Kaydın en son görüldüğü zaman damgası
    last_seen: float = field(default_factory=time.time)


@dataclass
class ConntrackEntry:
    """Durum Takipli Güvenlik Duvarı Bağlantı Takip (Conntrack) Kaydı."""
    # 5'li demet bağlantı akış anahtarı: (src_ip, src_port, dst_ip, dst_port, protocol)
    flow_id: str
    # Bağlantı durumu: "NEW", "ESTABLISHED", "RELATED", "CLOSED"
    state: str
    # Bu oturum üzerinden geçen paket sayısı
    packets_seen: int = 1
    # Bu oturum üzerinden geçen bayt miktarı
    bytes_seen: int = 0
    # En son görüldüğü zaman damgası
    last_seen: float = field(default_factory=time.time)


# ------------------------------------------------------------------------------
# AĞ DOĞRULAMA VE BAYRAK ANALİZ FONKSİYONLARI
# ------------------------------------------------------------------------------

def validate_ipv4_address(ip_str: str) -> bool:
    """
    Verilen dizginin geçerli bir IPv4 adresi formatında olduğunu doğrular.
    """
    # Boş veya boşluklu verileri reddet
    if not ip_str or not isinstance(ip_str, str) or not ip_str.strip():
        # Geçersiz IP hatası fırlat
        raise NetworkValidationError(f"Gecersiz IPv4 adresi: '{ip_str}'.")
    
    # Standart ipaddress modülü ile ayrıştırmayı dene
    try:
        # IPv4 adresi olarak doğrula
        ipaddress.IPv4Address(ip_str.strip())
        # Başarılı ise True döndür
        return True
    except ipaddress.AddressValueError:
        # Hatalı IP formatı istisnası fırlat
        raise NetworkValidationError(f"Gecersiz IPv4 adresi: '{ip_str}'.")


def validate_tcp_flags(flags: List[str]) -> None:
    """
    RFC 793 kurallarına göre TCP bayrak kombinasyonlarını denetler.
    SYN+FIN, Null Scan (Bayrak yok) veya Xmas Scan gibi saldırı desenlerini reddeder.
    """
    # Bayrakları büyük harfe dönüştür ve kümeye al
    flag_set = {f.strip().upper() for f in flags if f.strip()}
    
    # 1. Null Scan Kontrolü: Hiçbir bayrak set edilmemişse (Bayrak listesi boşsa)
    if not flag_set:
        # Null Scan saldırısı tespit edildi hatası ver
        raise InvalidPacketFlagsError(
            "Gecersiz TCP bayrak kombinasyonu: Null Scan (Flags = 0) saldirisi tespit edildi ve engellendi."
        )
        
    # 2. SYN + FIN İhlali: Bir bağlantı hem başlatılıp hem aynı anda sonlandırılamaz (RFC 793)
    if "SYN" in flag_set and "FIN" in flag_set:
        # SYN+FIN saldırı taraması hatası fırlat
        raise InvalidPacketFlagsError(
            "Gecersiz TCP bayrak kombinasyonu tespit edildi: SYN+FIN saldiri taramasi reddedildi."
        )
        
    # 3. Xmas Scan İhlali: FIN + PSH + URG bayraklarının hepsi birden set edilmişse
    if "FIN" in flag_set and "PSH" in flag_set and "URG" in flag_set:
        # Xmas Scan saldırı taraması hatası ver
        raise InvalidPacketFlagsError(
            "Gecersiz TCP bayrak kombinasyonu tespit edildi: Xmas Scan (FIN+PSH+URG) reddedildi."
        )


# ------------------------------------------------------------------------------
# DURUM TAKİPLİ GÜVENLİK DUVARI MOTORU (STATEFUL FIREWALL ENGINE)
# ------------------------------------------------------------------------------

class StatefulFirewall:
    """
    L4 Durum Takipli (Stateful Inspection / Conntrack) Güvenlik Duvarı Simülatörü.
    """

    def __init__(self, default_policy: str = "DROP", max_conntrack_entries: int = 1000):
        # Varsayılan politika (DROP veya ACCEPT)
        self.default_policy = default_policy.upper()
        # Durum tablosunun maksimum girdi sınırı
        self.max_conntrack_entries = max_conntrack_entries
        # Bağlantı takip tablosu (Conntrack Table)
        self.conntrack_table: Dict[str, ConntrackEntry] = {}
        # İzin verilen port ve kural listesi: (direction, dst_port) -> action
        self.rules: List[Dict[str, Any]] = []

    def add_rule(self, direction: str, dst_port: int, action: str = "ACCEPT", description: str = "") -> None:
        """Güvenlik duvarına yeni bir erişim kuralı ekler."""
        # Kuralı listeye ekle
        self.rules.append({
            "direction": direction.upper(),
            "dst_port": dst_port,
            "action": action.upper(),
            "description": description
        })

    def _get_flow_key(self, pkt: TCPPacket) -> Tuple[str, str]:
        """İleri ve ters yönlü 5'li demet anahtarlarını üretir."""
        # İleri yönlü akış anahtarı
        forward_key = f"{pkt.src_ip}:{pkt.src_port}->{pkt.dst_ip}:{pkt.dst_port}"
        # Ters yönlü akış anahtarı
        reverse_key = f"{pkt.dst_ip}:{pkt.dst_port}->{pkt.src_ip}:{pkt.src_port}"
        # İkisini demet olarak döndür
        return forward_key, reverse_key

    def process_packet(self, pkt: TCPPacket, direction: str = "INGRESS") -> str:
        """
        Gelen bir TCP paketini durum tablosuna ve güvenlik kurallarına göre işler.
        """
        # IP adreslerini doğrula
        validate_ipv4_address(pkt.src_ip)
        validate_ipv4_address(pkt.dst_ip)
        # TCP bayraklarını analiz et ve anomali taramalarını engelle
        validate_tcp_flags(pkt.flags)
        
        # Akış anahtarlarını çıkar
        fwd_key, rev_key = self._get_flow_key(pkt)
        flag_set = {f.upper() for f in pkt.flags}
        
        # 1. Mevcut bir oturumun devamı mı? (ESTABLISHED kontrolü)
        if fwd_key in self.conntrack_table:
            # İleri yönlü akış tablosunda mevcut
            entry = self.conntrack_table[fwd_key]
            # Paket sayısını ve zamanını güncelle
            entry.packets_seen += 1
            entry.last_seen = time.time()
            # Eğer FIN veya RST geldiyse oturumu kapat
            if "FIN" in flag_set or "RST" in flag_set:
                entry.state = "CLOSED"
            return "ACCEPT (ESTABLISHED)"
            
        elif rev_key in self.conntrack_table:
            # Ters yönlü akış tablosunda mevcut (karşı taraf yanıt dönüyor)
            entry = self.conntrack_table[rev_key]
            # Yanıt geldiği için durum kesinlikle ESTABLISHED olur
            entry.state = "ESTABLISHED"
            entry.packets_seen += 1
            entry.last_seen = time.time()
            # Eğer FIN veya RST geldiyse oturumu kapat
            if "FIN" in flag_set or "RST" in flag_set:
                entry.state = "CLOSED"
            return "ACCEPT (ESTABLISHED/REPLY)"
            
        # 2. Tabloda bulunmayan paket için yeni oturum kontrolü (NEW)
        # Sadece SYN içeren paket yeni bir oturum başlatabilir
        if "SYN" in flag_set and "ACK" not in flag_set:
            # Kurallar arasında eşleşme ara
            matched = False
            for rule in self.rules:
                if rule["direction"] == direction.upper() and rule["dst_port"] == pkt.dst_port:
                    if rule["action"] == "ACCEPT":
                        matched = True
                        break
                        
            # Eğer kural eşleştiyse yeni oturum aç
            if matched:
                # Durum tablosu kapasitesini denetle
                if len(self.conntrack_table) >= self.max_conntrack_entries:
                    # Tablo taşması istisnası fırlat
                    raise ConntrackOverflowError(
                        "Guvenlik duvari conntrack durum tablosu maksimum kapasiteye ulasti! Yeni oturum acilamaz."
                    )
                # Yeni oturum kaydını tabloya ekle
                self.conntrack_table[fwd_key] = ConntrackEntry(
                    flow_id=fwd_key,
                    state="NEW",
                    packets_seen=1,
                    bytes_seen=len(pkt.payload)
                )
                return "ACCEPT (NEW)"
            else:
                # Kural eşleşmediğinde varsayılan düşürme
                raise FirewallDropError(
                    f"Guvenlik duvari varsayilan {self.default_policy} politikasi: "
                    f"Port {pkt.dst_port} icin erisim kurali bulunamadi."
                )
                
        # 3. Durum tablosunda olmayan ancak SYN içermeyen paket (Beklenmedik ACK / RST vb.)
        # Bu durum aktif bir ağ taraması veya oturum enjeksiyonu denemesidir
        raise FirewallDropError(
            f"Durum takipli guvenlik duvari: Durum tablosunda bulunmayan beklenmedik "
            f"{pkt.flags} paketi engellendi (INVALID State)."
        )


# ------------------------------------------------------------------------------
# PORT ADRES DÖNÜŞÜMÜ MOTORU (PAT / NAPT ENGINE)
# ------------------------------------------------------------------------------

class PATEngine:
    """
    Port Adres Dönüşümü (Port Address Translation / PAT / NAT Overload) Simülatörü.
    """

    def __init__(
        self,
        public_ip: str = "203.0.113.10",
        port_range_start: int = 10000,
        port_range_end: int = 65535,
        timeout_seconds: int = 300
    ):
        # Genel (dış) IP adresi
        self.public_ip = public_ip
        # Kullanılabilir dinamik port aralığı
        self.port_range_start = port_range_start
        self.port_range_end = port_range_end
        # Oturum zaman aşımı süresi
        self.timeout_seconds = timeout_seconds
        # İleri yönlü tablo: (internal_ip, internal_port, dst_ip, dst_port) -> NATMapping
        self.outbound_table: Dict[Tuple[str, int, str, int], NATMapping] = {}
        # Ters yönlü tablo: (translated_port, dst_ip, dst_port) -> NATMapping
        self.inbound_table: Dict[Tuple[int, str, int], NATMapping] = {}
        # Tahsis edilmiş portların kümesi
        self.allocated_ports: Set[int] = set()

    def translate_outbound(self, pkt: TCPPacket) -> TCPPacket:
        """
        İç ağdan çıkan paketi genel IP ve dinamik bir port ile dönüştürür (SNAT / PAT).
        """
        # IP'leri doğrula
        validate_ipv4_address(pkt.src_ip)
        validate_ipv4_address(pkt.dst_ip)
        
        # Oturum anahtarı
        outbound_key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
        
        # Eğer bu oturum için daha önce bir port tahsis edilmişse
        if outbound_key in self.outbound_table:
            mapping = self.outbound_table[outbound_key]
            mapping.last_seen = time.time()
            # Paketi dönüştür ve döndür
            return TCPPacket(
                src_ip=self.public_ip,
                src_port=mapping.translated_port,
                dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port,
                flags=pkt.flags,
                payload=pkt.payload
            )
            
        # Yeni bir port tahsis et
        chosen_port: Optional[int] = None
        for port in range(self.port_range_start, self.port_range_end + 1):
            if port not in self.allocated_ports:
                chosen_port = port
                break
                
        # Eğer boş port bulunamadıysa havuz tükenmiştir
        if chosen_port is None:
            raise NATExhaustionError(
                f"PAT port havuzu tukendi: {self.port_range_start}-{self.port_range_end} araliginda bos port kalmadi."
            )
            
        # Portu tahsis et ve kaydet
        self.allocated_ports.add(chosen_port)
        mapping = NATMapping(
            internal_ip=pkt.src_ip,
            internal_port=pkt.src_port,
            public_ip=self.public_ip,
            translated_port=chosen_port,
            destination_ip=pkt.dst_ip,
            destination_port=pkt.dst_port
        )
        self.outbound_table[outbound_key] = mapping
        # Ters yönlü tabloya da kaydet
        self.inbound_table[(chosen_port, pkt.dst_ip, pkt.dst_port)] = mapping
        
        # Dönüştürülmüş paketi döndür
        return TCPPacket(
            src_ip=self.public_ip,
            src_port=chosen_port,
            dst_ip=pkt.dst_ip,
            dst_port=pkt.dst_port,
            flags=pkt.flags,
            payload=pkt.payload
        )

    def translate_inbound(self, pkt: TCPPacket) -> TCPPacket:
        """
        Dış dünyadan gelen yanıt paketini iç ağdaki gerçek istemciye dönüştürür (DNAT).
        """
        # IP'leri doğrula
        validate_ipv4_address(pkt.src_ip)
        validate_ipv4_address(pkt.dst_ip)
        
        # Gelen yanıtın eşleştiği NAT kaydını ara
        inbound_key = (pkt.dst_port, pkt.src_ip, pkt.src_port)
        
        # Eğer tabloda kayıt bulunamazsa paket düşürülür
        if inbound_key not in self.inbound_table:
            raise FirewallDropError(
                f"NAT tablosunda eslesme bulunamadi: Port {pkt.dst_port} icin aktif bir oturum kaydi yok."
            )
            
        mapping = self.inbound_table[inbound_key]
        mapping.last_seen = time.time()
        
        # Hedef IP ve portu iç istemcinin orijinal değerlerine dönüştür
        return TCPPacket(
            src_ip=pkt.src_ip,
            src_port=pkt.src_port,
            dst_ip=mapping.internal_ip,
            dst_port=mapping.internal_port,
            flags=pkt.flags,
            payload=pkt.payload
        )


# ------------------------------------------------------------------------------
# VEKİL SUNUCU MOTORU (FORWARD & REVERSE PROXY ENGINE)
# ------------------------------------------------------------------------------

class ProxyEngine:
    """
    İleri Yönlü (Forward) ve Ters Yönlü (Reverse) Vekil Sunucu Güvenlik Modülü.
    """

    def __init__(
        self,
        trusted_proxies: Optional[List[str]] = None,
        allowed_connect_ports: Optional[List[int]] = None
    ):
        # Güvenilir ters vekil IP listesi
        self.trusted_proxies = set(trusted_proxies or ["127.0.0.1", "10.0.0.1"])
        # Forward proxy CONNECT tüneline izin verilen portlar (varsayılan yalnızca 443)
        self.allowed_connect_ports = set(allowed_connect_ports or [443])
        # Arka uç havuzu ve yük dengeleme indeksi
        self.backend_pool = ["10.0.0.11:8080", "10.0.0.12:8080"]
        self.current_backend_idx = 0

    def process_reverse_proxy_request(
        self,
        client_ip: str,
        incoming_headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Ters vekil sunucuya gelen HTTP isteğini doğrular, X-Forwarded-For sahteciliğini önler
        ve arka uç sunucusuna yük dengeli yönlendirir.
        """
        # İstemci IP adresini doğrula
        validate_ipv4_address(client_ip)
        
        # İstek başlıklarının kopyasını al
        headers = dict(incoming_headers)
        
        # Güvenilmeyen istemciden gelen X-Forwarded-For başlığını denetle
        raw_xff = headers.get("X-Forwarded-For", "").strip()
        
        # Eğer istemci güvenilir proxy listesinde DEĞİLSE ve sahte XFF göndermişse
        if client_ip not in self.trusted_proxies and raw_xff:
            # Saldırganın iç IP (ör. 127.0.0.1) taklidi yaparak erişim denemesi kontrolü
            if "127.0.0.1" in raw_xff or "localhost" in raw_xff:
                raise ProxySecurityViolationError(
                    f"Guvenilmeyen istemciden ({client_ip}) gelen sahte X-Forwarded-For basligi engellendi."
                )
            # Normal güvenilmeyen XFF başlığını ez (overwrite)
            headers["X-Forwarded-For"] = client_ip
        elif client_ip in self.trusted_proxies and raw_xff:
            # Güvenilir proxy zincirine yeni IP'yi ekle
            headers["X-Forwarded-For"] = f"{raw_xff}, {client_ip}"
        else:
            # Yeni XFF başlığı ekle
            headers["X-Forwarded-For"] = client_ip
            
        # Round-robin ile arka uç sunucu seç
        selected_backend = self.backend_pool[self.current_backend_idx]
        self.current_backend_idx = (self.current_backend_idx + 1) % len(self.backend_pool)
        
        # İşlenmiş istek nesnesini döndür
        return {
            "selected_backend": selected_backend,
            "sanitized_headers": headers,
            "client_ip": client_ip,
            "status": "FORWARDED"
        }

    def process_forward_proxy_connect(
        self,
        method: str,
        target_host_port: str
    ) -> Dict[str, Any]:
        """
        İleri vekil sunucuda HTTPS tünelleme için gelen HTTP CONNECT isteğini denetler.
        Yalnızca izin verilen güvenli portlara (ör. 443) tünel açılmasına izin verir.
        """
        # Metot CONNECT değilse normal istektir
        if method.upper() != "CONNECT":
            return {"status": "ALLOWED_STANDARD_HTTP", "target": target_host_port}
            
        # Hedef portu ayır
        if ":" not in target_host_port:
            raise NetworkValidationError("CONNECT hedefi 'host:port' formatinda olmalidir.")
            
        host, port_str = target_host_port.split(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            raise NetworkValidationError(f"Gecersiz port numarasi: '{port_str}'.")
            
        # Portun izin verilen güvenli portlar arasında olduğunu denetle
        if port not in self.allowed_connect_ports:
            raise ProxyAccessDeniedError(
                f"Forward Proxy CONNECT metoduna yalnizca guvenli portlar "
                f"({list(self.allowed_connect_ports)}) icin izin verilir. Port {port} engellendi."
            )
            
        # Başarılı tünel onayı döndür
        return {
            "status": "TUNNEL_ESTABLISHED",
            "host": host,
            "port": port,
            "message": "HTTP 200 Connection Established"
        }
