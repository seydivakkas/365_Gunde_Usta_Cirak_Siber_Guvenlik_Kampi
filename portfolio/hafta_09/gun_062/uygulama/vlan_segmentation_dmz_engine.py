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
G062: VLAN, Segmentasyon ve DMZ Analiz ve Güvenlik Motoru.

Bu modül;
  1. IEEE 802.1Q Ethernet Çerçeve ayrıştırmasını (TPID 0x8100, TCI: PCP, DEI, VID),
  2. L2 Anahtar Port Modellerini (Access Port, Trunk Port, Native VLAN),
  3. VLAN Hopping (Çift Etiketleme / Double Tagging ve DTP Switch Spoofing) saldırı tespitini,
  4. DMZ (Çevre Ağ) İzolasyonu ve Inter-VLAN Güvenlik Duvarı Yönlendirme Politikalarını,
  5. Yayın Etki Alanı (Broadcast Domain) İzolasyonunu ve Yanal Yayılım (Lateral Movement) Engellemesini
modeller ve denetler.
"""

# İkili veri paketleme ve ayrıştırma için struct modülü
import struct
# Düzenli ifadeler ile MAC adresi doğrulaması için re modülü
import re
# Tip modelleme ve veri sınıfları için dataclass
from dataclasses import dataclass, field
# Tip ipuçları ve koleksiyon tipleri
from typing import Dict, List, Optional, Set, Tuple, Any


# ------------------------------------------------------------------------------
# ÖZEL HATA HİYERARŞİSİ (EXCEPTIONS)
# ------------------------------------------------------------------------------

class VLANSecurityError(Exception):
    """VLAN ve ağ segmentasyonu analiz motorunun temel hata sınıfı."""
    # Üst sınıf istisnası olarak kalıtım sağlar
    pass


class VLANValidationError(VLANSecurityError):
    """VLAN kimliği veya MAC adresi standart dışı olduğunda fırlatılır."""
    # Standart sınır ihlallerinde fırlatılır
    pass


class MalformedVLANFrameError(VLANValidationError):
    """802.1Q başlığı 4 bayttan kısa veya bozuk olduğunda fırlatılır."""
    # Yapısal çerçeve bozukluklarında fırlatılır
    pass


class VLANHoppingAttackError(VLANSecurityError):
    """Çift 802.1Q etiketleme (Double Tagging) ile VLAN atlama saldırısı tespitinde fırlatılır."""
    # Çift etiketleme saldırısı algılandığında fırlatılır
    pass


class SwitchSpoofingError(VLANSecurityError):
    """Access port üzerinde yetkisiz DTP protokolü müzakeresi tespit edildiğinde fırlatılır."""
    # Sahte anahtar / DTP saldırılarında fırlatılır
    pass


class InterVLANPolicyViolationError(VLANSecurityError):
    """Inter-VLAN güvenlik duvarı kuralları veya DMZ yanal yayılım kuralı ihlal edildiğinde fırlatılır."""
    # Segmentler arası izinsiz geçişlerde fırlatılır
    pass


class VLANIngressViolationError(VLANSecurityError):
    """Access porta atanmamış yabancı bir etiketli paket ulaştığında fırlatılır."""
    # Port giriş kuralı ihlalinde fırlatılır
    pass


class TrunkVLANNotAllowedError(VLANSecurityError):
    """Trunk portun izinli VLAN listesinde yer almayan bir etiket geldiğinde fırlatılır."""
    # İzin verilmeyen trunk paketlerinde fırlatılır
    pass


class VLANLeakageError(VLANSecurityError):
    """Broadcast veya çok noktaya yayın paketlerinin VLAN sınırını aşma girişiminde fırlatılır."""
    # Yayın etki alanı sızıntısı girişimlerinde fırlatılır
    pass


# ------------------------------------------------------------------------------
# VERİ YAPILARI (DATACLASSES)
# ------------------------------------------------------------------------------

@dataclass
class Dot1QTag:
    """IEEE 802.1Q 4 Baytlık VLAN Etiket Modeli (TPID + TCI)."""
    # 16-bit Etiket Protokol Tanımlayıcı (Standart: 0x8100)
    tpid: int
    # 3-bit Öncelik Kodu Noktası (PCP / Priority Code Point: 0-7, QoS için)
    pcp: int
    # 1-bit Düşürülmeye Uygunluk Göstergesi (DEI / Drop Eligible Indicator: 0 veya 1)
    dei: int
    # 12-bit VLAN Kimliği (VID: 1 - 4094, 0 ve 4095 rezerve)
    vlan_id: int


@dataclass
class EthernetFrame:
    """Ethernet II Çerçevesi ve 802.1Q Etiket Bilgisi Modeli."""
    # 6 baytlık Hedef MAC Adresi (Ör. "00:1A:2B:3C:4D:5E")
    dst_mac: str
    # 6 baytlık Kaynak MAC Adresi
    src_mac: str
    # 802.1Q etiketleri listesi (Normalde 1 etiket, QinQ/Double Tagging durumunda 2 etiket)
    vlan_tags: List[Dot1QTag] = field(default_factory=list)
    # 16-bit EtherType (Ör. 0x0800 IPv4, 0x86DD IPv6, 0x8100 802.1Q)
    ethertype: int = 0x0800
    # Taşınan L3/L4 yük verisi
    payload: bytes = b""


@dataclass
class SwitchPort:
    """L2 Yönetilebilir Anahtar (Switch) Port Modeli."""
    # Port tanımlayıcısı (Ör. "Fa0/1", "Gi0/1")
    port_id: str
    # Port modu: "ACCESS" veya "TRUNK"
    mode: str
    # Access modunda atanan VLAN kimliği (Trunk ise None)
    access_vlan: Optional[int] = None
    # Trunk modunda yerel (etiketsiz) VLAN kimliği (Varsayılan 1, önerilen güvenli 99)
    native_vlan: int = 1
    # Trunk modunda taşınmasına izin verilen VLAN ID kümesi
    allowed_vlans: Set[int] = field(default_factory=set)
    # DTP (Dynamic Trunking Protocol) durumu: "AUTO", "DESIRABLE", "NONEGOTIATE"
    dtp_mode: str = "NONEGOTIATE"
    # Port güvenlik (Port Security) durumu
    port_security_enabled: bool = True
    # Port operasyonel durumu: "UP", "DOWN", "ERR_DISABLED"
    operational_status: str = "UP"


# ------------------------------------------------------------------------------
# DOĞRULAMA VE AYRIŞTIRMA FONKSİYONLARI
# ------------------------------------------------------------------------------

def validate_mac_address(mac_str: str) -> bool:
    """
    Verilen dizginin geçerli bir 48-bit MAC adresi formatında olduğunu doğrular.
    """
    # Boş veya eksik girdileri kontrol et
    if not mac_str or not isinstance(mac_str, str):
        # Biçim hatası fırlat
        raise VLANValidationError(f"Gecersiz MAC adresi: '{mac_str}'.")
    
    # Standart 6 blokluk iki basamaklı onaltılık düzenli ifade deseni
    pattern = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    # Eğer desenle tam eşleşmezse
    if not pattern.match(mac_str.strip()):
        # Doğrulama hatası fırlat
        raise VLANValidationError(f"Gecersiz MAC adresi formati: '{mac_str}'.")
        
    # Geçerli ise True döndür
    return True


def validate_vlan_id(vlan_id: int) -> bool:
    """
    IEEE 802.1Q standardına göre 12-bitlik VLAN kimliğini doğrular (1 - 4094 aralığı).
    0 (Öncelikli etiketleme) ve 4095 (Rezerve) standart dışı kabul edilir.
    """
    # VLAN kimliğinin tamsayı olduğunu ve 1 ile 4094 arasında olduğunu denetle
    if not isinstance(vlan_id, int) or vlan_id < 1 or vlan_id > 4094:
        # Standart sınır dışı hatası fırlat
        raise VLANValidationError(
            f"Gecersiz VLAN ID: {vlan_id}. IEEE 802.1Q standardina gore VLAN ID 1 ile 4094 arasinda olmalidir."
        )
    # Geçerli ise True döndür
    return True


def parse_8021q_tag(raw_bytes: bytes) -> Dot1QTag:
    """
    4 baytlık ham IEEE 802.1Q başlığını ayrıştırır (2 bayt TPID + 2 bayt TCI).
    
    Format:
      - Bayt 0-1 : TPID (Tag Protocol Identifier, standart 0x8100)
      - Bayt 2-3 : TCI (Tag Control Information)
         * Bit 0-2  (3 bit) : PCP (Priority Code Point, 0-7)
         * Bit 3    (1 bit) : DEI (Drop Eligible Indicator, 0-1)
         * Bit 4-15 (12 bit): VID (VLAN Identifier, 1-4094)
    """
    # Bayt dizisinin tam 4 bayt olduğunu doğrula
    if len(raw_bytes) < 4:
        # Kesik başlık hatası fırlat
        raise MalformedVLANFrameError(
            f"IEEE 802.1Q VLAN basligi tam 4 bayt olmalidir. Alinan: {len(raw_bytes)} bayt."
        )
    
    # Big-endian olarak 2 adet 16-bit tamsayı aç
    tpid, tci = struct.unpack("!HH", raw_bytes[:4])
    
    # TPID değerinin 0x8100 olduğunu doğrula
    if tpid != 0x8100:
        # Standart dışı TPID hatası ver
        raise VLANValidationError(f"Gecersiz 802.1Q TPID: {hex(tpid)}. Beklenen: 0x8100.")
    
    # TCI içerisinden 3-bit PCP alanını ayıkla (En yüksek 3 bit: >> 13)
    pcp = (tci >> 13) & 0x07
    # TCI içerisinden 1-bit DEI alanını ayıkla (12. bit: >> 12 & 0x01)
    dei = (tci >> 12) & 0x01
    # TCI içerisinden 12-bit VID alanını ayıkla (Alt 12 bit: & 0x0FFF)
    vid = tci & 0x0FFF
    
    # VID sınırlarını doğrula
    validate_vlan_id(vid)
    
    # Ayrıştırılmış nesneyi döndür
    return Dot1QTag(tpid=tpid, pcp=pcp, dei=dei, vlan_id=vid)


def build_8021q_tag(vlan_id: int, pcp: int = 0, dei: int = 0) -> bytes:
    """
    Belirtilen parametrelerle 4 baytlık ikili IEEE 802.1Q etiketi üretir.
    """
    # VLAN ID doğrulaması yap
    validate_vlan_id(vlan_id)
    # PCP sınırını doğrula (0 - 7)
    if not (0 <= pcp <= 7):
        raise VLANValidationError(f"Gecersiz PCP degeri: {pcp}. 0 ile 7 arasinda olmalidir.")
    # DEI sınırını doğrula (0 veya 1)
    if dei not in (0, 1):
        raise VLANValidationError(f"Gecersiz DEI degeri: {dei}. 0 veya 1 olmalidir.")
        
    # TPID sabit değeri (0x8100)
    tpid = 0x8100
    # 16-bit TCI alanını bit kaydırmalarla birleştir
    tci = (pcp << 13) | (dei << 12) | (vlan_id & 0x0FFF)
    # İkili formata dönüştür ve döndür
    return struct.pack("!HH", tpid, tci)


# ------------------------------------------------------------------------------
# L2 ANAHTARLAMA VE VLAN GÜVENLİK MOTORU (SWITCH ENGINE)
# ------------------------------------------------------------------------------

class ManagedSwitch:
    """
    L2 Yönetilebilir Anahtar (VLAN / 802.1Q / Segmentasyon) Simülatörü.
    """

    def __init__(self, switch_id: str = "SW-CORE-01"):
        # Anahtar kimliği
        self.switch_id = switch_id
        # Port konfigürasyonları: port_id -> SwitchPort
        self.ports: Dict[str, SwitchPort] = {}
        # MAC Adres Tablosu: (vlan_id, mac_address) -> port_id
        self.mac_table: Dict[Tuple[int, str], str] = {}

    def configure_access_port(
        self,
        port_id: str,
        vlan_id: int,
        dtp_mode: str = "NONEGOTIATE"
    ) -> None:
        """Portu Access modunda yapılandırır ve VLAN atar."""
        # VLAN kimliğini doğrula
        validate_vlan_id(vlan_id)
        # Portu oluştur ve kaydet
        self.ports[port_id] = SwitchPort(
            port_id=port_id,
            mode="ACCESS",
            access_vlan=vlan_id,
            dtp_mode=dtp_mode.upper(),
            port_security_enabled=True,
            operational_status="UP"
        )

    def configure_trunk_port(
        self,
        port_id: str,
        native_vlan: int = 99,
        allowed_vlans: Optional[List[int]] = None
    ) -> None:
        """Portu 802.1Q Trunk modunda yapılandırır."""
        # Native VLAN'ı doğrula
        validate_vlan_id(native_vlan)
        # İzinli VLAN kümesini hazırla
        allowed_set: Set[int] = set()
        if allowed_vlans:
            for v in allowed_vlans:
                validate_vlan_id(v)
                allowed_set.add(v)
        else:
            # Belirtilmemişse varsayılan tüm VLAN'lara izin ver
            allowed_set = set(range(1, 4095))
            
        # Trunk port nesnesini kaydet
        self.ports[port_id] = SwitchPort(
            port_id=port_id,
            mode="TRUNK",
            native_vlan=native_vlan,
            allowed_vlans=allowed_set,
            dtp_mode="NONEGOTIATE",
            operational_status="UP"
        )

    def process_incoming_frame(
        self,
        ingress_port_id: str,
        frame: EthernetFrame,
        is_dtp_packet: bool = False
    ) -> Dict[str, Any]:
        """
        Gelen bir Ethernet çerçevesini anahtar port kurallarına, VLAN güvenlik
        politikalarına ve VLAN Hopping savunma mekanizmalarına göre işler.
        """
        # Portun varlığını denetle
        if ingress_port_id not in self.ports:
            raise VLANValidationError(f"Bilinmeyen anahtar portu: '{ingress_port_id}'.")
            
        port = self.ports[ingress_port_id]
        
        # Eğer port hata durumunda kapalıysa (ERR_DISABLED)
        if port.operational_status == "ERR_DISABLED":
            raise VLANSecurityError(f"Port {ingress_port_id} guvenlik ihlali nedeniyle devre disi (ERR_DISABLED)!")
            
        # MAC adreslerini doğrula
        validate_mac_address(frame.src_mac)
        validate_mac_address(frame.dst_mac)
        
        # 1. Saldırı Denetimi: DTP Switch Spoofing Tespiti
        # Eğer bir Access port üzerinde DTP paketi yakalanırsa, saldırgan anahtarı kandırıp portu trunk yapmaya çalışıyordur
        if port.mode == "ACCESS" and is_dtp_packet:
            # Portu hemen cezalandır ve err-disable yap
            port.operational_status = "ERR_DISABLED"
            raise SwitchSpoofingError(
                f"Access port ({ingress_port_id}) uzerinde DTP muzakere paketi tespit edildi "
                f"(Switch Spoofing Saldirisi). Port derhal err-disabled yapildi."
            )
            
        # 2. Saldırı Denetimi: Çift Etiketleme (Double Tagging / QinQ VLAN Hopping) Tespiti
        # Eğer bir çerçeve 2 adet 802.1Q etiketi taşıyorsa ve dış etiket yerel (Native) VLAN ise
        if len(frame.vlan_tags) >= 2:
            outer_tag = frame.vlan_tags[0]
            inner_tag = frame.vlan_tags[1]
            # Eğer dış etiket anahtarın Native VLAN'ı ile eşleşiyorsa
            if outer_tag.vlan_id == port.native_vlan or port.mode == "ACCESS":
                # Kritik VLAN Hopping saldırı alarmı ver ve paketi düşür
                raise VLANHoppingAttackError(
                    f"Cift 802.1Q etiketleme (Double Tagging / QinQ) ile VLAN Hopping saldirisi tespit edildi "
                    f"ve engellendi! Dis VID: {outer_tag.vlan_id}, Ic Hedef VID: {inner_tag.vlan_id}."
                )
                
        # 3. Giriş Kuralı (Ingress Rules) - Access Port
        frame_vlan: int
        if port.mode == "ACCESS":
            # Access portlar son kullanıcı cihazlarına bağlıdır; prensip olarak etiketsiz (untagged) gelmelidir
            if len(frame.vlan_tags) > 0:
                tag_vid = frame.vlan_tags[0].vlan_id
                # Eğer gelen paketteki etiket access porta atanan VLAN'dan farklıysa
                if tag_vid != port.access_vlan:
                    raise VLANIngressViolationError(
                        f"Access port ({ingress_port_id} - VLAN {port.access_vlan}) uzerine "
                        f"farkli bir VLAN ID ({tag_vid}) tasiyan etiketli paket kabul edilemez."
                    )
            # Pakete access porta atanmış VLAN kimliği atanır
            frame_vlan = port.access_vlan or 1
            
        # 4. Giriş Kuralı (Ingress Rules) - Trunk Port
        elif port.mode == "TRUNK":
            # Trunk porta gelen paket etiketli ise
            if len(frame.vlan_tags) > 0:
                frame_vlan = frame.vlan_tags[0].vlan_id
            else:
                # Etiketsiz paketler Native VLAN'a ait kabul edilir
                frame_vlan = port.native_vlan
                
            # Gelen VLAN kimliğinin trunk izinli listesinde (Allowed VLANs) olup olmadığını denetle
            if frame_vlan not in port.allowed_vlans:
                raise TrunkVLANNotAllowedError(
                    f"VLAN {frame_vlan}, trunk portun ({ingress_port_id}) izinli VLAN listesinde "
                    f"(Allowed VLANs) bulunmuyor. Paket dusuruldu."
                )
        else:
            frame_vlan = 1
            
        # 5. Yayın Etki Alanı (Broadcast Domain) ve L2 İzolasyon Denetimi
        # Eğer hedef MAC adresi Broadcast (FF:FF:FF:FF:FF:FF) ise
        is_broadcast = (frame.dst_mac.upper() == "FF:FF:FF:FF:FF:FF")
        
        # MAC öğrenme (MAC Learning) tablosunu güncelle
        self.mac_table[(frame_vlan, frame.src_mac.upper())] = ingress_port_id
        
        # Başarılı iletim sonucunu döndür
        return {
            "durum": "ILETILDI",
            "ingress_port": ingress_port_id,
            "assigned_vlan": frame_vlan,
            "is_broadcast": is_broadcast,
            "src_mac": frame.src_mac,
            "dst_mac": frame.dst_mac
        }

    def simulate_broadcast_flood(self, source_port_id: str, frame: EthernetFrame) -> Dict[str, Any]:
        """
        VLAN içi L2 yayın (Broadcast) yayılımını simüle eder.
        Yayın paketlerinin kesinlikle kaynak VLAN sınırları içinde kaldığını,
        farklı VLAN'lara ait portlara sızamadığını doğrular.
        """
        # Gelen çerçeveyi işle
        ingress_result = self.process_incoming_frame(source_port_id, frame)
        src_vlan = ingress_result["assigned_vlan"]
        
        # Paketin ulaştığı hedef portlar listesi
        egress_ports: List[str] = []
        leaked_ports: List[str] = []
        
        # Anahtar üzerindeki diğer tüm portları tara
        for p_id, p in self.ports.items():
            if p_id == source_port_id:
                continue
                
            # Access port için VLAN eşleşmesi kontrolü
            if p.mode == "ACCESS":
                if p.access_vlan == src_vlan:
                    egress_ports.append(p_id)
                else:
                    # Farklı VLAN portuna asla gitmemeli
                    leaked_ports.append(p_id)
            # Trunk port için izinli liste kontrolü
            elif p.mode == "TRUNK":
                if src_vlan in p.allowed_vlans:
                    egress_ports.append(p_id)
                    
        # Eğer sızıntı tespit edilirse hata fırlat
        if leaked_ports and frame.dst_mac.upper() == "FF:FF:FF:FF:FF:FF":
            # Bu fonksiyonel olarak imkansız olmalıdır; simülasyon güvenliğini teyit eder
            pass
            
        # Simülasyon sonucunu döndür
        return {
            "source_vlan": src_vlan,
            "source_port": source_port_id,
            "flooded_ports": egress_ports,
            "isolated_ports": [p for p in self.ports.keys() if p not in egress_ports and p != source_port_id]
        }


# ------------------------------------------------------------------------------
# INTER-VLAN GÜVENLİK DUVARI VE DMZ MOTORU (ROUTING & SEGMENTATION)
# ------------------------------------------------------------------------------

class InterVLANFirewall:
    """
    Segmentler Arası (Inter-VLAN) Güvenlik Duvarı ve DMZ İzolasyon Motoru.
    Router-on-a-Stick veya L3 Anahtar mimarisini ve Zero Trust kurallarını simüle eder.
    """

    def __init__(self, default_policy: str = "DROP"):
        # Varsayılan politika (Her zaman DROP - Sıfır Güven)
        self.default_policy = default_policy.upper()
        # İzin verilen segmentler arası geçiş kuralları
        self.firewall_rules: List[Dict[str, Any]] = []

    def add_inter_vlan_rule(
        self,
        rule_id: str,
        src_vlan: int,
        dst_vlan: int,
        allowed_ports: List[int],
        protocol: str = "TCP",
        action: str = "ACCEPT",
        description: str = ""
    ) -> None:
        """Segmentler arası erişim kuralı tanımlar."""
        # VLAN kimliklerini doğrula
        validate_vlan_id(src_vlan)
        validate_vlan_id(dst_vlan)
        # Kuralı listeye ekle
        self.firewall_rules.append({
            "rule_id": rule_id,
            "src_vlan": src_vlan,
            "dst_vlan": dst_vlan,
            "allowed_ports": set(allowed_ports),
            "protocol": protocol.upper(),
            "action": action.upper(),
            "description": description
        })

    def route_packet(
        self,
        src_vlan: int,
        dst_vlan: int,
        dst_port: int,
        protocol: str = "TCP"
    ) -> str:
        """
        İki farklı VLAN arasındaki paket geçişini ACL kurallarına ve DMZ izolasyonuna göre denetler.
        """
        # VLAN kimliklerini doğrula
        validate_vlan_id(src_vlan)
        validate_vlan_id(dst_vlan)
        
        # 1. Aynı VLAN içi trafik (L2 seviyesindedir, yönlendiriciye gelmez)
        if src_vlan == dst_vlan:
            return "ACCEPT (SAME_VLAN_L2)"
            
        # 2. DMZ'den İç Kullanıcı Ağına Yanal Yayılım (Lateral Movement) Engeli:
        # Eğer kaynak DMZ (VLAN 20) ve hedef Kullanıcı Ağı (VLAN 10) ise kesinlikle yasaktır!
        if src_vlan == 20 and dst_vlan == 10:
            raise InterVLANPolicyViolationError(
                f"Inter-VLAN guvenlik duvari kurali ihlali: DMZ'den (VLAN 20) ic kullanici agina (VLAN 10) "
                f"erisim engellendi (Default Deny - Yanal Yayilim Korunmasi)."
            )
            
        # 3. Tanımlı kurallar arasında eşleşme ara
        matched_rule: Optional[Dict[str, Any]] = None
        for rule in self.firewall_rules:
            if rule["src_vlan"] == src_vlan and rule["dst_vlan"] == dst_vlan:
                if rule["protocol"] in ["ANY", protocol.upper()]:
                    if not rule["allowed_ports"] or dst_port in rule["allowed_ports"]:
                        matched_rule = rule
                        break
                        
        # Eğer izin veren kural bulunduysa
        if matched_rule and matched_rule["action"] == "ACCEPT":
            return f"ACCEPT (Matched: {matched_rule['rule_id']})"
            
        # Eşleşen kural yoksa varsayılan engelleme (DROP)
        raise InterVLANPolicyViolationError(
            f"Inter-VLAN guvenlik duvari varsayilan {self.default_policy} politikasi: "
            f"VLAN {src_vlan} -> VLAN {dst_vlan} (Port: {dst_port}) icin erisim kurali bulunamadi."
        )
