# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G050: TCP Üçlü El Sıkışma (Three-Way Handshake) Analiz ve Güvenlik Denetim Motoru.
Bu modül RFC 793 ve RFC 9293 standartlarına uygun olarak TCP başlıklarını ikili (binary)
düzeyde oluşturur, ayrıştırır, durum makinelerini (State Machine) simüle eder,
sağlama toplamını (checksum) hesaplar ve SYN Flood / Port Tarama anomalilerini tespit eder.
"""

# İkili bayt paketleme ve açma işlemleri için Python struct kütüphanesi
import struct
# IP adresi doğrulaması ve dönüştürmesi için ipaddress kütüphanesi
import ipaddress
# JSON veri yapılarını okuma ve yazma için json modülü
import json
# Dosya ve dizin yolu çözümlemeleri için os modülü
import os
# Tip ipuçları ve veri yapıları tanımlamaları için typing modülü
from typing import Dict, List, Any, Optional, Tuple


class TCPValidationError(ValueError):
    """TCP başlık, bayrak veya el sıkışma doğrulama hataları için özel istisna sınıfı."""
    # Özel istisna gövdesi standart miras mekanizmasıyla çalışır
    pass


class TCPFlags:
    """TCP kontrol bayrakları (Control Bits) bit düzeyinde yönetim ve doğrulama sınıfı."""
    # FIN bayrağı biti (Bağlantı sonlandırma - Bit 0)
    FIN = 0x01
    # SYN bayrağı biti (Sıra numarası eşitleme / Bağlantı başlatma - Bit 1)
    SYN = 0x02
    # RST bayrağı biti (Bağlantıyı sıfırlama / Reddetme - Bit 2)
    RST = 0x04
    # PSH bayrağı biti (Veriyi doğrudan uygulamaya iletme - Bit 3)
    PSH = 0x08
    # ACK bayrağı biti (Onay numarası geçerli - Bit 4)
    ACK = 0x10
    # URG bayrağı biti (Acil durum işaretçisi geçerli - Bit 5)
    URG = 0x20
    # ECE bayrağı biti (ECN-Echo tıkanıklık bildirimi - Bit 6)
    ECE = 0x40
    # CWR bayrağı biti (Tıkanıklık penceresi küçültüldü - Bit 7)
    CWR = 0x80

    @classmethod
    def from_dict(cls, flag_dict: Dict[str, Any]) -> int:
        """Sözlük formatındaki bayrak değerlerini 8-bitlik tamsayı maskesine çevirir."""
        # Girdinin sözlük tipi olduğunu teyit eder
        if not isinstance(flag_dict, dict):
            # Geçersiz tip durumunda istisna yükseltir
            raise TCPValidationError("TCP bayrakları sözlük (dict) tipinde olmalıdır.")
        # Bayrak maskesini sıfır olarak başlatır
        mask = 0
        # SYN bayrağı aktifse maskeye ekler
        if flag_dict.get("SYN", 0):
            # SYN bitini açar
            mask |= cls.SYN
        # ACK bayrağı aktifse maskeye ekler
        if flag_dict.get("ACK", 0):
            # ACK bitini açar
            mask |= cls.ACK
        # FIN bayrağı aktifse maskeye ekler
        if flag_dict.get("FIN", 0):
            # FIN bitini açar
            mask |= cls.FIN
        # RST bayrağı aktifse maskeye ekler
        if flag_dict.get("RST", 0):
            # RST bitini açar
            mask |= cls.RST
        # PSH bayrağı aktifse maskeye ekler
        if flag_dict.get("PSH", 0):
            # PSH bitini açar
            mask |= cls.PSH
        # URG bayrağı aktifse maskeye ekler
        if flag_dict.get("URG", 0):
            # URG bitini açar
            mask |= cls.URG
        # ECE bayrağı aktifse maskeye ekler
        if flag_dict.get("ECE", 0):
            # ECE bitini açar
            mask |= cls.ECE
        # CWR bayrağı aktifse maskeye ekler
        if flag_dict.get("CWR", 0):
            # CWR bitini açar
            mask |= cls.CWR
        # Elde edilen 8-bitlik maskeyi döner
        return mask

    @classmethod
    def to_string_list(cls, mask: int) -> List[str]:
        """Tamsayı bayrak maskesini insan tarafından okunabilir metin listesine çevirir."""
        # Bayrak isimlerini toplayacak liste
        flags = []
        # SYN biti kontrolü
        if mask & cls.SYN:
            # SYN metnini ekler
            flags.append("SYN")
        # ACK biti kontrolü
        if mask & cls.ACK:
            # ACK metnini ekler
            flags.append("ACK")
        # FIN biti kontrolü
        if mask & cls.FIN:
            # FIN metnini ekler
            flags.append("FIN")
        # RST biti kontrolü
        if mask & cls.RST:
            # RST metnini ekler
            flags.append("RST")
        # PSH biti kontrolü
        if mask & cls.PSH:
            # PSH metnini ekler
            flags.append("PSH")
        # URG biti kontrolü
        if mask & cls.URG:
            # URG metnini ekler
            flags.append("URG")
        # ECE biti kontrolü
        if mask & cls.ECE:
            # ECE metnini ekler
            flags.append("ECE")
        # CWR biti kontrolü
        if mask & cls.CWR:
            # CWR metnini ekler
            flags.append("CWR")
        # Listeyi döner
        return flags


def calculate_tcp_checksum(source_ip: str, dest_ip: str, tcp_header_and_payload: bytes) -> int:
    """RFC 793 Sahte Başlık (Pseudo-Header) ve TCP segmenti üzerinden RFC 1071 sağlama toplamı hesaplar."""
    # Kaynak IP adresini ikili 4 bayta çevirir
    src_bytes = ipaddress.IPv4Address(source_ip).packed
    # Hedef IP adresini ikili 4 bayta çevirir
    dst_bytes = ipaddress.IPv4Address(dest_ip).packed
    # Protokol numarası: TCP için 6'dır
    proto = 6
    # TCP segmentinin toplam uzunluğu (başlık + yük)
    tcp_len = len(tcp_header_and_payload)
    
    # 12 baytlık IPv4 Sahte Başlığı (Pseudo Header) inşa edilir
    # Format: Kaynak IP (4B) + Hedef IP (4B) + Sıfır Baytı (1B) + Protokol (1B) + TCP Uzunluğu (2B)
    pseudo_header = src_bytes + dst_bytes + struct.pack("!BBH", 0, proto, tcp_len)
    
    # Sahte başlık ile TCP başlık ve yük verisi birleştirilir
    full_data = pseudo_header + tcp_header_and_payload
    
    # Eğer toplam veri tek sayıda bayttan oluşuyorsa sonuna 0 baytı dolgulanır
    if len(full_data) % 2 != 0:
        # 1 baytlık sıfır dolgusu eklenir
        full_data += b"\x00"
        
    # 16-bitlik kelimeler halinde toplama akümülatörü
    total_sum = 0
    # İkişer baytlık adımlarla tüm veriyi tarar
    for i in range(0, len(full_data), 2):
        # 16-bitlik büyük sonlu (big-endian) kelimeyi çözer
        word = (full_data[i] << 8) + full_data[i + 1]
        # Akümülatöre ekler
        total_sum += word
        
    # 16-bit taşmaları (overflow carry) bir'in tümleyeni kuralıyla alt 16 bite ekler
    while total_sum > 0xFFFF:
        # Üst bitleri kaydırır ve alt bitlerle toplar
        total_sum = (total_sum & 0xFFFF) + (total_sum >> 16)
        
    # Sonucun tersi (bit NOT) alınarak sağlama toplamı elde edilir
    checksum = ~total_sum & 0xFFFF
    # 16-bitlik tamsayı döner
    return checksum


class TCPPacket:
    """RFC 793 standart TCP paket başlığı ve yükü veri modeli."""

    def __init__(
        self,
        kaynak_ip: str,
        hedef_ip: str,
        kaynak_port: int,
        hedef_port: int,
        seq_no: int,
        ack_no: int = 0,
        flags: int = TCPFlags.SYN,
        window_size: int = 64240,
        data_offset: int = 5,
        urgent_pointer: int = 0,
        payload: bytes = b"",
    ) -> None:
        # Kaynak port numarası tip ve sınır kontrolü (1 - 65535)
        if not isinstance(kaynak_port, int) or kaynak_port <= 0 or kaynak_port > 65535:
            # Geçersiz kaynak portunda hata yükseltir
            raise TCPValidationError(f"Geçersiz kaynak port numarası (1-65535 olmalıdır): {kaynak_port}")
        # Hedef port numarası tip ve sınır kontrolü (1 - 65535)
        if not isinstance(hedef_port, int) or hedef_port <= 0 or hedef_port > 65535:
            # Geçersiz hedef portunda hata yükseltir
            raise TCPValidationError(f"Geçersiz hedef port numarası (1-65535 olmalıdır): {hedef_port}")
        # Sıra numarası (Sequence Number) kontrolü (0 - 4294967295)
        if not isinstance(seq_no, int) or seq_no < 0 or seq_no > 0xFFFFFFFF:
            # Negatif veya 32-bit dışı sıra numarasında hata verir
            raise TCPValidationError(f"Sıra numarası (seq_no) 0-4294967295 aralığında olmalıdır: {seq_no}")
        # Onay numarası (Acknowledgment Number) kontrolü (0 - 4294967295)
        if not isinstance(ack_no, int) or ack_no < 0 or ack_no > 0xFFFFFFFF:
            # Negatif veya 32-bit dışı onay numarasında hata verir
            raise TCPValidationError(f"Onay numarası (ack_no) 0-4294967295 aralığında olmalıdır: {ack_no}")
        # Veri ofseti (Başlık uzunluğu kelime sayısı) kontrolü (Minimum 5 = 20 bayt)
        if not isinstance(data_offset, int) or data_offset < 5 or data_offset > 15:
            # Standart dışı veri ofsetinde hata fırlatır
            raise TCPValidationError(f"TCP veri ofseti 5 ile 15 arasında olmalıdır: {data_offset}")
        # Pencere boyutu kontrolü (0 - 65535)
        if not isinstance(window_size, int) or window_size < 0 or window_size > 65535:
            # Geçersiz pencere boyutunda hata yükseltir
            raise TCPValidationError(f"Pencere boyutu 0-65535 aralığında olmalıdır: {window_size}")
        # Bayrak maskesinin tamsayı olduğunu ve 0-255 aralığında olduğunu denetler
        if not isinstance(flags, int) or flags < 0 or flags > 255:
            # Geçersiz bayrak maskesinde hata fırlatır
            raise TCPValidationError(f"TCP bayrakları 0-255 aralığında bir tamsayı olmalıdır: {flags}")

        # Kaynak IP adresini doğrular
        try:
            # IPv4 doğrulaması yürütür
            self.kaynak_ip: str = str(ipaddress.IPv4Address(kaynak_ip))
        # Hata durumunda istisna fırlatır
        except Exception as err:
            # Açıklayıcı IP hatası döner
            raise TCPValidationError(f"Geçersiz kaynak IP adresi: {kaynak_ip} - Hata: {str(err)}")

        # Hedef IP adresini doğrular
        try:
            # IPv4 doğrulaması yürütür
            self.hedef_ip: str = str(ipaddress.IPv4Address(hedef_ip))
        # Hata durumunda istisna fırlatır
        except Exception as err:
            # Açıklayıcı hedef IP hatası döner
            raise TCPValidationError(f"Geçersiz hedef IP adresi: {hedef_ip} - Hata: {str(err)}")

        # Kaynak portu saklar
        self.kaynak_port: int = kaynak_port
        # Hedef portu saklar
        self.hedef_port: int = hedef_port
        # Sıra numarasını saklar
        self.seq_no: int = seq_no
        # Onay numarasını saklar
        self.ack_no: int = ack_no
        # Veri ofsetini saklar
        self.data_offset: int = data_offset
        # Bayrak maskesini saklar
        self.flags: int = flags
        # Pencere boyutunu saklar
        self.window_size: int = window_size
        # Acil durum işaretçisini saklar
        self.urgent_pointer: int = urgent_pointer
        # Yük (payload) baytlarını saklar
        self.payload: bytes = payload
        # Sağlama toplamı alanı (başlangıçta sıfır)
        self.checksum: int = 0

    def to_bytes(self) -> bytes:
        """TCP başlığı ve yükünü ikili (binary) formata paketler ve sağlama toplamını hesaplar."""
        # Veri ofseti (4 bit) ve ayrılmış alan (4 bit) birleştirilir
        data_offset_and_reserved = (self.data_offset << 4) & 0xF0
        
        # İlk olarak sağlama toplamı (checksum) alanı 0 olarak başlık paketlenir
        # Format: Kaynak Port (2B), Hedef Port (2B), Seq (4B), Ack (4B), Offset/Res (1B), Flags (1B), Window (2B), Checksum=0 (2B), UrgPtr (2B)
        preliminary_header = struct.pack(
            "!HHIIBBHHH",
            self.kaynak_port,
            self.hedef_port,
            self.seq_no,
            self.ack_no,
            data_offset_and_reserved,
            self.flags,
            self.window_size,
            0,
            self.urgent_pointer,
        )
        
        # Sahte başlık ile sağlama toplamı hesaplanır
        self.checksum = calculate_tcp_checksum(
            self.kaynak_ip,
            self.hedef_ip,
            preliminary_header + self.payload,
        )
        
        # Gerçek hesaplanan sağlama toplamı ile başlık yeniden paketlenir
        final_header = struct.pack(
            "!HHIIBBHHH",
            self.kaynak_port,
            self.hedef_port,
            self.seq_no,
            self.ack_no,
            data_offset_and_reserved,
            self.flags,
            self.window_size,
            self.checksum,
            self.urgent_pointer,
        )
        
        # Başlık ve yükün birleşimini döner
        return final_header + self.payload

    @classmethod
    def from_bytes(cls, raw_bytes: bytes, kaynak_ip: str, hedef_ip: str) -> "TCPPacket":
        """İkili bayt dizisinden TCP paketini ayrıştırır ve alanlarını doğrular."""
        # Girdinin bayt dizisi olduğunu denetler
        if not isinstance(raw_bytes, bytes):
            # Geçersiz tipte hata fırlatır
            raise TCPValidationError("TCP paketi bayt (bytes) tipinde olmalıdır.")
        # Minimum TCP başlık boyutu 20 bayttır
        if len(raw_bytes) < 20:
            # 20 bayttan kısa veride istisna üretir
            raise TCPValidationError(f"TCP başlığı en az 20 bayt olmalıdır, gelen: {len(raw_bytes)} bayt")
            
        # İlk 20 baytlık sabit TCP başlığını çözer
        src_port, dst_port, seq, ack, offset_res, flags, win, chk, urg = struct.unpack("!HHIIBBHHH", raw_bytes[:20])
        # Veri ofsetini üst 4 bitten çıkarır
        data_offset = (offset_res >> 4) & 0x0F
        # Veri ofseti 5'ten küçük olamaz
        if data_offset < 5:
            # Hatalı veri ofsetinde istisna fırlatır
            raise TCPValidationError(f"Geçersiz TCP başlık uzunluğu (veri ofseti): {data_offset}")
            
        # Başlığın toplam bayt uzunluğunu hesaplar (offset * 4 bayt)
        header_len = data_offset * 4
        # Veri boyutunun hesaplanan başlık boyutundan kısa olmadığını denetler
        if len(raw_bytes) < header_len:
            # Eksik başlık verisinde hata verir
            raise TCPValidationError(f"Eksik TCP başlık verisi: beklenen {header_len}, gelen {len(raw_bytes)}")
            
        # Başlıktan sonra kalan veri yüktür (payload)
        payload = raw_bytes[header_len:]
        
        # Yeni TCPPacket nesnesini oluşturur
        pkt = cls(
            kaynak_ip=kaynak_ip,
            hedef_ip=hedef_ip,
            kaynak_port=src_port,
            hedef_port=dst_port,
            seq_no=seq,
            ack_no=ack,
            flags=flags,
            window_size=win,
            data_offset=data_offset,
            urgent_pointer=urg,
            payload=payload,
        )
        # Paketteki orijinal sağlama toplamını saklar
        pkt.checksum = chk
        # Ayrıştırılan nesneyi döner
        return pkt


class TCPHandshakeSession:
    """Tek bir TCP oturumunun üç aşamalı el sıkışma durum makinesi (State Machine)."""

    def __init__(self, session_id: str) -> None:
        # Oturum benzersiz kimliği (client_ip:port -> server_ip:port)
        self.session_id: str = session_id
        # İstemci durum değişkeni (Başlangıç: CLOSED)
        self.client_state: str = "CLOSED"
        # Sunucu durum değişkeni (Başlangıç: LISTEN)
        self.server_state: str = "LISTEN"
        # İstemcinin başlangıç sıra numarası (ISN_c)
        self.client_isn: Optional[int] = None
        # Sunucunun başlangıç sıra numarası (ISN_s)
        self.server_isn: Optional[int] = None
        # El sıkışmanın başarıyla tamamlanıp tamamlanmadığı
        self.is_established: bool = False
        # Oturumda görülen paketlerin listesi
        self.packet_history: List[TCPPacket] = []
        # Oturuma ait güvenlik alarmları listesi
        self.security_alerts: List[str] = []

    def process_packet(self, packet: TCPPacket) -> str:
        """Gelen TCP paketini durum makinesine uygular ve durum geçişini yönetir."""
        # Paketi geçmiş listesine kaydeder
        self.packet_history.append(packet)
        # Bayrak maskesini alır
        f = packet.flags

        # 1. ADIM: İstemci Bağlantı Başlatma İsteği (SYN)
        if (f & TCPFlags.SYN) and not (f & TCPFlags.ACK):
            # El sıkışma paketinde payload kontrolü (Zafiyet / Anomali tespiti)
            if len(packet.payload) > 0:
                # Handshake sırasında veri taşınması kural dışıdır
                self.security_alerts.append("SYN paketinde beklenmeyen veri yükü (Payload) tespit edildi!")
            
            # İstemci ISN değerini kaydeder
            self.client_isn = packet.seq_no
            # İstemci durumu SYN_SENT olur
            self.client_state = "SYN_SENT"
            # Sunucu durumu SYN_RECEIVED olur
            self.server_state = "SYN_RECEIVED"
            # Adım sonucunu metin olarak döner
            return "STEP_1_SYN_SENT"

        # 2. ADIM: Sunucu Kabul ve Eşitleme Yanıtı (SYN + ACK)
        elif (f & TCPFlags.SYN) and (f & TCPFlags.ACK):
            # Sunucu cevabında önceki istemci ISN kontrolü
            if self.client_isn is None:
                # İstemci SYN göndermeden gelen SYN-ACK anomalidir
                self.security_alerts.append("Yetkisiz veya beklenmeyen SYN-ACK paketi (İstemci SYN göndermedi)!")
                # Anomaliyi bildirir
                return "UNEXPECTED_SYN_ACK"
                
            # Onay numarasının (Ack No) istemci ISN + 1 olup olmadığını teyit eder
            expected_ack = (self.client_isn + 1) & 0xFFFFFFFF
            # Beklenen onay numarası kontrolü
            if packet.ack_no != expected_ack:
                # Hatalı Ack numarasında güvenlik alarmı üretir
                self.security_alerts.append(f"Hatalı Ack numarası! Beklenen: {expected_ack}, Gelen: {packet.ack_no}")
                # Hata durumunu döner
                return "INVALID_ACK_NUMBER"

            # Sunucu ISN değerini kaydeder
            self.server_isn = packet.seq_no
            # İstemci bu paketi alınca ESTABLISHED durumuna geçer
            self.client_state = "ESTABLISHED"
            # Adım sonucunu döner
            return "STEP_2_SYN_ACK_RECEIVED"

        # 3. ADIM: İstemci Nihai Onay Yanıtı (ACK)
        elif (f & TCPFlags.ACK) and not (f & TCPFlags.SYN) and not (f & TCPFlags.FIN) and not (f & TCPFlags.RST):
            # Sunucu ISN kontrolü
            if self.server_isn is None:
                # Sunucu SYN-ACK göndermeden gelen ACK kontrolsüzdür
                return "ACK_WITHOUT_PRIOR_SYN_ACK"
                
            # Beklenen onay numarası: Sunucu ISN + 1
            expected_ack = (self.server_isn + 1) & 0xFFFFFFFF
            # Onay numarası eşleşmesi kontrolü
            if packet.ack_no == expected_ack:
                # Sunucu da ESTABLISHED durumuna geçer
                self.server_state = "ESTABLISHED"
                # Oturum kuruldu bayrağı aktifleşir
                self.is_established = True
                # Başarılı el sıkışma sonucunu döner
                return "STEP_3_ESTABLISHED"
            # Farklı ack numarası durumunda
            else:
                # Hatalı ack uyarısı
                self.security_alerts.append(f"3. Adım Ack numarası uyuşmazlığı! Beklenen: {expected_ack}, Gelen: {packet.ack_no}")
                # Hata durumunu döner
                return "INVALID_HANDSHAKE_FINAL_ACK"

        # Bağlantı Sıfırlama (RST) Kontrolü
        elif f & TCPFlags.RST:
            # Bağlantı sıfırlanır
            self.client_state = "CLOSED"
            # Sunucu durumu da sıfırlanır
            self.server_state = "CLOSED"
            # RST durumunu bildirir
            return "CONNECTION_RESET"

        # Diğer durumlar
        return "DATA_OR_OTHER"


class TCPHandshakeAnalyzer:
    """TCP paket akışlarını inceleyen, anomalileri yakalayan ve raporlayan üst motor."""

    def __init__(self) -> None:
        # Aktif oturumları takip eden sözlük
        self.sessions: Dict[str, TCPHandshakeSession] = {}
        # Genel güvenlik anomalileri listesi
        self.anomalies: List[Dict[str, Any]] = []

    def load_and_analyze_json(self, json_path: str) -> None:
        """JSON dosyasındaki paketleri sırayla ayrıştırır ve el sıkışma analizini yürütür."""
        # Dosyanın varlığını teyit eder
        if not os.path.exists(json_path):
            # Dosya yoksa istisna üretir
            raise TCPValidationError(f"Paket dosyası bulunamadı: {json_path}")
        # Dosyayı okur
        with open(json_path, "r", encoding="utf-8") as f:
            # JSON verisini listeye çevirir
            packets_data = json.load(f)

        # Listenin tipini doğrular
        if not isinstance(packets_data, list):
            # Geçersiz yapıda hata fırlatır
            raise TCPValidationError("Paketler verisi liste (list) olmalıdır.")

        # Her paketi döngüyle inceler
        for p_data in packets_data:
            # Bayrak sözlüğünü maskeye dönüştürür
            flags_mask = TCPFlags.from_dict(p_data.get("flags", {}))
            
            # Hex yük varsa bayta çevirir
            payload_hex = p_data.get("payload_hex", "")
            # Yük baytlarını hazırlar
            payload_bytes = bytes.fromhex(payload_hex) if payload_hex else b""

            # TCPPacket nesnesini oluşturur
            pkt = TCPPacket(
                kaynak_ip=p_data["kaynak_ip"],
                hedef_ip=p_data["hedef_ip"],
                kaynak_port=p_data["kaynak_port"],
                hedef_port=p_data["hedef_port"],
                seq_no=p_data["seq_no"],
                ack_no=p_data.get("ack_no", 0),
                flags=flags_mask,
                window_size=p_data.get("window_size", 64240),
                data_offset=p_data.get("data_offset", 5),
                payload=payload_bytes,
            )

            # Paketin ikili bütünlüğünü to_bytes ve from_bytes ile doğrular
            raw_pkt_bytes = pkt.to_bytes()
            # Tekrar ayrıştırır
            parsed_pkt = TCPPacket.from_bytes(raw_pkt_bytes, pkt.kaynak_ip, pkt.hedef_ip)

            # Anomali kontrollerini yürütür
            self.check_packet_anomalies(pkt, p_data.get("paket_id", "UNKNOWN"))

            # Oturum anahtarını oluşturur
            session_key = f"{pkt.kaynak_ip}:{pkt.kaynak_port}->{pkt.hedef_ip}:{pkt.hedef_port}"
            # Ters oturum anahtarı (sunucudan istemciye dönüş)
            reverse_key = f"{pkt.hedef_ip}:{pkt.hedef_port}->{pkt.kaynak_ip}:{pkt.kaynak_port}"

            # Eğer ters oturum varsa onun üzerinden devam eder
            if reverse_key in self.sessions:
                # Ters oturumu kullanır
                active_session = self.sessions[reverse_key]
            # Yoksa mevcut anahtar için yeni veya var olan oturumu alır
            else:
                # Oturum yoksa başlatır
                if session_key not in self.sessions:
                    # Yeni oturum nesnesi
                    self.sessions[session_key] = TCPHandshakeSession(session_key)
                # Aktif oturumu seçer
                active_session = self.sessions[session_key]

            # Paketi oturum durum makinesine uygular
            active_session.process_packet(pkt)

    def check_packet_anomalies(self, pkt: TCPPacket, paket_id: str) -> None:
        """Kural dışı bayrak kombinasyonlarını ve port tarama taktiklerini denetler."""
        # Bayrak maskesini alır
        f = pkt.flags

        # 1. ÇELİŞKİLİ BAYRAKLAR: SYN ve FIN aynı anda set edilemez (RFC kuralı ihlali)
        if (f & TCPFlags.SYN) and (f & TCPFlags.FIN):
            # Kritik protokol ihlali alarmı
            self.anomalies.append({
                "paket_id": paket_id,
                "kategori": "KURAL_DISI_BAYRAK_SYN_FIN",
                "seviye": "KRITIK",
                "kaynak": f"{pkt.kaynak_ip}:{pkt.kaynak_port}",
                "hedef": f"{pkt.hedef_ip}:{pkt.hedef_port}",
                "mesaj": "SYN ve FIN bayrakları aynı anda set edilmiş! Güvenlik duvarı baypas veya anomali girişimi."
            })

        # 2. XMAS SCAN ANOMALİSİ: FIN + PSH + URG (Tüm ışıklar yanıyor)
        if (f & TCPFlags.FIN) and (f & TCPFlags.PSH) and (f & TCPFlags.URG):
            # XMAS tarama alarmı
            self.anomalies.append({
                "paket_id": paket_id,
                "kategori": "PORT_TARAMA_XMAS",
                "seviye": "YUKSEK",
                "kaynak": f"{pkt.kaynak_ip}:{pkt.kaynak_port}",
                "hedef": f"{pkt.hedef_ip}:{pkt.hedef_port}",
                "mesaj": "XMAS Port Taraması tespit edildi (FIN+PSH+URG bayrakları aktif)!"
            })

        # 3. NULL SCAN ANOMALİSİ: Hiçbir bayrak set edilmemiş (Flags == 0)
        if f == 0:
            # NULL tarama alarmı
            self.anomalies.append({
                "paket_id": paket_id,
                "kategori": "PORT_TARAMA_NULL",
                "seviye": "YUKSEK",
                "kaynak": f"{pkt.kaynak_ip}:{pkt.kaynak_port}",
                "hedef": f"{pkt.hedef_ip}:{pkt.hedef_port}",
                "mesaj": "NULL Port Taraması tespit edildi (Tüm kontrol bayrakları sıfır)!"
            })

        # 4. GİZLİ SYN / HALF-OPEN SCAN İPUCU: SYN-ACK gelmeden tekil RST veya handshake tamamlanmadan RST
        if (f & TCPFlags.RST) and pkt.seq_no > 0 and pkt.ack_no == 0:
            # Şüpheli RST alarmı
            self.anomalies.append({
                "paket_id": paket_id,
                "kategori": "GIZLI_SYN_TARAMASI_SUPHESI",
                "seviye": "ORTA",
                "kaynak": f"{pkt.kaynak_ip}:{pkt.kaynak_port}",
                "hedef": f"{pkt.hedef_ip}:{pkt.hedef_port}",
                "mesaj": "Şüpheli RST paketi tespit edildi (Stealth SYN Port Taraması belirtisi)!"
            })

        # 5. SYN FLOOD İPUCU: Küçük pencere boyutlu ve sahte IP aralığından gelen izole SYN
        if (f & TCPFlags.SYN) and not (f & TCPFlags.ACK) and pkt.window_size <= 1024:
            # Şüpheli SYN Flood alarmı
            self.anomalies.append({
                "paket_id": paket_id,
                "kategori": "SYN_FLOOD_BELIRTISI",
                "seviye": "YUKSEK",
                "kaynak": f"{pkt.kaynak_ip}:{pkt.kaynak_port}",
                "hedef": f"{pkt.hedef_ip}:{pkt.hedef_port}",
                "mesaj": "Anormal düşük pencere boyutlu izole SYN paketi tespit edildi (SYN Flood DoS belirtisi)!"
            })

    def generate_markdown_report(self) -> str:
        """TCP üçlü el sıkışma ve güvenlik analiz sonuçlarını Markdown formatında derler."""
        # Rapor satırlarını toplayacak liste
        lines: List[str] = []
        # Ana başlık
        lines.append("# 📊 TCP Üçlü El Sıkışma (Three-Way Handshake) ve Güvenlik Denetim Raporu\n")
        # Lisans bildirimi
        lines.append("**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  ")
        # Telif hakkı
        lines.append("*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*\n")
        # Ayırıcı çizgi
        lines.append("---\n")

        # 1. BÖLÜM: Oturum ve El Sıkışma Durumları
        lines.append("## 1. TCP Oturumları ve Durum Makinesi Özeti\n")
        # Tablo başlığı
        lines.append("| Oturum Kimliği | Paket Sayısı | İstemci Durumu | Sunucu Durumu | El Sıkışma Tamamlandı mı? | Güvenlik Uyarıları |")
        # Ayırıcı
        lines.append("|---|---|---|---|---|---|")
        
        # Oturumları döngüyle tabloya ekler
        for sess_id, sess in self.sessions.items():
            # Tamamlanma ikonu
            tamam_ikon = "✅ EVET" if sess.is_established else "❌ HAYIR (Yarım Açık)"
            # Güvenlik uyarıları metni
            uyarilar = ", ".join(sess.security_alerts) if sess.security_alerts else "Yok (Temiz)"
            # Satırı biçimlendirir
            satir = (
                f"| `{sess_id}` | {len(sess.packet_history)} | `{sess.client_state}` | "
                f"`{sess.server_state}` | **{tamam_ikon}** | {uyarilar} |"
            )
            # Listeye ekler
            lines.append(satir)
        # Boşluk bırakır
        lines.append("")

        # 2. BÖLÜM: Güvenlik Anomalileri ve Port Tarama Bulguları
        lines.append("## 2. Tespit Edilen Güvenlik Anomalileri ve Tarama Girişimleri\n")
        # Anomali yoksa tebrik mesajı
        if not self.anomalies:
            # Temiz trafik bildirimi
            lines.append("✅ **Denetim Başarılı:** Trafikte kural dışı bayrak veya SYN Flood anomalisi saptanmadı.\n")
        # Anomali varsa tablo oluşturur
        else:
            # Tablo başlığı
            lines.append("| No | Paket ID | Kategori | Seviye | Kaynak | Hedef | Güvenlik Riski ve Açıklama |")
            # Ayırıcı
            lines.append("|---|---|---|---|---|---|---|")
            # Her bir anomaliyi ekler
            for idx, a in enumerate(self.anomalies, 1):
                # Seviye ikonu
                ikon = "🚨" if a["seviye"] == "KRITIK" else "⚠️"
                # Satır formatı
                satir = f"| {idx} | `{a['paket_id']}` | `{a['kategori']}` | {ikon} **{a['seviye']}** | `{a['kaynak']}` | `{a['hedef']}` | {a['mesaj']} |"
                # Satırı ekler
                lines.append(satir)
            # Boşluk
            lines.append("")

        # 3. BÖLÜM: TCP Savunma ve Sıkılaştırma İlkeleri
        lines.append("## 3. TCP Seviyesinde Savunma ve Sıkılaştırma İlkeleri\n")
        # İlk kural
        lines.append("1. **SYN Cookies (RFC 4987):** Sunucularda SYN Backlog kuyruğunun tükenmesini önlemek amacıyla, SYN-ACK paketindeki ISN değeri kriptografik özet olarak hesaplanmalı; el sıkışma tamamlanana kadar bellek ayrılmamalıdır.")
        # İkinci kural
        lines.append("2. **Stateful Firewall & Connection Tracking:** Güvenlik duvarlarında el sıkışması tamamlanmamış (ESTABLISHED durumuna geçmemiş) paketlerin iç ağ sunucularına geçişine kesinlikle izin verilmemelidir.")
        # Üçüncü kural
        lines.append("3. **Rastgele ve Kriptografik ISN Üretimi (RFC 6528):** Öngörülebilir sıra numaraları ile oturum kaçırma (TCP Session Hijacking) saldırılarını engellemek adına güvenilir ISN algoritmaları zorunlu kılınmalıdır.")
        # Dördüncü kural
        lines.append("4. **Kural Dışı Bayrak Filtreleme:** Güvenlik duvarı çekirdeğinde `SYN+FIN`, `XMAS` (FIN+PSH+URG) ve `NULL` paketleri doğrudan düşürülmeli (DROP) ve saldırı alarmı üretilmelidir.\n")

        # Metni birleştirip döner
        return "\n".join(lines)


if __name__ == "__main__":
    # Konsol başlangıç bilgisi
    print("================================================================================")
    # Başlık
    print("[+] Gün 050: TCP Üçlü El Sıkışma Analiz ve Güvenlik Denetim Motoru Başlatılıyor...")
    # Çizgi
    print("================================================================================")

    # Örnek paket JSON yolunu belirler
    json_path = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "sample_tcp_handshake_packets.json")
    # Yolu normalize eder
    json_path = os.path.abspath(json_path)

    # Analiz motoru nesnesini başlatır
    analyzer = TCPHandshakeAnalyzer()
    # JSON verisini yükler ve analiz eder
    analyzer.load_and_analyze_json(json_path)

    # Konsola oturum sonuçlarını yazar
    print(f"[*] Toplam İncelenen TCP Oturumu Sayısı: {len(analyzer.sessions)}")
    # Her oturumun durumunu yazdırır
    for sess_id, sess in analyzer.sessions.items():
        # Durum bilgisini basar
        durum_str = "BAŞARILI (ESTABLISHED)" if sess.is_established else "YARIM AÇIK / HATA"
        # Ekrana yazdırır
        print(f"    -> Oturum: {sess_id} | Durum: {durum_str} (Paket: {len(sess.packet_history)})")

    # Tespit edilen güvenlik anomalilerini yazdırır
    print(f"\n[*] Tespit Edilen Güvenlik Anomalileri ve Tarama Belirtileri: {len(analyzer.anomalies)}")
    # Döngüyle her bir anomaliyi ekrana yazar
    for idx, a in enumerate(analyzer.anomalies, 1):
        # Bilgi satırını ekrana basar
        print(f"    [{idx}] {a['seviye']} | {a['kategori']} | Kaynak: {a['kaynak']} -> {a['mesaj']}")

    # Markdown raporunu derler
    rapor_md = analyzer.generate_markdown_report()

    # Rapor dosyasının kaydedileceği konumu belirler
    rapor_cikti_yolu = os.path.join(os.path.dirname(__file__), "..", "kanit", "gercek", "tcp_el_sikisma_raporu.txt")
    # Yolu normalize eder
    rapor_cikti_yolu = os.path.abspath(rapor_cikti_yolu)
    # Dizin oluşturur
    os.makedirs(os.path.dirname(rapor_cikti_yolu), exist_ok=True)
    # Dosyaya kaydeder
    with open(rapor_cikti_yolu, "w", encoding="utf-8") as f:
        # Metni yazar
        f.write(rapor_md)

    # Tamamlanma bildirimini ekrana basar
    print(f"\n[+] TCP El Sıkışma Analiz Raporu Başarıyla Kaydedildi: {rapor_cikti_yolu}")
    print("================================================================================")
