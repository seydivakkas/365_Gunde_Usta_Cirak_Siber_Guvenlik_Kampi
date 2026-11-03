# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G052: UDP (User Datagram Protocol) ve Kullanım Alanları Analizörü.  # G052: UDP (User Datagram Protocol) ve Kullanım Alanları Analizörü.
Bu modül RFC 768 standartlarına uygun UDP başlık paketleme, ayrıştırma,  # Bu modül RFC 768 standartlarına uygun UDP başlık paketleme, ayrıştırma,
sahte başlık (pseudo-header) ile sağlama toplamı (checksum) hesaplama,  # sahte başlık (pseudo-header) ile sağlama toplamı (checksum) hesaplama,
DNS/NTP/DHCP/SNMP gibi kritik servislerin yük analizi ve  # DNS/NTP/DHCP/SNMP gibi kritik servislerin yük analizi ve
UDP Amplifikasyon / Yansıtma (Reflection DDoS) ile UDP Flood / Port Taraması  # UDP Amplifikasyon / Yansıtma (Reflection DDoS) ile UDP Flood / Port Taraması
tespit mekanizmalarını içermektedir.  # tespit mekanizmalarını içermektedir.
"""

import ipaddress  # IPv4 ve IPv6 adres formatı ve geçerlilik denetimleri için standart kütüphane
import math  # Entropi ve logaritmik hesaplamalar için matematik modülü
import struct  # İkili (binary) ağ bayt dizisi paketleme ve açma işlemleri modülü
from typing import Any, Dict, List, Optional, Tuple  # Tip ipuçları ve statik tip denetimi tanımları


class UDPProtocolError(Exception):  # Nesne yönelimli veri modeli ve işlev sınıfı tanımı
    """UDP protokol işlemleri için temel özel hata sınıfı."""

    pass  # Temel hata hiyerarşisi oluşturmak üzere boş gövde tanımlanır


class UDPValidationError(UDPProtocolError):  # Nesne yönelimli veri modeli ve işlev sınıfı tanımı
    """Geçersiz port, başlık uzunluğu veya biçim hatalarında fırlatılan istisna."""

    pass  # Doğrulama hatalarını protokol hatalarından ayrıştırmak için türetilir


class UDPChecksumMismatchError(UDPProtocolError):  # Nesne yönelimli veri modeli ve işlev sınıfı tanımı
    """Sağlama toplamı (checksum) doğrulanamadığında fırlatılan hata."""

    pass  # Paket bütünlüğü bozulduğunda veya veri değiştirildiğinde fırlatılır


class UDPAmplificationRiskError(UDPProtocolError):  # Nesne yönelimli veri modeli ve işlev sınıfı tanımı
    """Yüksek amplifikasyon (yükseltme) faktörü tespit edildiğinde fırlatılan hata."""

    pass  # DDoS yansıtma ve amplifikasyon tehditleri tespit edildiğinde uyarır


def validate_ipv4_address(ip_str: str) -> bytes:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
    """
    IPv4 adresinin 4 oktetli standart noktalı gösterimini doğrular ve 4 baytlık ikili değere çevirir.  # IPv4 adresinin 4 oktetli standart noktalı gösterimini doğrular ve 4 baytlık ikili değere çevirir.
    Hatalı IP biçiminde UDPValidationError fırlatır.  # Hatalı IP biçiminde UDPValidationError fırlatır.
    """
    try:  # IP adresi dönüştürme ve sözdizimi denetimi bloğu
        ip_obj = ipaddress.IPv4Address(ip_str)  # IPv4 nesnesi oluşturularak sözdizimi ve oktetler denetlenir
        return ip_obj.packed  # Ağ bayt sırasında (Big-Endian) 4 baytlık ikili IP temsilini döndürür
    except (ipaddress.AddressValueError, ValueError) as err:  # Geçersiz IP dizgisi veya format hatası yakalanır
        raise UDPValidationError(f"Geçersiz IPv4 adresi biçimi: '{ip_str}'. Hata: {err}")  # Net doğrulama hatası bildirilir


class UDPHeader:  # Nesne yönelimli veri modeli ve işlev sınıfı tanımı
    """
    RFC 768 standart 8 baytlık UDP Başlığı Modeli.  # RFC 768 standart 8 baytlık UDP Başlığı Modeli.
    Yapı:  # Yapı:
    0      7 8     15 16    23 24    31  # 0      7 8     15 16    23 24    31
    +--------+--------+--------+--------+
    |     Source      |   Destination   |
    |      Port       |      Port       |
    +--------+--------+--------+--------+
    |                 |                 |
    |     Length      |    Checksum     |
    +--------+--------+--------+--------+
    """

    HEADER_FORMAT: str = "!HHHH"  # Ağ bayt sırası (Big-Endian) ile 4 adet 16-bit işaretsiz tamsayı
    HEADER_SIZE: int = 8  # UDP başlığı RFC 768 gereğince sabit 8 bayt uzunluğundadır

    def __init__(self, src_port: int, dst_port: int, length: int, checksum: int = 0) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """UDP başlık alanlarını doğrular ve nesneyi başlatır."""
        self._validate_fields(src_port, dst_port, length, checksum)  # Tüm alan sınır değerlerini doğrula
        self.src_port: int = src_port  # Kaynak port numarası (0-65535)
        self.dst_port: int = dst_port  # Hedef port numarası (0-65535)
        self.length: int = length  # Başlık ve veri toplam uzunluğu (bayt)
        self.checksum: int = checksum  # 16-bit birin tümleyeni sağlama toplamı

    def _validate_fields(self, src_port: int, dst_port: int, length: int, checksum: int) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """UDP alanlarının RFC 768 tamsayı sınırlarına uygunluğunu denetler."""
        if not isinstance(src_port, int) or src_port < 0 or src_port > 65535:  # Kaynak port aralık kontrolü
            raise UDPValidationError(f"Kaynak port 0 ile 65535 arasında olmalıdır: {src_port}")  # Aralık dışı port hatası
        if not isinstance(dst_port, int) or dst_port < 0 or dst_port > 65535:  # Hedef port aralık kontrolü
            raise UDPValidationError(f"Hedef port 0 ile 65535 arasında olmalıdır: {dst_port}")  # Aralık dışı port hatası
        if not isinstance(length, int) or length < self.HEADER_SIZE:  # Uzunluk minimum 8 bayt olmalıdır
            raise UDPValidationError(f"UDP toplam uzunluğu en az 8 bayt (başlık boyutu) olmalıdır: {length}")  # Alt sınır ihlali
        if length > 65535:  # 16-bit maksimum uzunluk sınırı kontrolü
            raise UDPValidationError(f"UDP toplam uzunluğu 65535 baytı aşamaz: {length}")  # Üst sınır ihlali
        if not isinstance(checksum, int) or checksum < 0 or checksum > 65535:  # Checksum 16-bit aralık kontrolü
            raise UDPValidationError(f"Sağlama toplamı 0 ile 65535 arasında olmalıdır: {checksum}")  # Geçersiz checksum

    def pack(self) -> bytes:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """UDP başlığını 8 baytlık ikili (binary) ağ dizisine dönüştürür."""
        return struct.pack(self.HEADER_FORMAT, self.src_port, self.dst_port, self.length, self.checksum)  # İkili paketleme

    @classmethod  # Metot davranışını niteleyen Python dekoratörü
    def unpack(cls, data: bytes) -> "UDPHeader":  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """8 baytlık ikili veriyi ayrıştırarak UDPHeader nesnesi oluşturur."""
        if len(data) < cls.HEADER_SIZE:  # Veri boyutu en az başlık boyutu kadar olmalıdır
            raise UDPValidationError(f"UDP başlığı ayrıştırmak için en az 8 bayt veri gerekir, alınan: {len(data)}")  # Yetersiz veri
        src_port, dst_port, length, checksum = struct.unpack(cls.HEADER_FORMAT, data[:cls.HEADER_SIZE])  # Ayrıştırma
        return cls(src_port=src_port, dst_port=dst_port, length=length, checksum=checksum)  # Doğrulanmış nesne döndür

    @staticmethod  # Metot davranışını niteleyen Python dekoratörü
    def calculate_checksum(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> int:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """
        RFC 768 / RFC 1071 kurallarına göre IPv4 Sahte Başlığı (Pseudo-Header) ile  # RFC 768 / RFC 1071 kurallarına göre IPv4 Sahte Başlığı (Pseudo-Header) ile
        16-bit birin tümleyeni (one's complement) sağlama toplamı hesaplar.  # 16-bit birin tümleyeni (one's complement) sağlama toplamı hesaplar.
        Sahte Başlık Yapısı (12 Bayt):  # Sahte Başlık Yapısı (12 Bayt):
        - Kaynak IP (4 Bayt)  # - Kaynak IP (4 Bayt)
        - Hedef IP (4 Bayt)  # - Hedef IP (4 Bayt)
        - Sıfır (1 Bayt, 0x00)  # - Sıfır (1 Bayt, 0x00)
        - Protokol (1 Bayt, UDP = 17 / 0x11)  # - Protokol (1 Bayt, UDP = 17 / 0x11)
        - UDP Uzunluğu (2 Bayt)  # - UDP Uzunluğu (2 Bayt)
        """
        src_ip_bytes = validate_ipv4_address(src_ip)  # Kaynak IP 4 bayta dönüştürülür
        dst_ip_bytes = validate_ipv4_address(dst_ip)  # Hedef IP 4 bayta dönüştürülür
        udp_length = 8 + len(payload)  # UDP başlığı (8 bayt) ve yük boyutu toplamı

        pseudo_header = src_ip_bytes + dst_ip_bytes + struct.pack("!BBH", 0, 17, udp_length)  # 12 baytlık sahte başlık
        udp_header_zero_checksum = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)  # Checksum alanı 0 olan başlık
        data_to_checksum = pseudo_header + udp_header_zero_checksum + payload  # Sağlama toplamına girecek tam veri

        if len(data_to_checksum) % 2 != 0:  # Eğer veri boyutu tek sayı ise RFC standardı gereği 1 bayt 0 padding eklenir
            data_to_checksum += b"\x00"  # 1 baytlık sıfır dolgusu

        total_sum = 0  # 16-bit toplamı saklamak için sayaç başlatılır
        for i in range(0, len(data_to_checksum), 2):  # 16-bit (2 bayt) adımlarla döngü
            word = (data_to_checksum[i] << 8) + data_to_checksum[i + 1]  # 2 bayttan 16-bit kelime oluşturulur
            total_sum += word  # Kelime kümülatif toplama eklenir

        while (total_sum >> 16) > 0:  # Taşan bitler (eldeler - carries) 16 bitin üzerine çıkarsa katlanır
            total_sum = (total_sum & 0xFFFF) + (total_sum >> 16)  # Eldeler alt 16 bite eklenir (One's complement addition)

        checksum = (~total_sum) & 0xFFFF  # Toplamın tümleyeni (NOT işlemi) alınır ve 16-bit maskelenir
        if checksum == 0:  # RFC 768: Eğer hesaplanan checksum 0 ise 0xFFFF olarak iletilmelidir (0x0000 checksum yok demektir)
            checksum = 0xFFFF  # Sıfır yerine 0xFFFF atanır
        return checksum  # Nihai hesaplanan 16-bit sağlama toplamı döndürülür


class UDPDatagram:  # Nesne yönelimli veri modeli ve işlev sınıfı tanımı
    """Tam bir UDP Datagramı (Başlık + Yük + IP Metaverileri) temsil sınıfı."""

    def __init__(  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        self,  # self,
        src_ip: str,  # src_ip: str,
        dst_ip: str,  # dst_ip: str,
        header: UDPHeader,  # header: UDPHeader,
        payload: bytes = b"",  # payload: bytes = b"",
        timestamp: float = 0.0,  # timestamp: float = 0.0,
    ) -> None:  # ) -> None:
        """UDP Datagram nesnesini başlatır ve uzunluk tutarlılığını denetler."""
        validate_ipv4_address(src_ip)  # Kaynak IP formatını doğrula
        validate_ipv4_address(dst_ip)  # Hedef IP formatını doğrula
        expected_len = UDPHeader.HEADER_SIZE + len(payload)  # Beklenen toplam uzunluk
        if header.length != expected_len:  # Başlıktaki uzunluk ile gerçek yükün tutarlılık denetimi
            raise UDPValidationError(  # Tanımlı güvenlik ve biçim kuralı ihlalinde fırlatılan istisna
                f"Belirtilen UDP uzunluğu ({header.length}) başlık + yük toplamı ({expected_len}) ile uyuşmuyor."  # f"Belirtilen UDP uzunluğu ({header.length}) başlık + yük toplamı ({expected_len}) ile uyuşmuyor."
            )  # Tutarsızlık hatası fırlatılır
        self.src_ip: str = src_ip  # Kaynak IP adresi
        self.dst_ip: str = dst_ip  # Hedef IP adresi
        self.header: UDPHeader = header  # 8 baytlık UDP başlığı
        self.payload: bytes = payload  # Uygulama katmanı yükü (payload)
        self.timestamp: float = timestamp  # Paketin yakalanma / oluşturulma zaman damgası

    def verify_checksum(self) -> bool:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """
        RFC 768 kurallarına göre datagram sağlama toplamını doğrular.  # RFC 768 kurallarına göre datagram sağlama toplamını doğrular.
        Eğer başlık checksum değeri 0x0000 ise, IPv4'te checksum devre dışı bırakılmış kabul edilir (True).  # Eğer başlık checksum değeri 0x0000 ise, IPv4'te checksum devre dışı bırakılmış kabul edilir (True).
        Aksi halde sahte başlık ile yeniden hesaplanan checksum ile karşılaştırılır.  # Aksi halde sahte başlık ile yeniden hesaplanan checksum ile karşılaştırılır.
        """
        if self.header.checksum == 0:  # RFC 768 gereği IPv4'te checksum=0 'sağlama toplamı iletilmedi/devre dışı' demektir
            return True  # Doğrulama geçerli kabul edilir (checksum disabled)
        computed = UDPHeader.calculate_checksum(  # computed = UDPHeader.calculate_checksum(
            self.src_ip, self.dst_ip, self.header.src_port, self.header.dst_port, self.payload  # self.src_ip, self.dst_ip, self.header.src_port, self.header.dst_port, self.payload
        )  # Beklenen sağlama toplamı hesaplanır
        return computed == self.header.checksum  # Eşleşme durumu boolean olarak döndürülür

    def serialize(self) -> bytes:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Datagramı iletime hazır ikili (binary) bayt dizisine dönüştürür."""
        return self.header.pack() + self.payload  # Başlık ve yük baytları birleştirilerek döndürülür

    @classmethod  # Metot davranışını niteleyen Python dekoratörü
    def create(  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        cls,  # cls,
        src_ip: str,  # src_ip: str,
        dst_ip: str,  # dst_ip: str,
        src_port: int,  # src_port: int,
        dst_port: int,  # dst_port: int,
        payload: bytes = b"",  # payload: bytes = b"",
        timestamp: float = 0.0,  # timestamp: float = 0.0,
        compute_checksum: bool = True,  # compute_checksum: bool = True,
    ) -> "UDPDatagram":  # ) -> "UDPDatagram":
        """Kullanışlı fabrika metodu: Checksum'ı otomatik hesaplayarak datagram üretir."""
        length = UDPHeader.HEADER_SIZE + len(payload)  # Toplam uzunluk hesaplanır
        chk = 0  # Varsayılan sağlama toplamı sıfır
        if compute_checksum:  # Eğer sağlama toplamı hesaplanması isteniyorsa
            chk = UDPHeader.calculate_checksum(src_ip, dst_ip, src_port, dst_port, payload)  # Checksum hesapla
        header = UDPHeader(src_port=src_port, dst_port=dst_port, length=length, checksum=chk)  # Başlık oluştur
        return cls(src_ip=src_ip, dst_ip=dst_ip, header=header, payload=payload, timestamp=timestamp)  # Datagram döndür

    @classmethod  # Metot davranışını niteleyen Python dekoratörü
    def parse_raw(  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        cls, raw_data: bytes, src_ip: str, dst_ip: str, timestamp: float = 0.0  # cls, raw_data: bytes, src_ip: str, dst_ip: str, timestamp: float = 0.0
    ) -> "UDPDatagram":  # ) -> "UDPDatagram":
        """İkili ağ paketinden UDPHeader ve yükü ayrıştırarak UDPDatagram oluşturur."""
        header = UDPHeader.unpack(raw_data)  # İlk 8 baytı başlık olarak aç
        payload = raw_data[UDPHeader.HEADER_SIZE:header.length]  # Belirtilen uzunluğa kadar olan kısmı yük olarak al
        return cls(src_ip=src_ip, dst_ip=dst_ip, header=header, payload=payload, timestamp=timestamp)  # Datagram döndür


class UDPProtocolAnalyzer:  # Nesne yönelimli veri modeli ve işlev sınıfı tanımı
    """
    UDP Protokol ve Kullanım Alanları Güvenlik Analizörü.  # UDP Protokol ve Kullanım Alanları Güvenlik Analizörü.
    Özellikler:  # Özellikler:
    - Protokol sınıflandırma (DNS, NTP, DHCP, SNMP, Syslog, QUIC)  # - Protokol sınıflandırma (DNS, NTP, DHCP, SNMP, Syslog, QUIC)
    - Amplifikasyon / Yansıtma DDoS risk puanlaması (BAF hesaplama)  # - Amplifikasyon / Yansıtma DDoS risk puanlaması (BAF hesaplama)
    - UDP Port Taraması (Port Sweep) ve UDP Flood anomali tespiti  # - UDP Port Taraması (Port Sweep) ve UDP Flood anomali tespiti
    - Kaminsky DNS Cache Poisoning savunması için Kaynak Port Entropi Denetimi  # - Kaminsky DNS Cache Poisoning savunması için Kaynak Port Entropi Denetimi
    """

    KNOWN_PORTS: Dict[int, str] = {  # KNOWN_PORTS: Dict[int, str] = {
        53: "DNS",  # Etki Alanı Ad Sistemi (Domain Name System)
        67: "DHCP_SERVER",  # Dinamik Ana Bilgisayar Yapılandırma Protokolü Sunucu Portu
        68: "DHCP_CLIENT",  # DHCP İstemci Portu
        69: "TFTP",  # Basit Dosya Aktarım Protokolü (Trivial File Transfer Protocol)
        123: "NTP",  # Ağ Zaman Protokolü (Network Time Protocol)
        161: "SNMP",  # Basit Ağ Yönetim Protokolü (Simple Network Management Protocol)
        162: "SNMP_TRAP",  # SNMP Tuzak Bildirim Portu
        514: "SYSLOG",  # Sistem Günlük Kaydı Protokolü
        5060: "SIP",  # Oturum Başlatma Protokolü (VoIP)
        443: "QUIC_HTTP3",  # UDP üzerinden çalışan güvenli HTTP/3 ve QUIC
    }  # Yaygın UDP servis portları haritası

    def classify_datagram(self, datagram: UDPDatagram) -> Dict[str, Any]:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Datagramın hedef/kaynak portu ve yük özniteliklerine göre protokolünü ve amacını sınıflandırır."""
        src_p = datagram.header.src_port  # Kaynak port
        dst_p = datagram.header.dst_port  # Hedef port
        payload = datagram.payload  # Uygulama verisi

        matched_port = dst_p if dst_p in self.KNOWN_PORTS else (src_p if src_p in self.KNOWN_PORTS else None)  # Eşleşen port
        proto_name = self.KNOWN_PORTS.get(matched_port, "GENERIC_UDP") if matched_port else "GENERIC_UDP"  # Protokol adı

        details: Dict[str, Any] = {  # details: Dict[str, Any] = {
            "protokol": proto_name,  # Tespit edilen protokol adı
            "kaynak_port": src_p,  # Kaynak port numarası
            "hedef_port": dst_p,  # Hedef port numarası
            "yuk_uzunlugu": len(payload),  # Yük uzunluğu
            "checksum_gecerli": datagram.verify_checksum(),  # Sağlama toplamı doğrulama sonucu
            "detaylar": {},  # Protokole özgü derin analiz verileri
        }  # }

        if proto_name == "DNS" and len(payload) >= 12:  # DNS başlığı en az 12 bayt olmalıdır
            tx_id, flags, qd_count, an_count, ns_count, ar_count = struct.unpack("!HHHHHH", payload[:12])  # DNS başlık açımı
            is_response = bool(flags & 0x8000)  # QR biti (0: Sorgu / Query, 1: Yanıt / Response)
            details["detaylar"] = {  # details["detaylar"] = {
                "dns_transaction_id": hex(tx_id),  # 16-bit işlem kimliği
                "tur": "RESPONSE" if is_response else "QUERY",  # Sorgu veya yanıt tipi
                "soru_sayisi": qd_count,  # İletilen soru sayısı
                "cevap_sayisi": an_count,  # Dönen cevap sayısı
                "ek_kayit_sayisi": ar_count,  # EDNS0 / Ek kayıt sayısı (amplifikasyon göstergesi)
            }  # }
        elif proto_name == "NTP" and len(payload) >= 4:  # NTP yükü ilk baytı kontrol edilir
            first_byte = payload[0]  # İlk bayt: LI (2 bit) + VN (3 bit) + Mode (3 bit)
            leap_indicator = (first_byte >> 6) & 0x03  # Artık saniye uyarısı (0: yok, 3: senkronize değil)
            version = (first_byte >> 3) & 0x07  # NTP versiyonu (genellikle 3 veya 4)
            mode = first_byte & 0x07  # Mod (3: Client, 4: Server, 7: Private/monlist)
            mode_names = {1: "Symmetric Active", 2: "Symmetric Passive", 3: "Client", 4: "Server", 5: "Broadcast", 7: "Private/Monlist"}  # Mod adları
            details["detaylar"] = {  # details["detaylar"] = {
                "ntp_version": version,  # NTP protokol sürümü
                "leap_indicator": leap_indicator,  # Sıçrama göstergesi
                "mode_kod": mode,  # Sayısal mod kodu
                "mode_aciklama": mode_names.get(mode, f"Bilinmeyen Mod ({mode})"),  # Mod açıklaması
                "monlist_riski": (mode == 7),  # Mode 7 monlist amplifikasyon riski bayrağı
            }  # }
        elif proto_name in ("DHCP_SERVER", "DHCP_CLIENT") and len(payload) >= 240:  # DHCP/BOOTP sabit başlığı 236 bayt + 4 bayt cookie
            op_code = payload[0]  # BOOTP işlem kodu (1: BOOTREQUEST, 2: BOOTREPLY)
            magic_cookie = payload[236:240]  # DHCP Sihirli Çerezi (0x63, 0x82, 0x53, 0x63)
            details["detaylar"] = {  # details["detaylar"] = {
                "op_code": "BOOTREQUEST" if op_code == 1 else ("BOOTREPLY" if op_code == 2 else f"UNKNOWN({op_code})"),  # İşlem kodu
                "gecerli_magic_cookie": (magic_cookie == b"\x63\x82\x53\x63"),  # DHCP standardı doğrulaması
            }  # }
        return details  # Sınıflandırılmış analiz sözlüğü döndürülür

    @staticmethod  # Metot davranışını niteleyen Python dekoratörü
    def evaluate_amplification_factor(request_size: int, response_size: int, protocol: str) -> Dict[str, Any]:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """
        Bant Genişliği Amplifikasyon Faktörünü (BAF = Yanıt_Boyutu / İstek_Boyutu) hesaplar  # Bant Genişliği Amplifikasyon Faktörünü (BAF = Yanıt_Boyutu / İstek_Boyutu) hesaplar
        ve DDoS yansıtma tehdit seviyesini belirler.  # ve DDoS yansıtma tehdit seviyesini belirler.
        """
        safe_req_size = max(1, request_size)  # Sıfıra bölme hatasını önlemek için alt sınır
        baf = response_size / safe_req_size  # BAF (Bandwidth Amplification Factor) hesaplanır

        if baf >= 30.0 or (protocol == "NTP" and response_size > 1000):  # Kritik amplifikasyon eşiği
            seviye = "CRITICAL"  # Kritik risk derecesi
            risk_aciklamasi = f"{protocol} protokolünde BAF={baf:.2f}x ile devasa yansıtma / amplifikasyon DDoS riski tespit edildi!"  # Tehdit uyarısı
            onerilen_savunma = [  # onerilen_savunma = [
                "RFC 2827 / BCP 38: Ağ çıkışlarında kaynak IP doğrulaması (uRPF) ile IP sahteciliğini önleyin.",  # "RFC 2827 / BCP 38: Ağ çıkışlarında kaynak IP doğrulaması (uRPF) ile IP sahteciliğini önleyin.",
                "RRL (Response Rate Limiting): Aynı istemci IP'sine dönülen yanıt oranını kısıtlayın.",  # "RRL (Response Rate Limiting): Aynı istemci IP'sine dönülen yanıt oranını kısıtlayın.",
                "NTP Sunucularında 'monlist' ve Mode 7 sorgularını 'noquery' direktifiyle tamamen devre dışı bırakın.",  # "NTP Sunucularında 'monlist' ve Mode 7 sorgularını 'noquery' direktifiyle tamamen devre dışı bırakın.",
                "Açık DNS Çözümleyicilerini (Open Resolvers) kapatın; yalnızca yetkili iç ağlara sorgu izni verin.",  # "Açık DNS Çözümleyicilerini (Open Resolvers) kapatın; yalnızca yetkili iç ağlara sorgu izni verin.",
            ]  # Önerilen mühendislik kontrolleri
        elif baf >= 5.0:  # Orta / şüpheli seviye
            seviye = "SUSPICIOUS"  # Şüpheli risk derecesi
            risk_aciklamasi = f"{protocol} protokolünde BAF={baf:.2f}x amplifikasyon katsayısı gözlemlendi; izleme gerektirir."  # Açıklama
            onerilen_savunma = ["Rate limiting ve protokol doğrulama denetimlerini devreye alın."]  # Savunma
        else:  # Normal / dengeli trafik
            seviye = "SAFE"  # Güvenli
            risk_aciklamasi = f"{protocol} trafiğinde istek ve yanıt boyutları simetriktir (BAF={baf:.2f}x)."  # Normal durum
            onerilen_savunma = ["Standart güvenlik duvarı filtrelemesi yeterlidir."]  # Standart kontrol

        return {  # return {
            "protokol": protocol,  # Analiz edilen protokol
            "istek_bayt": request_size,  # İstek bayt boyutu
            "yanit_bayt": response_size,  # Yanıt bayt boyutu
            "baf_katsayisi": round(baf, 2),  # Yuvarlanmış BAF katsayısı
            "tehdit_seviyesi": seviye,  # Tehdit kategorisi
            "risk_aciklamasi": risk_aciklamasi,  # Açıklama metni
            "onerilen_savunma": onerilen_savunma,  # Savunma maddeleri listesi
        }  # Değerlendirme raporu döndürülür

    @staticmethod  # Metot davranışını niteleyen Python dekoratörü
    def audit_source_port_randomization(port_list: List[int]) -> Dict[str, Any]:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """
        DNS/NTP istemcilerinin kaynak port seçimindeki rastgeleliği (entropi) denetler.  # DNS/NTP istemcilerinin kaynak port seçimindeki rastgeleliği (entropi) denetler.
        Sıralı (sequential) veya tahmin edilebilir portlar Kaminsky DNS Cache Poisoning  # Sıralı (sequential) veya tahmin edilebilir portlar Kaminsky DNS Cache Poisoning
        ve UDP oturum enjeksiyonuna karşı savunmasızdır.  # ve UDP oturum enjeksiyonuna karşı savunmasızdır.
        """
        if len(port_list) < 3:  # İstatistiksel analiz için en az 3 port örneği gerekir
            return {"durum": "INSUFFICIENT_DATA", "guvenli_mi": False, "aciklama": "Yetersiz örneklem."}  # Yetersiz veri dönüşü

        diffs = [port_list[i + 1] - port_list[i] for i in range(len(port_list) - 1)]  # Ardışık portlar arasındaki farklar
        is_strictly_sequential = all(d == 1 for d in diffs)  # Portlar ardışık +1 şeklinde artıyor mu kontrolü
        is_constant_step = len(set(diffs)) == 1  # Tüm adımlar sabit bir farkla mı ilerliyor kontrolü

        # Basit Shannon Entropi yaklaşımı (port dağılımı çeşitliliği)
        port_counts: Dict[int, int] = {}  # Port frekansları sözlüğü
        for p in port_list:  # Port listesinde gezin
            port_counts[p] = port_counts.get(p, 0) + 1  # Portun görülme sıklığını artır
        total = len(port_list)  # Toplam port sayısı
        entropy = -sum((cnt / total) * math.log2(cnt / total) for cnt in port_counts.values())  # Entropi formülü

        ephemeral_count = sum(1 for p in port_list if 1024 <= p <= 65535)  # Ephemeral port aralığında olanların sayısı
        ephemeral_ratio = ephemeral_count / total  # Ephemeral port oranı

        if is_strictly_sequential or is_constant_step:  # Eğer portlar tahmin edilebilir şekilde artıyorsa
            guvenli_mi = False  # Güvensiz
            zafiyet = "KAMINSKY_DNS_POISONING_VULNERABLE (Tahmin Edilebilir Sıralı Kaynak Portları)"  # Zafiyet tanımı
            tavsiye = "İstemci/Çözümleyici RFC 5452 gereğince Kaynak Port Rastgeleleştirmesini (SPRs) etkinleştirmelidir."  # Tavsiye
        else:  # Portlar rastgele dağılıyorsa
            guvenli_mi = True  # Güvenli
            zafiyet = "YOK (Yüksek Port Entropisi)"  # Zafiyet bulunmadı
            tavsiye = "Mevcut kaynak port entropisi Kaminsky zehirleme saldırılarına karşı dirençlidir."  # Tavsiye

        return {  # return {
            "orneklem_boyutu": total,  # İncelenen port sayısı
            "entropi_degeri": round(entropy, 3),  # Hesaplanan Shannon entropisi
            "ephemeral_orani": round(ephemeral_ratio, 2),  # Ephemeral port kullanım oranı
            "sirali_mi": is_strictly_sequential,  # Kesin ardışık artış bayrağı
            "guvenli_mi": guvenli_mi,  # Güvenlik değerlendirmesi
            "zafiyet": zafiyet,  # Zafiyet detayı
            "tavsiye": tavsiye,  # Çözüm tavsiyesi
        }  # Entropi raporu döndürülür

    @staticmethod  # Metot davranışını niteleyen Python dekoratörü
    def detect_traffic_anomalies(  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        datagrams: List[UDPDatagram], flood_pps_threshold: float = 100.0, scan_port_threshold: int = 5  # datagrams: List[UDPDatagram], flood_pps_threshold: float = 100.0, scan_port_threshold: int = 5
    ) -> Dict[str, Any]:  # ) -> Dict[str, Any]:
        """
        UDP trafiğindeki anomalileri analiz eder:  # UDP trafiğindeki anomalileri analiz eder:
        1. UDP Flood: Belirli bir kaynak IP'den gelen aşırı yüksek paket hızı (pps).  # 1. UDP Flood: Belirli bir kaynak IP'den gelen aşırı yüksek paket hızı (pps).
        2. UDP Port Sweep / Scan: Tek bir kaynak IP'den birçok farklı hedef porta paket gönderilmesi.  # 2. UDP Port Sweep / Scan: Tek bir kaynak IP'den birçok farklı hedef porta paket gönderilmesi.
        """
        ip_packet_times: Dict[str, List[float]] = {}  # Kaynak IP başına paket zaman damgaları listesi
        ip_dst_ports: Dict[str, set] = {}  # Kaynak IP başına hedeflenen benzersiz portlar kümesi
        anomalies: List[Dict[str, Any]] = []  # Tespit edilen anomali kayıtları listesi

        for dg in datagrams:  # Tüm datagramlar üzerinde döngü
            src = dg.src_ip  # Kaynak IP
            dst_p = dg.header.dst_port  # Hedef port
            t = dg.timestamp  # Zaman damgası

            if src not in ip_packet_times:  # Eğer IP ilk kez görülüyorsa
                ip_packet_times[src] = []  # Boş liste ata
                ip_dst_ports[src] = set()  # Boş küme ata

            ip_packet_times[src].append(t)  # Zaman damgasını kaydet
            ip_dst_ports[src].add(dst_p)  # Hedef portu kümeye ekle

        for src, times in ip_packet_times.items():  # Her kaynak IP için istatistikleri değerlendir
            distinct_ports = ip_dst_ports[src]  # Hedeflenen benzersiz port sayısı
            if len(distinct_ports) >= scan_port_threshold:  # Eğer eşikten fazla farklı porta paket atıldıysa
                anomalies.append({  # anomalies.append({
                    "tip": "UDP_PORT_SWEEP_SCAN",  # Anomali tipi: Port taraması
                    "kaynak_ip": src,  # Şüpheli kaynak IP
                    "hedef_port_sayisi": len(distinct_ports),  # Taranan port sayısı
                    "ornek_portlar": sorted(list(distinct_ports))[:10],  # İlk 10 taranan port
                    "aciklama": f"{src} adresinden {len(distinct_ports)} farklı UDP portuna tarama trafiği gözlemlendi.",  # Açıklama
                })  # Anomali listesine ekle

            if len(times) >= 2:  # Hız hesabı için en az 2 paket zamanı gereklidir
                duration = max(0.001, max(times) - min(times))  # Toplam süre (sıfıra bölmeyi engelle)
                pps = len(times) / duration  # Saniye başına düşen paket sayısı (PPS)
                if pps >= flood_pps_threshold:  # Eğer PPS eşiği aşıldıysa
                    anomalies.append({  # anomalies.append({
                        "tip": "UDP_FLOOD_ATTACK",  # Anomali tipi: UDP Flood
                        "kaynak_ip": src,  # Saldırgan kaynak IP
                        "paket_hizi_pps": round(pps, 2),  # Tespit edilen paket hızı
                        "toplam_paket": len(times),  # Gönderilen toplam paket
                        "aciklama": f"{src} adresinden {pps:.2f} pps hızında aşırı yoğun UDP trafiği gözlemlendi (Flood).",  # Açıklama
                    })  # Anomali listesine ekle

        return {  # return {
            "toplam_paket_incelendi": len(datagrams),  # İncelenen toplam paket sayısı
            "farkli_kaynak_sayisi": len(ip_packet_times),  # Farklı kaynak IP adedi
            "anomali_tespit_edildi_mi": len(anomalies) > 0,  # Anomali var mı bayrağı
            "tespit_edilen_anomaliler": anomalies,  # Tespit listesi
        }  # Anomali raporu sözlüğü döndürülür
