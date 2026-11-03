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
G060: HTTP/2 ve HTTP/3 Mimari, İkili Çerçeveleme ve QUIC Güvenlik Analiz Motoru.

Bu modül; RFC 7540 / RFC 9113 (HTTP/2 İkili Çerçeveleme), RFC 9000 (QUIC Taşıma Protokolü)
ve RFC 9114 (HTTP/3) standartlarına dayalı olarak;
  1. 9 Baytlık HTTP/2 ikili çerçeve başlıklarını ayrıştırır ve sınırlar,
  2. Akış seviyesi ve bağlantı seviyesi kural ihlallerini denetler,
  3. CVE-2023-44487 HTTP/2 Hızlı Sıfırlama (Rapid Reset) DDoS saldırısını tespit eder,
  4. RFC 9000 3x Anti-Amplification (Yükseltme Önleme) sınırını denetler,
  5. HTTP/2 ve HTTP/3 Hat Başı Tıkanması (Head-of-Line Blocking) davranışlarını karşılaştırır.
"""

# Standart ikili veri paketleme ve açma kütüphanesi
import struct
# Veri sınıfları ve tip modelleme kütüphanesi
from dataclasses import dataclass, field
# Tip ipuçları ve koleksiyon türleri
from typing import Dict, List, Optional, Tuple, Any
# Zaman damgaları ve pencere hesaplamaları için zaman modülü
import time


# ------------------------------------------------------------------------------
# ÖZEL HATA HİYERARŞİSİ (EXCEPTIONS)
# ------------------------------------------------------------------------------

class HTTPAnalyzerError(Exception):
    """HTTP analiz motorunun temel istisna sınıfı."""
    # Üst sınıf mirası sağlar
    pass


class HTTP2ValidationError(HTTPAnalyzerError):
    """HTTP/2 protokol kuralları ihlal edildiğinde fırlatılır."""
    # Kural doğrulama hatalarında fırlatılır
    pass


class HTTP2MalformedFrameError(HTTP2ValidationError):
    """Bozuk, kesilmiş veya bayt uzunluğu uyumsuz HTTP/2 çerçevelerinde fırlatılır."""
    # Yapısal ikili çerçeve hatalarında fırlatılır
    pass


class HTTP2RapidResetAttackError(HTTP2ValidationError):
    """CVE-2023-44487 Rapid Reset DDoS saldırısı tespit edildiğinde fırlatılır."""
    # Hızlı sıfırlama taşkınlarında fırlatılır
    pass


class QUICAmplificationError(HTTPAnalyzerError):
    """RFC 9000 Bölüm 8.1 Anti-Amplification 3x kuralı aşıldığında fırlatılır."""
    # UDP yükseltme engeli ihlalinde fırlatılır
    pass


# ------------------------------------------------------------------------------
# HTTP/2 VE HTTP/3 SABİTLERİ (RFC 7540 / RFC 9114)
# ------------------------------------------------------------------------------

# HTTP/2 Çerçeve Tipleri (Frame Types - RFC 7540 Bölüm 6)
HTTP2_FRAME_TYPES: Dict[int, str] = {
    # 0x00: İstek veya yanıt gövdesi yükü (Data payload)
    0x00: "DATA",
    # 0x01: İstek/yanıt başlıkları (Headers bloğu)
    0x01: "HEADERS",
    # 0x02: Akış önceliklendirme parametreleri
    0x02: "PRIORITY",
    # 0x03: Bir akışın derhal sonlandırılması/iptali
    0x03: "RST_STREAM",
    # 0x04: Bağlantı veya uç nokta yapılandırma ayarları
    0x04: "SETTINGS",
    # 0x05: Sunucu itme (server push) taahhüdü
    0x05: "PUSH_PROMISE",
    # 0x06: Canlılık ve gecikme (RTT) ölçüm mesajı
    0x06: "PING",
    # 0x07: Bağlantının kapatıldığını bildiren genel çerçeve
    0x07: "GOAWAY",
    # 0x08: Akış kontrolü (flow control) pencere güncellemesi
    0x08: "WINDOW_UPDATE",
    # 0x09: Büyük başlık bloklarının devam çerçevesi
    0x09: "CONTINUATION"
}

# HTTP/2 Standart Hata Kodları (Error Codes - RFC 7540 Bölüm 7)
HTTP2_ERROR_CODES: Dict[int, str] = {
    # 0x0: Başarılı, hata yok
    0x0: "NO_ERROR",
    # 0x1: Genel protokol ihlali
    0x1: "PROTOCOL_ERROR",
    # 0x2: Sunucu içi işleme hatası
    0x2: "INTERNAL_ERROR",
    # 0x3: Akış kontrol penceresi ihlali
    0x3: "FLOW_CONTROL_ERROR",
    # 0x4: SETTINGS bekleme süresi aşımı
    0x4: "SETTINGS_TIMEOUT",
    # 0x5: Kapatılmış akışa çerçeve gönderimi
    0x5: "STREAM_CLOSED",
    # 0x6: Çerçeve boyutu sınır aşımı
    0x6: "FRAME_SIZE_ERROR",
    # 0x7: İstenen akış reddedildi
    0x7: "REFUSED_STREAM",
    # 0x8: Akış iptal edildi (Rapid Reset saldırısında kötüye kullanılır)
    0x8: "CANCEL",
    # 0x9: Sıkıştırma hatası (HPACK)
    0x9: "COMPRESSION_ERROR",
    # 0xA: TCP bağlantı hatası
    0xA: "CONNECT_ERROR",
    # 0xB: Aşırı yüklenme durumu
    0xB: "ENHANCE_YOUR_CALM"
}

# Varsayılan maksimum HTTP/2 çerçeve yükü boyutu (16384 bayt = 16 KB)
DEFAULT_MAX_FRAME_SIZE = 16384

# RFC 9000 Bölüm 8.1 uyarınca doğrulanmamış istemciye gönderilebilecek maksimum katsayı (3x)
QUIC_ANTI_AMPLIFICATION_FACTOR = 3


# ------------------------------------------------------------------------------
# VERİ YAPILARI (DATACLASSES)
# ------------------------------------------------------------------------------

@dataclass
class HTTP2FrameHeader:
    """9 Baytlık Standart HTTP/2 Çerçeve Başlığı Modeli (RFC 7540 Bölüm 4.1)."""
    # 24-bit yük uzunluğu (0 - 16,777,215 bayt)
    payload_length: int
    # 8-bit çerçeve tipi kodu
    frame_type: int
    # Çerçeve tipinin insan tarafından okunabilir metin adı
    frame_type_name: str
    # 8-bit çerçeve bayrakları (ör. END_STREAM = 0x1, END_HEADERS = 0x4)
    flags: int
    # 31-bit akış kimliği (Stream Identifier)
    stream_id: int
    # Başlığın kendisinin sabit bayt uzunluğu (her zaman 9 bayttır)
    header_length: int = 9


# ------------------------------------------------------------------------------
# İKİLİ ÇERÇEVE AYRIŞTIRMA VE DOĞRULAMA (BINARY FRAMING)
# ------------------------------------------------------------------------------

def parse_http2_frame_header(data: bytes) -> HTTP2FrameHeader:
    """
    Ham bayt dizisinden 9 baytlık standart HTTP/2 çerçeve başlığını ayrıştırır ve doğrular.
    
    Başlık Düzeni (9 Bayt):
      +-----------------------------------------------+
      |                 Length (24)                   |
      +---------------+---------------+---------------+
      |   Type (8)    |   Flags (8)   |
      +-+-------------+---------------+---------------+
      |R|                 Stream Identifier (31)      |
      +=+=============================================+
    """
    # Veri uzunluğunun en az 9 bayt olduğunu kontrol et
    if len(data) < 9:
        # 9 bayttan kısa ise bozuk çerçeve hatası üret
        raise HTTP2MalformedFrameError(
            f"HTTP/2 cerceve basligi en az 9 bayt uzunlugunda olmalidir. Alinan bayt: {len(data)}"
        )
    
    # İlk 3 bayttan 24-bit uzunluğu büyük sonlu (big-endian) olarak ayrıştır
    payload_len = int.from_bytes(data[0:3], byteorder="big")
    
    # 4. ve 5. baytlardan Type (1 bayt) ve Flags (1 bayt) değerlerini oku
    frame_type = data[3]
    flags = data[4]
    
    # Son 4 bayttan 32-bit tamsayı oku ve 1-bitlik rezerve biti maskele (0x7FFFFFFF)
    raw_stream_id = struct.unpack("!I", data[5:9])[0]
    # En yüksek anlamlı biti (R - Reserved) sıfırla, 31-bit akış ID'sini elde et
    stream_id = raw_stream_id & 0x7FFFFFFF
    
    # Çerçeve tipinin RFC 7540 standartlarında tanımlı olup olmadığını denetle
    if frame_type not in HTTP2_FRAME_TYPES:
        # Tanımsız çerçeve tipi hatası fırlat
        raise HTTP2ValidationError(
            f"Bilinmeyen HTTP/2 cerceve tipi: {frame_type}. Tanimli tipler: {list(HTTP2_FRAME_TYPES.keys())}."
        )
        
    # Varsayılan maksimum çerçeve boyutu aşımını kontrol et (16384 bayt)
    if payload_len > DEFAULT_MAX_FRAME_SIZE:
        # Taşıma sınırı aşımı hatası fırlat
        raise HTTP2ValidationError(
            f"HTTP/2 cerceve boyutu izin verilen maksimum siniri ({DEFAULT_MAX_FRAME_SIZE} bayt) asamaz. "
            f"Bildirilen: {payload_len} bayt."
        )
        
    # Gövde verisinin bildirilen boyutla tam uyuşup uyuşmadığını doğrula
    total_expected = 9 + payload_len
    # Eğer akıştaki toplam bayt beklenen boyuttan eksikse
    if len(data) < total_expected:
        # Veri akışı kesilmesi hatası fırlat
        raise HTTP2MalformedFrameError(
            f"Bildirilen cerceve boyutu ({payload_len} bayt) ile mevcut yuk boyutu "
            f"({len(data) - 9} bayt) uyusmuyor. Veri akisi kesilmis."
        )
        
    # Çerçeve tipi ile Akış ID ilişkisini doğrula (RFC 7540 kuralları)
    # DATA, HEADERS, PRIORITY, RST_STREAM çerçeveleri mutlaka bir akışa ait olmalıdır (Stream ID > 0)
    if frame_type in [0x00, 0x01, 0x02, 0x03] and stream_id == 0:
        # Akış ID 0 ihlali hatası ver
        frame_name = HTTP2_FRAME_TYPES[frame_type]
        raise HTTP2ValidationError(
            f"{frame_name} cercevesi Akis ID 0 uzerinden gonderilemez. Yalnizca pozitif akislar icindir."
        )
        
    # SETTINGS ve PING çerçeveleri yalnızca bağlantı seviyesinde geçerlidir (Stream ID == 0 olmalıdır)
    if frame_type in [0x04, 0x06] and stream_id != 0:
        # Bağlantı seviyesi ihlali hatası ver
        frame_name = HTTP2_FRAME_TYPES[frame_type]
        raise HTTP2ValidationError(
            f"{frame_name} cercevesi yalnizca baglanti seviyesinde (Akis ID 0) gecerlidir. "
            f"Gelen Akis ID: {stream_id}."
        )
        
    # Başlık nesnesini oluştur ve döndür
    return HTTP2FrameHeader(
        payload_length=payload_len,
        frame_type=frame_type,
        frame_type_name=HTTP2_FRAME_TYPES[frame_type],
        flags=flags,
        stream_id=stream_id
    )


def validate_frame_payload_rules(header: HTTP2FrameHeader, payload: bytes) -> None:
    """
    Belirli çerçeve tipleri için RFC 7540 özel yük (payload) kısıtlamalarını doğrular.
    """
    # RST_STREAM çerçevesi (Type 0x03): Tam olarak 4 baytlık hata kodu içermelidir (RFC 7540 Bölüm 6.4)
    if header.frame_type == 0x03:
        if len(payload) != 4:
            raise HTTP2MalformedFrameError(
                f"RST_STREAM cercevesi tam olarak 4 baytlik hata kodu tasimalidir. Alinan: {len(payload)} bayt."
            )
            
    # PING çerçevesi (Type 0x06): Tam olarak 8 baytlık yük içermelidir (RFC 7540 Bölüm 6.7)
    if header.frame_type == 0x06:
        if len(payload) != 8:
            raise HTTP2MalformedFrameError(
                f"PING cercevesi tam olarak 8 baytlik yuk tasimalidir. Alinan: {len(payload)} bayt."
            )
            
    # SETTINGS çerçevesi (Type 0x04): Her ayar 6 bayt olduğundan (2 bayt Tanımlayıcı + 4 bayt Değer),
    # toplam yük uzunluğu kesinlikle 6'nın katı olmalıdır (RFC 7540 Bölüm 6.5)
    if header.frame_type == 0x04:
        if len(payload) % 6 != 0:
            raise HTTP2MalformedFrameError(
                f"SETTINGS cerceve yuku 6 baytin kati olmalidir. Alinan: {len(payload)} bayt."
            )


# ------------------------------------------------------------------------------
# GÜVENLİK TEHDİT ANALİZİ (RAPID RESET & ANTI-AMPLIFICATION)
# ------------------------------------------------------------------------------

def detect_rapid_reset_attack(
    reset_count: int,
    window_seconds: float = 1.0,
    threshold: int = 100
) -> bool:
    """
    CVE-2023-44487 HTTP/2 Rapid Reset DDoS saldırısını tespit eder.
    Saldırgan bir akış açar (HEADERS) ve sunucu kaynağı ayırır ayırmaz hemen ardından
    RST_STREAM göndererek sunucuyu boğar. Belirli bir zaman penceresindeki iptal sayısı
    eşiği aşarsa saldırı alarmı verilir.
    """
    # Sıfırlama oranını (iptal/saniye) hesapla
    rate = reset_count / max(0.001, window_seconds)
    
    # Eğer iptal oranı izin verilen eşik değerini aşıyorsa
    if rate > threshold:
        # Rapid Reset saldırı istisnası fırlat
        raise HTTP2RapidResetAttackError(
            f"HTTP/2 Rapid Reset Saldirisi (CVE-2023-44487) tespit edildi! "
            f"RST_STREAM iptal orani: {rate:.1f} iptal/sn (Esik: {threshold})."
        )
        
    # Eşik aşılmadıysa işlem güvenlidir
    return True


def enforce_quic_anti_amplification(
    client_initial_bytes: int,
    attempted_server_bytes: int,
    is_address_validated: bool = False
) -> bool:
    """
    RFC 9000 Bölüm 8.1 QUIC Yükseltme Önleme (Anti-Amplification Limit) kuralını denetler.
    Sunucu, istemcinin IP adresinin sahte (spoofed) olmadığını doğrulayana kadar,
    istemciden aldığı toplam bayt miktarının en fazla 3 katı (3x) kadar veri gönderebilir.
    Bu kural sunucuların UDP Amplification DDoS silahı olarak kullanılmasını engeller.
    """
    # Eğer istemci adresi kriptografik olarak doğrulandıysa limit kalkar
    if is_address_validated:
        return True
        
    # İzin verilen maksimum sunucu yanıt boyutu (3 katı)
    allowed_max_bytes = client_initial_bytes * QUIC_ANTI_AMPLIFICATION_FACTOR
    
    # Eğer sunucunun göndermeye çalıştığı bayt sınırı aşıyorsa
    if attempted_server_bytes > allowed_max_bytes:
        # Anti-amplification ihlali hatası fırlat
        raise QUICAmplificationError(
            f"QUIC Anti-Amplification Limiti (3x) asildi! Dogrulanmamis istemciye en fazla "
            f"{allowed_max_bytes} bayt gonderilebilir. Gonderme girisimi: {attempted_server_bytes} bayt."
        )
        
    # Sınır aşılmadıysa izin ver
    return True


# ------------------------------------------------------------------------------
# PROTOKOL SİMÜLASYONU VE KARŞILAŞTIRMA MATRİSİ
# ------------------------------------------------------------------------------

def simulate_hol_blocking(
    packet_loss_stream_id: int,
    total_streams: int = 3
) -> Dict[str, Any]:
    """
    HTTP/2 (TCP üzerinde) ve HTTP/3 (QUIC / UDP üzerinde) protokollerinin
    paket kaybı anındaki Hat Başı Tıkanması (Head-of-Line Blocking) davranışını simüle eder.
    """
    # Simülasyon sonuç nesnesini oluştur
    http2_stream_status: Dict[int, str] = {}
    http3_stream_status: Dict[int, str] = {}
    
    # 1'den total_streams'e kadar her akış için durum belirle
    for s_id in range(1, total_streams + 1):
        # HTTP/2: Tek bir TCP segmenti kaybolursa TÜM akışlar TCP kuyruğunda kilitlenir
        http2_stream_status[s_id] = "BLOKLANDI (TCP Kuyruk Beklemesi)"
        
        # HTTP/3 (QUIC): Yalnızca paketi kaybolan akış bekler, diğer akışlar bağımsızca akar
        if s_id == packet_loss_stream_id:
            http3_stream_status[s_id] = "BEKLIYOR (Yalnizca bu akisin yeniden iletimi bekleniyor)"
        else:
            http3_stream_status[s_id] = "AKIS DEVAM EDIYOR (Sifir Blokaj - Bagimsiz QUIC Akisi)"
            
    # Karşılaştırma sonucunu döndür
    return {
        "kaybolan_paket_akisi": packet_loss_stream_id,
        "toplam_akis_sayisi": total_streams,
        "http2_sonucu": {
            "tasima_protokolu": "TCP",
            "etki": "Tum akislar durdu (TCP Head-of-Line Blocking)",
            "akis_durumlari": http2_stream_status
        },
        "http3_sonucu": {
            "tasima_protokolu": "QUIC (UDP)",
            "etki": "Diger tum akislar kesintisiz calisti (Bagimsiz Akis Mimarisi)",
            "akis_durumlari": http3_stream_status
        }
    }


def compare_http_versions_detailed() -> Dict[str, Any]:
    """
    HTTP/1.1, HTTP/2 ve HTTP/3 protokollerinin mimari, performans ve
    güvenlik farklarını gösteren teknik karşılaştırma matrisini üretir.
    """
    # Kapsamlı karşılaştırma matrisini sözlük olarak döndür
    return {
        "tasima_katmani": {
            "http_1_1": "TCP (Metin tabanli istek/yanit)",
            "http_2": "TCP (Ikili cerceveleme ve akis coklama)",
            "http_3": "QUIC uzerinde UDP (Kullanici alaninda guvenli tasıma)"
        },
        "head_of_line_blocking": {
            "http_1_1": "Uygulama katmaninda tam blokaj (1 baglanti = 1 istek)",
            "http_2": "Uygulama katmaninda cozuldu, ancak TCP katmaninda blokaj devam eder",
            "http_3": "Tamamen cozuldu (QUIC bagimsiz akis yonetimi)"
        },
        "baslik_sikistirma": {
            "http_1_1": "Yok (Her istekte tum basliklar acikca tekrar gonderilir)",
            "http_2": "HPACK (Statik ve Dinamik tablo - Akislar arasi senkronizasyon gerektirir)",
            "http_3": "QPACK (Sirali olmayan baslik acma - HoL blokaji onler)"
        },
        "baglanti_kurulum_gecikmesi": {
            "http_1_1": "TCP (1-RTT) + TLS (1-2 RTT) = 2-3 RTT",
            "http_2": "TCP (1-RTT) + TLS (1-2 RTT) = 2-3 RTT",
            "http_3": "QUIC + TLS 1.3 Birlesik El Sikismasi = 1-RTT veya 0-RTT"
        },
        "baglanti_gocu_connection_migration": {
            "http_1_1": "Desteklenmez (IP degisince baglanti kopar)",
            "http_2": "Desteklenmez (IP degisince TCP baglantisi sonlanir)",
            "http_3": "Desteklenir (Connection ID sayesinde ag degisimi kesintisizdir)"
        },
        "ana_guvenlik_tehditleri": {
            "http_1_1": "Request Smuggling, Eavesdropping, Pipelining aciklari",
            "http_2": "Rapid Reset (CVE-2023-44487), HPACK Bomb, Ping Flood",
            "http_3": "UDP Amplification DDoS, Algoritmik Islem Yuklenmesi"
        }
    }


def build_synthetic_h2_frame(
    frame_type: int,
    flags: int,
    stream_id: int,
    payload: bytes
) -> bytes:
    """
    Birim testler ve laboratuvar simülasyonları için standart 9 baytlık
    HTTP/2 çerçevesini ikili (binary) olarak inşa eder.
    """
    # Yük uzunluğunu 24-bit büyük sonlu (big-endian) 3 bayta dönüştür
    length_bytes = len(payload).to_bytes(3, byteorder="big")
    # Tip (1 bayt) ve Bayraklar (1 bayt)
    type_and_flags = bytes([frame_type, flags])
    # 31-bit akış kimliğini 4 bayt büyük sonlu tamsayıya paketle
    stream_id_bytes = struct.pack("!I", stream_id & 0x7FFFFFFF)
    
    # 9 baytlık başlığı oluştur
    header = length_bytes + type_and_flags + stream_id_bytes
    
    # Başlık ve yükü birleştirerek döndür
    return header + payload
