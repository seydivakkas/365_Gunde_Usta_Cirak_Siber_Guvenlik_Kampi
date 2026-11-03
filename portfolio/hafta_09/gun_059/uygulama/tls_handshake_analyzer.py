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
G059: HTTPS ve TLS El Sıkışması (Handshake) Analiz ve Güvenlik Motoru.

Bu modül, TLS Kayıt Katmanı (Record Layer) ve El Sıkışma (Handshake) protokol
mesajlarını RFC 5246 (TLS 1.2), RFC 8446 (TLS 1.3) ve RFC 6066 (SNI) standartlarına
uygun olarak ayrıştırır, kriptografik zayıflıkları, sürüm düşürme (downgrade) saldırılarını,
CRIME sıkıştırma risklerini ve iletme gizliliği (PFS) ihlallerini denetler.
"""

# Standart ikili veri paketleme ve ayrıştırma kütüphanesi
import struct
# Güvenli rastgele bayt üretimi için kriptografik modül
import secrets
# Veri yapılarını tip güvenliğiyle modellemek için dataclass
from dataclasses import dataclass, field
# Tip ipuçları ve koleksiyon tipleri
from typing import Optional, List, Dict, Tuple, Any
# Düzenli ifadeler ile hostname ve veri deseni doğrulama
import re


# ------------------------------------------------------------------------------
# ÖZEL HATA SINIFLARI (EXCEPTION HIERARCHY)
# ------------------------------------------------------------------------------

class TLSAnalyzerError(Exception):
    """TLS analiz motorunun temel hata sınıfı."""
    # Üst sınıf istisnası olarak kalıtım sağlar
    pass


class TLSValidationError(TLSAnalyzerError):
    """TLS protokol kuralları veya güvenlik gereksinimleri ihlal edildiğinde fırlatılır."""
    # Protokol doğrulaması başarısız olduğunda fırlatılır
    pass


class TLSMalformedRecordError(TLSValidationError):
    """Bozuk, kesilmiş veya bayt uzunluğu uyumsuz TLS kayıtlarında fırlatılır."""
    # Kayıt katmanı yapısal bozukluklarında fırlatılır
    pass


class TLSDowngradeDetectedError(TLSValidationError):
    """Man-in-the-Middle (MitM) sürüm düşürme saldırısı tespit edildiğinde fırlatılır."""
    # Güvenlik koruması sentinel baytları uyuşmazlığında fırlatılır
    pass


# ------------------------------------------------------------------------------
# PROTOKOL SABİTLERİ VE EŞLEŞTİRMELER
# ------------------------------------------------------------------------------

# TLS Kayıt Katmanı İçerik Tipleri (Content Types - RFC 5246 / RFC 8446)
TLS_CONTENT_TYPES: Dict[int, str] = {
    # Şifreleme parametrelerinin değiştiğini bildiren mesaj (TLS 1.3'te uyumluluk harici kaldırıldı)
    20: "ChangeCipherSpec",
    # Kritik hata veya uyarı bildiren mesaj (ör. bad_record_mac, close_notify)
    21: "Alert",
    # Oturum kurma ve anahtar mutabakatı protokol mesajları
    22: "Handshake",
    # Asıl şifrelenmiş HTTP verisini (HTTPS) taşıyan yük
    23: "ApplicationData"
}

# TLS El Sıkışma Mesaj Tipleri (Handshake Types)
TLS_HANDSHAKE_TYPES: Dict[int, str] = {
    # İstemcinin sunucuya başlattığı ilk tanışma mesajı
    1: "ClientHello",
    # Sunucunun istemciye kriptografik seçimlerini bildirdiği yanıt
    2: "ServerHello",
    # Oturum biletinin verildiği mesaj
    4: "NewSessionTicket",
    # TLS 1.3 şifrelenmiş uzantı bildirimleri
    8: "EncryptedExtensions",
    # Sunucu veya istemci X.509 dijital sertifikası
    11: "Certificate",
    # TLS 1.2 DHE/ECDHE geçici anahtar parametreleri
    12: "ServerKeyExchange",
    # Çift taraflı mTLS kimlik doğrulaması için sunucu sertifika talebi
    13: "CertificateRequest",
    # TLS 1.2 sunucu selamlama evresinin tamamlandığını bildiren mesaj
    14: "ServerHelloDone",
    # Sertifika özel anahtar sahipliğini kanıtlayan imza
    15: "CertificateVerify",
    # TLS 1.2 istemci anahtar takas mesajı (Pre-Master Secret aktarımı)
    16: "ClientKeyExchange",
    # El sıkışmanın bütünlüğünü doğrulayan HMAC/AEAD özeti mesajı
    20: "Finished"
}

# TLS Protokol Sürüm Kodları
TLS_VERSIONS: Dict[int, str] = {
    # Tarihi SSL 3.0 sürümü (POODLE nedeniyle yasaklı)
    0x0300: "SSL 3.0",
    # RFC 2246 TLS 1.0 (BEAST nedeniyle güvensiz)
    0x0301: "TLS 1.0",
    # RFC 4346 TLS 1.1 (Zayıf algoritmalar nedeniyle tedavülden kalktı)
    0x0302: "TLS 1.1",
    # RFC 5246 TLS 1.2 (Yaygın kullanılan standart)
    0x0303: "TLS 1.2",
    # RFC 8446 TLS 1.3 (Modern, 1-RTT, güvenli standart)
    0x0304: "TLS 1.3"
}

# Güvensiz veya Zayıf Olarak İşaretlenen Şifreleme Paketleri (Cipher Suites)
INSECURE_CIPHER_KEYWORDS: List[str] = [
    # Şifreleme yapılmadığını belirten tehlikeli paket
    "NULL",
    # 40-bit veya 56-bit tarihi dışa aktarma (export) zayıflığı
    "EXPORT",
    # Tek DES algoritması (tamamen kırılmış)
    "DES",
    # Triple-DES algoritması (Sweet32 zaafiyeti)
    "3DES",
    # Stream cipher RC4 algoritması (Bar Mitzvah / RC4 NOMORE zaafiyeti)
    "RC4",
    # Güvensiz MD5 hash algoritması
    "MD5",
    # Statik RSA anahtar değişimi (PFS - Perfect Forward Secrecy sağlamaz)
    "TLS_RSA_WITH",
    # Blok şifreleme CBC modu (Lucky13, POODLE varyantları)
    "_CBC_"
]

# RFC 8446 Bölüm 4.1.3 Sürüm Düşürme (Downgrade Protection) Sentinel Sabitleri
# TLS 1.3 destekleyen bir sunucu, istemcinin TLS 1.2 talep etmesi durumunda ServerHello.random son 8 baytına bu değeri yazar
DOWNGRADE_SENTINEL_TLS12 = bytes.fromhex("444f574e47524401")  # "DOWNGRD\x01"
# TLS 1.1 veya altına düşürüldüğünde kullanılan sentinel baytları
DOWNGRADE_SENTINEL_TLS11 = bytes.fromhex("444f574e47524402")  # "DOWNGRD\x02"

# RFC standardına göre tek bir TLS kaydının maksimum yük boyutu (16 KB = 16384 bayt)
MAX_TLS_RECORD_PAYLOAD_SIZE = 16384


# ------------------------------------------------------------------------------
# VERİ YAPILARI (DATACLASSES)
# ------------------------------------------------------------------------------

@dataclass
class TLSRecordHeader:
    """TLS Kayıt Katmanı (Record Layer) Başlık Veri Modeli."""
    # 1 baytlık içerik tipi (20: ChangeCipherSpec, 21: Alert, 22: Handshake, 23: ApplicationData)
    content_type: int
    # İçerik tipinin insan tarafından okunabilir metin karşılığı
    content_type_name: str
    # 2 baytlık ham protokol sürüm numarası (ör. 0x0303)
    version_raw: int
    # Protokol sürümünün metin karşılığı (ör. "TLS 1.2")
    version_name: str
    # 2 baytlık yük uzunluğu (big-endian tamsayı)
    payload_length: int
    # Başlığın kendisinin bayt uzunluğu (her zaman 5 bayttır)
    header_length: int = 5


@dataclass
class TLSSecurityFinding:
    """Güvenlik denetimi sonucunda tespit edilen bulgu modeli."""
    # Zaafiyet seviyesi: "KRITIK", "YUKSEK", "ORTA", "BILGI"
    severity: str
    # Kural veya zaafiyet kodu (ör. "CRIME_VULNERABILITY", "NO_FORWARD_SECRECY")
    code: str
    # Tespitin ayrıntılı açıklaması
    description: str
    # Sorunun giderilmesi için önerilen mimari aksiyon
    remediation: str


# ------------------------------------------------------------------------------
# TEMEL AYRIŞTIRICI VE DOĞRULAYICI FONKSİYONLAR
# ------------------------------------------------------------------------------

def parse_record_layer_header(data: bytes) -> TLSRecordHeader:
    """
    Ham bayt dizisinden 5 baytlık TLS Record Layer başlığını ayrıştırır ve doğrular.
    
    Format:
      - Bayt 0    : Content-Type (uint8)
      - Bayt 1-2  : Protocol Version (uint16 big-endian)
      - Bayt 3-4  : Length (uint16 big-endian)
    """
    # Veri uzunluğunun en az 5 bayt olduğunu kontrol et
    if len(data) < 5:
        # 5 bayttan kısa ise biçimsiz kayıt hatası üret
        raise TLSMalformedRecordError(
            f"TLS Record Layer basligi en az 5 bayt uzunlugunda olmalidir. Alinan bayt: {len(data)}"
        )
    
    # 5 baytlık başlığı big-endian olarak ayrıştır (B: 1 bayt, H: 2 bayt, H: 2 bayt)
    content_type, version_raw, payload_len = struct.unpack("!BHH", data[:5])
    
    # Content-Type'ın geçerli RFC değerlerinden biri olduğunu denetle
    if content_type not in TLS_CONTENT_TYPES:
        # Tanımsız içerik tipi hatası fırlat
        raise TLSValidationError(
            f"Bilinmeyen TLS Content-Type: {content_type}. Gecerli tipler: {list(TLS_CONTENT_TYPES.keys())}."
        )
    
    # SSL 2.0 (0x0200) veya SSL 3.0 (0x0300) eski sürümlerini kontrol et
    if version_raw < 0x0301:
        # Tarihi ve tehlikeli protokol sürümü tespiti
        version_label = TLS_VERSIONS.get(version_raw, f"0x{version_raw:04x}")
        # Güvensiz protokol sürümü reddedilir
        raise TLSValidationError(
            f"Eski ve guvensiz SSL/TLS surumu reddedildi: {version_label} (POODLE/DROWN riski)."
        )
    
    # RFC 5246 maksimum yük sınırını (16384 bayt) aşıp aşmadığını kontrol et
    if payload_len > MAX_TLS_RECORD_PAYLOAD_SIZE:
        # Taşıma sınırı aşımı hatası fırlat
        raise TLSValidationError(
            f"TLS Record uzunlugu izin verilen maksimum siniri ({MAX_TLS_RECORD_PAYLOAD_SIZE} bayt) asamaz. "
            f"Bildirilen: {payload_len} bayt."
        )
    
    # Veri akışında başlık haricinde kalan gövdenin bildirilen uzunlukla uyuşup uyuşmadığını doğrula
    total_expected = 5 + payload_len
    # Eğer toplam veri bildirilen boyuttan eksikse
    if len(data) < total_expected:
        # Veri kesilmesi veya taşması uyuşmazlığı hatası ver
        raise TLSMalformedRecordError(
            f"Bildirilen kayit uzunlugu ({payload_len} bayt) ile mevcut veri uzunlugu "
            f"({len(data) - 5} bayt) uyusmuyor. Veri akisi kesilmis."
        )

    # Eğer kayıt katmanı bir El Sıkışma (Handshake - 22) mesajı taşıyorsa
    if content_type == 22 and payload_len > 0:
        # El sıkışma başlığı en az 4 bayt olmalıdır (1 bayt tip + 3 bayt uzunluk)
        if payload_len < 4:
            # 4 bayttan kısa el sıkışma başlığı bozuk kayıt hatası fırlatır
            raise TLSMalformedRecordError(
                f"Handshake mesaji basligi en az 4 bayt olmalidir. Mevcut: {payload_len} bayt."
            )
        # 1 bayt Handshake tipini oku
        handshake_type = data[5]
        # Tanımlı el sıkışma mesaj tipleri arasında yer alıp almadığını doğrula
        if handshake_type not in TLS_HANDSHAKE_TYPES:
            # Geçersiz el sıkışma tipi tespit edildiğinde doğrulama hatası fırlat
            raise TLSValidationError(
                f"Gecersiz TLS Handshake tipi: {handshake_type}. Tanimli tipler: {list(TLS_HANDSHAKE_TYPES.keys())}."
            )
    
    # Başarılı ayrıştırma sonucunu nesne olarak döndür
    return TLSRecordHeader(
        content_type=content_type,
        content_type_name=TLS_CONTENT_TYPES[content_type],
        version_raw=version_raw,
        version_name=TLS_VERSIONS.get(version_raw, f"Bilinmeyen (0x{version_raw:04x})"),
        payload_length=payload_len
    )


def validate_sni_hostname(hostname: str) -> bool:
    """
    RFC 6066 Bölüm 3 standartlarına göre Server Name Indication (SNI) host adını doğrular.
    """
    # Boş veya boşluk karakterlerinden oluşan host adlarını reddet
    if not hostname or not hostname.strip():
        # Geçersiz SNI hatası fırlat
        raise TLSValidationError("SNI hostname alani bos veya yalnizca bosluk olamaz.")
    
    # Hostname içinde zararlı null-byte (\x00) bulunup bulunmadığını denetle
    if "\x00" in hostname:
        # Enjeksiyon engeli için hata fırlat
        raise TLSValidationError("SNI hostname icinde null-byte barindiramaz.")
    
    # Hostname uzunluğunun RFC standardındaki 255 karakteri aşmadığını doğrula
    if len(hostname) > 255:
        # Maksimum sınır aşımı hatası üret
        raise TLSValidationError(f"SNI hostname 255 karakterden uzun olamaz. Uzunluk: {len(hostname)}")
    
    # RFC 1035 / RFC 1123 domain adı sözdizimi doğrulaması (nokta ile ayrılmış etiketler)
    domain_regex = re.compile(
        r"^(?=.{1,255}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
    )
    # Düzenli ifade eşleşmesini kontrol et
    if not domain_regex.match(hostname):
        # Geçersiz karakter veya biçim uyarısı ver
        raise TLSValidationError(f"Gecersiz SNI domain formati: '{hostname}'.")
    
    # Başarılı ise True döndür
    return True


def check_compression_security(methods: List[int]) -> None:
    """
    TLS sıkıştırma algoritmalarını denetler. 0x00 (Null) haricindeki sıkıştırma
    yöntemleri CRIME saldırısına (CVE-2012-4929) yol açtığı için kesinlikle reddedilir.
    """
    # Eğer sıkıştırma listesi boşsa işlem yapma
    if not methods:
        # Boş liste geçilebilir
        return
    
    # 0x00 haricinde herhangi bir sıkıştırma algoritması tanımlı mı?
    non_null_compressions = [m for m in methods if m != 0]
    # Eğer DEFLATE veya başka bir yöntem seçilmişse
    if non_null_compressions:
        # CRIME güvenlik açığı hatası fırlat
        raise TLSValidationError(
            f"CRIME (CVE-2012-4929) zaafiyetine yol acan TLS veri sikistirma yontemleri tespit edildi: "
            f"{non_null_compressions}. TLS sikistirmasi devre disi birakilmalidir (yalnizca 0x00 kabul edilir)."
        )


def verify_downgrade_protection(
    client_supported_max_version: str,
    server_random: bytes,
    negotiated_version: str
) -> bool:
    """
    RFC 8446 Bölüm 4.1.3 uyarınca sürüm düşürme (downgrade) saldırısı denetimi yapar.
    Eğer istemci TLS 1.3 destekliyor ve sunucu TLS 1.2 ile yanıt veriyorsa,
    sunucunun ürettiği random alanının son 8 baytı 'DOWNGRD\x01' sentinel'i ile eşleştiğinde
    araya giren bir saldırganın (MitM) ClientHello paketini bozduğu kesinleşir.
    """
    # Sunucu random baytlarının en az 8 bayt olduğunu doğrula (standart 32 bayttır)
    if len(server_random) < 8:
        # Yetersiz rastgele veri hatası
        raise TLSValidationError("Server Random alani en az 8 bayt uzunlugunda olmalidir.")
    
    # Son 8 baytı çıkar
    last_8_bytes = server_random[-8:]
    
    # İstemci TLS 1.3 önermiş ancak sunucu ile TLS 1.2 uzlaşılmışsa
    if client_supported_max_version == "TLS 1.3" and negotiated_version == "TLS 1.2":
        # Son 8 bayt TLS 1.2 downgrade sentinel baytına eşit mi kontrol et
        if last_8_bytes == DOWNGRADE_SENTINEL_TLS12 or b"DOWNGRD\x01" in server_random:
            # Sürüm düşürme saldırısı tespit edildiğinde kritik hata fırlat
            raise TLSDowngradeDetectedError(
                "TLS Surum Dusurme (Downgrade Attack) tespit edildi! Sunucu gercekte TLS 1.3 destekliyor "
                "ancak aradaki ag saldirgani baglantiyi zorla TLS 1.2'ye dusurmeye calisiyor (RFC 8446 Sentinel Tespiti)."
            )
    
    # İstemci TLS 1.3 veya 1.2 desteklerken sunucu TLS 1.1 veya altına düştüyse
    if client_supported_max_version in ["TLS 1.3", "TLS 1.2"] and negotiated_version in ["TLS 1.1", "TLS 1.0"]:
        # TLS 1.1 downgrade sentinel'i kontrol et
        if last_8_bytes == DOWNGRADE_SENTINEL_TLS11 or b"DOWNGRD\x02" in server_random:
            # Kritik downgrade saldırısı hatası ver
            raise TLSDowngradeDetectedError(
                "Kritik TLS Surum Dusurme Saldirisi! Baglanti guvensiz TLS 1.1/1.0 seviyesine zorlaniyor."
            )
            
    # Hiçbir downgrade belirtisi yoksa güvenlidir
    return True


def assess_cipher_suite_security(cipher_suite_name: str) -> Dict[str, Any]:
    """
    Verilen şifreleme paketinin (Cipher Suite) kriptografik gücünü, iletme gizliliğini (PFS)
    ve zafiyet durumunu değerlendirir.
    """
    # Büyük harfe dönüştürerek standartlaştır
    cipher_upper = cipher_suite_name.strip().upper()
    # Zaafiyet bulguları listesi
    findings: List[str] = []
    # İletme gizliliği (PFS) bayrağı varsayılan olarak False
    pfs_supported = False
    
    # Geçici Diffie-Hellman (ECDHE / DHE) anahtar değişimi kontrolü
    if "ECDHE" in cipher_upper or "DHE" in cipher_upper:
        # Geçici anahtarlar iletme gizliliği (PFS) sağlar
        pfs_supported = True
    elif cipher_upper.startswith("TLS_AES_") or cipher_upper.startswith("TLS_CHACHA20_"):
        # TLS 1.3 şifreleme paketleri doğası gereği her zaman PFS zorunludur
        pfs_supported = True
    else:
        # Statik RSA anahtar değişimi varsa iletme gizliliği sağlanamaz
        findings.append("Iletme Gizliligi (PFS) bulunmuyor: Ozel anahtar sizdirilirsa gecmis trafik cozulur.")
    
    # Yasaklı veya güvensiz anahtar kelimeleri tara
    for kw in INSECURE_CIPHER_KEYWORDS:
        # Eğer yasaklı kelime cipher adında geçiyorsa
        if kw in cipher_upper:
            # Uygun güvenlik zafiyeti mesajını ekle
            if kw == "NULL":
                findings.append("Sifreleme yok (NULL Cipher): Trafik tamamen acik metindir!")
            elif kw == "EXPORT":
                findings.append("Tarihi zayif sifreleme (EXPORT 40/56 bit): FREAK saldirisina acik.")
            elif kw in ["DES", "3DES"]:
                findings.append("Zayif blok boyutu (64-bit DES/3DES): Sweet32 zaafiyeti.")
            elif kw == "RC4":
                findings.append("Kirilmis akis sifresi (RC4): Bar Mitzvah / NOMORE zaafiyetleri.")
            elif kw == "MD5":
                findings.append("Zayif kriptografik ozet algoritmasi (MD5): Carpisma saldirilari mumkun.")
            elif kw == "_CBC_":
                findings.append("Blok sifreleme CBC modu: Lucky Thirteen ve dolgu saldirilarina hassas.")
    
    # Genel güvenlik seviyesini belirle
    is_secure = (len(findings) == 0 and pfs_supported)
    
    # Değerlendirme sonucunu sözlük olarak döndür
    return {
        "cipher_suite": cipher_suite_name,
        "pfs_supported": pfs_supported,
        "is_secure": is_secure,
        "is_tls13_cipher": cipher_upper.startswith("TLS_AES_") or cipher_upper.startswith("TLS_CHACHA20_"),
        "findings": findings
    }


def compare_tls12_and_tls13() -> Dict[str, Any]:
    """
    TLS 1.2 ve TLS 1.3 protokolleri arasındaki mimari, performans (RTT)
    ve güvenlik farklarının kapsamlı teknik karşılaştırma matrisini üretir.
    """
    # Karşılaştırma matrisi verisini oluştur ve döndür
    return {
        "el_sikisma_gecikmesi": {
            "tls_1_2": "2-RTT (Uygulama verisi iletilmeden once 2 tam gidis-donus gerekir)",
            "tls_1_3": "1-RTT (Varsayilan olarak tek gidis-donuste anahtar degisimi ve selamlama biter)",
            "tls_1_3_0rtt": "0-RTT Early Data (Oturum devaminda istemci ilk pakette veri gonderebilir, ancak replay riski tasir)"
        },
        "kriptografik_budama": {
            "tls_1_2_durum": "Statik RSA, CBC modlari, RC4, 3DES, SHA-1 gibi tarihi algoritmalar desteklenir.",
            "tls_1_3_durum": "Yalnizca AEAD (GCM, Poly1305, CCM) ve yalnizca PFS zorunludur. Zayif algoritmalar tamamen kaldirilmistir."
        },
        "veri_sikistirma": {
            "tls_1_2": "Protokol seviyesinde sikistirma desteklenir (CRIME saldirisi riski dogurur).",
            "tls_1_3": "Protokol seviyesinde sikistirma tamamen yasaklanmistir (Sifir CRIME riski)."
        },
        "gizlilik_ve_metadene": {
            "tls_1_2": "Sertifikalar ve bircok uzanti agda acik metin olarak dinlenebilir.",
            "tls_1_3": "ServerHello disindaki tum el sikisma mesajlari (Sertifika dahil) sifrelenir (EncryptedExtensions)."
        }
    }


# ------------------------------------------------------------------------------
# SYNTHETIC RAW TLS PACKET GENERATOR (LAB & TEST TOOL)
# ------------------------------------------------------------------------------

def build_raw_client_hello_record(
    hostname: str,
    use_tls13: bool = True,
    include_insecure_ciphers: bool = False,
    enable_compression: bool = False
) -> bytes:
    """
    Birim testler ve laboratuvar simülasyonları için standartlara uygun
    ham ikili (binary) TLS ClientHello kaydı inşa eder.
    """
    # Hostname kurallarını doğrula
    validate_sni_hostname(hostname)
    
    # 32 bayt rastgele veri üret (Client Random)
    client_random = secrets.token_bytes(32)
    # Oturum kimliği (Session ID - 32 bayt sahte ID)
    session_id = secrets.token_bytes(32)
    
    # Şifreleme paket listesini hazırla
    if use_tls13:
        # TLS 1.3 şifreleme paketleri (RFC 8446)
        # 0x1301: TLS_AES_128_GCM_SHA256
        # 0x1302: TLS_AES_256_GCM_SHA384
        # 0x1303: TLS_CHACHA20_POLY1305_SHA256
        ciphers = [0x1302, 0x1303, 0x1301]
    else:
        # Standart TLS 1.2 ECDHE paketleri
        # 0xC02F: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        # 0xC030: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        ciphers = [0xC030, 0xC02F]
        
    # Eğer güvensiz paketlerin eklenmesi istendiyse
    if include_insecure_ciphers:
        # 0x002F: TLS_RSA_WITH_AES_128_CBC_SHA
        # 0x000A: TLS_RSA_WITH_3DES_EDE_CBC_SHA
        # 0x0005: TLS_RSA_WITH_RC4_128_SHA
        ciphers.extend([0x002F, 0x000A, 0x0005])
    
    # Şifreleme paketlerini ikili formata paketle (her biri 2 bayt)
    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    # Şifreleme paketleri uzunluğu (2 bayt big-endian)
    cipher_len = struct.pack("!H", len(cipher_bytes))
    
    # Sıkıştırma metotları
    if enable_compression:
        # 2 metot: 0x00 (Null) ve 0x01 (DEFLATE - Güvensiz)
        compression_bytes = b"\x02\x00\x01"
    else:
        # Yalnızca 1 metot: 0x00 (Null)
        compression_bytes = b"\x01\x00"
        
    # Uzantıları (Extensions) inşa et
    extensions_body = bytearray()
    
    # Uzantı 1: SNI (Server Name Indication - Type 0x0000)
    host_bytes = hostname.encode("utf-8")
    # ServerNameList yapısı: 2 bayt liste uzunluğu + 1 bayt tip (0=hostname) + 2 bayt isim boyutu + isim
    sni_list_payload = struct.pack("!BH", 0, len(host_bytes)) + host_bytes
    sni_extension_payload = struct.pack("!H", len(sni_list_payload)) + sni_list_payload
    # Uzantı başlığı: 2 bayt Tip (0) + 2 bayt Uzunluk
    extensions_body.extend(struct.pack("!HH", 0x0000, len(sni_extension_payload)))
    extensions_body.extend(sni_extension_payload)
    
    # Uzantı 2: Supported Versions (Type 0x002B) - TLS 1.3 için kritik uzantı
    if use_tls13:
        # 1 bayt uzunluk + 2 bayt TLS 1.3 (0x0304) + 2 bayt TLS 1.2 (0x0303)
        sup_versions_payload = b"\x04\x03\x04\x03\x03"
        extensions_body.extend(struct.pack("!HH", 0x002B, len(sup_versions_payload)))
        extensions_body.extend(sup_versions_payload)
        
        # Uzantı 3: Key Share (Type 0x0033) - TLS 1.3 geçici X25519 açık anahtar örneği
        # Grup 0x001D (X25519), 32 bayt sahte açık anahtar
        fake_pub_key = secrets.token_bytes(32)
        # 2 bayt client_shares uzunluğu + 2 bayt grup + 2 bayt key_exchange uzunluğu + anahtar
        ks_entry = struct.pack("!HH", 0x001D, len(fake_pub_key)) + fake_pub_key
        ks_payload = struct.pack("!H", len(ks_entry)) + ks_entry
        extensions_body.extend(struct.pack("!HH", 0x0033, len(ks_payload)))
        extensions_body.extend(ks_payload)
        
    # Toplam uzantı uzunluğunu 2 bayt olarak öne ekle
    extensions_payload = struct.pack("!H", len(extensions_body)) + bytes(extensions_body)
    
    # ClientHello Gövdesini Birleştir:
    # 2 bayt Legacy Version (0x0303 - TLS 1.2 uyumluluğu) + 32 bayt Random + 1 bayt SessionID boyutu + SessionID + Ciphers + Compressions + Extensions
    client_hello_body = bytearray()
    client_hello_body.extend(struct.pack("!H", 0x0303))
    client_hello_body.extend(client_random)
    client_hello_body.extend(struct.pack("!B", len(session_id)))
    client_hello_body.extend(session_id)
    client_hello_body.extend(cipher_len)
    client_hello_body.extend(cipher_bytes)
    client_hello_body.extend(compression_bytes)
    client_hello_body.extend(extensions_payload)
    
    # Handshake Başlığını Oluştur:
    # 1 bayt Type (1 = ClientHello) + 3 bayt Length (24-bit big endian)
    handshake_len = len(client_hello_body)
    handshake_header = struct.pack("!B", 1) + handshake_len.to_bytes(3, byteorder="big")
    handshake_record_payload = handshake_header + bytes(client_hello_body)
    
    # Record Layer Başlığını Oluştur:
    # 1 bayt Content-Type (22 = Handshake) + 2 bayt Version (0x0303) + 2 bayt Length
    record_header = struct.pack("!BHH", 22, 0x0303, len(handshake_record_payload))
    
    # Nihai paketi döndür
    return record_header + handshake_record_payload


# ------------------------------------------------------------------------------
# ANA DEĞERLENDİRME VE RAPORLAMA FONKSİYONU
# ------------------------------------------------------------------------------

def analyze_tls_handshake_session(scenario_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Belirli bir TLS el sıkışma senaryosunu baştan uca analiz eder,
    protokol parametrelerini ayrıştırır ve siber güvenlik skorunu üretir.
    """
    # Senaryo adı ve protokol sürümünü al
    senaryo_adi = scenario_data.get("senaryo_adi", "Bilinmeyen Senaryo")
    protokol_surumu = scenario_data.get("protokol_surumu", "TLS 1.2")
    ciphers = scenario_data.get("cipher_suites", [])
    compressions = scenario_data.get("compression_methods", [0])
    has_downgrade = scenario_data.get("has_downgrade_sentinel", False)
    is_0rtt = scenario_data.get("session_resumption_0rtt", False)
    sni = scenario_data.get("sni_hostname", "localhost")
    
    # SNI doğrulamasını işlet
    sni_valid = validate_sni_hostname(sni)
    
    # Bulgular listesi
    security_findings: List[TLSSecurityFinding] = []
    
    # Sıkıştırma kontrolü yap
    try:
        check_compression_security(compressions)
    except TLSValidationError as err:
        security_findings.append(TLSSecurityFinding(
            severity="KRITIK",
            code="CRIME_VULNERABILITY",
            description=str(err),
            remediation="TLS duzeyinde veri sikistirmasini derhal kapatin. Yalnizca Null (0x00) kabul edin."
        ))
        
    # Downgrade kontrolü yap
    if has_downgrade:
        security_findings.append(TLSSecurityFinding(
            severity="KRITIK",
            code="DOWNGRADE_ATTACK_DETECTED",
            description="Sunucu random alaninda DOWNGRD sentineli tespit edildi. Agda aktif MitM saldirisi mevcut.",
            remediation="TLS 1.3 destekleyen istemciler icin TLS 1.2'ye yapay gecisleri engelleyin."
        ))
        
    # 0-RTT kontrolü yap
    if is_0rtt:
        security_findings.append(TLSSecurityFinding(
            severity="ORTA",
            code="TLS13_0RTT_REPLAY_RISK",
            description="TLS 1.3 0-RTT Erken Veri aktarimi aktif. Ag saldirganlari tarafindan tekrar (replay) saldirisi yapilabilir.",
            remediation="0-RTT isteklerini yalnizca idempotent ve guvenli HTTP metodlarinda (GET/HEAD) kabul edin."
        ))
        
    # Şifreleme paketlerini değerlendir
    secure_ciphers_count = 0
    for c in ciphers:
        eval_res = assess_cipher_suite_security(c)
        if eval_res["is_secure"]:
            secure_ciphers_count += 1
        else:
            for f in eval_res["findings"]:
                security_findings.append(TLSSecurityFinding(
                    severity="YUKSEK",
                    code="INSECURE_CIPHER_SUITE",
                    description=f"{c} paketi guvensiz: {f}",
                    remediation="Zayif sifreleme paketini sunucu ve istemci beyaz listesinden cikarin."
                ))
                
    # Güvenlik skoru hesapla (100 üzerinden)
    base_score = 100
    for finding in security_findings:
        if finding.severity == "KRITIK":
            base_score -= 40
        elif finding.severity == "YUKSEK":
            base_score -= 20
        elif finding.severity == "ORTA":
            base_score -= 10
            
    # Skoru 0 ile 100 arasında sınırla
    final_score = max(0, min(100, base_score))
    
    # Karşılaştırma matrisini al
    karsilastirma = compare_tls12_and_tls13()
    
    # Rapor nesnesini oluştur ve döndür
    return {
        "senaryo_adi": senaryo_adi,
        "protokol_surumu": protokol_surumu,
        "sni_hostname": sni,
        "sni_gecerli": sni_valid,
        "toplam_sifre_paketi_sayisi": len(ciphers),
        "guvenli_sifre_paketi_sayisi": secure_ciphers_count,
        "guvenlik_skoru": final_score,
        "genel_durum": "GUVENLI" if final_score >= 80 else ("KOSULLU" if final_score >= 50 else "TEHLIKELI"),
        "bulgular": [
            {
                "seviye": f.severity,
                "kod": f.code,
                "aciklama": f.description,
                "cozum": f.remediation
            }
            for f in security_findings
        ],
        "karsilastirma_matrisi": karsilastirma
    }
